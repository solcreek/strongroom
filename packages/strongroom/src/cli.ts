#!/usr/bin/env node
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { Strongroom, StrongroomError } from './client.ts';
import { openapi, schemas, capabilities } from '../../../service/contract.ts';
import { parseConfig } from '../../../service/config.ts';

const help = {
  name: 'strongroom', version: capabilities.version, nonInteractive: true,
  commands: {
    encrypt: 'Read EncryptInput JSON from stdin or --input FILE; return {envelope}.',
    decrypt: 'Read DecryptInput JSON from stdin or --input FILE; return {plaintext}.',
    schema: 'Return OpenAPI; schema encrypt or schema decrypt returns the input JSON Schema. No network or credentials needed.',
    capabilities: 'Return local CLI/API capabilities. No network or credentials needed.',
    doctor: 'Check remote readiness and API version. Does not exercise token permissions or KMS.',
    'config-check': 'Validate STRONGROOM_CONFIG or JSON from --input FILE; no secrets returned.',
    init: 'Create random LOCAL DEVELOPMENT keys and tokens in --directory DIR (default .strongroom), with private file permissions.',
  },
  flags: { '--input': 'FILE or - (stdin)', '--output': 'Write JSON to a NEW file with mode 0600; existing files are never overwritten.', '--directory': 'init output directory', '--help': 'This JSON document', '--version': 'JSON version' },
  environment: ['STRONGROOM_URL', 'STRONGROOM_TOKEN', 'STRONGROOM_TOKEN_FILE'],
  output: { success: 'One JSON object on stdout, or --output FILE.', error: 'One JSON error object on stderr. No stack traces.' },
  exitCodes: { '0': 'success', '2': 'input/configuration error', '3': 'authentication/authorization error', '4': 'request/decryption rejected', '5': 'retryable network/provider error', '1': 'other failure' },
  limits: { maxInputBytes: 524288 },
};
function fail(message: string): never { throw new StrongroomError('INVALID_INPUT', message); }
async function readInput(file?: string): Promise<unknown> {
  let value: string;
  if (file && file !== '-') {
    if ((await stat(file)).size > 524288) fail('Input exceeds 524288 bytes.');
    value = await readFile(file, 'utf8');
  } else {
    if (process.stdin.isTTY) fail('Provide JSON on stdin or --input FILE. Run schema for input definitions.');
    const parts: Buffer[] = []; let length = 0;
    for await (const chunk of process.stdin) {
      const bytes = Buffer.from(chunk); length += bytes.length;
      if (length > 524288) fail('Input exceeds 524288 bytes.'); parts.push(bytes);
    }
    value = Buffer.concat(parts).toString('utf8');
  }
  try { return JSON.parse(value); } catch { fail('Input must be valid JSON. Run schema for input definitions.'); }
}
async function initialize(directory: string) {
  const dir = resolve(directory);
  await mkdir(dir, { recursive: false, mode: 0o700 });
  const token = randomBytes(32).toString('base64url');
  const config = { keys: { primary: { provider: 'local', kek: randomBytes(32).toString('base64url') } }, principals: [{
    tokenSha256: createHash('sha256').update(token).digest('hex'), tenantId: 'development', permissions: ['encrypt', 'decrypt'], keys: ['primary'],
  }] };
  const configPath = resolve(dir, 'config.json'), serverEnv = resolve(dir, 'server.env'), clientEnv = resolve(dir, 'client.env');
  const secret = { mode: 0o600, flag: 'wx' };
  await writeFile(configPath, JSON.stringify(config, null, 2) + '\n', secret);
  await writeFile(serverEnv, `STRONGROOM_ALLOW_LOCAL=true\nSTRONGROOM_CONFIG='${JSON.stringify(config)}'\n`, secret);
  await writeFile(clientEnv, `STRONGROOM_URL=http://127.0.0.1:8787\nSTRONGROOM_TOKEN=${token}\n`, secret);
  await writeFile(resolve(dir, '.gitignore'), '*\n', secret);
  return { mode: 'local-development-only', directory: dir, config: configPath, serverEnv, clientEnv, tenantId: 'development', key: 'primary' };
}
async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 1 && argv[0] === '--version') return { version: capabilities.version };
  if (argv.includes('--help') || argv.length === 0) return help;
  const command = argv.shift()!;
  const options: Record<string, string> = {};
  let schemaName: string | undefined;
  if (command === 'schema' && argv[0] && !argv[0].startsWith('--')) schemaName = argv.shift();
  const allowed = command === 'init' ? ['--directory', '--output'] : ['encrypt', 'decrypt', 'config-check'].includes(command) ? ['--input', '--output'] : ['--output'];
  while (argv.length) {
    const flag = argv.shift()!;
    if (!allowed.includes(flag) || Object.hasOwn(options, flag)) fail('Unknown or repeated option. Run --help.');
    const value = argv.shift(); if (!value || value.startsWith('--')) fail('Option requires a value.'); options[flag] = value;
  }
  let result: unknown;
  switch (command) {
    case 'schema':
      if (schemaName && !['encrypt', 'decrypt'].includes(schemaName)) fail('Schema must be encrypt or decrypt.');
      result = schemaName ? { $schema: 'https://json-schema.org/draft/2020-12/schema', ...(schemaName === 'encrypt' ? schemas.EncryptInput : schemas.DecryptInput) } : openapi; break;
    case 'capabilities': result = { ...capabilities, cli: help }; break;
    case 'init': result = await initialize(options['--directory'] ?? '.strongroom'); break;
    case 'config-check': {
      let c;
      try { c = parseConfig({ ...process.env, ...(options['--input'] ? { STRONGROOM_CONFIG: JSON.stringify(await readInput(options['--input'])) } : {}) }); }
      catch { throw new StrongroomError('INVALID_CONFIG', 'Configuration is invalid. Check the documented schema and local-provider opt-in.'); }
      result = { valid: true, keyCount: Object.keys(c.keys).length, principalCount: c.principals.length, providers: [...new Set(Object.values(c.keys).map(v => v.provider))] }; break;
    }
    case 'encrypt': case 'decrypt': case 'doctor': {
      let token = process.env.STRONGROOM_TOKEN;
      if (!token && process.env.STRONGROOM_TOKEN_FILE) token = (await readFile(process.env.STRONGROOM_TOKEN_FILE, 'utf8')).trim();
      const client = new Strongroom({ url: process.env.STRONGROOM_URL ?? '', token: token ?? '' });
      if (command === 'doctor') {
        await client.ready(); const c = await client.capabilities(); result = { ready: true, apiVersion: c.apiVersion, checks: ['configuration', 'api-version'], unchecked: ['token-permissions', 'kms-connectivity'] };
      } else {
        const input = await readInput(options['--input']);
        result = command === 'encrypt' ? { envelope: await client.encrypt(input as never) } : { plaintext: await client.decrypt(input as never) };
      }
      break;
    }
    default: fail('Unknown command. Run --help.');
  }
  if (options['--output']) {
    await writeFile(options['--output'], JSON.stringify(result) + '\n', { mode: 0o600, flag: 'wx' });
    return undefined;
  }
  return result;
}
try {
  const result = await main();
  if (result !== undefined) process.stdout.write(JSON.stringify(result) + '\n');
} catch (error) {
  const e = error instanceof StrongroomError ? error : new StrongroomError('IO_ERROR', 'File operation failed; verify paths, permissions, and that output does not already exist.');
  process.stderr.write(JSON.stringify({ error: e.toJSON() }) + '\n');
  process.exitCode = e.retryable ? 5 : ['INVALID_INPUT', 'INVALID_CONFIG', 'IO_ERROR'].includes(e.code) ? 2 : [401, 403].includes(e.status) ? 3 : e.status >= 400 && e.status < 500 ? 4 : 1;
}
