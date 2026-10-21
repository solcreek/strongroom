#!/usr/bin/env node
import { readFile, writeFile, mkdir, open, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { Strongroom, StrongroomError } from './client.ts';
import { openapi, schemas, capabilities } from '../../../service/contract.ts';
import { ConfigError, parseConfig } from '../../../service/config.ts';
import { setupAws, teardownAws } from './setup-aws.ts';
import { setupGcp, teardownGcp } from './setup-gcp.ts';

const help = {
  name: 'strongroom', version: capabilities.version, nonInteractive: true,
  commands: {
    encrypt: 'Read EncryptInput JSON from stdin or --input FILE; return {envelope}. With --plaintext-file FILE (raw bytes, e.g. a data key), the input is just {context, key}.',
    decrypt: 'Read DecryptInput JSON from stdin or --input FILE. Choose where the secret goes, exactly one of: --output FILE ({plaintext} in a NEW 0600 file), --plaintext-file FILE (raw bytes in a NEW 0600 file; stdout returns {plaintextFile, bytes}), or --reveal ({plaintext} on stdout). With --envelope FILE (an encrypt result or a bare envelope), the input is just {context}.',
    schema: 'Return OpenAPI; schema encrypt or schema decrypt returns the input JSON Schema. No network or credentials needed.',
    capabilities: 'Return local CLI/API capabilities. No network or credentials needed.',
    doctor: 'Check remote readiness and API version. Does not exercise token permissions or KMS; use probe.',
    probe: 'Roundtrip a random synthetic value through the service with --key KEY --tenant TENANT: encrypt, decrypt, and confirm a changed context is rejected. Exercises the token grants and the real KMS; nothing is stored.',
    'config-check': 'Validate STRONGROOM_CONFIG or JSON from --input FILE; no secrets returned.',
    init: 'Create one LOCAL DEVELOPMENT deployment for --tenant (default development) on --port (default 8787) in --directory DIR (default .strongroom): random key and token, private file permissions. Run it once per tenant for a multi-tenant setup.',
    'setup aws': 'Create (or reuse) KMS alias/NAME and a least-privilege IAM user, or grant --role-name, using your aws CLI session; write a complete STRONGROOM_CONFIG and a caller token to a new private --directory; verify with a real Encrypt/Decrypt. Requires --tenant. Use --dry-run first: it prints the plan and the IAM permissions you need.',
    'setup gcp': 'Create (or reuse) Cloud KMS key ring NAME and CryptoKey --key, a service account NAME granted only that key, and a key file; or grant an existing Cloud Run/GKE --service-account (metadataServer, no key file). Uses your gcloud session; writes a complete STRONGROOM_CONFIG and a caller token to a new private --directory; verifies with real encrypt/decrypt. Requires --tenant. Use --dry-run first.',
    'teardown gcp': 'Inverse of setup gcp, for --tenant T or --name N: remove the key binding and delete the service account (or only the binding with --service-account). Versions are scheduled for destruction only with --delete-key; the key and its name are kept, since a deleted CryptoKey name can never be reused.',
    'teardown aws': 'Inverse of setup aws, for --tenant T or --name N: delete the IAM user and its access keys (or the role policy). The KMS key is kept unless --delete-key, which schedules deletion in 7 days.',
    token: 'Write a new random bearer token to a NEW --token-file FILE (mode 0600); return its SHA-256 digest, and a principal entry when --keys is given. A principal has no tenant: the deployment serves one ($.tenantId).',
  },
  flags: { '--input': 'FILE or - (stdin)', '--output': 'Write JSON to a NEW file with mode 0600; existing files are never overwritten.', '--directory': 'init output directory', '--port': 'init: local port for this deployment (default 8787)', '--token-file': 'token: new private file for the bearer token', '--tenant': 'setup and init: the one tenant the new deployment serves (setup derives resource names from it); teardown: derive the names to remove; probe: the context tenantId', '--keys': 'token: comma-separated key references', '--permissions': 'token: comma-separated encrypt,decrypt (default both)', '--key': 'probe and setup: key reference (setup default primary)', '--name': 'setup/teardown: resource name for the KMS alias or key ring and the IAM identity (default: derived from --tenant, sr-TENANT or sr-SLUG-HASH)', '--region': 'setup/teardown: AWS region (default: profile region)', '--profile': 'setup/teardown: aws CLI profile', '--role-name': 'setup/teardown: existing ECS task / EKS pod role to grant instead of creating a user', '--dry-run': 'setup: print the plan only (no value)', '--delete-key': 'teardown: also schedule KMS key deletion (no value)', '--no-verify': 'setup: skip the live Encrypt/Decrypt check (no value)', '--project': 'setup/teardown gcp: project (default: gcloud config)', '--location': 'setup/teardown gcp: Cloud KMS location (default global)', '--keyring': 'setup/teardown gcp: key ring (default --name)', '--service-account': 'setup/teardown gcp: existing workload service account to grant instead of creating one', '--protection-level': 'setup gcp: software (default) or hsm', '--destroy-scheduled-duration': 'setup gcp: how long destroyed versions stay restorable, 24h-120d (default 7d; fixed at key creation)', '--envelope': 'decrypt: file holding {envelope} or an envelope', '--reveal': 'decrypt: print {plaintext} on stdout (no value); without it decrypt needs --output or --plaintext-file', '--plaintext-file': 'encrypt: read raw plaintext bytes from FILE; decrypt: write raw plaintext bytes to a NEW 0600 FILE','--record': 'probe: recordId (default strongroom-probe)', '--help': 'This JSON document', '--version': 'JSON version' },
  environment: ['STRONGROOM_URL', 'STRONGROOM_TOKEN', 'STRONGROOM_TOKEN_FILE', 'STRONGROOM_CLOUD_RUN_ID_TOKEN (Cloud Run invoker IAM, e.g. $(gcloud auth print-identity-token))'],
  output: { success: 'One JSON object on stdout, or --output FILE.', error: 'One JSON error object on stderr. No stack traces.' },
  exitCodes: { '0': 'success', '2': 'input/configuration error', '3': 'authentication/authorization error', '4': 'request/decryption rejected', '5': 'retryable network/provider error', '6': 'service KMS credentials or key need operator action; do not retry unchanged', '1': 'other failure' },
  limits: { maxInputBytes: 524288 },
};
function fail(message: string): never { throw new StrongroomError('INVALID_INPUT', message); }
async function readInput(file?: string): Promise<unknown> {
  let bytes: Buffer;
  if (file && file !== '-') {
    if ((await stat(file)).size > 524288) fail('Input exceeds 524288 bytes.');
    bytes = await readFile(file);
  } else {
    if (process.stdin.isTTY) fail('Provide JSON on stdin or --input FILE. Run schema for input definitions.');
    const parts: Buffer[] = []; let length = 0;
    for await (const chunk of process.stdin) {
      const bytes = Buffer.from(chunk); length += bytes.length;
      if (length > 524288) fail('Input exceeds 524288 bytes.'); parts.push(bytes);
    }
    bytes = Buffer.concat(parts);
  }
  if (bytes.length > 524288) fail('Input exceeds 524288 bytes.');
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('Input must be valid UTF-8 JSON. Run schema for input definitions.'); }
}
// One local deployment per call, like production: run init once per tenant, each with its own --directory and --port.
async function initialize(directory: string, tenantId = 'development', portText = '8787') {
  // The tenant lands inside a single-quoted line in server.env, so allow only characters that cannot break out of it.
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(tenantId)) throw new StrongroomError('INVALID_INPUT', '--tenant must match ^[A-Za-z0-9._-]{1,64}$ for local development.', 0, false, undefined, '--tenant');
  const port = Number(portText);
  if (!/^\d+$/.test(portText) || port < 1 || port > 65535) throw new StrongroomError('INVALID_INPUT', '--port must be an integer from 1 to 65535.', 0, false, undefined, '--port');
  const dir = resolve(directory);
  await mkdir(dir, { recursive: false, mode: 0o700 });
  const token = randomBytes(32).toString('base64url');
  const config = { tenantId, keys: { primary: { provider: 'local', kek: randomBytes(32).toString('base64url') } }, principals: [{
    tokenSha256: createHash('sha256').update(token).digest('hex'), permissions: ['encrypt', 'decrypt'], keys: ['primary'],
  }] };
  const configPath = resolve(dir, 'config.json'), serverEnv = resolve(dir, 'server.env'), clientEnv = resolve(dir, 'client.env');
  const secret = { mode: 0o600, flag: 'wx' };
  await writeFile(configPath, JSON.stringify(config, null, 2) + '\n', secret);
  await writeFile(serverEnv, `STRONGROOM_ALLOW_LOCAL=true\nPORT=${port}\nSTRONGROOM_CONFIG='${JSON.stringify(config)}'\n`, secret);
  await writeFile(clientEnv, `STRONGROOM_URL=http://127.0.0.1:${port}\nSTRONGROOM_TOKEN=${token}\n`, secret);
  await writeFile(resolve(dir, '.gitignore'), '*\n', secret);
  return { mode: 'local-development-only', directory: dir, config: configPath, serverEnv, clientEnv, tenantId, key: 'primary', url: `http://127.0.0.1:${port}`,
    next: `node --env-file=${serverEnv} dist/server.js in a shell without PORT, HOST or any STRONGROOM_* variable set (already-set variables win over the file), then use ${clientEnv} for the CLI or SDK` };
}
// The token itself only ever reaches the new private file; stdout carries the digest the service configuration needs.
async function createToken(options: Record<string, string>) {
  const file = options['--token-file'];
  if (!file) fail('token requires --token-file FILE (a new path).');
  const list = (v?: string) => v?.split(',').map(s => s.trim()).filter(Boolean);
  const keys = list(options['--keys']), permissions = list(options['--permissions']) ?? ['encrypt', 'decrypt'];
  if (keys?.length === 0) fail('--keys needs at least one key reference.');
  if (permissions.some(p => !['encrypt', 'decrypt'].includes(p)) || new Set(permissions).size !== permissions.length) fail('--permissions must be encrypt, decrypt or encrypt,decrypt.');
  const token = randomBytes(32).toString('base64url');
  await writeFile(file, token + '\n', { mode: 0o600, flag: 'wx' });
  const tokenSha256 = createHash('sha256').update(token).digest('hex');
  return { tokenFile: resolve(file), tokenSha256, ...(keys ? { principal: { tokenSha256, permissions, keys } } : {}),
    next: 'Add the principal to STRONGROOM_CONFIG.principals; give the application STRONGROOM_TOKEN_FILE.' };
}
// Each failing step keeps the service error code, so exit codes and retryability stay meaningful.
async function probe(client: Strongroom, options: Record<string, string>) {
  const key = options['--key'], tenantId = options['--tenant'];
  if (!key || !tenantId) fail('probe requires --key KEY and --tenant TENANT.');
  const context = { tenantId, recordId: options['--record'] ?? 'strongroom-probe', purpose: 'strongroom-probe' };
  const plaintext = `probe-${randomBytes(16).toString('base64url')}`;
  const steps: { step: string; ms: number }[] = [];
  const step = async <T>(name: string, run: () => Promise<T>): Promise<T> => {
    const started = performance.now();
    try { const value = await run(); steps.push({ step: name, ms: Math.round(performance.now() - started) }); return value; }
    catch (e) {
      if (!(e instanceof StrongroomError)) throw e;
      throw new StrongroomError(e.code, `probe step ${name} failed: ${e.message}`, e.status, e.retryable, e.requestId, e.path);
    }
  };
  const envelope = await step('encrypt', () => client.encrypt({ key, context, plaintext }));
  await step('decrypt', async () => { if (await client.decrypt({ envelope, context }) !== plaintext) throw new StrongroomError('PROBE_MISMATCH', 'Decrypted value differs from the probe value.'); });
  await step('context-binding', async () => {
    try { await client.decrypt({ envelope, context: { ...context, purpose: 'strongroom-probe-changed' } }); }
    catch (e) { if (e instanceof StrongroomError && e.code === 'DECRYPT_FAILED') return; throw e; }
    throw new StrongroomError('PROBE_CONTEXT_NOT_BOUND', 'A changed context decrypted successfully; the service must not be used.');
  });
  return { ok: true, key, tenantId, steps, envelopeBytes: JSON.stringify(envelope).length };
}
async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 1 && argv[0] === '--version') return { version: capabilities.version };
  if (argv.includes('--help') || argv.length === 0) return help;
  const command = argv.shift()!;
  const options: Record<string, string> = {};
  let schemaName: string | undefined;
  if (['schema', 'setup', 'teardown'].includes(command) && argv[0] && !argv[0].startsWith('--')) schemaName = argv.shift();
  const booleans = ['--dry-run', '--delete-key', '--no-verify', '--reveal'];
  const allowed = command === 'setup' && schemaName === 'gcp' ? ['--name', '--tenant', '--key', '--project', '--location', '--keyring', '--service-account', '--protection-level', '--destroy-scheduled-duration', '--directory', '--dry-run', '--no-verify', '--output']
    : command === 'teardown' && schemaName === 'gcp' ? ['--name', '--tenant', '--key', '--project', '--location', '--keyring', '--service-account', '--delete-key', '--output']
    : command === 'setup' ? ['--name', '--tenant', '--key', '--region', '--profile', '--role-name', '--directory', '--dry-run', '--no-verify', '--output'] : command === 'teardown' ? ['--name', '--tenant', '--region', '--profile', '--role-name', '--delete-key', '--output'] : command === 'init' ? ['--directory', '--tenant', '--port', '--output'] : command === 'token' ? ['--token-file', '--keys', '--permissions', '--output'] : command === 'probe' ? ['--key', '--tenant', '--record', '--output'] : command === 'decrypt' ? ['--input', '--output', '--envelope', '--plaintext-file', '--reveal'] : command === 'encrypt' ? ['--input', '--output', '--plaintext-file'] : command === 'config-check' ? ['--input', '--output'] : ['--output'];
  while (argv.length) {
    const flag = argv.shift()!;
    if (!allowed.includes(flag) || Object.hasOwn(options, flag)) fail('Unknown or repeated option. Run --help.');
    if (booleans.includes(flag)) { options[flag] = 'true'; continue; }
    const value = argv.shift(); if (!value || value.startsWith('--')) fail('Option requires a value.'); options[flag] = value;
  }
  // Agents' and scripts' stdout often ends up in a transcript or a log, so a secret goes there only on request.
  // Decided before any input is read or any request is sent.
  if (command === 'decrypt') {
    const destinations = ['--output', '--plaintext-file', '--reveal'].filter(f => options[f]);
    if (destinations.length === 0) fail('decrypt returns a secret. Pass --output FILE or --plaintext-file FILE to write it to a new private file, or --reveal to print it on stdout.');
    if (destinations.length > 1) fail(`Choose one of --output, --plaintext-file or --reveal, not ${destinations.join(' and ')}.`);
  }
  let result: unknown;
  switch (command) {
    case 'schema':
      if (schemaName && !['encrypt', 'decrypt'].includes(schemaName)) fail('Schema must be encrypt or decrypt.');
      result = schemaName ? { $schema: 'https://json-schema.org/draft/2020-12/schema', ...(schemaName === 'encrypt' ? schemas.EncryptInput : schemas.DecryptInput) } : openapi; break;
    case 'capabilities': result = { ...capabilities, cli: help }; break;
    case 'init': result = await initialize(options['--directory'] ?? '.strongroom', options['--tenant'], options['--port']); break;
    case 'token': result = await createToken(options); break;
    case 'setup': case 'teardown':
      if (schemaName !== 'aws' && schemaName !== 'gcp') fail(`Usage: strongroom ${command} aws|gcp ... Run --help.`);
      result = schemaName === 'gcp' ? (command === 'setup' ? await setupGcp(options) : await teardownGcp(options))
        : command === 'setup' ? await setupAws(options) : await teardownAws(options); break;
    case 'config-check': {
      const serialized = options['--input'] ? JSON.stringify(await readInput(options['--input'])) : process.env.STRONGROOM_CONFIG;
      let c;
      try { c = parseConfig({ ...process.env, STRONGROOM_CONFIG: serialized }); }
      catch (error) { throw new StrongroomError('INVALID_CONFIG', error instanceof Error ? error.message : 'Configuration is invalid.', 0, false, undefined, error instanceof ConfigError ? error.path : undefined); }
      result = { valid: true, tenantId: c.tenantId, keyCount: Object.keys(c.keys).length, principalCount: c.principals.length, providers: [...new Set(Object.values(c.keys).map(v => v.provider))] }; break;
    }
    case 'encrypt': case 'decrypt': case 'doctor': case 'probe': {
      let token = process.env.STRONGROOM_TOKEN;
      if (!token && process.env.STRONGROOM_TOKEN_FILE) token = (await readFile(process.env.STRONGROOM_TOKEN_FILE, 'utf8')).trim();
      const client = new Strongroom({ url: process.env.STRONGROOM_URL ?? '', token: token ?? '', ...(process.env.STRONGROOM_CLOUD_RUN_ID_TOKEN ? { cloudRunIdToken: process.env.STRONGROOM_CLOUD_RUN_ID_TOKEN.trim() } : {}) });
      if (command === 'doctor') {
        await client.ready(); const c = await client.capabilities(); result = { ready: true, apiVersion: c.apiVersion, checks: ['configuration', 'api-version'], unchecked: ['token-permissions', 'kms-connectivity'], next: 'strongroom probe --key KEY --tenant TENANT' };
      } else if (command === 'probe') {
        result = await probe(client, options);
      } else {
        let input = await readInput(options['--input']);
        if (options['--envelope']) {
          const stored = await readInput(options['--envelope']) as Record<string, unknown> | null;
          const envelope = stored && typeof stored === 'object' && 'envelope' in stored ? stored.envelope : stored;
          if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).join() !== 'context') fail('With --envelope, input must be exactly {"context": {...}}.');
          input = { envelope, context: (input as { context: unknown }).context };
        }
        const file = options['--plaintext-file'];
        if (file && command === 'encrypt') {
          if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).sort().join() !== 'context,key') fail('With --plaintext-file, input must be exactly {"context": {...}, "key": "..."}.');
          // Bound the read itself: stat cannot size a FIFO or a file that grows while it is read.
          const buffer = Buffer.alloc(capabilities.maxPlaintextBytes + 1);
          try {
            let size = 0;
            const handle = await open(file, 'r');
            try {
              for (let n = 1; n > 0 && size < buffer.length; size += n) n = (await handle.read(buffer, size, buffer.length - size, null)).bytesRead;
            } finally { await handle.close(); }
            if (size > capabilities.maxPlaintextBytes) fail(`Plaintext file exceeds ${capabilities.maxPlaintextBytes} bytes.`);
            result = { envelope: await client.encrypt({ ...(input as object), plaintext: buffer.subarray(0, size) } as never) };
          } finally { buffer.fill(0); }
        } else if (file) {
          const plaintext = await client.decryptBytes(input as never);
          try { await writeFile(file, plaintext, { mode: 0o600, flag: 'wx' }); result = { plaintextFile: resolve(file), bytes: plaintext.length }; } finally { plaintext.fill(0); }
        } else result = command === 'encrypt' ? { envelope: await client.encrypt(input as never) } : { plaintext: await client.decrypt(input as never) };
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
  process.exitCode = e.retryable ? 5 : ['KMS_ACCESS_DENIED', 'KMS_KEY_UNAVAILABLE', 'NOT_CONFIGURED'].includes(e.code) ? 6 : ['INVALID_INPUT', 'INVALID_CONFIG', 'IO_ERROR', 'AWS_CLI_MISSING', 'AWS_PROFILE_NOT_FOUND', 'GCP_CLI_MISSING', 'GCP_API_DISABLED', 'RESOURCE_EXISTS', 'KEY_UNUSABLE'].includes(e.code) ? 2 : [401, 403].includes(e.status) ? 3 : e.status >= 400 && e.status < 500 ? 4 : 1;
}
