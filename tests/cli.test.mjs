import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, stat, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
const cli = resolve('packages/strongroom/dist/cli.js');
export async function runCli(args, { input = '', env = {} } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { env: { ...process.env, STRONGROOM_TOKEN: '', STRONGROOM_URL: '', STRONGROOM_TOKEN_FILE: '', ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', b => stdout += b); child.stderr.on('data', b => stderr += b);
    child.on('error', reject); child.on('close', code => resolve({ code, stdout, stderr })); child.stdin.on('error', () => {}); child.stdin.end(input);
  });
}
test('CLI discovery is JSON and needs no credentials or network', async () => {
  for (const args of [[], ['--help'], ['--version'], ['capabilities'], ['schema'], ['schema', 'encrypt'], ['schema', 'decrypt']]) {
    const r = await runCli(args); assert.equal(r.code, 0, r.stderr); assert.doesNotThrow(() => JSON.parse(r.stdout)); assert.equal(r.stderr, '');
  }
  for (const args of [['nope'], ['schema', 'nope'], ['encrypt', '--token', 'never-accept-secrets-in-argv'], ['schema', '--output'], ['schema', '--output', 'a', '--output', 'b']]) {
    const r = await runCli(args); assert.equal(r.code, 2); assert.equal(r.stdout, ''); assert.equal(JSON.parse(r.stderr).error.code, 'INVALID_INPUT');
  }
});
test('CLI init generates private random credentials, refuses overwrite and keeps secrets off stdout', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'strongroom-cli-'));
  try {
    const dir = join(parent, 'dev');
    const r = await runCli(['init', '--directory', dir]); assert.equal(r.code, 0, r.stderr);
    const info = JSON.parse(r.stdout); const config = JSON.parse(await readFile(info.config, 'utf8'));
    assert.equal(info.mode, 'local-development-only'); assert.equal((await stat(dir)).mode & 0o777, 0o700);
    assert.equal((await stat(info.clientEnv)).mode & 0o777, 0o600);
    assert.equal((await stat(info.config)).mode & 0o777, 0o600);
    assert.equal(Buffer.from(config.keys.primary.kek, 'base64url').length, 32);
    assert.ok(!r.stdout.includes(config.keys.primary.kek));
    assert.equal((await runCli(['init', '--directory', dir])).code, 2);
    const check = await runCli(['config-check', '--input', info.config], { env: { STRONGROOM_ALLOW_LOCAL: 'true' } });
    assert.equal(check.code, 0, check.stderr); assert.equal(JSON.parse(check.stdout).valid, true);
    assert.equal((await runCli(['config-check', '--input', info.config], { env: { STRONGROOM_ALLOW_LOCAL: 'false' } })).code, 2);
    const output = join(parent, 'schema.json');
    assert.equal((await runCli(['schema', '--output', output])).stdout, '');
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    assert.equal((await runCli(['schema', '--output', output])).code, 2);
    await writeFile(join(parent, 'bad.json'), 'broken');
    assert.equal((await runCli(['config-check', '--input', join(parent, 'bad.json')])).code, 2);
  } finally { await rm(parent, { recursive: true, force: true }); }
});
