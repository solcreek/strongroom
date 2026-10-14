import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, stat, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from './cli-helper.mjs';
import { createHash } from 'node:crypto';
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
    await writeFile(join(parent, 'principal.json'), JSON.stringify({ ...config, principals: [{ ...config.principals[0], permissions: ['admin'] }] }));
    const diagnosed = await runCli(['config-check', '--input', join(parent, 'principal.json')], { env: { STRONGROOM_ALLOW_LOCAL: 'true' } });
    assert.equal(diagnosed.code, 2); assert.equal(JSON.parse(diagnosed.stderr).error.path, '$.principals[0].permissions');
    await writeFile(join(parent, 'bad.json'), 'broken');
    assert.equal((await runCli(['config-check', '--input', join(parent, 'bad.json')])).code, 2);
  } finally { await rm(parent, { recursive: true, force: true }); }
});
test('CLI exit codes separate operator-side KMS failures from retryable ones', async () => {
  const { createServer } = await import('node:http');
  for (const [code, status, retryable, exit] of [['KMS_ACCESS_DENIED', 502, false, 6], ['KMS_KEY_UNAVAILABLE', 502, false, 6], ['KMS_UNAVAILABLE', 503, true, 5], ['DECRYPT_FAILED', 400, false, 4]]) {
    const server = createServer((_, res) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: { code, message: 'x', retryable, requestId: 'r' } })); });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    try {
      const r = await runCli(['encrypt'], { input: '{}', env: { STRONGROOM_URL: `http://127.0.0.1:${server.address().port}`, STRONGROOM_TOKEN: 'a'.repeat(43) } });
      assert.equal(r.code, exit, code); assert.equal(JSON.parse(r.stderr).error.code, code);
    } finally { server.close(); }
  }
});
test('CLI token writes the secret only to a new private file and prints a ready principal', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'strongroom-token-'));
  try {
    const file = join(parent, 'token');
    const r = await runCli(['token', '--token-file', file, '--tenant', 'acme', '--keys', 'primary, backup', '--permissions', 'decrypt']); assert.equal(r.code, 0, r.stderr);
    const out = JSON.parse(r.stdout), token = (await readFile(file, 'utf8')).trim();
    assert.equal((await stat(file)).mode & 0o777, 0o600); assert.match(token, /^[A-Za-z0-9_-]{43}$/); assert.ok(!r.stdout.includes(token));
    assert.equal(out.tokenSha256, createHash('sha256').update(token).digest('hex'));
    assert.deepEqual(out.principal, { tokenSha256: out.tokenSha256, tenantId: 'acme', permissions: ['decrypt'], keys: ['primary', 'backup'] });
    assert.equal((await runCli(['token', '--token-file', file])).code, 2);
    const bare = await runCli(['token', '--token-file', join(parent, 'bare')]); assert.equal(JSON.parse(bare.stdout).principal, undefined);
    for (const args of [['token'], ['token', '--token-file', join(parent, 'x'), '--tenant', 'a'], ['token', '--token-file', join(parent, 'y'), '--tenant', 'a', '--keys', 'k', '--permissions', 'admin'], ['token', '--token-file', join(parent, 'z'), '--input', 'f']])
      assert.equal((await runCli(args)).code, 2, args.join(' '));
  } finally { await rm(parent, { recursive: true, force: true }); }
});
