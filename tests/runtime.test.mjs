import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { Miniflare } from 'miniflare';
import { Strongroom } from '../packages/strongroom/src/client.ts';
import { env, token, context, encryptToken } from './helpers.mjs';

async function freePort() {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; await new Promise(r => server.close(r)); return port;
}
async function cli(args, url, input, auth = token) {
  const child = spawn(process.execPath, ['packages/strongroom/src/cli.ts', ...args], { env: { ...process.env, STRONGROOM_URL: url, STRONGROOM_TOKEN: auth }, stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', b => stdout += b); child.stderr.on('data', b => stderr += b); child.stdin.on('error', () => {});
  child.stdin.end(input); const [code] = await once(child, 'close'); return { code, stdout, stderr };
}
test('real workerd and Node HTTP hosts interoperate through SDK and CLI', { timeout: 30000 }, async () => {
  const mf = new Miniflare({ modules: true, scriptPath: 'dist/worker.js', modulesRoot: 'dist', modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }], compatibilityDate: '2026-07-01', host: '127.0.0.1', port: 0, bindings: env });
  let child;
  try {
    const workerUrl = String(await mf.ready); const port = await freePort();
    child = spawn(process.execPath, ['dist/server.js'], { env: { ...process.env, ...env, PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '', stdout = '';
    child.stderr.on('data', b => stderr += b); child.stdout.on('data', b => stdout += b);
    const nodeUrl = `http://127.0.0.1:${port}`;
    for (let attempt = 0; attempt < 100; attempt++) {
      if (child.exitCode !== null) throw new Error(`Server failed: ${stderr}`);
      try { if ((await fetch(`${nodeUrl}/readyz`)).ok) break; } catch { /* starting */ }
      await new Promise(r => setTimeout(r, 25));
    }
    const worker = new Strongroom({ url: workerUrl, token }), node = new Strongroom({ url: nodeUrl, token });
    for (const [writer, reader] of [[worker, node], [node, worker]]) {
      const envelope = await writer.encrypt({ key: 'primary', context, plaintext: 'cross-runtime-secret-🔑' });
      assert.equal(await reader.decrypt({ envelope, context }), 'cross-runtime-secret-🔑');
      await assert.rejects(reader.decrypt({ envelope, context: { ...context, recordId: 'wrong' } }), { code: 'DECRYPT_FAILED' });
    }
    const encrypted = await cli(['encrypt'], workerUrl, JSON.stringify({ key: 'primary', context, plaintext: 'cli-secret' }));
    assert.equal(encrypted.code, 0, encrypted.stderr); assert.equal(encrypted.stderr, '');
    const input = JSON.stringify({ envelope: JSON.parse(encrypted.stdout).envelope, context });
    const decrypted = await cli(['decrypt'], nodeUrl, input);
    assert.equal(decrypted.code, 0, decrypted.stderr); assert.deepEqual(JSON.parse(decrypted.stdout), { plaintext: 'cli-secret' });
    const denied = await cli(['decrypt'], workerUrl, input, encryptToken);
    assert.equal(denied.code, 3); assert.equal(denied.stdout, ''); assert.equal(JSON.parse(denied.stderr).error.code, 'FORBIDDEN');
    assert.equal((await cli(['encrypt'], workerUrl, '{bad-json')).code, 2);
    assert.equal((await cli(['encrypt'], workerUrl, '{}')).code, 4);
    assert.equal((await cli(['doctor'], workerUrl, '')).code, 0);
    assert.ok(!stderr.includes('cli-secret')); assert.ok(!stderr.includes('cross-runtime-secret')); assert.equal(stdout, '');
  } finally {
    if (child && child.exitCode === null) { child.kill('SIGTERM'); await once(child, 'close'); }
    await mf.dispose();
  }
});
test('Worker fails closed on missing configuration, while liveness stays available', async () => {
  const mf = new Miniflare({ modules: true, scriptPath: 'dist/worker.js', modulesRoot: 'dist', modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }], compatibilityDate: '2026-07-01', bindings: {} });
  try {
    assert.equal((await mf.dispatchFetch('http://localhost/healthz')).status, 200);
    const response = await mf.dispatchFetch('http://localhost/readyz');
    assert.equal(response.status, 503); assert.equal((await response.json()).error.code, 'NOT_CONFIGURED');
  } finally { await mf.dispose(); }
});
test('Node refuses to listen without valid configuration', async () => {
  const child = spawn(process.execPath, ['dist/server.js'], { env: { ...process.env, STRONGROOM_CONFIG: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = ''; child.stderr.on('data', b => stderr += b);
  assert.equal((await once(child, 'close'))[0], 1); assert.equal(JSON.parse(stderr).error.code, 'NOT_CONFIGURED');
});
