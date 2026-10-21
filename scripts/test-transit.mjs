// Runs a real, ephemeral, loopback-only Vault/OpenBao dev server. No external account.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { once } from 'node:events';
import assert from 'node:assert/strict';
import { Miniflare } from 'miniflare';
import { Strongroom } from '../packages/strongroom/src/client.ts';
import { sha256 } from '../service/encoding.ts';
const binary = process.env.TRANSIT_BIN;
if (!binary) throw new Error('Set TRANSIT_BIN to a Vault or OpenBao binary.');
const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
const port = server.address().port; await new Promise(r => server.close(r));
const rootToken = randomBytes(32).toString('base64url');
const address = `http://127.0.0.1:${port}`;
// Dev output includes root credentials: deliberately discard it.
const child = spawn(binary, ['server', '-dev', '-dev-no-store-token', `-dev-listen-address=127.0.0.1:${port}`], {
  env: { ...process.env, BAO_DEV_ROOT_TOKEN_ID: rootToken, VAULT_DEV_ROOT_TOKEN_ID: rootToken, BAO_LOG_LEVEL: 'error', VAULT_LOG_LEVEL: 'error' }, stdio: 'ignore',
});
let mf;
try {
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error('Transit dev server could not start.');
    try { if ((await fetch(`${address}/v1/sys/health`)).ok) break; } catch { /* starting */ }
    await new Promise(r => setTimeout(r, 50));
  }
  const admin = async (path, body) => {
    const r = await fetch(`${address}/v1/${path}`, { method: 'POST', headers: { 'x-vault-token': rootToken, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    assert.ok(r.ok, `Transit setup failed: ${r.status}`); return r;
  };
  await admin('sys/mounts/transit', { type: 'transit' });
  await admin('transit/keys/strongroom', { type: 'aes256-gcm96', derived: true, exportable: false, allow_plaintext_backup: false });
  await admin('sys/policies/acl/strongroom', { policy: 'path "transit/encrypt/strongroom" { capabilities = ["update"] }\npath "transit/decrypt/strongroom" { capabilities = ["update"] }' });
  const scoped = await (await admin('auth/token/create', { policies: ['strongroom'], no_default_policy: true, ttl: '10m' })).json();
  const token = randomBytes(32).toString('base64url');
  const key = { provider: 'openbao', url: address, mount: 'transit', keyName: 'strongroom', token: scoped.auth.client_token };
  const probe = await fetch(`${address}/v1/transit/encrypt/strongroom`, { method: 'POST', headers: { 'x-vault-token': scoped.auth.client_token, 'content-type': 'application/json' },
    body: JSON.stringify({ plaintext: Buffer.alloc(32).toString('base64'), context: Buffer.from('probe').toString('base64'), associated_data: Buffer.from('probe').toString('base64') }) });
  if (!probe.ok) throw new Error(`Transit protocol probe: ${probe.status} ${JSON.stringify((await probe.json()).errors)}`);
  const config = { tenantId: 'test', keys: { primary: key, vault: { ...key, provider: 'vault' } }, principals: [{ tokenSha256: await sha256(token), permissions: ['encrypt', 'decrypt'], keys: ['primary', 'vault'] }] };
  mf = new Miniflare({ modules: true, scriptPath: 'dist/worker.js', modulesRoot: 'dist', modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }], compatibilityDate: '2026-07-01',
    host: '127.0.0.1', port: 0, bindings: { STRONGROOM_CONFIG: JSON.stringify(config), STRONGROOM_ALLOW_LOCAL: 'true' } });
  const client = new Strongroom({ url: String(await mf.ready), token });
  const context = { tenantId: 'test', recordId: 'record', purpose: 'api-key' };
  const envelope = await client.encrypt({ key: 'primary', context, plaintext: 'ephemeral-test-key' });
  assert.match(envelope.wrappedKey, /^(vault|bao):v1:/);
  assert.equal(await client.decrypt({ envelope, context }), 'ephemeral-test-key');
  await assert.rejects(client.decrypt({ envelope, context: { ...context, recordId: 'wrong' } }), { code: 'DECRYPT_FAILED' });
  await admin('transit/keys/strongroom/rotate', {});
  const rotated = await client.encrypt({ key: 'primary', context, plaintext: 'rotated' });
  assert.match(rotated.wrappedKey, /^(vault|bao):v2:/);
  assert.equal(await client.decrypt({ envelope, context }), 'ephemeral-test-key');
  assert.equal(await client.decrypt({ envelope: rotated, context }), 'rotated');
  const viaVault = await client.encrypt({ key: 'vault', context, plaintext: 'vault-adapter' });
  assert.equal(await client.decrypt({ envelope: viaVault, context }), 'vault-adapter');
  await admin('auth/token/revoke', { token: scoped.auth.client_token });
  await assert.rejects(client.decrypt({ envelope, context }), { code: 'KMS_ACCESS_DENIED', retryable: false });
  console.log('Real Transit + workerd: roundtrip, context rejection, key rotation, both adapters and revoked credentials passed.');
} finally {
  await mf?.dispose();
  if (child.exitCode === null) { child.kill('SIGTERM'); await once(child, 'close'); }
}
