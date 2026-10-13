import { spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { Strongroom } from '../packages/strongroom/src/client.ts';
const token = randomBytes(32).toString('base64url');
const config = { keys: { primary: { provider: 'local', kek: randomBytes(32).toString('base64url') } }, principals: [{ tokenSha256: createHash('sha256').update(token).digest('hex'), tenantId: 'test', permissions: ['encrypt', 'decrypt'], keys: ['primary'] }] };
function docker(args, env = {}) {
  const r = spawnSync('docker', args, { encoding: 'utf8', env: { ...process.env, ...env } });
  if (r.status !== 0) throw new Error('Docker command failed; ensure the daemon is running and the test image exists.');
  return r.stdout.trim();
}
const id = docker(['run', '--rm', '-d', '--read-only', '-p', '127.0.0.1::8080', '-e', 'STRONGROOM_CONFIG', '-e', 'STRONGROOM_ALLOW_LOCAL', process.env.STRONGROOM_TEST_IMAGE ?? 'strongroom:ci'], { STRONGROOM_CONFIG: JSON.stringify(config), STRONGROOM_ALLOW_LOCAL: 'true' });
try {
  const port = docker(['port', id, '8080/tcp']).split(':').at(-1);
  const client = new Strongroom({ url: `http://127.0.0.1:${port}`, token });
  for (let attempt = 0; attempt < 50; attempt++) {
    try { await client.ready(); break; } catch { await new Promise(r => setTimeout(r, 100)); }
  }
  const context = { tenantId: 'test', recordId: 'record', purpose: 'api-key' };
  const envelope = await client.encrypt({ key: 'primary', context, plaintext: 'container-test-key' });
  assert.equal(await client.decrypt({ envelope, context }), 'container-test-key');
  assert.equal(docker(['exec', id, 'id', '-u']), '1000');
  console.log('Container: non-root, read-only filesystem and HTTP roundtrip passed.');
} finally { docker(['stop', id]); }
