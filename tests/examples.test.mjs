import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

// The examples are documentation that runs: each asserts its own properties and exits non-zero on a failure.
async function run(name) {
  const child = spawn(process.execPath, [`examples/${name}/main.mjs`], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', b => stdout += b); child.stderr.on('data', b => stderr += b);
  const [code] = await once(child, 'close');
  assert.equal(code, 0, stderr);
  return stdout.trim().split('\n').map(line => JSON.parse(line));
}
test('examples run end to end and keep secrets out of what they store and show', { timeout: 60000 }, async () => {
  const byok = await run('byok-api-keys');
  assert.deepEqual(byok.map(s => s.step), ['stored', 'chat', 'settings-cannot-decrypt', 'swapped-envelope-rejected', 'rotated']);
  assert.equal(byok[0].plaintextInRow, false);

  const oauth = await run('oauth-integrations');
  assert.equal(oauth.find(s => s.step === 'concurrent-refresh').refreshes, 1);
  assert.equal(oauth.find(s => s.step === 'connected').plaintextInRow, false);
  assert.deepEqual(oauth.find(s => s.step === 'lost-lease'), { step: 'lost-lease', outcome: 'reconnect-required', providerCalled: false });
  assert.deepEqual(oauth.find(s => s.step === 'stalled-writer-after-reconnect'), { step: 'stalled-writer-after-reconnect', staleWriteRejected: true });
  assert.deepEqual(oauth.find(s => s.step === 'reconnect-during-refresh'), { step: 'reconnect-during-refresh', usesFreshGrant: true });
  assert.deepEqual(oauth.find(s => s.step === 'retryable-before-refresh'), { step: 'retryable-before-refresh', leaseReleased: true, retried: 'refreshed' });

  const data = await run('tenant-data-keys');
  assert.deepEqual(data.map(s => s.step), ['files-written', 'read', 'cross-tenant-refused', 'rotated', 'shredded']);
  assert.equal(data[0].plaintextOnVolume, false); assert.equal(data.at(-1).globexSnapshotReadable, false);

  const agent = await run('agent-tools');
  assert.equal(agent[0].secretInTranscript, false);
  assert.deepEqual(agent[0].entries, [
    { user: 'alice', outcome: 'sent msg_42' },
    { user: 'alice', outcome: 'rejected recipient eve@elsewhere.test for key [redacted]' },
    { user: 'mallory', outcome: 'credential not available to this user' },
  ]);
});
