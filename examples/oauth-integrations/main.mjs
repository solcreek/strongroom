// Scenario: an integration platform stores each customer's OAuth tokens (Slack, GitHub, Google ...).
// Background workers refresh access tokens; refresh tokens rotate on every use, and many identity
// providers revoke the whole grant when an old refresh token is replayed. So a refresh must happen once,
// and its result must be written back exactly once.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Strongroom } from '../../packages/strongroom/dist/index.js';
import { startDeployment, step } from '../shared/stack.mjs';

// Stand-in identity provider with refresh-token rotation and reuse detection.
const idp = (() => {
  const live = new Set(), used = new Set();
  let calls = 0;
  const issue = () => { const refresh = `rt-${randomBytes(8).toString('hex')}`; live.add(refresh); return { access: `at-${randomBytes(8).toString('hex')}`, refresh, expiresIn: 3600 }; };
  return {
    authorize: issue,
    calls: () => calls,
    async refresh(token) {
      calls++;
      await new Promise(r => setTimeout(r, 20));
      if (used.has(token)) { live.clear(); throw new Error('invalid_grant: refresh token reused, grant revoked'); }
      if (!live.delete(token)) throw new Error('invalid_grant');
      used.add(token); return issue();
    },
  };
})();

// Stand-in database. Every write goes through compare-and-set on a version that only ever increases,
// reconnects included: a version reused after a reset would let a stalled worker's stale write land.
const rows = new Map();
const db = {
  get: id => rows.get(id),
  insert(id, row) { if (rows.has(id)) return false; rows.set(id, { ...row, version: 0 }); return true; },
  update(id, version, patch) {
    const row = rows.get(id); if (!row || row.version !== version) return false;
    rows.set(id, { ...row, ...patch, version: version + 1 }); return true;
  },
};
const update = db.update;
// Test harness edits (expiring a token, aging a lease) also go through compare-and-set.
const edit = (id, patch) => assert.ok(update(id, db.get(id).version, patch));

const acme = await startDeployment('acme');
try {
  // The OAuth callback only stores tokens (encrypt); the refresher reads and rewrites them (both).
  const callback = new Strongroom({ url: acme.url, token: acme.tokens.ingest });
  const refresher = new Strongroom({ url: acme.url, token: acme.tokens.both });
  // Different purposes, so an access-token envelope can never be passed off as a refresh token.
  const context = (id, purpose) => ({ tenantId: 'acme', recordId: `connection/${id}`, purpose });

  // A first connection inserts the row; a reconnect replaces it through compare-and-set, never by
  // resetting it, so its version keeps increasing past any version a stalled worker still holds.
  async function connect(id) {
    const t = idp.authorize();
    const fresh = { status: 'active', leaseUntil: 0, expiresAt: Date.now() + t.expiresIn * 1000,
      access: await callback.encrypt({ key: 'primary', context: context(id, 'oauth-access-token'), plaintext: t.access }),
      refresh: await callback.encrypt({ key: 'primary', context: context(id, 'oauth-refresh-token'), plaintext: t.refresh }) };
    // Read the version only after encrypting, then write in one step.
    while (!db.insert(id, fresh) && !update(id, db.get(id).version, fresh)) { /* lost a race: re-read */ }
  }

  // Exactly one worker refreshes: it takes a lease with compare-and-set; the others wait for the new
  // version instead of replaying the same refresh token.
  async function accessToken(id, worker) {
    for (;;) {
      const row = db.get(id);
      if (row.status === 'reconnect-required') return { worker, reconnect: true };
      if (row.expiresAt - Date.now() > 60_000) return { worker, token: await refresher.decrypt({ envelope: row.access, context: context(id, 'oauth-access-token') }) };
      // A lease that expired without being cleared means a refresh may have reached the provider and
      // then been lost, so the stored refresh token may already be consumed. Replaying it would revoke
      // the grant: stop and ask the customer to reconnect instead. No lease length makes a retry safe.
      if (row.leaseUntil !== 0 && row.leaseUntil < Date.now()) {
        update(id, row.version, { status: 'reconnect-required', leaseUntil: 0 });
        continue;
      }
      if (row.leaseUntil === 0 && update(id, row.version, { leaseUntil: Date.now() + 30_000 })) {
        const leased = db.get(id);
        // Before the provider sees the token nothing is consumed: on failure (a retryable KMS_UNAVAILABLE,
        // say) release the lease so a retry is safe. Only a failure after the provider call may leave the
        // lease to expire into reconnect-required.
        let refreshToken;
        try { refreshToken = await refresher.decrypt({ envelope: leased.refresh, context: context(id, 'oauth-refresh-token') }); }
        catch (e) { update(id, leased.version, { leaseUntil: 0 }); throw e; }
        const t = await idp.refresh(refreshToken);
        // Encrypt before writing, and write both envelopes in one update so they never disagree.
        const [access, refresh] = await Promise.all([
          refresher.encrypt({ key: 'primary', context: context(id, 'oauth-access-token'), plaintext: t.access }),
          refresher.encrypt({ key: 'primary', context: context(id, 'oauth-refresh-token'), plaintext: t.refresh }),
        ]);
        if (update(id, leased.version, { access, refresh, expiresAt: Date.now() + t.expiresIn * 1000, leaseUntil: 0 })) return { worker, token: t.access, refreshed: true };
        // Someone else wrote the row meanwhile: either the lease was declared lost (reconnect-required) or
        // the customer reconnected with a fresh grant. Re-read and act on what the row says now; the tokens
        // this worker obtained belong to the superseded grant and are dropped.
        continue;
      }
      await new Promise(r => setTimeout(r, 10)); // someone else holds the lease
    }
  }

  await connect('c1');
  step('connected', { envelopes: ['access', 'refresh'], plaintextInRow: /"(at|rt)-/.test(JSON.stringify(db.get('c1'))) });

  edit('c1', { expiresAt: Date.now() }); // the access token has expired
  const results = await Promise.all(['w1', 'w2', 'w3'].map(w => accessToken('c1', w)));
  assert.equal(new Set(results.map(r => r.token)).size, 1);
  step('concurrent-refresh', { workers: results.length, refreshes: results.filter(r => r.refreshed).length, sameToken: true });

  // What the lease prevents: two workers refresh with the same token. The second replays a token the
  // provider already rotated, and the provider revokes the whole grant.
  await connect('c2');
  const stale = await refresher.decrypt({ envelope: db.get('c2').refresh, context: context('c2', 'oauth-refresh-token') });
  await idp.refresh(stale);
  await assert.rejects(idp.refresh(stale), /reused/);
  step('without-lease', { outcome: 'second refresh replayed the old token; the provider revoked the grant' });

  // A worker takes the lease, the provider consumes the refresh token, and the worker dies before
  // writing the new tokens back. Once its lease expires, the next worker must not retry the refresh.
  await connect('c3');
  const crashed = db.get('c3');
  assert.ok(update('c3', crashed.version, { leaseUntil: Date.now() + 30_000, expiresAt: Date.now() }));
  await idp.refresh(await refresher.decrypt({ envelope: crashed.refresh, context: context('c3', 'oauth-refresh-token') }));
  edit('c3', { leaseUntil: Date.now() - 1 }); // the lease has expired
  const calls = idp.calls();
  const recovered = await accessToken('c3', 'w4');
  assert.deepEqual([recovered.reconnect, idp.calls(), db.get('c3').status], [true, calls, 'reconnect-required']);
  step('lost-lease', { outcome: 'reconnect-required', providerCalled: false });

  // The "crashed" worker was only stalled. The customer reconnects and a new worker refreshes; then the
  // stalled worker resumes and tries to write with the version its lease gave it. It must be refused.
  const stalledVersion = crashed.version + 1;
  await connect('c3');
  // The invariant that makes this safe: a reconnect never brings the version back to one a worker holds.
  assert.ok(db.get('c3').version > stalledVersion);
  edit('c3', { expiresAt: Date.now() });
  assert.ok((await accessToken('c3', 'w5')).refreshed);
  const current = db.get('c3');
  assert.equal(update('c3', stalledVersion, { access: crashed.access, refresh: crashed.refresh, leaseUntil: 0 }), false);
  assert.deepEqual(db.get('c3'), current);
  step('stalled-writer-after-reconnect', { staleWriteRejected: true });

  // The customer reconnects while a worker is mid-refresh. The worker's write is refused, and it must
  // pick up the fresh grant rather than report a reconnect that already happened.
  await connect('c5');
  edit('c5', { expiresAt: Date.now() });
  const refresh = idp.refresh;
  let release, entered;
  const inside = new Promise(r => { entered = r; });
  idp.refresh = async token => { entered(); await new Promise(r => { release = r; }); return refresh(token); };
  const midRefresh = accessToken('c5', 'w7');
  await inside;
  await connect('c5');
  const fresh = await refresher.decrypt({ envelope: db.get('c5').access, context: context('c5', 'oauth-access-token') });
  release();
  const outcome = await midRefresh;
  idp.refresh = refresh;
  assert.deepEqual([outcome.reconnect, outcome.token, db.get('c5').status], [undefined, fresh, 'active']);
  step('reconnect-during-refresh', { usesFreshGrant: true });

  // A failure before the provider call consumed nothing, so it must not cost a reconnect: the lease is
  // released and the next attempt refreshes normally. Here Strongroom is briefly unreachable.
  await connect('c4');
  edit('c4', { expiresAt: Date.now() });
  const decrypt = refresher.decrypt;
  refresher.decrypt = async () => { throw Object.assign(new Error('Unable to reach Strongroom.'), { code: 'NETWORK_ERROR', retryable: true }); };
  await assert.rejects(accessToken('c4', 'w5'), { code: 'NETWORK_ERROR' });
  refresher.decrypt = decrypt;
  assert.equal(db.get('c4').leaseUntil, 0);
  const retried = await accessToken('c4', 'w5');
  assert.ok(retried.refreshed);
  step('retryable-before-refresh', { leaseReleased: true, retried: 'refreshed' });
} finally { await acme.stop(); }
