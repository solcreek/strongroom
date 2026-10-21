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

// Stand-in database row with a version column for compare-and-set.
const db = new Map();
const update = (id, version, patch) => {
  const row = db.get(id); if (row.version !== version) return false;
  db.set(id, { ...row, ...patch, version: version + 1 }); return true;
};

const acme = await startDeployment('acme');
try {
  // The OAuth callback only stores tokens (encrypt); the refresher reads and rewrites them (both).
  const callback = new Strongroom({ url: acme.url, token: acme.tokens.ingest });
  const refresher = new Strongroom({ url: acme.url, token: acme.tokens.both });
  // Different purposes, so an access-token envelope can never be passed off as a refresh token.
  const context = (id, purpose) => ({ tenantId: 'acme', recordId: `connection/${id}`, purpose });

  async function connect(id) {
    const t = idp.authorize();
    db.set(id, { version: 0, status: 'active', leaseUntil: 0, expiresAt: Date.now() + t.expiresIn * 1000,
      access: await callback.encrypt({ key: 'primary', context: context(id, 'oauth-access-token'), plaintext: t.access }),
      refresh: await callback.encrypt({ key: 'primary', context: context(id, 'oauth-refresh-token'), plaintext: t.refresh }) });
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
        const refreshToken = await refresher.decrypt({ envelope: leased.refresh, context: context(id, 'oauth-refresh-token') });
        const t = await idp.refresh(refreshToken);
        // Encrypt before writing, and write both envelopes in one update so they never disagree.
        const [access, refresh] = await Promise.all([
          refresher.encrypt({ key: 'primary', context: context(id, 'oauth-access-token'), plaintext: t.access }),
          refresher.encrypt({ key: 'primary', context: context(id, 'oauth-refresh-token'), plaintext: t.refresh }),
        ]);
        // If the lease was declared lost meanwhile, the connection is already marked for reconnection.
        if (!update(id, leased.version, { access, refresh, expiresAt: Date.now() + t.expiresIn * 1000, leaseUntil: 0 })) return { worker, reconnect: true };
        return { worker, token: t.access, refreshed: true };
      }
      await new Promise(r => setTimeout(r, 10)); // someone else holds the lease
    }
  }

  await connect('c1');
  step('connected', { envelopes: ['access', 'refresh'], plaintextInRow: /"(at|rt)-/.test(JSON.stringify(db.get('c1'))) });

  db.set('c1', { ...db.get('c1'), expiresAt: Date.now() }); // the access token has expired
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
  db.set('c3', { ...db.get('c3'), leaseUntil: Date.now() - 1 }); // the lease has expired
  const calls = idp.calls();
  const recovered = await accessToken('c3', 'w4');
  assert.deepEqual([recovered.reconnect, idp.calls(), db.get('c3').status], [true, calls, 'reconnect-required']);
  step('lost-lease', { outcome: 'reconnect-required', providerCalled: false });
} finally { await acme.stop(); }
