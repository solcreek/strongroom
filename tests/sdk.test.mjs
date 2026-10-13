import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Strongroom, StrongroomError } from '../packages/strongroom/src/client.ts';
import { appWith, context, token, encryptToken } from './helpers.mjs';
const options = { url: 'http://127.0.0.1:8787', token };
test('SDK roundtrip against actual Rust Wasm and HTTP contract', async () => {
  const app = appWith();
  const client = new Strongroom({ ...options, fetch: (url, init) => app.fetch(new Request(url, init)) });
  const envelope = await client.encrypt({ key: 'primary', context, plaintext: 'fake-key' });
  assert.equal(await client.decrypt({ envelope, context }), 'fake-key');
  assert.equal(await client.ready(), true); assert.equal((await client.capabilities()).apiVersion, 'v1');
  await assert.rejects(client.decrypt({ envelope, context: { ...context, purpose: 'wrong' } }), e => {
    assert.ok(e instanceof StrongroomError); assert.equal(e.code, 'DECRYPT_FAILED'); assert.equal(e.status, 400); assert.equal(e.retryable, false); assert.ok(e.requestId); return true;
  });
  await assert.rejects(client.encrypt({ key: 'primary', context: { ...context, recordId: '' }, plaintext: 'x' }), e => e.path === '$.context.recordId' && e.toJSON().path === '$.context.recordId');
  const restricted = new Strongroom({ ...options, token: encryptToken, fetch: (url, init) => app.fetch(new Request(url, init)) });
  await assert.rejects(restricted.decrypt({ envelope, context }), { status: 403, code: 'FORBIDDEN' });
});
test('SDK rejects unsafe origins and bad credentials before sending requests', () => {
  for (const url of ['', 'http://remote.example', 'https://name:password@example.com', 'https://example.com/path', 'https://example.com?token=secret']) assert.throws(() => new Strongroom({ ...options, url }), { code: 'INVALID_CONFIG' });
  assert.throws(() => new Strongroom({ ...options, token: 'short' }), { code: 'INVALID_CONFIG' });
  for (const timeoutMs of [0, -1, NaN, 120001]) assert.throws(() => new Strongroom({ ...options, timeoutMs }), { code: 'INVALID_CONFIG' });
  assert.ok(new Strongroom({ ...options, url: 'https://example.com' }));
});
test('SDK forbids redirects, bounds responses, sanitizes transport failures and exposes retryability', async () => {
  const broken = [new Response('not json'), new Response(null), new Response('x'.repeat(524289)), new Response('{}', { status: 500 }), new Response('{}')];
  for (const response of broken) {
    const client = new Strongroom({ ...options, fetch: async (_, init) => { assert.equal(init.redirect, 'manual'); return response; } });
    await assert.rejects(client.encrypt({}), { code: 'INVALID_RESPONSE' });
  }
  const offline = new Strongroom({ ...options, fetch: async () => { throw new Error('sensitive-provider-details'); } });
  await assert.rejects(offline.ready(), e => e.code === 'NETWORK_ERROR' && e.retryable && !e.message.includes('sensitive'));
  const unavailable = new Strongroom({ ...options, fetch: async () => new Response(JSON.stringify({ error: { code: 'KMS_UNAVAILABLE', message: 'Unavailable.', retryable: true } }), { status: 503 }) });
  await assert.rejects(unavailable.ready(), e => e.toJSON().code === 'KMS_UNAVAILABLE' && e.retryable);
  for (const method of ['decrypt', 'ready', 'capabilities']) {
    const client = new Strongroom({ ...options, fetch: async () => new Response('{}') });
    await assert.rejects(client[method]({}), { code: 'INVALID_RESPONSE' });
  }
});
test('SDK cancellation and timeouts are distinguishable without automatic retries', async () => {
  let calls = 0;
  const abortable = async (_, init) => {
    calls++; await new Promise((_, reject) => {
      if (init.signal.aborted) return reject(init.signal.reason);
      init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true });
    });
  };
  const keepAlive = setTimeout(() => {}, 1000);
  try {
    const client = new Strongroom({ ...options, timeoutMs: 10, fetch: abortable });
    await assert.rejects(client.ready(), { code: 'TIMEOUT', retryable: true });
    await assert.rejects(client.ready({ signal: AbortSignal.abort() }), { code: 'ABORTED', retryable: false });
    assert.equal(calls, 2);
  } finally { clearTimeout(keepAlive); }
});
test('SDK sends a Cloud Run ID token separately and names gateway rejections', async () => {
  const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln';
  let seen;
  const client = new Strongroom({ url: 'https://run.example', token: 'a'.repeat(43), cloudRunIdToken: jwt, fetch: async (url, init) => { seen = init.headers; return new Response(JSON.stringify({ status: 'ready' })); } });
  await client.ready();
  assert.equal(seen['x-serverless-authorization'], `Bearer ${jwt}`); assert.equal(seen.authorization, `Bearer ${'a'.repeat(43)}`);
  assert.throws(() => new Strongroom({ url: 'https://run.example', token: 'a'.repeat(43), cloudRunIdToken: 'not-a-jwt' }), { code: 'INVALID_CONFIG' });
  for (const [status, code] of [[403, 'GATEWAY_REJECTED'], [401, 'GATEWAY_REJECTED'], [404, 'GATEWAY_REJECTED'], [502, 'INVALID_RESPONSE'], [200, 'INVALID_RESPONSE']]) {
    const gated = new Strongroom({ url: 'https://run.example', token: 'a'.repeat(43), fetch: async () => new Response('<html>Error: Forbidden</html>', { status, headers: { 'content-type': 'text/html' } }) });
    await assert.rejects(gated.ready(), e => e.code === code && e.status === status && e.retryable === false && !e.message.includes('<html>'));
  }
});
