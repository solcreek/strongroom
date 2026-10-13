import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appWith, env, config, context, token, tenantBToken, encryptToken, request, encrypt } from './helpers.mjs';
import { parseConfig } from '../service/config.ts';
import { equalHash, crc32c, utf8 } from '../service/encoding.ts';
import { errorResponse } from '../service/app.ts';
import { kmsJson } from '../service/transport.ts';

test('Wasm HTTP roundtrips preserve empty, Unicode, and maximum UTF-8 text; fresh envelopes', async () => {
  const app = appWith();
  for (const plaintext of ['', '秘密🔑\n', 'x'.repeat(65536)]) {
    const envelope = await encrypt(app, plaintext);
    assert.equal(JSON.stringify(envelope).includes('fake-user-api-key'), false);
    const response = await app.fetch(request('/v1/decrypt', { envelope, context }));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.ok(response.headers.get('x-request-id'));
    assert.deepEqual(await response.json(), { plaintext });
  }
  assert.notDeepEqual(await encrypt(app), await encrypt(app));
});
test('auth, tenant, operation and key permissions are independent checks', async () => {
  const app = appWith(); const envelope = await encrypt(app);
  for (const [path, body, auth, status, code] of [
    ['/v1/encrypt', {}, '', 401, 'UNAUTHENTICATED'],
    ['/v1/encrypt', {}, 'wrong'.repeat(10), 401, 'UNAUTHENTICATED'],
    ['/v1/decrypt', { envelope, context }, encryptToken, 403, 'FORBIDDEN'],
    ['/v1/decrypt', { envelope, context }, tenantBToken, 403, 'FORBIDDEN'],
    ['/v1/decrypt', { envelope, context: { ...context, tenantId: 'b' } }, tenantBToken, 400, 'DECRYPT_FAILED'],
    ['/v1/encrypt', { plaintext: 'x', context, key: 'restricted' }, token, 403, 'FORBIDDEN'],
    ['/v1/encrypt', { plaintext: 'x', context, key: 'missing' }, token, 403, 'FORBIDDEN'],
  ]) {
    const response = await app.fetch(request(path, body, auth));
    assert.equal(response.status, status); assert.equal((await response.json()).error.code, code);
  }
});
test('tampering and context changes fail closed', async () => {
  const app = appWith(); const envelope = await encrypt(app);
  for (const changed of [{ ...context, recordId: 'another' }, { ...context, purpose: 'another' }]) {
    assert.equal((await (await app.fetch(request('/v1/decrypt', { envelope, context: changed }))).json()).error.code, 'DECRYPT_FAILED');
  }
  for (const field of ['nonce', 'ciphertext', 'wrappedKey']) {
    const changed = { ...envelope, [field]: (envelope[field][0] === 'A' ? 'B' : 'A') + envelope[field].slice(1) };
    assert.equal((await app.fetch(request('/v1/decrypt', { envelope: changed, context }))).status, 400);
  }
  for (const change of [{ version: 2 }, { algorithm: 'none' }, { extra: true }, { ciphertext: 'AA==' }, { wrappedKey: '' }]) {
    assert.equal((await (await app.fetch(request('/v1/decrypt', { envelope: { ...envelope, ...change }, context }))).json()).error.code, 'INVALID_REQUEST');
  }
});
test('strict schema, Unicode, sizes, media types and routing', async () => {
  const app = appWith(); const valid = { plaintext: 'x', key: 'primary', context };
  for (const body of [null, [], {}, { ...valid, entropy: 'caller supplied' }, { ...valid, plaintext: '\ud800' },
    { ...valid, plaintext: 'x'.repeat(65537) }, { ...valid, plaintext: '秘密'.repeat(12000) },
    { ...valid, context: { ...context, purpose: '' } }, { ...valid, context: { ...context, extra: 1 } }, { ...valid, key: '../key' }]) {
    assert.equal((await app.fetch(request('/v1/encrypt', body))).status, 400);
  }
  for (const [body, headers, status] of [
    ['{bad', { 'content-type': 'application/json' }, 400],
    [JSON.stringify(valid), { 'content-type': 'text/plain' }, 415],
    ['x'.repeat(524289), { 'content-type': 'application/json' }, 413],
    ['{}', { 'content-type': 'application/json', 'content-length': '524289' }, 413],
  ]) assert.equal((await app.fetch(request('/v1/encrypt', {}, token, { body, headers: { ...headers, authorization: `Bearer ${token}` } }))).status, status);
  assert.equal((await app.fetch(new Request('http://localhost/v1/encrypt'))).status, 405);
  assert.equal((await app.fetch(new Request('http://localhost/missing'))).status, 404);
  for (const path of ['/healthz', '/readyz', '/openapi.json', '/v1/capabilities']) {
    assert.equal((await app.fetch(new Request(`http://localhost${path}`))).status, 200);
    assert.equal((await app.fetch(request(path, {}))).status, 405);
  }
});
test('invalid configuration never starts and local keys require opt-in', () => {
  assert.throws(() => parseConfig({}));
  assert.throws(() => parseConfig({ ...env, STRONGROOM_ALLOW_LOCAL: 'false' }));
  for (const c of [null, {}, { ...config, extra: true }, { ...config, keys: {} }, { ...config, principals: [] },
    { ...config, principals: [...config.principals, config.principals[0]] },
    { ...config, keys: { primary: { provider: 'unknown' } } },
    { ...config, keys: { primary: { provider: 'local', kek: 'AAA' } } },
    { ...config, principals: [{ ...config.principals[0], keys: ['missing'] }] },
    { ...config, principals: [{ ...config.principals[0], permissions: ['admin'] }] },
  ]) assert.throws(() => parseConfig({ ...env, STRONGROOM_CONFIG: JSON.stringify(c) }));
  assert.equal(equalHash('a'.repeat(64), 'a'.repeat(64)), true);
  assert.equal(equalHash('b'.repeat(64), 'a'.repeat(64)), false);
  assert.equal(crc32c(utf8.encode('123456789')), '3808858755');
});
test('provider errors are sanitized and never return envelope or plaintext', async () => {
  const kms = { provider: 'vault', url: 'https://vault.example', mount: 'transit', keyName: 'strongroom', token: 'upstream-secret' };
  const app = appWith({ STRONGROOM_CONFIG: JSON.stringify({ ...config, keys: { primary: kms, restricted: kms } }) }, async () => new Response('upstream-secret: fake-user-api-key', { status: 503 }));
  const response = await app.fetch(request('/v1/encrypt', { plaintext: 'fake-user-api-key', context, key: 'primary' }));
  assert.equal(response.status, 503);
  const body = await response.text(); assert.ok(!body.includes('fake-user-api-key')); assert.ok(!body.includes('upstream-secret'));
  assert.equal(JSON.parse(body).error.retryable, true);
  assert.equal((await errorResponse(new Error('secret')).json()).error.code, 'INTERNAL_ERROR');
});
test('request and provider deadlines fail closed', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const pending = kmsJson(async (_url, init) => new Promise((_, reject) => {
    init.signal.addEventListener('abort', () => reject(new Error('secret transport detail')), { once: true });
  }), 'https://example.com');
  t.mock.timers.tick(8000);
  await assert.rejects(pending, { code: 'KMS_UNAVAILABLE' });
  t.mock.timers.reset();

  const original = globalThis.setTimeout;
  t.mock.method(globalThis, 'setTimeout', (fn, delay, ...args) => {
    if (delay === 8000) return original(fn, 1, ...args);
    return original(fn, delay, ...args);
  });
  const stream = new ReadableStream({ start() {} });
  const app = appWith();
  const response = await app.fetch(request('/v1/encrypt', {}, token, { body: stream, duplex: 'half' }));
  assert.equal(response.status, 408); assert.equal((await response.json()).error.code, 'REQUEST_TIMEOUT');
});
test('unauthorized and malformed envelopes never reach KMS', async () => {
  let calls = 0;
  const provider = { provider: 'vault', url: 'https://vault.example', mount: 'transit', keyName: 'test', token: 'test' };
  const app = appWith({ STRONGROOM_CONFIG: JSON.stringify({ ...config, keys: { primary: provider, restricted: provider } }) }, async () => { calls++; throw new Error('unexpected'); });
  const envelope = await encrypt(appWith());
  await app.fetch(request('/v1/decrypt', { envelope, context }, tenantBToken));
  await app.fetch(request('/v1/decrypt', { envelope: { ...envelope, version: 2 }, context }));
  await app.fetch(request('/v1/decrypt', { envelope, context }, encryptToken));
  assert.equal(calls, 0);
});
