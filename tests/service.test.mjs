import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appWith, env, config, context, token, tenantBToken, encryptToken, request, encrypt } from './helpers.mjs';
import { parseConfig } from '../service/config.ts';
import { equalHash, crc32c, utf8, base64url } from '../service/encoding.ts';
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
test('binary plaintext roundtrips as raw octets; text stays JSON unless bytes are requested', async () => {
  const app = appWith(), bytes = { accept: 'application/octet-stream' };
  const decrypt = (envelope, headers = {}) => app.fetch(new Request('http://localhost/v1/decrypt', { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, ...headers }, body: JSON.stringify({ envelope, context }) }));
  const seal = async data => (await (await app.fetch(request('/v1/encrypt', { plaintextBase64url: base64url(data), context, key: 'primary' }))).json()).envelope;
  for (const data of [new Uint8Array(0), new Uint8Array([0xff, 0x00, 0xfe]), crypto.getRandomValues(new Uint8Array(32)), new Uint8Array(65536).fill(0x80)]) {
    const response = await decrypt(await seal(data), bytes);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type'), 'application/octet-stream');
    assert.equal(response.headers.get('cache-control'), 'no-store'); assert.ok(response.headers.get('x-request-id'));
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), data);
  }
  // Opening worked, so a binary envelope read as text is its own non-retryable code, not DECRYPT_FAILED.
  const binary = await seal(new Uint8Array([0xff]));
  const refused = await decrypt(binary);
  assert.equal(refused.status, 406); assert.deepEqual((({ code, retryable }) => ({ code, retryable }))((await refused.json()).error), { code: 'PLAINTEXT_NOT_TEXT', retryable: false });
  assert.equal((await decrypt(binary, { accept: 'application/json, application/octet-stream;q=0.5' })).status, 200);
  // Text envelopes read either way, a leading BOM survives, and other Accept values keep JSON.
  const text = await encrypt(app, '﻿秘密');
  assert.deepEqual(new Uint8Array(await (await decrypt(text, bytes)).arrayBuffer()), utf8.encode('﻿秘密'));
  for (const accept of ['text/plain', '*/*', 'application/octet-streamx']) assert.deepEqual(await (await decrypt(text, { accept })).json(), { plaintext: '﻿秘密' });
  assert.equal(await (await decrypt(await seal(utf8.encode('same text')))).json().then(r => r.plaintext), 'same text');
  // Errors stay JSON when bytes were requested.
  const failed = await decrypt({ ...binary, nonce: binary.nonce[0] === 'A' ? `B${binary.nonce.slice(1)}` : `A${binary.nonce.slice(1)}` }, bytes);
  assert.equal(failed.status, 400); assert.equal((await failed.json()).error.code, 'DECRYPT_FAILED');
  for (const [body, path] of [
    [{ plaintext: 'x', plaintextBase64url: 'eA', context, key: 'primary' }, '$'],
    ...['AP8=', 'AP9', '+/8', 'not base64!', 'A'.repeat(87383), 42, null].map(v => [{ plaintextBase64url: v, context, key: 'primary' }, '$.plaintextBase64url']),
    [{ plaintextBase64url: base64url(new Uint8Array(65537)), context, key: 'primary' }, '$.plaintextBase64url'],
  ]) {
    const { error } = await (await app.fetch(request('/v1/encrypt', body))).json();
    assert.equal(error.code, 'INVALID_REQUEST'); assert.equal(error.path, path, JSON.stringify(body).slice(0, 80));
  }
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
  // Diagnostics name the JSON path and rule so an agent can repair the file, and never echo supplied values.
  const secretKek = 'not-a-valid-kek-but-secret';
  for (const [c, path, hint] of [[null, '$', 'JSON object'], [{ ...config, extra: true }, '$', 'unknown field(s): extra'], [{ keys: {} }, '$', 'missing required field(s): principals'],
    [{ ...config, keys: { primary: { provider: 'local', kek: secretKek } } }, '$.keys.primary.kek', '32 random bytes'],
    [{ ...config, keys: { primary: { provider: 'nope' } } }, '$.keys.primary.provider', 'aws, gcp'],
    [{ ...config, keys: { primary: { provider: 'aws', region: 'us-east-1', keyId: 'alias/secret-alias', accessKeyId: 'a', secretAccessKey: 'b' } } }, '$.keys.primary.keyId', 'aws kms describe-key'],
    [{ ...config, principals: [config.principals[0], config.principals[0]] }, '$.principals[1].tokenSha256', 'duplicates'],
    [{ ...config, principals: [{ ...config.principals[0], keys: ['missing'] }] }, '$.principals[0].keys', 'defined in $.keys'],
  ]) assert.throws(() => parseConfig({ ...env, STRONGROOM_CONFIG: JSON.stringify(c) }), e => e.path === path && e.message.startsWith(`${path}: `) && e.message.includes(hint) && !e.message.includes('secret'));
  assert.equal(equalHash('a'.repeat(64), 'a'.repeat(64)), true);
  assert.equal(equalHash('b'.repeat(64), 'a'.repeat(64)), false);
  assert.equal(crc32c(utf8.encode('123456789')), '3808858755');
});
test('provider errors are sanitized and never return envelope or plaintext', async () => {
  const kms = { provider: 'vault', url: 'https://vault.example', mount: 'transit', keyName: 'strongroom', token: 'upstream-secret' };
  const events = [];
  let status = 503;
  const app = appWith({ STRONGROOM_CONFIG: JSON.stringify({ ...config, keys: { primary: kms, restricted: kms } }) }, async () => new Response('{"errors":["upstream-secret: fake-user-api-key"]}', { status }), e => events.push(e));
  const response = await app.fetch(request('/v1/encrypt', { plaintext: 'fake-user-api-key', context, key: 'primary' }));
  assert.equal(response.status, 503);
  const body = await response.text(); assert.ok(!body.includes('fake-user-api-key')); assert.ok(!body.includes('upstream-secret'));
  assert.equal(JSON.parse(body).error.retryable, true);
  // Credentials rejected upstream: not retryable, distinct from a context mismatch, and the operator log names the upstream status only.
  status = 403;
  const denied = await app.fetch(request('/v1/encrypt', { plaintext: 'fake-user-api-key', context, key: 'primary' }));
  assert.equal(denied.status, 502); assert.deepEqual((({ code, retryable }) => ({ code, retryable }))((await denied.json()).error), { code: 'KMS_ACCESS_DENIED', retryable: false });
  assert.deepEqual(events.map(({ requestId, ...e }) => (assert.match(requestId, /^[0-9a-f-]{36}$/), e)), [
    { severity: 'WARNING', event: 'kms_error', operation: 'encrypt', key: 'primary', provider: 'vault', code: 'KMS_UNAVAILABLE', upstreamStatus: 503, upstreamCode: null },
    { severity: 'ERROR', event: 'kms_error', operation: 'encrypt', key: 'primary', provider: 'vault', code: 'KMS_ACCESS_DENIED', upstreamStatus: 403, upstreamCode: null },
  ]);
  assert.ok(!JSON.stringify(events).includes('secret') && !JSON.stringify(events).includes('fake-user-api-key'));
  assert.equal((await errorResponse(new Error('secret')).json()).error.code, 'INTERNAL_ERROR');
});
test('request and provider deadlines fail closed', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const pending = kmsJson(async (_url, init) => new Promise((_, reject) => {
    init.signal.addEventListener('abort', () => reject(new Error('secret transport detail')), { once: true });
  }), 'https://example.com', {}, () => { throw new Error('unreachable'); });
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
test('INVALID_REQUEST names the offending field without echoing its value', async () => {
  const app = appWith(); const envelope = await encrypt(app);
  for (const [path, body, expected] of [['/v1/encrypt', { plaintext: 'x', key: 'primary' }, '$'], ['/v1/encrypt', { plaintext: 'x', key: 'primary', context: { ...context, recordId: '' } }, '$.context.recordId'],
    ['/v1/encrypt', { plaintext: 'x', key: 'primary', context: { ...context, extra: 'secret-value' } }, '$.context'], ['/v1/encrypt', { plaintext: 'x', key: 'bad key!', context }, '$.key'],
    ['/v1/encrypt', { plaintext: 'x'.repeat(65537), key: 'primary', context }, '$.plaintext'], ['/v1/decrypt', { envelope: { ...envelope, key: 'secret value' }, context }, '$.envelope.key'],
    ['/v1/decrypt', { envelope: { ...envelope, nonce: 'secret' }, context }, '$.envelope']]) {
    const { error } = await (await app.fetch(request(path, body))).json();
    assert.equal(error.code, 'INVALID_REQUEST'); assert.equal(error.path, expected); assert.ok(error.message.startsWith(`${expected}: `)); assert.ok(!error.message.includes('secret'));
  }
});
