import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createProvider, classifyAws, classifyGcp, classifyOAuth, classifyTransit } from '../service/providers.ts';
import { parseConfig } from '../service/config.ts';
import { readFile } from 'node:fs/promises';
import { kmsJson, upstreamCode } from '../service/transport.ts';
import { base64, unbase64, crc32c, utf8 } from '../service/encoding.ts';
import { config, env } from './helpers.mjs';
const dek = new Uint8Array(32).fill(13), aad = utf8.encode('bound-context');
const aws = { provider: 'aws', region: 'us-east-1', keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012', accessKeyId: 'TESTACCESSKEY', secretAccessKey: 'test-secret', sessionToken: 'test-session' };
const transit = { provider: 'vault', url: 'https://vault.example', mount: 'team/transit', keyName: 'strongroom', token: 'secret', namespace: 'team' };
const response = (value, status = 200) => new Response(JSON.stringify(value), { status });
test('AWS signs requests, pins immutable key ARN and sends identical encryption context', async () => {
  const requests = [];
  const p = createProvider(aws, async (request, init) => {
    requests.push(request); const body = await request.json();
    assert.equal(init.redirect, 'manual'); assert.ok(init.signal);
    assert.match(request.headers.get('authorization'), /^AWS4-HMAC-SHA256 Credential=TESTACCESSKEY\//);
    assert.equal(request.headers.get('x-amz-security-token'), 'test-session');
    assert.equal(body.KeyId, aws.keyId); assert.equal(body.EncryptionContext.strongroom, base64(aad));
    return response({ KeyId: aws.keyId, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT', CiphertextBlob: 'opaque', Plaintext: base64(dek) });
  });
  assert.equal(await p.wrap(dek, aad), 'opaque'); assert.deepEqual(await p.unwrap('opaque', aad), dek);
  assert.equal(requests[0].url, 'https://kms.us-east-1.amazonaws.com/');
  assert.equal(requests[1].headers.get('x-amz-target'), 'TrentService.Decrypt');
  await assert.rejects(createProvider(aws, async () => response({ KeyId: 'wrong' })).wrap(dek, aad), { code: 'KMS_UNAVAILABLE' });
  await assert.rejects(createProvider(aws, async () => response({ KeyId: aws.keyId, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT', Plaintext: 'AA==' })).unwrap('opaque', aad), { code: 'KMS_UNAVAILABLE' });
});
for (const provider of ['vault', 'openbao']) test(`${provider} Transit wraps only the DEK, with AAD, derivation context and namespace`, async () => {
  const p = createProvider({ ...transit, provider }, async (url, init) => {
    assert.match(url, /^https:\/\/vault.example\/v1\/team\/transit\/(encrypt|decrypt)\/strongroom$/);
    const body = JSON.parse(init.body);
    assert.equal(body.context, base64(aad)); assert.equal(body.associated_data, base64(aad));
    assert.equal(init.headers['x-vault-token'], 'secret'); assert.equal(init.headers['x-vault-namespace'], 'team');
    if (url.includes('/encrypt/')) { assert.deepEqual(unbase64(body.plaintext), dek); return response({ data: { ciphertext: 'vault:v1:opaque' } }); }
    assert.equal(body.ciphertext, 'vault:v1:opaque'); return response({ data: { plaintext: base64(dek) } });
  });
  assert.equal(await p.wrap(dek, aad), 'vault:v1:opaque'); assert.deepEqual(await p.unwrap('vault:v1:opaque', aad), dek);
});
test('GCP uses signed OAuth assertion, coalesces token requests, validates CRC32C and key name', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const privateKey = `-----BEGIN PRIVATE KEY-----\n${base64(new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)))}\n-----END PRIVATE KEY-----`;
  const gcp = { provider: 'gcp', keyId: 'projects/test/locations/global/keyRings/test/cryptoKeys/strongroom', serviceAccount: { clientEmail: 'test@example.iam.gserviceaccount.com', privateKey } };
  let tokens = 0, corrupt = false;
  const p = createProvider(gcp, async (url, init) => {
    if (url.includes('oauth2')) {
      tokens++;
      const jwt = new URLSearchParams(init.body).get('assertion');
      const [head, claims, sig] = jwt.split('.');
      assert.ok(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', pair.publicKey, Buffer.from(sig, 'base64url'), utf8.encode(`${head}.${claims}`)));
      const claim = JSON.parse(Buffer.from(claims, 'base64url'));
      assert.equal(claim.iss, gcp.serviceAccount.clientEmail); assert.equal(claim.exp - claim.iat, 3600);
      return response({ access_token: 'oauth-token', expires_in: 3600 });
    }
    assert.equal(init.headers.authorization, 'Bearer oauth-token');
    const body = JSON.parse(init.body); assert.equal(body.additionalAuthenticatedData, base64(aad)); assert.equal(body.additionalAuthenticatedDataCrc32c, crc32c(aad));
    if (url.endsWith(':encrypt')) {
      assert.equal(body.plaintextCrc32c, crc32c(dek));
      return response({ name: `${gcp.keyId}/cryptoKeyVersions/1`, ciphertext: base64(dek), ciphertextCrc32c: corrupt ? '0' : crc32c(dek), verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true });
    }
    return response({ plaintext: base64(dek), plaintextCrc32c: corrupt ? '0' : crc32c(dek) });
  });
  await Promise.all([p.wrap(dek, aad), p.wrap(dek, aad)]); assert.equal(tokens, 1);
  assert.deepEqual(await p.unwrap(base64(dek), aad), dek); assert.equal(tokens, 1);
  corrupt = true;
  await assert.rejects(p.wrap(dek, aad), { code: 'KMS_UNAVAILABLE' });
  await assert.rejects(p.unwrap(base64(dek), aad), { code: 'KMS_UNAVAILABLE' });
  await assert.rejects(p.unwrap('!bad', aad), { code: 'DECRYPT_FAILED' });
});
test('provider configurations reject aliases, URL credentials, insecure remote URLs and unknown fields', () => {
  const gcp = { provider: 'gcp', keyId: 'projects/test/locations/global/keyRings/test/cryptoKeys/strongroom', serviceAccount: { clientEmail: 'test@example.com', privateKey: '-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----' } };
  for (const k of [aws, transit, { ...transit, provider: 'openbao' }, gcp]) {
    assert.ok(parseConfig({ ...env, STRONGROOM_CONFIG: JSON.stringify({ ...config, keys: { primary: k, restricted: k } }) }));
  }
  for (const k of [{ ...aws, keyId: 'alias/test' }, { ...aws, region: 'us-west-2' }, { ...transit, url: 'http://remote.example' },
    { ...transit, url: 'https://user:password@vault.example' }, { ...transit, mount: '../escape' }, { ...transit, url: 'https://vault.example/?x=1' }, { ...transit, unknown: 1 },
    { ...gcp, keyId: 'invalid' }, { ...gcp, serviceAccount: { clientEmail: 'test', privateKey: 'invalid' } }]) {
    assert.throws(() => parseConfig({ ...env, STRONGROOM_CONFIG: JSON.stringify({ ...config, keys: { primary: k, restricted: k } }) }));
  }
});
const classify = () => { throw new Error('classify must not run'); };
test('upstream failures, redirects, malformed or oversized responses never expose upstream messages', async () => {
  for (const [fetcher, code] of [[async () => { throw new Error('credential-leak'); }, 'NETWORK_ERROR'], [async () => new Response('secret', { status: 302, headers: { location: 'https://attacker.example' } }), undefined],
    [async () => new Response('invalid-json'), 'INVALID_RESPONSE'], [async () => response(null), 'INVALID_RESPONSE'], [async () => response([]), 'INVALID_RESPONSE'],
    [async () => new Response('x'.repeat(65537)), 'RESPONSE_TOO_LARGE'], [async () => new Response(null), 'INVALID_RESPONSE']]) {
    await assert.rejects(kmsJson(fetcher, 'https://example', {}, classify), e => e.code === 'KMS_UNAVAILABLE' && e.retryable && e.upstream.code === code && !e.message.includes('credential-leak'));
  }
  // Unparseable error bodies still reach the classifier with the status alone; messages never become codes.
  for (const body of ['credential-leak', JSON.stringify({ __type: 'x y' }), JSON.stringify({ errors: ['permission denied', 'x'] }), JSON.stringify({ error: { status: 'A'.repeat(65) } })]) {
    let seen; await assert.rejects(kmsJson(async () => new Response(body, { status: 418 }), 'https://example', {}, u => { seen = u; return new Error('mapped'); }));
    assert.deepEqual(seen, { status: 418, code: undefined });
  }
  assert.equal(upstreamCode({ __type: 'com.amazonaws.kms#DisabledException' }), 'DisabledException');
});

// Replays every live-recorded upstream failure (tests/fixtures/kms, produced by scripts/test-live.mjs --record)
// through the real adapter, so the error contract is pinned to observed provider behaviour without network access.
const fixtures = await Promise.all(['aws', 'gcp', 'openbao'].map(async p => JSON.parse(await readFile(new URL(`./fixtures/kms/${p}.json`, import.meta.url), 'utf8'))));
const replayConfig = {
  aws: () => aws,
  gcp: () => ({ provider: 'gcp', keyId: 'projects/p/locations/global/keyRings/r/cryptoKeys/k', authorizedUser: { clientId: 'id', clientSecret: 'secret', refreshToken: 'refresh' } }),
  openbao: () => ({ ...transit, provider: 'openbao' }),
};
const replayWrapped = { aws: 'opaque', gcp: base64(dek), openbao: 'vault:v1:opaque' };
for (const fixture of fixtures) {
  test(`${fixture.provider} replays ${fixture.scenarios.length} live-recorded failures (verified ${fixture.verified})`, async () => {
    assert.ok(fixture.scenarios.length >= 8);
    for (const s of fixture.scenarios) {
      const upstream = () => new Response(s.upstream.body === null ? null : JSON.stringify(s.upstream.body), { status: s.upstream.status });
      const p = createProvider(replayConfig[fixture.provider](), async url => {
        if (String(url.url ?? url).includes('oauth2')) return s.upstream.endpoint === 'token' ? upstream() : response({ access_token: 'oauth-token', expires_in: 3600 });
        assert.notEqual(s.upstream.endpoint, 'token', `${s.name}: KMS must not be called after a token failure`);
        return upstream();
      });
      const run = s.operation === 'wrap' ? p.wrap(dek, aad) : p.unwrap(replayWrapped[fixture.provider], aad);
      await assert.rejects(run, e => {
        assert.deepEqual({ code: e.code, status: e.status, retryable: e.retryable }, s.expect, s.name);
        assert.equal(e.upstream.status, s.upstream.status, s.name);
        assert.equal(e.upstream.code, upstreamCode(s.upstream.body), s.name);
        return true;
      });
    }
  });
}
test('every non-retryable KMS code is reachable from a recorded fixture', () => {
  const seen = new Set(fixtures.flatMap(f => f.scenarios.map(s => s.expect.code)));
  for (const code of ['DECRYPT_FAILED', 'KMS_ACCESS_DENIED', 'KMS_KEY_UNAVAILABLE', 'KMS_UNAVAILABLE']) assert.ok(seen.has(code), code);
});
test('classifiers cover statuses no live run can safely provoke: throttling, 5xx and unknown codes stay retryable', () => {
  for (const op of ['Encrypt', 'Decrypt']) for (const u of [{ status: 400, code: 'ThrottlingException' }, { status: 500, code: 'KMSInternalException' }, { status: 503, code: 'DependencyTimeoutException' }, { status: 400, code: 'SomethingNew' }])
    assert.equal(classifyAws(op)(u).code, 'KMS_UNAVAILABLE');
  assert.equal(classifyAws('Encrypt')({ status: 400, code: 'InvalidCiphertextException' }).code, 'KMS_UNAVAILABLE');
  assert.equal(classifyAws('Encrypt')({ status: 400, code: 'KMSInvalidStateException' }).code, 'KMS_KEY_UNAVAILABLE');
  for (const op of ['encrypt', 'decrypt']) for (const u of [{ status: 429, code: 'RESOURCE_EXHAUSTED' }, { status: 503, code: 'UNAVAILABLE' }, { status: 500, code: 'INTERNAL' }, { status: 504, code: 'DEADLINE_EXCEEDED' }])
    assert.equal(classifyGcp(op)(u).code, 'KMS_UNAVAILABLE');
  assert.equal(classifyGcp('encrypt')({ status: 400, code: 'INVALID_ARGUMENT' }).code, 'KMS_UNAVAILABLE');
  for (const u of [{ status: 500 }, { status: 503 }, { status: 429 }, { status: 400, code: 'temporarily_unavailable' }]) assert.equal(classifyOAuth(u).code, 'KMS_UNAVAILABLE');
  assert.equal(classifyOAuth({ status: 400 }).code, 'KMS_ACCESS_DENIED');
  for (const op of ['encrypt', 'decrypt']) { assert.equal(classifyTransit(op)({ status: 429 }).code, 'KMS_UNAVAILABLE'); assert.equal(classifyTransit(op)({ status: 500 }).code, 'KMS_UNAVAILABLE'); }
  assert.equal(classifyTransit('encrypt')({ status: 400 }).code, 'KMS_UNAVAILABLE');
});
test('GCP authorized-user and metadata-server credentials, token invalidation and config exclusivity', async () => {
  const keyId = 'projects/p/locations/global/keyRings/r/cryptoKeys/k';
  const kms = (url, init) => {
    const body = JSON.parse(init.body);
    return url.endsWith(':encrypt') ? response({ name: `${keyId}/cryptoKeyVersions/1`, ciphertext: base64(dek), ciphertextCrc32c: crc32c(dek), verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true })
      : response({ plaintext: body.ciphertext, plaintextCrc32c: crc32c(dek) });
  };
  const seen = [];
  const user = createProvider({ provider: 'gcp', keyId, authorizedUser: { clientId: 'cid', clientSecret: 'cs', refreshToken: 'rt', quotaProject: 'billing' } }, async (url, init) => {
    if (url === 'https://oauth2.googleapis.com/token') { seen.push(Object.fromEntries(new URLSearchParams(init.body))); return response({ access_token: 'user-token', expires_in: 3599 }); }
    assert.equal(init.headers.authorization, 'Bearer user-token'); assert.equal(init.headers['x-goog-user-project'], 'billing');
    return kms(url, init);
  });
  assert.deepEqual(await user.unwrap(await user.wrap(dek, aad), aad), dek);
  assert.deepEqual(seen, [{ grant_type: 'refresh_token', client_id: 'cid', client_secret: 'cs', refresh_token: 'rt' }]);
  let tokens = 0, reject = false;
  const metadata = createProvider({ provider: 'gcp', keyId, metadataServer: true }, async (url, init) => {
    if (url.startsWith('http://metadata.google.internal/')) {
      assert.match(url, /\/instance\/service-accounts\/default\/token\?scopes=https:\/\/www\.googleapis\.com\/auth\/cloudkms$/);
      assert.equal(init.headers['metadata-flavor'], 'Google'); assert.equal(init.method, undefined);
      tokens++; return response({ access_token: `meta-${tokens}`, expires_in: 3000, token_type: 'Bearer' });
    }
    assert.equal(init.headers['x-goog-user-project'], undefined);
    if (reject) { reject = false; return response({ error: { code: 401, status: 'UNAUTHENTICATED' } }, 401); }
    return kms(url, init);
  });
  await metadata.wrap(dek, aad); await metadata.wrap(dek, aad); assert.equal(tokens, 1);
  // A token revoked before its nominal expiry is dropped after the first 401, not reused for an hour.
  reject = true; await assert.rejects(metadata.wrap(dek, aad), { code: 'KMS_ACCESS_DENIED' });
  await metadata.wrap(dek, aad); assert.equal(tokens, 2);
  await assert.rejects(createProvider({ provider: 'gcp', keyId, serviceAccount: { clientEmail: 'a@b', privateKey: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----' } }, async () => { throw new Error('no network'); }).wrap(dek, aad),
    e => e.code === 'KMS_ACCESS_DENIED' && e.upstream.code === 'INVALID_PRIVATE_KEY');
  const parse = k => parseConfig({ ...env, STRONGROOM_CONFIG: JSON.stringify({ ...config, keys: { primary: k, restricted: k } }) });
  assert.ok(parse({ provider: 'gcp', keyId, metadataServer: true }));
  assert.ok(parse({ provider: 'gcp', keyId, authorizedUser: { clientId: 'a', clientSecret: 'b', refreshToken: 'c' } }));
  for (const [k, path] of [[{ provider: 'gcp', keyId }, '$.keys.primary'], [{ provider: 'gcp', keyId, metadataServer: true, authorizedUser: {} }, '$.keys.primary'],
    [{ provider: 'gcp', keyId, metadataServer: 'yes' }, '$.keys.primary.metadataServer'], [{ provider: 'gcp', keyId, authorizedUser: { clientId: 'a', clientSecret: 'b' } }, '$.keys.primary.authorizedUser'],
    [{ provider: 'gcp', keyId, authorizedUser: { clientId: 'a', clientSecret: 'b', refreshToken: 'c', quotaProject: '' } }, '$.keys.primary.authorizedUser.quotaProject']])
    assert.throws(() => parse(k), e => e.path === path);
});
