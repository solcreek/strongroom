import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createProvider, classifyAws, classifyGcp, classifyOAuth, classifyTransit } from '../service/providers.ts';
import { parseConfig } from '../service/config.ts';
import { kmsJson, upstreamCode } from '../service/transport.ts';
import { base64, unbase64, crc32c, utf8 } from '../service/encoding.ts';
import { config, env } from './helpers.mjs';
const dek = new Uint8Array(32).fill(13), aad = utf8.encode('bound-context');
const aws = { provider: 'aws', region: 'us-east-1', keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012', accessKeyId: 'TESTACCESSKEY', secretAccessKey: 'test-secret', sessionToken: 'test-session' };
const transit = { provider: 'vault', url: 'https://vault.example', mount: 'team/transit', keyName: 'strongroom', token: 'secret', namespace: 'team' };
const response = value => new Response(JSON.stringify(value));
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
