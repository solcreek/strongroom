import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createProvider } from '../service/providers.ts';
import { parseConfig } from '../service/config.ts';
import { kmsJson } from '../service/transport.ts';
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
    assert.equal(init.redirect, 'error'); assert.ok(init.signal);
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
  for (const k of [aws, transit, { ...transit, provider: 'openbao' }]) {
    assert.ok(parseConfig({ ...env, STRONGROOM_CONFIG: JSON.stringify({ ...config, keys: { primary: k, restricted: k } }) }));
  }
  for (const k of [{ ...aws, keyId: 'alias/test' }, { ...aws, region: 'us-west-2' }, { ...transit, url: 'http://remote.example' },
    { ...transit, url: 'https://user:password@vault.example' }, { ...transit, mount: '../escape' }, { ...transit, url: 'https://vault.example/?x=1' }, { ...transit, unknown: 1 }]) {
    assert.throws(() => parseConfig({ ...env, STRONGROOM_CONFIG: JSON.stringify({ ...config, keys: { primary: k, restricted: k } }) }));
  }
});
test('upstream failures, redirects, malformed or oversized responses never expose upstream messages', async () => {
  for (const fetcher of [async () => { throw new Error('credential-leak'); }, async () => new Response('credential-leak', { status: 403 }),
    async () => new Response('secret', { status: 302, headers: { location: 'https://attacker.example' } }),
    async () => new Response('invalid-json'), async () => response(null), async () => new Response('x'.repeat(65537)), async () => new Response(null)]) {
    await assert.rejects(kmsJson(fetcher, 'https://example'), e => e.code === 'KMS_UNAVAILABLE' && !e.message.includes('credential-leak'));
  }
  await assert.rejects(kmsJson(async () => new Response('bad-ciphertext', { status: 400 }), 'https://example', {}, true), { code: 'DECRYPT_FAILED' });
});
