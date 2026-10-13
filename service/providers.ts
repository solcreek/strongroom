import { AwsClient } from 'aws4fetch';
import type { KeyConfig } from './config.ts';
import { base64, base64url, unbase64, unbase64url, crc32c, utf8 } from './encoding.ts';
import { decryptFailed, unavailable } from './errors.ts';
import { kmsJson, type Fetch } from './transport.ts';

export interface KeyProvider { wrap(key: Uint8Array<ArrayBuffer>, aad: Uint8Array<ArrayBuffer>): Promise<string>; unwrap(wrapped: string, aad: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> }
function checkedKey(value: unknown): Uint8Array<ArrayBuffer> {
  try { const key = unbase64(value as string); if (key.length === 32) return key; } catch { /* sanitized below */ }
  throw unavailable();
}
function checkedCiphertext(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 16384) throw unavailable();
  return value;
}
export function createProvider(supplied: KeyConfig, fetcher: Fetch = fetch): KeyProvider {
  const config = supplied;
  if (config.provider === 'local') {
    const raw = unbase64url(config.kek);
    const promise = crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']); raw.fill(0);
    return {
      async wrap(key, aad) {
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, await promise, key));
        const blob = new Uint8Array(60); blob.set(nonce); blob.set(ciphertext, 12);
        return base64url(blob);
      },
      async unwrap(wrapped, aad) {
        try {
          const blob = unbase64url(wrapped); if (blob.length !== 60) throw decryptFailed();
          return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.subarray(0, 12), additionalData: aad }, await promise, blob.subarray(12)));
        } catch { throw decryptFailed(); }
      },
    };
  }
  if (config.provider === 'aws') {
    const client = new AwsClient({ accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey, sessionToken: config.sessionToken, region: config.region, service: 'kms', retries: 0 });
    const url = `https://kms.${config.region}.${config.region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com'}/`;
    const call = async (op: 'Encrypt' | 'Decrypt', value: string, aad: Uint8Array) => {
      const request = await client.sign(url, { method: 'POST', headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': `TrentService.${op}` },
        body: JSON.stringify({ KeyId: config.keyId, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT', EncryptionContext: { strongroom: base64(aad) }, [op === 'Encrypt' ? 'Plaintext' : 'CiphertextBlob']: value }) });
      const result = await kmsJson(fetcher, request, {}, op === 'Decrypt');
      if (result.KeyId !== config.keyId || result.EncryptionAlgorithm !== 'SYMMETRIC_DEFAULT') throw unavailable();
      return result;
    }
    return {
      async wrap(key, aad) { return checkedCiphertext((await call('Encrypt', base64(key), aad)).CiphertextBlob); },
      async unwrap(wrapped, aad) { return checkedKey((await call('Decrypt', wrapped, aad)).Plaintext); },
    };
  }
  if (config.provider === 'gcp') {
    let cached: { value: string; until: number } | undefined;
    let inflight: Promise<string> | undefined;
    const token = async (): Promise<string> => {
      if (cached && Date.now() < cached.until) return cached.value;
      if (inflight) return inflight;
      inflight = (async () => {
        const now = Math.floor(Date.now() / 1000);
        const header = base64url(utf8.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
        const claims = base64url(utf8.encode(JSON.stringify({ iss: config.serviceAccount.clientEmail, scope: 'https://www.googleapis.com/auth/cloudkms', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 })));
        const pkcs8 = unbase64(config.serviceAccount.privateKey.replace(/-----[A-Z ]+-----|\s/g, ''));
        let key: CryptoKey;
        try { key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']); }
        finally { pkcs8.fill(0); }
        const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, utf8.encode(`${header}.${claims}`));
        const result = await kmsJson(fetcher, 'https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${header}.${claims}.${base64url(new Uint8Array(sig))}` }).toString() });
        if (typeof result.access_token !== 'string' || result.access_token.length < 1 || !Number.isFinite(result.expires_in) || result.expires_in <= 60) throw unavailable();
        cached = { value: result.access_token, until: Date.now() + Math.min(result.expires_in - 60, 3540) * 1000 };
        return cached.value;
      })();
      try { return await inflight; } finally { inflight = undefined; }
    }
    const call = async (op: 'encrypt' | 'decrypt', bytes: Uint8Array, aad: Uint8Array) => {
      const field = op === 'encrypt' ? 'plaintext' : 'ciphertext';
      return kmsJson(fetcher, `https://cloudkms.googleapis.com/v1/${config.keyId}:${op}`, {
        method: 'POST', headers: { authorization: `Bearer ${await token()}`, 'content-type': 'application/json' },
        body: JSON.stringify({ [field]: base64(bytes), [`${field}Crc32c`]: crc32c(bytes), additionalAuthenticatedData: base64(aad), additionalAuthenticatedDataCrc32c: crc32c(aad) }),
      }, op === 'decrypt');
    }
    return {
      async wrap(key, aad) {
        const r = await call('encrypt', key, aad);
        if (typeof r.name !== 'string' || !r.name.startsWith(`${config.keyId}/cryptoKeyVersions/`) || !r.verifiedPlaintextCrc32c || !r.verifiedAdditionalAuthenticatedDataCrc32c || crc32c(unbase64(r.ciphertext)) !== r.ciphertextCrc32c) throw unavailable();
        return checkedCiphertext(r.ciphertext);
      },
      async unwrap(wrapped, aad) {
        let bytes: Uint8Array<ArrayBuffer>;
        try { bytes = unbase64(wrapped); } catch { throw decryptFailed(); }
        const r = await call('decrypt', bytes, aad);
        const key = checkedKey(r.plaintext);
        if (crc32c(key) !== r.plaintextCrc32c) { key.fill(0); throw unavailable(); }
        return key;
      },
    };
  }
  const origin = new URL(config.url).origin;
  const transit = async (op: string, value: string, aad: Uint8Array) => {
    const headers: Record<string, string> = { 'content-type': 'application/json', 'x-vault-token': config.token };
    if (config.namespace) headers['x-vault-namespace'] = config.namespace;
    const r = await kmsJson(fetcher, `${origin}/v1/${config.mount}/${op}/${config.keyName}`, { method: 'POST', headers,
      body: JSON.stringify({ [op === 'encrypt' ? 'plaintext' : 'ciphertext']: value, context: base64(aad), associated_data: base64(aad) }) }, op === 'decrypt');
    if (!r.data || typeof r.data !== 'object') throw unavailable();
    return r.data;
  }
  return {
    async wrap(key, aad) { return checkedCiphertext((await transit('encrypt', base64(key), aad)).ciphertext); },
    async unwrap(wrapped, aad) { return checkedKey((await transit('decrypt', wrapped, aad)).plaintext); },
  };
}
