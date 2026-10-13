import { AwsClient } from 'aws4fetch';
import type { Bindings, KeyConfig } from './config.ts';
import { base64, base64url, unbase64, unbase64url, crc32c, utf8 } from './encoding.ts';
import { accessDenied, decryptFailed, keyUnavailable, ServiceError, unavailable } from './errors.ts';
import { kmsJson, type Classify, type Fetch } from './transport.ts';

export interface KeyProvider { wrap(key: Uint8Array<ArrayBuffer>, aad: Uint8Array<ArrayBuffer>): Promise<string>; unwrap(wrapped: string, aad: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> }
// A 2xx response that violates the provider contract: fail closed and retryable, tagged for operator logs.
const malformed = () => Object.assign(unavailable(), { upstream: { status: 200, code: 'INVALID_RESPONSE' } }) as ServiceError;
function checkedKey(value: unknown): Uint8Array<ArrayBuffer> {
  try { const key = unbase64(value as string); if (key.length === 32) return key; } catch { /* sanitized below */ }
  throw malformed();
}
function checkedCiphertext(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 16384) throw malformed();
  return value;
}
// Observed live: AWS KMS reports every client-side error, including denied credentials, as HTTP 400 with `__type`.
const awsDenied = new Set(['AccessDeniedException', 'UnrecognizedClientException', 'InvalidSignatureException', 'IncompleteSignature', 'IncompleteSignatureException',
  'ExpiredTokenException', 'InvalidClientTokenId', 'MissingAuthenticationToken', 'MissingAuthenticationTokenException', 'SignatureDoesNotMatch']);
const awsKey = new Set(['NotFoundException', 'DisabledException', 'KMSInvalidStateException', 'InvalidKeyUsageException']);
export const classifyAws = (op: 'Encrypt' | 'Decrypt'): Classify => ({ status, code = '' }) =>
  op === 'Decrypt' && ['InvalidCiphertextException', 'IncorrectKeyException'].includes(code) ? decryptFailed()
    : awsDenied.has(code) || status === 401 || status === 403 ? accessDenied() : awsKey.has(code) ? keyUnavailable() : unavailable();
// Google returns canonical `error.status`; a disabled or destroyed version is FAILED_PRECONDITION.
export const classifyGcp = (op: 'encrypt' | 'decrypt'): Classify => ({ status, code }) =>
  status === 401 || status === 403 ? accessDenied() : status === 404 || code === 'FAILED_PRECONDITION' ? keyUnavailable()
    : op === 'decrypt' && code === 'INVALID_ARGUMENT' ? decryptFailed() : unavailable();
// OAuth token endpoints: a rejected assertion, client or refresh token will not recover by retrying.
export const classifyOAuth: Classify = ({ status, code }) =>
  [400, 401, 403].includes(status) && (code === undefined || ['invalid_grant', 'invalid_client', 'unauthorized_client', 'invalid_scope'].includes(code)) ? accessDenied() : unavailable();
// Vault/OpenBao: the status carries the meaning, except a missing key or a version below min_decryption_version (400).
export const classifyTransit = (op: 'encrypt' | 'decrypt'): Classify => ({ status, code }) =>
  status === 401 || status === 403 ? accessDenied() : status === 404 || code === 'key_not_found' || code === 'version_disallowed' ? keyUnavailable() : op === 'decrypt' && [400, 422].includes(status) ? decryptFailed() : unavailable();
// Caches a short-lived credential and coalesces concurrent loads; `drop` forgets it after an upstream rejection,
// so a revoked credential is not reused until its nominal expiry.
function credentialCache<T>(load: () => Promise<{ value: T; until: number }>) {
  let cached: { value: T; until: number } | undefined, inflight: Promise<{ value: T; until: number }> | undefined;
  return {
    async get(): Promise<T> {
      if (cached && Date.now() < cached.until) return cached.value;
      inflight ??= load().finally(() => { inflight = undefined; });
      cached = await inflight; return cached.value;
    },
    async guard<R>(run: () => Promise<R>): Promise<R> {
      try { return await run(); } catch (e) { if (e instanceof ServiceError && e.code === 'KMS_ACCESS_DENIED') cached = undefined; throw e; }
    },
  };
}
export function createProvider(supplied: KeyConfig, fetcher: Fetch = fetch, env: Bindings = {}): KeyProvider {
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
    const signer = (c: { accessKeyId: string; secretAccessKey: string; sessionToken?: string }) => new AwsClient({ ...c, region: config.region, service: 'kms', retries: 0 });
    const clients = 'containerCredentials' in config
      ? credentialCache(async () => { const c = await awsContainerCredentials(env, fetcher); return { value: signer(c), until: c.until }; })
      : (fixed => ({ get: async () => fixed, guard: <R>(run: () => Promise<R>) => run() }))(signer(config));
    const url = `https://kms.${config.region}.${config.region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com'}/`;
    const call = async (op: 'Encrypt' | 'Decrypt', value: string, aad: Uint8Array) => {
      const request = await (await clients.get()).sign(url, { method: 'POST', headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': `TrentService.${op}` },
        body: JSON.stringify({ KeyId: config.keyId, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT', EncryptionContext: { strongroom: base64(aad) }, [op === 'Encrypt' ? 'Plaintext' : 'CiphertextBlob']: value }) });
      const result = await kmsJson(fetcher, request, {}, classifyAws(op));
      if (result.KeyId !== config.keyId || result.EncryptionAlgorithm !== 'SYMMETRIC_DEFAULT') throw malformed();
      return result;
    }
    return {
      wrap: (key, aad) => clients.guard(async () => checkedCiphertext((await call('Encrypt', base64(key), aad)).CiphertextBlob)),
      unwrap: (wrapped, aad) => clients.guard(async () => checkedKey((await call('Decrypt', wrapped, aad)).Plaintext)),
    };
  }
  if (config.provider === 'gcp') {
    const tokenRequest = gcpTokenSource(config, fetcher);
    const tokens = credentialCache(async () => {
      const result = await tokenRequest();
      if (typeof result.access_token !== 'string' || result.access_token.length < 1 || !Number.isFinite(result.expires_in) || result.expires_in <= 60) throw malformed();
      return { value: result.access_token as string, until: Date.now() + Math.min(result.expires_in - 60, 3540) * 1000 };
    });
    const call = async (op: 'encrypt' | 'decrypt', bytes: Uint8Array, aad: Uint8Array) => {
      const field = op === 'encrypt' ? 'plaintext' : 'ciphertext';
      const headers: Record<string, string> = { authorization: `Bearer ${await tokens.get()}`, 'content-type': 'application/json' };
      if ('authorizedUser' in config && config.authorizedUser.quotaProject) headers['x-goog-user-project'] = config.authorizedUser.quotaProject;
      const r = await kmsJson(fetcher, `https://cloudkms.googleapis.com/v1/${config.keyId}:${op}`, { method: 'POST', headers,
        body: JSON.stringify({ [field]: base64(bytes), [`${field}Crc32c`]: crc32c(bytes), additionalAuthenticatedData: base64(aad), additionalAuthenticatedDataCrc32c: crc32c(aad) }),
      }, classifyGcp(op));
      return r;
    }
    const guard = tokens.guard;
    return {
      wrap: (key, aad) => guard(async () => {
        const r = await call('encrypt', key, aad);
        let ciphertext: Uint8Array;
        try { ciphertext = unbase64(r.ciphertext); } catch { throw malformed(); }
        if (typeof r.name !== 'string' || !r.name.startsWith(`${config.keyId}/cryptoKeyVersions/`) || r.verifiedPlaintextCrc32c !== true || r.verifiedAdditionalAuthenticatedDataCrc32c !== true || crc32c(ciphertext) !== r.ciphertextCrc32c) throw malformed();
        return checkedCiphertext(r.ciphertext);
      }),
      unwrap: (wrapped, aad) => guard(async () => {
        let bytes: Uint8Array<ArrayBuffer>;
        try { bytes = unbase64(wrapped); } catch { throw decryptFailed(); }
        const r = await call('decrypt', bytes, aad);
        const key = checkedKey(r.plaintext);
        if (crc32c(key) !== r.plaintextCrc32c) { key.fill(0); throw malformed(); }
        return key;
      }),
    };
  }
  const origin = new URL(config.url).origin;
  const transit = async (op: 'encrypt' | 'decrypt', value: string, aad: Uint8Array) => {
    const headers: Record<string, string> = { 'content-type': 'application/json', 'x-vault-token': config.token };
    if (config.namespace) headers['x-vault-namespace'] = config.namespace;
    const r = await kmsJson(fetcher, `${origin}/v1/${config.mount}/${op}/${config.keyName}`, { method: 'POST', headers,
      body: JSON.stringify({ [op === 'encrypt' ? 'plaintext' : 'ciphertext']: value, context: base64(aad), associated_data: base64(aad) }) }, classifyTransit(op));
    if (!r.data || typeof r.data !== 'object') throw malformed();
    return r.data;
  }
  return {
    async wrap(key, aad) { return checkedCiphertext((await transit('encrypt', base64(key), aad)).ciphertext); },
    async unwrap(wrapped, aad) { return checkedKey((await transit('decrypt', wrapped, aad)).plaintext); },
  };
}
type GcpConfig = Extract<KeyConfig, { provider: 'gcp' }>;
// One OAuth access-token source per credential type. Each returns the raw token response for shared validation and caching.
function gcpTokenSource(config: GcpConfig, fetcher: Fetch): () => Promise<Record<string, any>> {
  const form = (body: Record<string, string>) => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body).toString() });
  if ('serviceAccount' in config) return async () => {
    const now = Math.floor(Date.now() / 1000);
    const header = base64url(utf8.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
    const claims = base64url(utf8.encode(JSON.stringify({ iss: config.serviceAccount.clientEmail, scope: 'https://www.googleapis.com/auth/cloudkms', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 })));
    let key: CryptoKey;
    try {
      const pkcs8 = unbase64(config.serviceAccount.privateKey.replace(/-----[A-Z ]+-----|\s/g, ''));
      try { key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']); }
      finally { pkcs8.fill(0); }
    } catch { throw Object.assign(accessDenied(), { upstream: { status: 0, code: 'INVALID_PRIVATE_KEY' } }); }
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, utf8.encode(`${header}.${claims}`));
    return kmsJson(fetcher, 'https://oauth2.googleapis.com/token', form({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${header}.${claims}.${base64url(new Uint8Array(sig))}` }), classifyOAuth);
  };
  if ('authorizedUser' in config) return () => kmsJson(fetcher, 'https://oauth2.googleapis.com/token',
    form({ grant_type: 'refresh_token', client_id: config.authorizedUser.clientId, client_secret: config.authorizedUser.clientSecret, refresh_token: config.authorizedUser.refreshToken }), classifyOAuth);
  // Cloud Run, GKE Workload Identity and Compute Engine. Unreachable from Cloudflare Workers.
  return () => kmsJson(fetcher, 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloudkms',
    { headers: { 'metadata-flavor': 'Google' } }, classifyOAuth);
}
// ECS/Fargate task roles (relative URI) and EKS Pod Identity (full URI plus authorization token), per the AWS SDK
// container credential provider. Unavailable in Cloudflare Workers.
const containerHosts = ['169.254.170.2', '169.254.170.23', '[fd00:ec2::23]', '127.0.0.1', '[::1]', 'localhost'];
async function awsContainerCredentials(env: Bindings, fetcher: Fetch) {
  const fail = (code: string) => Object.assign(accessDenied(), { upstream: { status: 0, code } }) as ServiceError;
  let url: URL;
  try {
    if (env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) url = new URL(`http://169.254.170.2${env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}`);
    else if (env.AWS_CONTAINER_CREDENTIALS_FULL_URI) url = new URL(env.AWS_CONTAINER_CREDENTIALS_FULL_URI);
    else throw fail('NO_CONTAINER_CREDENTIALS');
  } catch (e) { throw e instanceof ServiceError ? e : fail('INVALID_CONTAINER_CREDENTIALS_URI'); }
  // A plain-HTTP endpoint must be link-local or loopback, or the role credentials could be fetched from elsewhere.
  if (url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && containerHosts.includes(url.hostname)))) throw fail('INVALID_CONTAINER_CREDENTIALS_URI');
  const headers: Record<string, string> = {};
  if (env.AWS_CONTAINER_AUTHORIZATION_TOKEN) headers.authorization = env.AWS_CONTAINER_AUTHORIZATION_TOKEN;
  const r = await kmsJson(fetcher, url.href, { headers }, ({ status }) => status === 401 || status === 403 ? accessDenied() : unavailable());
  const until = Date.parse(r.Expiration) - 300_000;
  if (![r.AccessKeyId, r.SecretAccessKey, r.Token].every(v => typeof v === 'string' && v.length > 0) || !Number.isFinite(until)) throw malformed();
  // Credentials within five minutes of expiry are used for this call only.
  return { accessKeyId: r.AccessKeyId as string, secretAccessKey: r.SecretAccessKey as string, sessionToken: r.Token as string, until: Math.max(until, Date.now()) };
}
