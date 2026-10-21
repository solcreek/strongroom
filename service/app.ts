import type { Context, Envelope } from '../packages/strongroom/src/types.ts';
import { fields, keyPattern, object, parseConfig, text, type Bindings, type Principal } from './config.ts';
import { base64url, equalHash, sha256, unbase64url, utf8 } from './encoding.ts';
import { decryptFailed, invalid, notText, ServiceError, unavailable } from './errors.ts';
import { createProvider } from './providers.ts';
import { capabilities, openapi } from './contract.ts';
import type { Fetch } from './transport.ts';

export type Core = (input: string) => string;
// Operator events: one JSON object each, never plaintext, tokens, DEKs, configuration values or upstream messages.
export type Log = (event: Record<string, unknown>) => void;
export const stderrLog: Log = event => console.error(JSON.stringify(event));
const headers = (type: string, requestId: string) => ({ 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId });
export function json(value: unknown, status = 200, requestId = crypto.randomUUID()): Response {
  return new Response(JSON.stringify(value), { status, headers: headers('application/json; charset=utf-8', requestId) });
}
// Decrypt answers with raw bytes only when the caller lists application/octet-stream with a nonzero q; JSON stays the default.
const wantsBytes = (request: Request) => (request.headers.get('accept') ?? '').split(',').some(range => {
  const [type, ...params] = range.split(';').map(s => s.trim().toLowerCase());
  const q = params.find(p => p.startsWith('q='));
  return type === 'application/octet-stream' && !(q && Number(q.slice(2)) === 0);
});
export function errorResponse(error: unknown, requestId = crypto.randomUUID()): Response {
  const e = error instanceof ServiceError ? error : new ServiceError('INTERNAL_ERROR', 500, 'An internal error occurred.');
  return json({ error: { code: e.code, message: e.message, retryable: e.retryable, requestId, ...(e.path ? { path: e.path } : {}) } }, e.status, requestId);
}
async function body(request: Request): Promise<Record<string, unknown>> {
  if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json') throw new ServiceError('UNSUPPORTED_MEDIA_TYPE', 415, 'Use application/json.');
  const limit = capabilities.maxRequestBytes;
  if (Number(request.headers.get('content-length')) > limit) throw new ServiceError('PAYLOAD_TOO_LARGE', 413, 'Request is too large.');
  const reader = request.body?.getReader();
  if (!reader) throw invalid();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => {
    reject(new ServiceError('REQUEST_TIMEOUT', 408, 'Request body timed out.'));
    void reader.cancel().catch(() => {});
  }, 8000); });
  try {
    return await Promise.race([timeout, (async () => {
      const chunks: Uint8Array[] = []; let size = 0;
      while (true) {
        const { done, value } = await reader.read(); if (done) break;
        size += value.length;
        if (size > limit) { void reader.cancel().catch(() => {}); throw new ServiceError('PAYLOAD_TOO_LARGE', 413, 'Request is too large.'); }
        chunks.push(value);
      }
      const all = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
      try {
        const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(all));
        if (!object(value)) throw invalid();
        return value;
      } catch { throw invalid(); }
    })()]);
  } finally { clearTimeout(timer); }
}
function shape(value: unknown, path: string, required: string[]): asserts value is Record<string, unknown> {
  try { fields(value, required); } catch { throw invalid(path, `must be an object with exactly: ${required.join(', ')}.`); }
}
function context(value: unknown): asserts value is Context {
  shape(value, '$.context', ['tenantId', 'recordId', 'purpose']);
  for (const f of ['tenantId', 'recordId', 'purpose']) if (!text(value[f], 256)) throw invalid(`$.context.${f}`, 'must be a well-formed string of 1-256 UTF-8 bytes.');
}
export function createApp(env: Bindings, core: Core, fetcher: Fetch = fetch, log: Log = stderrLog): { fetch(request: Request): Promise<Response> } {
  // Configuration is compiled once per host instance. No default keys or authorization.
  const config = parseConfig(env);
  const providers = new Map(Object.entries(config.keys).map(([key, value]) => [key, createProvider(value, fetcher, env)]));
  async function authenticate(request: Request): Promise<Principal> {
    const auth = request.headers.get('authorization') ?? '';
    if (!/^Bearer [A-Za-z0-9_-]{32,256}$/.test(auth)) throw new ServiceError('UNAUTHENTICATED', 401, 'A valid bearer token is required.');
    const hash = await sha256(auth.slice(7));
    let principal: Principal | undefined;
    for (const p of config.principals) if (equalHash(p.tokenSha256, hash)) principal = p;
    if (!principal) throw new ServiceError('UNAUTHENTICATED', 401, 'A valid bearer token is required.');
    return principal;
  }
  function run(value: unknown): any { return JSON.parse(core(JSON.stringify(value))); }
  return { async fetch(request) {
    const requestId = crypto.randomUUID();
    try {
      const path = new URL(request.url).pathname;
      const publicRoutes: Record<string, unknown> = { '/healthz': { status: 'ok' }, '/readyz': { status: 'ready', checks: ['configuration'] }, '/openapi.json': openapi, '/v1/capabilities': capabilities };
      if (Object.hasOwn(publicRoutes, path)) {
        if (request.method !== 'GET') throw new ServiceError('METHOD_NOT_ALLOWED', 405, 'Use GET.');
        return json(publicRoutes[path], 200, requestId);
      }
      if (!['/v1/encrypt', '/v1/decrypt'].includes(path)) throw new ServiceError('NOT_FOUND', 404, 'Unknown API endpoint.');
      if (request.method !== 'POST') throw new ServiceError('METHOD_NOT_ALLOWED', 405, 'Use POST.');
      const principal = await authenticate(request);
      const op = path === '/v1/encrypt' ? 'encrypt' : 'decrypt';
      if (!principal.permissions.includes(op)) throw new ServiceError('FORBIDDEN', 403, 'Operation is not permitted.');
      const input = await body(request);
      // Text arrives as `plaintext`, bytes as `plaintextBase64url`; exactly one of them.
      const field = Object.hasOwn(input, 'plaintextBase64url') ? 'plaintextBase64url' : 'plaintext';
      shape(input, '$', op === 'encrypt' ? [field, 'context', 'key'] : ['envelope', 'context']);
      context(input.context);
      const key = op === 'encrypt' ? input.key : object(input.envelope) ? input.envelope.key : undefined;
      if (typeof key !== 'string' || !keyPattern.test(key)) throw invalid(op === 'encrypt' ? '$.key' : '$.envelope.key', 'must be a configured key reference matching ^[A-Za-z0-9_-]{1,64}$.');
      // The tenant stays in the AAD, so even a miswired key cannot open another deployment's envelopes.
      if (input.context.tenantId !== config.tenantId || !principal.keys.includes(key) || !providers.has(key)) throw new ServiceError('FORBIDDEN', 403, 'Tenant or key is not permitted.');
      const provider = providers.get(key)!;
      const kmsFailure = (e: unknown) => {
        const error = e instanceof ServiceError ? e : unavailable();
        // `severity` is the field Cloud Logging maps to a log level; operator-action codes are ERROR.
        const severity = ['KMS_ACCESS_DENIED', 'KMS_KEY_UNAVAILABLE'].includes(error.code) ? 'ERROR' : 'WARNING';
        log({ severity, event: 'kms_error', requestId, operation: op, key, provider: config.keys[key].provider, code: error.code, upstreamStatus: error.upstream?.status ?? null, upstreamCode: error.upstream?.code ?? null });
        return error;
      };
      if (op === 'encrypt') {
        const max = capabilities.maxPlaintextBytes, value = input[field];
        let plaintext: Uint8Array<ArrayBuffer> | undefined;
        if (field === 'plaintext') {
          if (typeof value === 'string' && value.isWellFormed()) plaintext = utf8.encode(value);
          if (!plaintext || plaintext.length > max) throw invalid('$.plaintext', `must be well-formed text of at most ${max} UTF-8 bytes.`);
        } else {
          try { if (typeof value === 'string' && value.length <= Math.ceil(max * 4 / 3)) plaintext = unbase64url(value); } catch { /* reported below */ }
          if (!plaintext || plaintext.length > max) throw invalid('$.plaintextBase64url', `must be canonical base64url without padding, encoding at most ${max} bytes.`);
        }
        const entropy = crypto.getRandomValues(new Uint8Array(44));
        try {
          let sealed: { envelope: Envelope; aad: string };
          try { sealed = run({ op: 'seal', plaintext: base64url(plaintext), context: input.context, key, entropy: base64url(entropy) }); } catch { throw invalid(); }
          try { sealed.envelope.wrappedKey = await provider.wrap(entropy.subarray(0, 32), unbase64url(sealed.aad)); }
          catch (e) { throw kmsFailure(e); }
          return json({ envelope: sealed.envelope }, 200, requestId);
        } finally { entropy.fill(0); plaintext.fill(0); }
      }
      let inspected: { aad: string };
      try { inspected = run({ op: 'inspect', ...input }); } catch { throw invalid('$.envelope', 'is not a valid version 1 envelope; see schema Envelope.'); }
      let dek: Uint8Array<ArrayBuffer>;
      try { dek = await provider.unwrap((input.envelope as unknown as Envelope).wrappedKey, unbase64url(inspected.aad)); }
      catch (e) { throw kmsFailure(e); }
      let plaintext: Uint8Array<ArrayBuffer>;
      try {
        try { plaintext = unbase64url(run({ op: 'open', ...input, dek: base64url(dek) }).plaintext); } catch { throw decryptFailed(); }
      } finally { dek.fill(0); }
      try {
        // Fetch copies a BufferSource body when the Response is built, so this buffer can be wiped right after.
        if (wantsBytes(request)) return new Response(plaintext, { status: 200, headers: headers('application/octet-stream', requestId) });
        // ignoreBOM keeps a leading U+FEFF that was part of the encrypted text.
        let text: string;
        try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext); } catch { throw notText(); }
        return json({ plaintext: text }, 200, requestId);
      } finally { plaintext.fill(0); }
    } catch (error) { return errorResponse(error, requestId); }
  } };
}
