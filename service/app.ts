import type { Context, Envelope } from '../packages/strongroom/src/types.ts';
import { fields, keyPattern, object, parseConfig, text, type Bindings, type Principal } from './config.ts';
import { base64url, equalHash, sha256, unbase64url, utf8 } from './encoding.ts';
import { decryptFailed, invalid, ServiceError, unavailable } from './errors.ts';
import { createProvider } from './providers.ts';
import { capabilities, openapi } from './contract.ts';
import type { Fetch } from './transport.ts';

export type Core = (input: string) => string;
export function json(value: unknown, status = 200, requestId = crypto.randomUUID()): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId } });
}
export function errorResponse(error: unknown, requestId = crypto.randomUUID()): Response {
  const e = error instanceof ServiceError ? error : new ServiceError('INTERNAL_ERROR', 500, 'An internal error occurred.');
  return json({ error: { code: e.code, message: e.message, retryable: e.retryable, requestId } }, e.status, requestId);
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
function context(value: unknown): asserts value is Context {
  try { fields(value, ['tenantId', 'recordId', 'purpose']); } catch { throw invalid(); }
  if (![value.tenantId, value.recordId, value.purpose].every(v => text(v, 256))) throw invalid();
}
export function createApp(env: Bindings, core: Core, fetcher: Fetch = fetch): { fetch(request: Request): Promise<Response> } {
  // Configuration is compiled once per host instance. No default keys or authorization.
  const config = parseConfig(env);
  const providers = new Map(Object.entries(config.keys).map(([key, value]) => [key, createProvider(value, fetcher)]));
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
      try { fields(input, op === 'encrypt' ? ['plaintext', 'context', 'key'] : ['envelope', 'context']); } catch { throw invalid(); }
      context(input.context);
      const key = op === 'encrypt' ? input.key : object(input.envelope) ? input.envelope.key : undefined;
      if (typeof key !== 'string' || !keyPattern.test(key)) throw invalid();
      if (input.context.tenantId !== principal.tenantId || !principal.keys.includes(key) || !providers.has(key)) throw new ServiceError('FORBIDDEN', 403, 'Tenant or key is not permitted.');
      const provider = providers.get(key)!;
      if (op === 'encrypt') {
        if (typeof input.plaintext !== 'string' || !input.plaintext.isWellFormed() || utf8.encode(input.plaintext).length > capabilities.maxPlaintextBytes) throw invalid();
        const entropy = crypto.getRandomValues(new Uint8Array(44));
        try {
          let sealed: { envelope: Envelope; aad: string };
          try { sealed = run({ op: 'seal', ...input, entropy: base64url(entropy) }); } catch { throw invalid(); }
          try { sealed.envelope.wrappedKey = await provider.wrap(entropy.subarray(0, 32), unbase64url(sealed.aad)); }
          catch (e) { throw e instanceof ServiceError ? e : unavailable(); }
          return json({ envelope: sealed.envelope }, 200, requestId);
        } finally { entropy.fill(0); }
      }
      let inspected: { aad: string };
      try { inspected = run({ op: 'inspect', ...input }); } catch { throw invalid(); }
      let dek: Uint8Array<ArrayBuffer>;
      try { dek = await provider.unwrap((input.envelope as unknown as Envelope).wrappedKey, unbase64url(inspected.aad)); }
      catch (e) { throw e instanceof ServiceError ? e : unavailable(); }
      try {
        let result: { plaintext: string };
        try { result = run({ op: 'open', ...input, dek: base64url(dek) }); } catch { throw decryptFailed(); }
        return json(result, 200, requestId);
      } finally { dek.fill(0); }
    } catch (error) { return errorResponse(error, requestId); }
  } };
}
