import type { DecryptInput, EncryptInput, Envelope } from './types.js';
export type { Context, Envelope, EncryptInput, DecryptInput, ErrorBody } from './types.js';

export class StrongroomError extends Error {
  code: string; status: number; retryable: boolean; requestId?: string; path?: string;
  // `path` is the JSON path of the offending input field, when the service or CLI can name one.
  constructor(code: string, message: string, status = 0, retryable = false, requestId?: string, path?: string) {
    super(message); this.name = 'StrongroomError'; this.code = code; this.status = status; this.retryable = retryable; this.requestId = requestId; this.path = path;
  }
  toJSON() { return { code: this.code, message: this.message, status: this.status, retryable: this.retryable, ...(this.requestId ? { requestId: this.requestId } : {}), ...(this.path ? { path: this.path } : {}) }; }
}
export interface ClientOptions {
  url: string; token: string; timeoutMs?: number; fetch?: typeof fetch;
  // Google ID token for a Cloud Run service with invoker IAM; sent as X-Serverless-Authorization so Authorization stays the Strongroom bearer.
  cloudRunIdToken?: string;
}
export interface RequestOptions { signal?: AbortSignal }
export function serviceUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new StrongroomError('INVALID_CONFIG', 'Set a valid Strongroom service URL.'); }
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
    throw new StrongroomError('INVALID_CONFIG', 'Use an HTTPS origin, or HTTP loopback for local development.');
  }
  return url;
}
function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
export class Strongroom {
  #url: URL; #token: string; #fetch: typeof fetch; #timeout: number; #platform: Record<string, string> = {};
  constructor(options: ClientOptions) {
    this.#url = serviceUrl(options.url);
    if (!/^[A-Za-z0-9_-]{32,256}$/.test(options.token)) throw new StrongroomError('INVALID_CONFIG', 'Set a valid Strongroom bearer token.');
    this.#token = options.token; this.#fetch = options.fetch ?? fetch; this.#timeout = options.timeoutMs ?? 20000;
    if (options.cloudRunIdToken !== undefined) {
      if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(options.cloudRunIdToken)) throw new StrongroomError('INVALID_CONFIG', 'cloudRunIdToken must be a Google ID token (JWT).');
      this.#platform = { 'x-serverless-authorization': `Bearer ${options.cloudRunIdToken}` };
    }
    if (!Number.isInteger(this.#timeout) || this.#timeout < 1 || this.#timeout > 120000) throw new StrongroomError('INVALID_CONFIG', 'timeoutMs must be between 1 and 120000.');
  }
  // `binary` asks for raw bytes on success; errors are JSON either way.
  async #request(path: string, input?: unknown, options: RequestOptions = {}, binary = false): Promise<any> {
    const timeout = AbortSignal.timeout(this.#timeout);
    const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
    try {
      const response = await this.#fetch(new URL(path, this.#url), { method: input === undefined ? 'GET' : 'POST',
        headers: { ...this.#platform, authorization: `Bearer ${this.#token}`, ...(input === undefined ? {} : { 'content-type': 'application/json' }), ...(binary ? { accept: 'application/octet-stream' } : {}) },
        ...(input === undefined ? {} : { body: JSON.stringify(input) }), redirect: 'manual', signal });
      const reader = response.body?.getReader();
      if (!reader) throw new StrongroomError('INVALID_RESPONSE', 'Service returned an invalid response.', response.status);
      const chunks: Uint8Array[] = []; let size = 0;
      try {
        while (true) {
          const { done, value } = await reader.read(); if (done) break;
          size += value.length;
          if (size > 524288) { value.fill(0); void reader.cancel().catch(() => {}); throw new StrongroomError('INVALID_RESPONSE', 'Service response exceeded the size limit.', response.status); }
          chunks.push(value);
        }
      } catch (e) { for (const chunk of chunks) chunk.fill(0); throw e; }
      // A response may carry plaintext: keep one copy, wipe the transport chunks.
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; chunk.fill(0); }
      if (binary && response.ok) {
        if (response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() === 'application/octet-stream') return bytes;
        bytes.fill(0);
        throw new StrongroomError('INVALID_RESPONSE', 'Service did not return binary plaintext; it may predate binary support.', response.status);
      }
      let result: any;
      try { result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
      catch {
        // Not Strongroom's JSON: a platform or proxy in front of it (Cloud Run IAM, an ALB, a WAF) answered instead.
        if ([401, 403, 404, 407].includes(response.status)) throw new StrongroomError('GATEWAY_REJECTED', `A gateway in front of Strongroom rejected the request (HTTP ${response.status}). For Cloud Run with invoker IAM, supply a Google ID token (STRONGROOM_CLOUD_RUN_ID_TOKEN); otherwise check STRONGROOM_URL.`, response.status);
        throw new StrongroomError('INVALID_RESPONSE', 'Service returned invalid JSON.', response.status);
      } finally { bytes.fill(0); }
      if (!response.ok) {
        const e = result?.error;
        if (typeof e?.code !== 'string' || typeof e?.message !== 'string' || typeof e?.retryable !== 'boolean') throw new StrongroomError('INVALID_RESPONSE', 'Service returned an invalid error.', response.status);
        throw new StrongroomError(e.code, e.message, response.status, e.retryable, e.requestId, typeof e.path === 'string' ? e.path : undefined);
      }
      return result;
    } catch (error) {
      if (error instanceof StrongroomError) throw error;
      if (options.signal?.aborted) throw new StrongroomError('ABORTED', 'Request was cancelled.');
      if (timeout.aborted) throw new StrongroomError('TIMEOUT', 'Service request timed out.', 0, true);
      throw new StrongroomError('NETWORK_ERROR', 'Unable to reach Strongroom.', 0, true);
    }
  }
  // Bytes travel as base64url text, which the runtime cannot wipe; the caller still owns and wipes `plaintext`.
  async encrypt(input: EncryptInput, options?: RequestOptions): Promise<Envelope> {
    const { plaintext, ...rest } = input ?? {} as EncryptInput;
    const result = await this.#request('/v1/encrypt', plaintext instanceof Uint8Array ? { ...rest, plaintextBase64url: base64url(plaintext) } : input, options);
    const e = result?.envelope;
    if (e?.version !== 1 || e?.algorithm !== 'A256GCM' || !['key', 'nonce', 'ciphertext', 'wrappedKey'].every(k => typeof e[k] === 'string' && e[k].length > 0)) throw new StrongroomError('INVALID_RESPONSE', 'Service returned an invalid envelope.');
    return e;
  }
  async decrypt(input: DecryptInput, options?: RequestOptions): Promise<string> {
    const result = await this.#request('/v1/decrypt', input, options);
    if (typeof result?.plaintext !== 'string') throw new StrongroomError('INVALID_RESPONSE', 'Service returned invalid plaintext.');
    return result.plaintext;
  }
  // Raw plaintext bytes, never converted to a string; wipe them with fill(0) after use.
  async decryptBytes(input: DecryptInput, options?: RequestOptions): Promise<Uint8Array<ArrayBuffer>> {
    return this.#request('/v1/decrypt', input, options, true);
  }
  async capabilities(options?: RequestOptions): Promise<Record<string, unknown>> {
    const result = await this.#request('/v1/capabilities', undefined, options);
    if (result?.name !== 'strongroom' || result?.apiVersion !== 'v1') throw new StrongroomError('INVALID_RESPONSE', 'Unsupported Strongroom API.');
    return result;
  }
  async ready(options?: RequestOptions): Promise<boolean> {
    const result = await this.#request('/readyz', undefined, options);
    if (result?.status !== 'ready') throw new StrongroomError('INVALID_RESPONSE', 'Service is not ready.');
    return true;
  }
}
