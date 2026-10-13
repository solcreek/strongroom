import type { DecryptInput, EncryptInput, Envelope } from './types.js';
export type { Context, Envelope, EncryptInput, DecryptInput, ErrorBody } from './types.js';

export class StrongroomError extends Error {
  code: string; status: number; retryable: boolean; requestId?: string;
  constructor(code: string, message: string, status = 0, retryable = false, requestId?: string) {
    super(message); this.name = 'StrongroomError'; this.code = code; this.status = status; this.retryable = retryable; this.requestId = requestId;
  }
  toJSON() { return { code: this.code, message: this.message, status: this.status, retryable: this.retryable, ...(this.requestId ? { requestId: this.requestId } : {}) }; }
}
export interface ClientOptions { url: string; token: string; timeoutMs?: number; fetch?: typeof fetch }
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
export class Strongroom {
  #url: URL; #token: string; #fetch: typeof fetch; #timeout: number;
  constructor(options: ClientOptions) {
    this.#url = serviceUrl(options.url);
    if (!/^[A-Za-z0-9_-]{32,256}$/.test(options.token)) throw new StrongroomError('INVALID_CONFIG', 'Set a valid Strongroom bearer token.');
    this.#token = options.token; this.#fetch = options.fetch ?? fetch; this.#timeout = options.timeoutMs ?? 20000;
    if (!Number.isInteger(this.#timeout) || this.#timeout < 1 || this.#timeout > 120000) throw new StrongroomError('INVALID_CONFIG', 'timeoutMs must be between 1 and 120000.');
  }
  async #request(path: string, input?: unknown, options: RequestOptions = {}): Promise<any> {
    const timeout = AbortSignal.timeout(this.#timeout);
    const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
    try {
      const response = await this.#fetch(new URL(path, this.#url), { method: input === undefined ? 'GET' : 'POST',
        headers: { authorization: `Bearer ${this.#token}`, ...(input === undefined ? {} : { 'content-type': 'application/json' }) },
        ...(input === undefined ? {} : { body: JSON.stringify(input) }), redirect: 'error', signal });
      const reader = response.body?.getReader();
      if (!reader) throw new StrongroomError('INVALID_RESPONSE', 'Service returned an invalid response.', response.status);
      const chunks: Uint8Array[] = []; let size = 0;
      while (true) {
        const { done, value } = await reader.read(); if (done) break;
        size += value.length;
        if (size > 524288) { void reader.cancel().catch(() => {}); throw new StrongroomError('INVALID_RESPONSE', 'Service response exceeded the size limit.', response.status); }
        chunks.push(value);
      }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      let result: any;
      try { result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
      catch { throw new StrongroomError('INVALID_RESPONSE', 'Service returned invalid JSON.', response.status); }
      if (!response.ok) {
        const e = result?.error;
        if (typeof e?.code !== 'string' || typeof e?.message !== 'string' || typeof e?.retryable !== 'boolean') throw new StrongroomError('INVALID_RESPONSE', 'Service returned an invalid error.', response.status);
        throw new StrongroomError(e.code, e.message, response.status, e.retryable, e.requestId);
      }
      return result;
    } catch (error) {
      if (error instanceof StrongroomError) throw error;
      if (options.signal?.aborted) throw new StrongroomError('ABORTED', 'Request was cancelled.');
      if (timeout.aborted) throw new StrongroomError('TIMEOUT', 'Service request timed out.', 0, true);
      throw new StrongroomError('NETWORK_ERROR', 'Unable to reach Strongroom.', 0, true);
    }
  }
  async encrypt(input: EncryptInput, options?: RequestOptions): Promise<Envelope> {
    const result = await this.#request('/v1/encrypt', input, options);
    const e = result?.envelope;
    if (e?.version !== 1 || e?.algorithm !== 'A256GCM' || !['key', 'nonce', 'ciphertext', 'wrappedKey'].every(k => typeof e[k] === 'string' && e[k].length > 0)) throw new StrongroomError('INVALID_RESPONSE', 'Service returned an invalid envelope.');
    return e;
  }
  async decrypt(input: DecryptInput, options?: RequestOptions): Promise<string> {
    const result = await this.#request('/v1/decrypt', input, options);
    if (typeof result?.plaintext !== 'string') throw new StrongroomError('INVALID_RESPONSE', 'Service returned invalid plaintext.');
    return result.plaintext;
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
