import { ServiceError, unavailable, type Upstream } from './errors.ts';
export type Fetch = typeof fetch;
// Maps a sanitized upstream failure to a stable service error. Providers own the mapping; see tests/fixtures/kms.
export type Classify = (upstream: Upstream) => ServiceError;
const safeCode = (value: unknown) => typeof value === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(value) ? value : undefined;
// Vault/OpenBao have no error codes; these exact messages are matched internally (never forwarded) to name a code.
const transitMessages: [RegExp, string][] = [[/^encryption key not found$/, 'key_not_found'], [/version is disallowed by policy/, 'version_disallowed']];
// AWS `__type` (may carry a `namespace#` prefix), Google `error.status`, OAuth `error`, Transit known messages.
export function upstreamCode(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const b = body as Record<string, any>;
  if (Array.isArray(b.errors)) return b.errors.length === 1 && typeof b.errors[0] === 'string' ? transitMessages.find(([re]) => re.test(b.errors[0]))?.[1] : undefined;
  if (typeof b.__type === 'string') return safeCode(b.__type.split('#').pop());
  if (b.error && typeof b.error === 'object') return safeCode(b.error.status);
  return safeCode(b.error);
}
function tagged(error: ServiceError, upstream: Upstream): ServiceError { error.upstream = upstream; return error; }
// Do not forward upstream bodies, exceptions, redirects, or credentials to callers/logs.
export async function kmsJson(fetcher: Fetch, url: string | Request, init: RequestInit, classify: Classify): Promise<Record<string, any>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  let status = 0;
  try {
    const response = await fetcher(url, { ...init, redirect: 'manual', signal: controller.signal });
    status = response.status;
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = []; let size = 0;
    while (reader) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 65536) { await reader.cancel(); throw tagged(unavailable(), { status, code: 'RESPONSE_TOO_LARGE' }); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    let result: unknown;
    try { result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { result = undefined; }
    if (!response.ok) {
      const upstream = { status, code: upstreamCode(result) };
      // Redirects and unclassified statuses fail closed as retryable unavailability.
      throw tagged(status >= 300 && status < 400 ? unavailable() : classify(upstream), upstream);
    }
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw tagged(unavailable(), { status, code: 'INVALID_RESPONSE' });
    return result as Record<string, any>;
  } catch (error) {
    if (error instanceof ServiceError) throw error;
    throw tagged(unavailable(), { status, code: controller.signal.aborted ? 'TIMEOUT' : 'NETWORK_ERROR' });
  } finally { clearTimeout(timer); }
}
