import { decryptFailed, ServiceError, unavailable } from './errors.ts';
export type Fetch = typeof fetch;
// Do not forward upstream bodies, exceptions, redirects, or credentials to callers/logs.
export async function kmsJson(fetcher: Fetch, url: string | Request, init: RequestInit = {}, decrypt = false): Promise<Record<string, any>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetcher(url, { ...init, redirect: 'error', signal: controller.signal });
    if (!response.ok) {
      await response.body?.cancel();
      if (decrypt && [400, 422].includes(response.status)) throw decryptFailed();
      throw unavailable();
    }
    const reader = response.body?.getReader();
    if (!reader) throw unavailable();
    const chunks: Uint8Array[] = []; let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 65536) { await reader.cancel(); throw unavailable(); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw unavailable();
    return result;
  } catch (error) {
    if (error instanceof ServiceError) throw error;
    throw unavailable();
  } finally { clearTimeout(timer); }
}
