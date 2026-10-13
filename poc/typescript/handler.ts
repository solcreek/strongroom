import { encode } from './core.ts';

export type Executor = (input: string) => string | Promise<string>;
export type Env = { POC_ONLY?: string; POC_TOKEN?: string; MOCK_KMS_DELAY_MS?: string };

/** Synthetic-data test endpoint. The token is a POC gate, not tenant authorization. */
export function makeHandler(execute: Executor) {
  return async (request: Request, env: Env): Promise<Response> => {
    const headers = { 'content-type': 'application/json', 'cache-control': 'no-store' };
    const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers });
    if (env.POC_ONLY !== 'true' || !env.POC_TOKEN || env.POC_TOKEN.length < 24) return reply(503, { error: 'POC explicitly disabled' });
    if (request.headers.get('authorization') !== `Bearer ${env.POC_TOKEN}`) return reply(401, { error: 'unauthorized' });
    const path = new URL(request.url).pathname;
    if (request.method !== 'POST' || !['/encrypt', '/decrypt'].includes(path)) return reply(404, { error: 'not found' });
    let size = 0;
    const chunks: Uint8Array[] = [];
    const reader = request.body?.getReader();
    if (!reader) return reply(400, { error: 'missing body' });
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 524288) { await reader.cancel(); return reply(413, { error: 'request too large' }); }
      chunks.push(value);
    }
    try {
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      const expected = path === '/encrypt' ? ['context', 'plaintext'] : ['context', 'envelope'];
      if (!body || Object.keys(body).sort().join(',') !== expected.join(',')) throw new Error('invalid fields');
      // Exactly one simulated remote KMS operation per encrypt or decrypt.
      const delay = Number(env.MOCK_KMS_DELAY_MS ?? 0);
      if (!Number.isFinite(delay) || delay < 0 || delay > 1000) return reply(503, { error: 'invalid POC config' });
      if (delay) await new Promise(resolve => setTimeout(resolve, delay));
      const command = path === '/encrypt'
        ? { op: 'encrypt', ...body, entropy: encode(crypto.getRandomValues(new Uint8Array(56))) }
        : { op: 'decrypt', ...body };
      const result = await execute(JSON.stringify(command));
      return new Response(result, { headers });
    } catch {
      return reply(400, { error: 'invalid request or authentication failed' });
    }
  };
}
