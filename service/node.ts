import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import init, { execute } from '../crates/core/pkg/strongroom_core.js';
import { createApp, errorResponse } from './app.ts';
import { ServiceError } from './errors.ts';
try {
  await init({ module_or_path: await readFile(new URL('./strongroom_core_bg.wasm', import.meta.url)) });
  const app = createApp(process.env, execute);
  const server = createServer(async (req, res) => {
    try {
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) if (value) headers.set(name, Array.isArray(value) ? value.join(', ') : value);
      const request = new Request(new URL(req.url ?? '/', 'http://localhost'), { method: req.method, headers,
        ...(['GET', 'HEAD'].includes(req.method ?? 'GET') ? {} : { body: Readable.toWeb(req) as ReadableStream<Uint8Array>, duplex: 'half' }) });
      const response = await app.fetch(request);
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      const response = errorResponse(new ServiceError('INVALID_REQUEST', 400, 'Invalid HTTP request.'));
      if (!res.headersSent) res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(await response.text());
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  const port = Number(process.env.PORT ?? 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
  server.listen(port, process.env.HOST ?? '127.0.0.1', () => process.stderr.write(JSON.stringify({ event: 'listening', port }) + '\n'));
  server.on('error', () => { process.stderr.write('{"error":{"code":"LISTEN_FAILED","message":"Unable to listen."}}\n'); process.exit(1); });
  const shutdown = () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(1), 10000).unref(); };
  process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
} catch {
  process.stderr.write('{"error":{"code":"NOT_CONFIGURED","message":"Run strongroom config-check with the service environment."}}\n'); process.exitCode = 1;
}
