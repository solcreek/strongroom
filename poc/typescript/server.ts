import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { execute } from './core.ts';
import { makeHandler } from './handler.ts';
const handler = makeHandler(execute);
const server = createServer(async (req, res) => {
  try {
    const body = ['GET', 'HEAD'].includes(req.method ?? 'GET') ? undefined : Readable.toWeb(req);
    const request = new Request(`http://localhost${req.url}`, {
      method: req.method, headers: req.headers as HeadersInit, body: body as ReadableStream | undefined,
      // @ts-ignore Node requires duplex for streamed requests
      duplex: 'half',
    });
    const result = await handler(request, process.env);
    res.writeHead(result.status, Object.fromEntries(result.headers));
    res.end(Buffer.from(await result.arrayBuffer()));
  } catch { res.writeHead(400); res.end(); }
});
server.listen(Number(process.env.PORT ?? 8787), '127.0.0.1', () => console.log('POC listening on loopback only'));
