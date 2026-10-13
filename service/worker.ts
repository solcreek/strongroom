import init, { execute } from '../crates/core/pkg/strongroom_core.js';
import module from '../crates/core/pkg/strongroom_core_bg.wasm';
import { createApp, errorResponse, json } from './app.ts';
import type { Bindings } from './config.ts';
import { ServiceError } from './errors.ts';
let cached: { config: string | undefined; local: string | undefined; app: ReturnType<typeof createApp> } | undefined;
let ready: Promise<unknown> | undefined;
export default { async fetch(request: Request, env: Bindings): Promise<Response> {
  if (new URL(request.url).pathname === '/healthz' && request.method === 'GET') return json({ status: 'ok' });
  try {
    ready ??= init({ module_or_path: module });
    await ready;
    if (!cached || cached.config !== env.STRONGROOM_CONFIG || cached.local !== env.STRONGROOM_ALLOW_LOCAL) {
      const app = createApp(env, execute);
      cached = { config: env.STRONGROOM_CONFIG, local: env.STRONGROOM_ALLOW_LOCAL, app };
    }
    return await cached.app.fetch(request);
  } catch { return errorResponse(new ServiceError('NOT_CONFIGURED', 503, 'Service configuration is invalid.')); }
} };
