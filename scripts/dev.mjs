import { readFile } from 'node:fs/promises';
import { Miniflare } from 'miniflare';
import { context } from 'esbuild';
const config = await readFile('.strongroom/config.json', 'utf8').catch(() => { throw new Error('Run npm run dev:init first.'); });
const mf = new Miniflare({ modules: true, scriptPath: 'dist/worker.js', modulesRoot: 'dist', modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }], compatibilityDate: '2026-07-01',
  host: '127.0.0.1', port: 8787, bindings: { STRONGROOM_CONFIG: config, STRONGROOM_ALLOW_LOCAL: 'true' } });
process.stderr.write(JSON.stringify({ event: 'ready', runtime: 'workerd', url: String(await mf.ready), clientEnv: '.strongroom/client.env' }) + '\n');
const build = await context({ entryPoints: ['service/worker.ts'], outfile: 'dist/worker.js', bundle: true, format: 'esm', target: 'es2022',
  plugins: [
    { name: 'wasm', setup(b) { b.onResolve({ filter: /\.wasm$/ }, () => ({ path: './strongroom_core_bg.wasm', external: true })); } },
    { name: 'reload', setup(b) { b.onEnd(async result => {
      if (result.errors.length) return;
      await mf.setOptions({ modules: true, scriptPath: 'dist/worker.js', modulesRoot: 'dist', modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }], compatibilityDate: '2026-07-01',
        host: '127.0.0.1', port: 8787, bindings: { STRONGROOM_CONFIG: config, STRONGROOM_ALLOW_LOCAL: 'true' } });
      process.stderr.write('{"event":"reloaded"}\n');
    }); } },
  ] });
await build.watch();
let stopping = false;
const stop = async () => { if (stopping) return; stopping = true; await build.dispose(); await mf.dispose(); process.exit(0); };
process.on('SIGINT', stop); process.on('SIGTERM', stop);
