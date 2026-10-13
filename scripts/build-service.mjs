import { build } from 'esbuild';
import { copyFileSync, mkdirSync } from 'node:fs';
mkdirSync('dist', { recursive: true });
await build({ entryPoints: ['service/worker.ts'], outfile: 'dist/worker.js', bundle: true, format: 'esm', target: 'es2022',
  plugins: [{ name: 'wasm', setup(b) { b.onResolve({ filter: /\.wasm$/ }, () => ({ path: './strongroom_core_bg.wasm', external: true })); } }] });
await build({ entryPoints: ['service/node.ts'], outfile: 'dist/server.js', bundle: true, format: 'esm', platform: 'node', target: 'node22' });
copyFileSync('crates/core/pkg/strongroom_core_bg.wasm', 'dist/strongroom_core_bg.wasm');
