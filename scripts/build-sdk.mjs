import { build } from 'esbuild';
import { spawnSync } from 'node:child_process';
await build({ entryPoints: ['packages/strongroom/src/client.ts'], outfile: 'packages/strongroom/dist/index.js', bundle: true, format: 'esm', target: 'es2022', sourcemap: true });
await build({ entryPoints: ['packages/strongroom/src/cli.ts'], outfile: 'packages/strongroom/dist/cli.js', bundle: true, format: 'esm', platform: 'node', target: 'node22', sourcemap: true });
const result = spawnSync('node_modules/.bin/tsc', ['-p', 'packages/strongroom/tsconfig.build.json'], { stdio: 'inherit' });
if (result.status !== 0) throw new Error('SDK declaration build failed');
