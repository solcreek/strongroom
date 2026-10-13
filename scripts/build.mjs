import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, copyFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { build } from 'esbuild';

const env = { ...process.env };
if (existsSync('.cache/cargo')) { env.CARGO_HOME = resolve('.cache/cargo'); env.CARGO_NET_OFFLINE = 'true'; }
if (existsSync('.cache/toolchain/bin/rustc')) {
  env.RUSTC = resolve('.cache/toolchain/bin/rustc');
  env.RUSTDOC = resolve('.cache/toolchain/bin/rustdoc');
}
export function run(command, args, extra = {}) {
  const result = spawnSync(command, args, { stdio: 'inherit', env: { ...env, ...extra } });
  if (result.status !== 0) throw new Error(`${command} failed: ${result.error ?? result.status}`);
}
// aes-gcm 0.10's ARM hardware backends are explicitly opt-in; keep the native baseline fair.
const nativeFlags = process.arch === 'arm64' ? { RUSTFLAGS: '--cfg aes_armv8 --cfg polyval_armv8' } : {};
run('cargo', ['test', '--locked', '--manifest-path', 'poc/rust/Cargo.toml'], nativeFlags);
run('cargo', ['build', '--locked', '--release', '--manifest-path', 'poc/rust/Cargo.toml', '--bin', 'native'], nativeFlags);
run('cargo', ['build', '--locked', '--release', '--manifest-path', 'poc/rust/Cargo.toml', '--lib', '--target', 'wasm32-unknown-unknown']);
const bindgen = existsSync('.cache/wasm-bindgen-0.2.105-aarch64-apple-darwin/wasm-bindgen')
  ? '.cache/wasm-bindgen-0.2.105-aarch64-apple-darwin/wasm-bindgen' : 'wasm-bindgen';
run(bindgen, ['poc/rust/target/wasm32-unknown-unknown/release/strongroom_poc.wasm', '--target', 'web', '--out-dir', 'poc/rust/pkg']);
mkdirSync('dist', { recursive: true });
await build({ entryPoints: ['poc/typescript/core.ts'], outfile: 'dist/core.js', bundle: true, format: 'esm', minify: true, target: 'es2022' });
await build({ entryPoints: ['poc/typescript/worker.ts'], outfile: 'dist/worker-ts.js', bundle: true, format: 'esm', minify: true, target: 'es2022' });
await build({ entryPoints: ['poc/typescript/wasm-worker.ts'], outfile: 'dist/worker-rust.js', bundle: true, format: 'esm', minify: true, target: 'es2022',
  plugins: [{ name: 'wasm', setup(b) { b.onResolve({ filter: /\.wasm$/ }, () => ({ path: './strongroom_poc_bg.wasm', external: true })); } }] });
copyFileSync('poc/rust/pkg/strongroom_poc_bg.wasm', 'dist/strongroom_poc_bg.wasm');
