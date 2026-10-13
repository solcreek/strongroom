import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
export const rustEnv = { ...process.env };
if (existsSync('.cache/cargo')) rustEnv.CARGO_HOME = resolve('.cache/cargo');
if (existsSync('.cache/toolchain/bin/rustc')) {
  rustEnv.RUSTC = resolve('.cache/toolchain/bin/rustc');
  rustEnv.RUSTDOC = resolve('.cache/toolchain/bin/rustdoc');
}
export function run(command, args, env = {}) {
  const result = spawnSync(command, args, { stdio: 'inherit', env: { ...rustEnv, ...env } });
  if (result.status !== 0) throw new Error(`${command} failed (${result.status ?? result.error})`);
}
export const bindgen = existsSync('.cache/wasm-bindgen-0.2.105-aarch64-apple-darwin/wasm-bindgen')
  ? '.cache/wasm-bindgen-0.2.105-aarch64-apple-darwin/wasm-bindgen' : 'wasm-bindgen';
