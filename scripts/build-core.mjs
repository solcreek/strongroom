import { mkdirSync, copyFileSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { run, bindgen } from './rust-env.mjs';
// wasm-bindgen's CLI must equal the crate version in Cargo.lock, or bindings fail with an opaque schema error.
const locked = readFileSync('Cargo.lock', 'utf8').match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
const installed = spawnSync(bindgen, ['--version'], { encoding: 'utf8' }).stdout?.trim().split(' ')[1];
if (installed !== locked) throw new Error(`wasm-bindgen CLI ${installed ?? 'not found'} does not match Cargo.lock ${locked}. Run: cargo install wasm-bindgen-cli --locked --version ${locked}`);
run('cargo', ['build', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '-p', 'strongroom-core']);
run(bindgen, ['target/wasm32-unknown-unknown/release/strongroom_core.wasm', '--target', 'web', '--out-dir', 'crates/core/pkg']);
mkdirSync('dist', { recursive: true });
copyFileSync('crates/core/pkg/strongroom_core_bg.wasm', 'dist/strongroom_core_bg.wasm');
