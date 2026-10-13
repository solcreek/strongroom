import { mkdirSync, copyFileSync } from 'node:fs';
import { run, bindgen } from './rust-env.mjs';
run('cargo', ['build', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '-p', 'strongroom-core']);
run(bindgen, ['target/wasm32-unknown-unknown/release/strongroom_core.wasm', '--target', 'web', '--out-dir', 'crates/core/pkg']);
mkdirSync('dist', { recursive: true });
copyFileSync('crates/core/pkg/strongroom_core_bg.wasm', 'dist/strongroom_core_bg.wasm');
