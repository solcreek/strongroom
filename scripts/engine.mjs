import { readFileSync } from 'node:fs';

export async function loadEngine(engine) {
  if (engine === 'typescript') return { execute: (await import('../dist/core.js')).execute };
  if (engine === 'rust-wasm') {
    const wasm = await import('../poc/rust/pkg/strongroom_poc.js');
    const exports = wasm.initSync({ module: new WebAssembly.Module(readFileSync('poc/rust/pkg/strongroom_poc_bg.wasm')) });
    return { execute: wasm.execute, memory: exports.memory };
  }
  throw new Error('unknown engine');
}
