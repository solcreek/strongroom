import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { platform, arch, cpus, totalmem } from 'node:os';
import { performance } from 'node:perf_hooks';

mkdirSync('results', { recursive: true });
const measurements = [];
const scenarios = [ [128, 1500, 0], [1024, 1000, 0], [16384, 300, 0], [128, 30, 10], [128, 30, 50] ];
const engines = ['typescript', 'rust-wasm', 'rust-native'];
for (let repeat = 0; repeat < 3; repeat++) {
  // Rotate order between repeats to reduce consistent warm-machine ordering effects.
  for (const [size, iterations, delay] of scenarios) {
    for (const engine of [...engines.slice(repeat), ...engines.slice(0, repeat)]) {
      const args = engine === 'rust-native'
        ? ['poc/rust/target/release/native', 'bench', `${size}`, `${iterations}`, `${delay}`]
        : [process.execPath, 'scripts/sample.mjs', engine, `${size}`, `${iterations}`, `${delay}`];
      const start = performance.now();
      const result = spawnSync(args[0], args.slice(1), { encoding: 'utf8' });
      if (result.status !== 0) throw new Error(result.stderr);
      const measurement = JSON.parse(result.stdout.trim());
      Object.assign(measurement, { repeat, processWallMs: performance.now() - start });
      measurements.push(measurement);
      console.log(`${engine} ${size}B delay=${delay}ms repeat=${repeat + 1}: p50=${measurement.p50Ms.toFixed(3)}ms`);
    }
  }
}
const files = ['dist/worker-ts.js', 'dist/worker-rust.js', 'poc/rust/pkg/strongroom_poc_bg.wasm', 'poc/rust/target/release/native'];
const artifacts = files.map(path => ({ path, bytes: statSync(path).size, gzipBytes: gzipSync(readFileSync(path)).length }));
const versions = { node: process.version, rust: spawnSync(existsSync('.cache/toolchain/bin/rustc') ? '.cache/toolchain/bin/rustc' : 'rustc', ['--version'], { encoding: 'utf8' }).stdout.trim() };
const report = { createdAt: new Date().toISOString(), platform: platform(), arch: arch(),
  cpu: cpus()[0]?.model, logicalCpus: cpus().length, machineMemoryBytes: totalmem(), versions,
  notes: ['Synthetic data and public mock wrapping key; no managed KMS calls.',
    'One sample = encrypt then decrypt, including RNG, JSON and base64; two simulated KMS delays per sample.',
    '100 warmups with zero delay; 5 warmups in delayed scenarios; measured operations sequential.',
    'Native Rust is a CLI baseline, not an HTTP server. Wasm runs inside Node here; Workers measured separately.',
    'RSS is whole process peak, includes runtime and warmup; Wasm linear memory is not total process memory.',
    'Process CPU time uses OS resource counters; startup and warmup included. No billing inference.',
    'Native aarch64 enables aes_armv8 and polyval_armv8 hardware backends; Wasm uses portable RustCrypto.'], artifacts, measurements };
writeFileSync('results/benchmark.json', JSON.stringify(report, null, 2) + '\n');
