import { build } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
await build({ entryPoints: ['scripts/workerd-test.mjs'], outfile: 'dist/workerd-test.js', bundle: true, format: 'esm',
  plugins: [{ name: 'wasm', setup(b) { b.onResolve({ filter: /\.wasm$/ }, () => ({ path: './strongroom_poc_bg.wasm', external: true })); } }] });
writeFileSync('dist/workerd.capnp', `using Workerd = import "/workerd/workerd.capnp";
const poc :Workerd.Config = (
  services = [(name = "poc", worker = (
    compatibilityDate = "2026-07-01",
    modules = [
      (name = "workerd-test.js", esModule = embed "workerd-test.js"),
      (name = "strongroom_poc_bg.wasm", wasm = embed "strongroom_poc_bg.wasm")
    ]
  ))]
);
`);
const command = 'node_modules/.bin/workerd';
const start = performance.now();
const result = spawnSync(command, ['test', 'dist/workerd.capnp'], { encoding: 'utf8', timeout: 120000 });
const output = result.stdout + result.stderr;
mkdirSync('results', { recursive: true });
writeFileSync('results/workerd-run.log', output);
if (result.status !== 0) throw new Error(output || String(result.error));
const match = output.match(/STRONGROOM_RESULTS=(\[[^\n]+\])/);
if (!match || !output.includes('STRONGROOM_COMPATIBILITY_OK')) throw new Error('Missing test results: ' + output);
const report = { createdAt: new Date().toISOString(),
  workerdVersion: spawnSync(command, ['--version'], { encoding: 'utf8' }).stdout.trim(),
  compatibilityPassed: true, harnessProcessWallMs: performance.now() - start,
  notes: ['Actual local workerd runtime, socket-free test entrypoint.',
    'Calls Worker fetch handlers with Request/Response in-process; no loopback HTTP transport.',
    'Cross-implementation decryption, context mismatch and ciphertext tampering tested.',
    'Workers clock advances at I/O boundaries: whole batches timed with a final 1ms timer, included in elapsed time.',
    'averageRoundtripMs is a batch average, NOT individual-request p50 or p95.',
    'Same isolate hosts both implementations. No per-engine RSS, CPU billing or cloud cold-start measurement.',
    'Synthetic KMS, not a real network/provider. Three repeats with alternating engine order.'],
  results: JSON.parse(match[1]) };
writeFileSync('results/workerd.json', JSON.stringify(report, null, 2) + '\n');
console.log('workerd interoperability/tampering checks passed');
for (const row of report.results) console.log(`${row.engine} ${row.size}B delay=${row.delayMsPerKmsCall}ms batch average=${row.averageRoundtripMs.toFixed(4)}ms`);
