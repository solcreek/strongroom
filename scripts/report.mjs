import { readFileSync, writeFileSync } from 'node:fs';
const core = JSON.parse(readFileSync('results/benchmark.json'));
const workers = JSON.parse(readFileSync('results/workerd.json'));
const validation = JSON.parse(readFileSync('results/validation.json'));
const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
const engines = ['typescript', 'rust-wasm', 'rust-native'];
const names = { typescript: 'TypeScript / Web Crypto', 'rust-wasm': 'Rust / Wasm', 'rust-native': 'Rust native CLI' };
const pick = (engine, size, delay = 0) => core.measurements.filter(x => x.engine === engine && x.size === size && x.delayMsPerKmsCall === delay);
const metric = (engine, size, key, delay = 0) => median(pick(engine, size, delay).map(x => x[key]));
const coreRows = [128, 1024, 16384].map(size => `| ${size} B | ${engines.map(e => metric(e, size, 'p50Ms').toFixed(3)).join(' | ')} |`).join('\n');
const p95Rows = [128, 1024, 16384].map(size => `| ${size} B | ${engines.map(e => metric(e, size, 'p95Ms').toFixed(3)).join(' | ')} |`).join('\n');
const resourceRows = engines.map(e => `| ${names[e]} | ${(metric(e, 128, 'processMaxRssBytes') / 1048576).toFixed(2)} | ${metric(e, 128, 'processCpuSeconds').toFixed(3)} |`).join('\n');
const delayRows = [10, 50].map(delay => `| ${delay} ms × 2 | ${engines.map(e => metric(e, 128, 'p50Ms', delay).toFixed(3)).join(' | ')} |`).join('\n');
const workerValue = (engine, size, delay) => median(workers.results.filter(r => r.engine === engine && r.size === size && r.delayMsPerKmsCall === delay).map(r => r.averageRoundtripMs));
const workerRows = [[128, 0], [1024, 0], [16384, 0], [128, 10]].map(([size, delay]) =>
  `| ${size} B | ${delay} ms × 2 | ${workerValue('typescript', size, delay).toFixed(3)} | ${workerValue('rust-wasm', size, delay).toFixed(3)} |`).join('\n');
const artifacts = core.artifacts.map(a => `| ${a.path} | ${(a.bytes / 1024).toFixed(2)} | ${(a.gzipBytes / 1024).toFixed(2)} |`).join('\n');
const speedup = workerValue('typescript', 128, 0) / workerValue('rust-wasm', 128, 0);
const text = `# Rust / TypeScript POC comparison

Rust is viable. The POC's Rust core compiled to both a native binary and Wasm; Rust / Wasm and TypeScript both passed local workerd verification and Wrangler deploy --dry-run.

For a 128-byte API key, the Rust / Wasm handler in local workerd is about ${speedup.toFixed(2)}x as fast as TypeScript, but one encrypt + decrypt differs by only ${(workerValue('typescript', 128, 0) - workerValue('rust-wasm', 128, 0)).toFixed(3)} ms. With a simulated 10 ms wait per KMS call, both take about 24 ms. This supports choosing a Rust core, but does not imply that a production service would speed up or save Workers cost in the same proportion.

Recommendation: build Strongroom on a shared Rust core, with Wasm + a thin host on Workers and a native HTTP adapter on container platforms. If the first release targets only Workers, TypeScript has a simpler build and artifacts, and its performance is sufficient for small API keys; Rust's main added value is the shared core and resource efficiency in native deployments. The next decision gate is an end-to-end measurement against a real sandbox KMS in the same region.

## Environment and method

- Core measurement time: ${core.createdAt}.
- Machine: ${core.cpu}, ${core.arch} / ${core.platform}; Node ${core.versions.node}; ${core.versions.rust}.
- Workers runtime: ${workers.workerdVersion}, compatibility date 2026-07-01.
- One roundtrip = encrypt + decrypt, including RNG, JSON, base64, a fresh DEK each time, and local simulated wrap / unwrap; it is not raw AES throughput.
- Each scenario is repeated three times. Core tables show the median of three runs' p50 or p95; workerd tables show the median of three batch averages. The two statistics are not the same test and must not be divided by each other.
- Rust native enables aes_armv8 / polyval_armv8 on ARM; Wasm uses portable RustCrypto; TypeScript uses the runtime's Web Crypto. There is no DEK cache.

## Core processing latency

In ms, no artificial KMS delay, p50. TypeScript and Wasm run in Node; Rust native is a CLI.

| Data size | TypeScript | Rust / Wasm | Rust native |
|---|---:|---:|---:|
${coreRows}

p95, still the median of three runs:

| Data size | TypeScript | Rust / Wasm | Rust native |
|---|---:|---:|---:|
${p95Rows}

## Local workerd handler

In ms, the median of three batch averages. The test runs the Request/Response handler, **with no TCP / HTTP transport**. The Workers clock advances only at I/O boundaries, so whole batches are measured with a final 1 ms timer; the timer overhead is included in the values. These are not per-request p50/p95, nor production Cloudflare billed CPU time.

| Data size | Simulated wait per KMS call | TypeScript | Rust / Wasm |
|---|---|---:|---:|
${workerRows}

The full loopback HTTP load test was not measured because the sandbox forbade listen. npm run bench:workers remains available for environments that allow local TCP, including concurrency 1 / 8. This round's compatibility and handler tests used workerd's built-in socketless test entry point.

## Native and Node process resources

128 B, 1500 measurements + 100 warm-up iterations; the table takes the median of three processes.

| Process | Peak RSS (MiB) | Whole-process CPU seconds |
|---|---:|---:|
${resourceRows}

RSS / CPU include the runtime, initialization and warm-up. The Rust CLI has no HTTP server, TLS or KMS SDK; its numbers are not production container service capacity. The Wasm row includes Node / V8 and must not be read as total Workers isolate memory or used to estimate cost directly. Raw Wasm linear memory figures are stored separately in JSON; they are only part of total memory.

## Simulated KMS wait

Core roundtrip at 128 B, p50, ms:

| Simulated wait | TypeScript | Rust / Wasm | Rust native |
|---|---:|---:|---:|
${delayRows}

These are artificial waits only, with no real KMS call. Rust native uses a thread sleep and Node uses a timer, with different wake-up precision on macOS; native's gap in this table is not a network performance conclusion. These numbers only show that tens of milliseconds of waiting swamp tens of microseconds of core difference; they cannot predict cloud KMS latency.

## Artifact sizes

Minified bundles and binaries used by the benchmark, KiB:

| Artifact | Uncompressed | gzip |
|---|---:|---:|
${artifacts}

A Rust Worker needs the JS host + Wasm, so both must be added together; Web Crypto lives in the host runtime and does not go into the TypeScript bundle.

A dry-run with the two real Wrangler configurations, Wrangler ${validation.wranglerDryRun.version}, reported: TypeScript upload ${validation.wranglerDryRun.typescript.uploadKiB} KiB / gzip ${validation.wranglerDryRun.typescript.gzipKiB.toFixed(2)} KiB; Rust / Wasm upload ${validation.wranglerDryRun.rustWasm.uploadKiB} KiB / gzip ${validation.wranglerDryRun.rustWasm.gzipKiB} KiB. Wrangler's default build differs from the benchmark's minification, so the numbers differ slightly. Both bundled successfully; nothing was published.

## Verified and not yet verified

- 2 Rust tests pass, including AES-256-GCM standard vectors.
- 17 Node tests pass, including nine cross-decryption combinations, boundaries, and context and tampering rejection.
- TypeScript typecheck passes.
- Local workerd: bidirectional cross-decryption, wrong tenant context and tampered ciphertext rejection pass.
- Both Wrangler deploy --dry-run runs pass.
- No real Cloudflare publication, cloud cold-start, CPU billing, total Workers memory or container platform deployment test.
- No real AWS / Google / Vault / OpenBao integration; the KMS simulation uses a public fixed key, and the POC cannot protect real user API keys.
- Rust / Wasm uses a JS host, not a complete workers-rs server. Native Rust currently has only a CLI baseline.

Raw data: [core](benchmark.json), [workerd](workerd.json), [HTTP test status](workers.json), [validation log](validation.json). Reproduction commands and the contract are in the [README](../README.md).
`;
writeFileSync('results/REPORT.md', text);
console.log('Wrote results/REPORT.md');
