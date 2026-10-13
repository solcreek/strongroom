import { Miniflare } from 'miniflare';
import { performance } from 'node:perf_hooks';
import { mkdirSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const token = 'synthetic-local-poc-token-32-characters';
const context = { tenantId: 'tenant-1', recordId: 'record-1', purpose: 'api-key' };
const results = [];

async function create(engine, delay) {
  const start = performance.now();
  const mf = new Miniflare({
    modules: true, scriptPath: `dist/worker-${engine === 'typescript' ? 'ts' : 'rust'}.js`,
    modulesRoot: 'dist', modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
    compatibilityDate: '2026-07-01', host: '127.0.0.1', port: 0,
    bindings: { POC_ONLY: 'true', POC_TOKEN: token, MOCK_KMS_DELAY_MS: String(delay) },
  });
  const url = await mf.ready;
  return { mf, url, startupMs: performance.now() - start };
}
async function request(url, operation, data, expected = 200) {
  const response = await fetch(new URL(operation, url), {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(data),
  });
  assert.equal(response.status, expected, await (response.status === expected ? Promise.resolve('') : response.text()));
  return response.json();
}
// Workerd compatibility and cross-worker interoperability before measurements.
const ts = await create('typescript', 0);
const rust = await create('rust-wasm', 0);
try {
  for (const [writer, reader] of [[ts, rust], [rust, ts]]) {
    const envelope = await request(writer.url, '/encrypt', { plaintext: 'synthetic-api-key-🔐', context });
    assert.equal((await request(reader.url, '/decrypt', { envelope, context })).plaintext, 'synthetic-api-key-🔐');
    await request(reader.url, '/decrypt', { envelope, context: { ...context, tenantId: 'other' } }, 400);
  }
  console.log('Local workerd interoperability and tenant-context checks passed');
} finally { await ts.mf.dispose(); await rust.mf.dispose(); }

for (let repeat = 0; repeat < 3; repeat++) {
  for (const engine of repeat % 2 ? ['rust-wasm', 'typescript'] : ['typescript', 'rust-wasm']) {
    for (const delay of [0, 10]) {
      const { mf, url, startupMs } = await create(engine, delay);
      try {
        for (const concurrency of [1, 8]) {
          const plaintext = 'x'.repeat(128);
          const once = async () => {
            const start = performance.now();
            const envelope = await request(url, '/encrypt', { plaintext, context });
            const result = await request(url, '/decrypt', { envelope, context });
            assert.equal(result.plaintext, plaintext);
            return performance.now() - start;
          };
          for (let i = 0; i < 10; i++) await once();
          const iterations = 80;
          const samples = [];
          let next = 0;
          const start = performance.now();
          await Promise.all(Array.from({ length: concurrency }, async () => {
            while (next++ < iterations) samples.push(await once());
          }));
          const elapsed = performance.now() - start;
          samples.sort((a, b) => a - b);
          results.push({ engine, repeat, size: 128, concurrency, iterations, delayMsPerKmsCall: delay,
            p50Ms: samples[40], p95Ms: samples[76], meanMs: samples.reduce((a, b) => a + b, 0) / iterations,
            roundtripsPerSecond: iterations / elapsed * 1000, localRuntimeStartupMs: startupMs });
          console.log(`${engine} local workerd c=${concurrency} delay=${delay} p50=${samples[40].toFixed(2)}ms`);
        }
      } finally { await mf.dispose(); }
    }
  }
}
mkdirSync('results', { recursive: true });
writeFileSync('results/workers.json', JSON.stringify({ createdAt: new Date().toISOString(),
  notes: ['Local Miniflare/workerd over loopback HTTP; not deployed Cloudflare measurements.',
    'Each sample is two HTTP requests: encrypt then decrypt. Includes harness, network loopback, and serialization overhead.',
    'Startup is starting a complete local workerd process, not a production isolate cold start.',
    'Fixed public mock wrapping key; delays are synthetic. No managed KMS or remote authentication tested.',
    'Workers CPU billing and per-isolate total memory are not measured.'], results }, null, 2) + '\n');
