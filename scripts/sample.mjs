// One process per measurement. Imports and Wasm initialization happen outside timed operations.
import { performance } from 'node:perf_hooks';
import { loadEngine } from './engine.mjs';
const [engine, sizeArg, iterationsArg, delayArg] = process.argv.slice(2);
const size = Number(sizeArg), iterations = Number(iterationsArg), delay = Number(delayArg);
const initStart = performance.now();
const { execute, memory } = await loadEngine(engine);
const initMs = performance.now() - initStart;
const context = { tenantId: 'tenant-1', recordId: 'record-1', purpose: 'api-key' };
const plaintext = 'x'.repeat(size);
const samples = [];
let envelopeBytes;
const pause = () => delay ? new Promise(resolve => setTimeout(resolve, delay)) : undefined;
const cpuStart = process.cpuUsage();
const warmups = delay > 0 ? 5 : 100;
for (let i = 0; i < iterations + warmups; i++) {
  const start = performance.now();
  const entropy = Buffer.from(crypto.getRandomValues(new Uint8Array(56))).toString('base64url');
  const request = JSON.stringify({ op: 'encrypt', plaintext, context, entropy });
  if (delay) await pause();
  const encrypted = await execute(request);
  const envelope = JSON.parse(encrypted);
  const decryptRequest = JSON.stringify({ op: 'decrypt', envelope, context });
  if (delay) await pause();
  const result = JSON.parse(await execute(decryptRequest));
  if (result.plaintext !== plaintext) throw new Error('roundtrip mismatch');
  envelopeBytes = Buffer.byteLength(encrypted);
  if (i >= warmups) samples.push(performance.now() - start);
}
samples.sort((a, b) => a - b);
const total = samples.reduce((a, b) => a + b, 0);
const cpu = process.cpuUsage();
console.log(JSON.stringify({ engine, size, iterations, delayMsPerKmsCall: delay,
  p50Ms: samples[Math.floor(iterations / 2)], p95Ms: samples[Math.min(Math.floor(iterations * .95), iterations - 1)],
  meanMs: total / iterations, roundtripsPerSecond: iterations / (total / 1000), envelopeBytes,
  moduleInitMs: initMs, maxRssKiB: process.resourceUsage().maxRSS,
  cpuIncludingWarmupMicros: process.cpuUsage(cpuStart), wasmLinearMemoryBytes: memory?.buffer.byteLength ?? null,
  processMaxRssBytes: process.resourceUsage().maxRSS * 1024, processCpuSeconds: (cpu.user + cpu.system) / 1e6 }));
