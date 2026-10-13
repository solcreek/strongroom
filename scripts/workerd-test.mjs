import ts from '../dist/worker-ts.js';
import rust from '../dist/worker-rust.js';

const env = { POC_ONLY: 'true', POC_TOKEN: 'synthetic-local-poc-token-32-characters' };
const context = { tenantId: 'tenant-1', recordId: 'record-1', purpose: 'api-key' };
const wait = () => new Promise(resolve => setTimeout(resolve, 1));
async function call(worker, operation, body, delay = 0, expected = 200) {
  const response = await worker.fetch(new Request(`https://poc.invalid/${operation}`, {
    method: 'POST', headers: { authorization: `Bearer ${env.POC_TOKEN}` }, body: JSON.stringify(body),
  }), { ...env, MOCK_KMS_DELAY_MS: String(delay) });
  if (response.status !== expected) throw new Error(`Unexpected response ${response.status}`);
  return response.json();
}
export default {
  async test() {
    for (const [writer, reader] of [[ts, rust], [rust, ts]]) {
      const envelope = await call(writer, 'encrypt', { plaintext: 'synthetic-🔐', context });
      const result = await call(reader, 'decrypt', { envelope, context });
      if (result.plaintext !== 'synthetic-🔐') throw new Error('interoperability failure');
      await call(reader, 'decrypt', { envelope, context: { ...context, tenantId: 'wrong' } }, 0, 400);
      const corrupt = { ...envelope, ciphertext: (envelope.ciphertext[0] === 'A' ? 'B' : 'A') + envelope.ciphertext.slice(1) };
      await call(reader, 'decrypt', { envelope: corrupt, context }, 0, 400);
    }
    console.log('STRONGROOM_COMPATIBILITY_OK');
    const rows = [];
    // Workers clocks advance at I/O boundaries. Time whole batches with an ending timer,
    // not individual synchronous operations. Timer overhead is explicitly included.
    for (let repeat = 0; repeat < 3; repeat++) {
      const order = repeat % 2 ? [['rust-wasm', rust], ['typescript', ts]] : [['typescript', ts], ['rust-wasm', rust]];
      for (const [engine, worker] of order) {
        for (const [size, iterations, delay] of [[128, 1000, 0], [1024, 500, 0], [16384, 100, 0], [128, 20, 10]]) {
          const plaintext = 'x'.repeat(size);
          const once = async () => {
            const envelope = await call(worker, 'encrypt', { plaintext, context }, delay);
            const result = await call(worker, 'decrypt', { envelope, context }, delay);
            if (result.plaintext !== plaintext) throw new Error('roundtrip failed');
          };
          for (let i = 0; i < (delay ? 5 : 50); i++) await once();
          await wait();
          const start = performance.now();
          for (let i = 0; i < iterations; i++) await once();
          await wait();
          const elapsed = performance.now() - start;
          if (elapsed <= 0) throw new Error('clock did not advance');
          rows.push({ engine, repeat, size, iterations, delayMsPerKmsCall: delay,
            batchElapsedMs: elapsed, averageRoundtripMs: elapsed / iterations });
        }
      }
    }
    console.log('STRONGROOM_RESULTS=' + JSON.stringify(rows));
  },
};
