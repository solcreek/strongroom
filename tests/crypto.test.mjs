import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { loadEngine } from '../scripts/engine.mjs';
import { makeHandler } from '../poc/typescript/handler.ts';

const native = input => {
  const result = spawnSync('poc/rust/target/release/native', [], { input: input + '\n', encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  if (JSON.parse(result.stdout).error) throw new Error('rejected');
  return result.stdout.trim();
};
const engines = { typescript: (await loadEngine('typescript')).execute, wasm: (await loadEngine('rust-wasm')).execute, native };
const context = { tenantId: '租戶-A', recordId: 'record-1', purpose: 'api-key' };
const entropy = Buffer.from(Array.from({ length: 56 }, (_, i) => i)).toString('base64url');
const encrypt = (execute, plaintext = 'synthetic-key-🔐', ctx = context) => execute(JSON.stringify({ op: 'encrypt', plaintext, context: ctx, entropy }));
const decrypt = (execute, envelope, ctx = context) => execute(JSON.stringify({ op: 'decrypt', envelope, context: ctx }));

test('same fixed fixture produces byte-identical envelopes across all three engines', async () => {
  const outputs = await Promise.all(Object.values(engines).map(execute => encrypt(execute)));
  assert.equal(outputs[0], outputs[1]);
  assert.equal(outputs[0], outputs[2]);
});
for (const [writer, enc] of Object.entries(engines)) {
  for (const [reader, dec] of Object.entries(engines)) {
    test(`${writer} → ${reader} interoperates, including empty, unicode and maximum payload`, async () => {
      for (const plaintext of ['', 'synthetic-key-🔐', 'x'.repeat(65536)]) {
        const envelope = JSON.parse(await encrypt(enc, plaintext));
        assert.equal(JSON.parse(await decrypt(dec, envelope)).plaintext, plaintext);
      }
    });
  }
}
for (const [name, execute] of Object.entries(engines)) {
  test(`${name}: rejects tampering, cross-context reuse and malformed inputs`, async () => {
    const envelope = JSON.parse(await encrypt(execute));
    for (const field of ['ciphertext', 'nonce', 'wrappedKey']) {
      const changed = structuredClone(envelope);
      const bytes = Buffer.from(changed[field], 'base64url');
      bytes[0] ^= 1;
      changed[field] = bytes.toString('base64url');
      await assert.rejects(async () => decrypt(execute, changed));
    }
    for (const field of ['tenantId', 'recordId', 'purpose']) {
      await assert.rejects(async () => decrypt(execute, envelope, { ...context, [field]: 'different' }));
    }
    for (const changed of [
      { ...envelope, version: 2 }, { ...envelope, algorithm: 'none' }, { ...envelope, keyId: 'arbitrary-key' },
      { ...envelope, ciphertext: '' }, { ...envelope, nonce: '***' }, { ...envelope, extra: 1 },
      { ...envelope, wrappedKey: 'AAAA' },
    ]) await assert.rejects(async () => decrypt(execute, changed));
    await assert.rejects(async () => encrypt(execute, 'x'.repeat(65537)));
    await assert.rejects(async () => encrypt(execute, 'x', { ...context, tenantId: '' }));
    await assert.rejects(async () => encrypt(execute, 'x', { ...context, extra: 'bad' }));
    await assert.rejects(async () => execute('{"op":"unknown"}'));
  });
  test(`${name}: fresh CSPRNG input changes ciphertext`, async () => {
    const command = () => JSON.stringify({ op: 'encrypt', plaintext: 'synthetic', context,
      entropy: Buffer.from(crypto.getRandomValues(new Uint8Array(56))).toString('base64url') });
    assert.notEqual(JSON.parse(await execute(command())).ciphertext, JSON.parse(await execute(command())).ciphertext);
  });
}
test('public HTTP gate: disabled by default, authentication, bounded body, rejects caller entropy', async () => {
  const handler = makeHandler(engines.typescript);
  const env = { POC_ONLY: 'true', POC_TOKEN: 'synthetic-token-for-local-testing' };
  const request = (body, token = env.POC_TOKEN) => new Request('http://localhost/encrypt', {
    method: 'POST', headers: { authorization: `Bearer ${token}` }, body: JSON.stringify(body),
  });
  assert.equal((await handler(request({ plaintext: 'synthetic', context }), {})).status, 503);
  assert.equal((await handler(request({ plaintext: 'synthetic', context }, 'wrong'), env)).status, 401);
  assert.equal((await handler(request({ plaintext: 'synthetic', context, entropy }), env)).status, 400);
  assert.equal((await handler(request({ plaintext: 'x'.repeat(524289), context }), env)).status, 413);
  const response = await handler(request({ plaintext: 'synthetic', context }), env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(JSON.parse(await decrypt(engines.native, await response.json())).plaintext, 'synthetic');
});
