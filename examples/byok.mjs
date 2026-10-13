import { Strongroom } from '../packages/strongroom/dist/index.js';
import { writeFile, readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
const strongroom = new Strongroom({ url: process.env.STRONGROOM_URL, token: process.env.STRONGROOM_TOKEN });
const context = { tenantId: 'development', recordId: 'user-123/openai', purpose: 'provider-api-key' };
const envelope = await strongroom.encrypt({ key: 'primary', context, plaintext: 'demo-key-not-a-real-credential' });
// Stand-in for the application's database: persist only the envelope.
await writeFile('.strongroom/example-envelope.json', JSON.stringify(envelope) + '\n', { mode: 0o600 });
const stored = JSON.parse(await readFile('.strongroom/example-envelope.json', 'utf8'));
assert.equal(await strongroom.decrypt({ envelope: stored, context }), 'demo-key-not-a-real-credential');
console.log(JSON.stringify({ encrypted: true, storedCiphertext: true, decrypted: true }));
