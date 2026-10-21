// Scenario: a SaaS lets each user paste their own provider API key (OpenAI, Stripe, ...) and calls the
// provider on their behalf. The database holds envelopes only; the key exists in plaintext only for the call.
import assert from 'node:assert/strict';
import { Strongroom, StrongroomError } from '../../packages/strongroom/dist/index.js';
import { startDeployment, step } from '../shared/stack.mjs';

// Stand-in for the third-party API.
const provider = { complete: (apiKey, prompt) => apiKey.startsWith('sk-test-') ? `echo: ${prompt}` : Promise.reject(new Error('401 from provider')) };

const acme = await startDeployment('acme');
try {
  // Least privilege: the settings page can only encrypt, the chat worker can only decrypt.
  const settings = new Strongroom({ url: acme.url, token: acme.tokens.ingest });
  const worker = new Strongroom({ url: acme.url, token: acme.tokens.use });
  const db = new Map(); // your database: "user/provider" -> { envelope, last4 }

  // The context is rebuilt from identifiers the app has already authorized, never taken from the request.
  const contextFor = (userId, name) => ({ tenantId: 'acme', recordId: `user/${userId}/provider/${name}`, purpose: 'provider-api-key' });

  async function saveKey(userId, name, apiKey) {
    const envelope = await settings.encrypt({ key: 'primary', context: contextFor(userId, name), plaintext: apiKey });
    // Keep a non-secret hint for the UI so showing the key never needs a decrypt.
    db.set(`${userId}/${name}`, { envelope, last4: apiKey.slice(-4) });
  }
  async function chat(userId, prompt) {
    const row = db.get(`${userId}/openai`);
    const apiKey = await worker.decrypt({ envelope: row.envelope, context: contextFor(userId, 'openai') });
    return provider.complete(apiKey, prompt); // use it and let it go: never log, cache or return the key
  }

  await saveKey('alice', 'openai', 'sk-test-alice-0000000000001234');
  const row = db.get('alice/openai');
  step('stored', { columns: Object.keys(row), plaintextInRow: JSON.stringify(row).includes('sk-test-alice'), last4: row.last4 });

  step('chat', { reply: await chat('alice', 'hello') });

  // The settings token cannot read stored keys back. A breach there still sees keys submitted while it lasts.
  await assert.rejects(settings.decrypt({ envelope: row.envelope, context: contextFor('alice', 'openai') }), (e) => e instanceof StrongroomError && e.code === 'FORBIDDEN');
  step('settings-cannot-decrypt', { code: 'FORBIDDEN' });

  // Someone with write access to the database copies Alice's envelope into Mallory's row.
  // The context binds the envelope to Alice's record, so it will not open as Mallory's.
  await saveKey('mallory', 'openai', 'sk-test-mallory-000000000009999');
  db.set('mallory/openai', { ...db.get('mallory/openai'), envelope: row.envelope });
  await assert.rejects(chat('mallory', 'use alice key'), { code: 'DECRYPT_FAILED' });
  step('swapped-envelope-rejected', { code: 'DECRYPT_FAILED' });

  // Rotating a key is just a new envelope written over the old one; nothing else to re-encrypt.
  await saveKey('alice', 'openai', 'sk-test-alice-rotated-000005678');
  step('rotated', { last4: db.get('alice/openai').last4, reply: await chat('alice', 'still works') });
} finally { await acme.stop(); }
