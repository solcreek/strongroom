// Scenario: a multi-tenant app keeps each tenant's files (SQLite databases, uploads, indexes) encrypted
// at rest under that tenant's own data key, and can make a tenant's data unrecoverable by destroying
// one KMS key ("crypto-shredding"), even in backups and volume snapshots.
//
// Bulk data never goes through Strongroom: the app encrypts it locally with a data encryption key (DEK).
// Strongroom only wraps that 32-byte DEK under the tenant's KMS key, once per process start.
import assert from 'node:assert/strict';
import { Strongroom } from '../../packages/strongroom/dist/index.js';
import { startDeployment, step } from '../shared/stack.mjs';

// One Strongroom deployment per tenant. The app's control plane keeps this routing table.
const deployments = { acme: await startDeployment('acme'), globex: await startDeployment('globex') };
const strongroom = tenant => new Strongroom({ url: deployments[tenant].url, token: deployments[tenant].tokens.both });
const dekContext = (tenant, version) => ({ tenantId: tenant, recordId: `storage/dek/v${version}`, purpose: 'tenant-storage-key' });

// Stand-in for the tenant volume: the wrapped DEK sits next to the data, as it would on disk.
const volume = new Map();

// A new tenant (or a key rotation) gets a fresh random DEK. Only its envelope is stored.
async function provision(tenant, version = 1) {
  const dek = crypto.getRandomValues(new Uint8Array(32));
  try {
    const envelope = await strongroom(tenant).encrypt({ key: 'primary', context: dekContext(tenant, version), plaintext: dek });
    volume.set(`${tenant}/dek/v${version}.json`, new TextEncoder().encode(JSON.stringify(envelope)));
  } finally { dek.fill(0); }
}

// Unwrap the DEK as bytes, import it as a non-extractable key, and wipe the bytes straight away.
// The unwrap path never makes a string, so the one buffer this code owns is wiped. Wrapping still
// sends the new DEK as base64url text, which no runtime can wipe (docs/security.md).
async function open(tenant, version = 1, files = volume) {
  const envelope = JSON.parse(new TextDecoder().decode(files.get(`${tenant}/dek/v${version}.json`)));
  const raw = await strongroom(tenant).decryptBytes({ envelope, context: dekContext(tenant, version) });
  try { return await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']); } finally { raw.fill(0); }
}

// Each file: [1-byte DEK version][12-byte nonce][ciphertext]. The tenant and path are authenticated,
// so a file cannot be moved to another path or tenant and still decrypt.
async function writeFile(tenant, key, version, path, text) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode(`${tenant}/${path}`) }, key, new TextEncoder().encode(text)));
  // Copy into one buffer: spreading a large ciphertext into arguments would overflow the call stack.
  const blob = new Uint8Array(13 + ciphertext.length);
  blob[0] = version; blob.set(nonce, 1); blob.set(ciphertext, 13);
  volume.set(`${tenant}/${path}`, blob);
}
async function readFile(tenant, keys, path, files = volume) {
  const blob = files.get(`${tenant}/${path}`);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.subarray(1, 13), additionalData: new TextEncoder().encode(`${tenant}/${path}`) }, keys[blob[0]], blob.subarray(13));
  return new TextDecoder().decode(plaintext);
}

try {
  for (const tenant of ['acme', 'globex']) {
    await provision(tenant);
    await writeFile(tenant, await open(tenant), 1, 'notes.db', `${tenant} private notes`);
  }
  step('files-written', { tenants: 2, plaintextOnVolume: [...volume.values()].some(b => new TextDecoder().decode(b).includes('private notes')) });

  const acmeKeys = { 1: await open('acme') };
  // Bulk files never touch Strongroom: a 1 MiB file is one local AES-GCM call under the unwrapped DEK.
  await writeFile('acme', acmeKeys[1], 1, 'index.bin', 'x'.repeat(1 << 20));
  step('read', { acme: await readFile('acme', acmeKeys, 'notes.db'), bulkBytes: (await readFile('acme', acmeKeys, 'index.bin')).length });

  // The path is authenticated: the same bytes copied to another path no longer decrypt, even under the right DEK.
  volume.set('acme/moved.db', volume.get('acme/notes.db'));
  await assert.rejects(readFile('acme', acmeKeys, 'moved.db'), { name: 'OperationError' });
  volume.delete('acme/moved.db');
  step('moved-file-rejected', { decrypts: false });

  // Tenants never share a deployment: acme's wrapped DEK sent to globex's deployment is refused.
  const acmeEnvelope = JSON.parse(new TextDecoder().decode(volume.get('acme/dek/v1.json')));
  await assert.rejects(strongroom('globex').decryptBytes({ envelope: acmeEnvelope, context: dekContext('acme', 1) }), { code: 'FORBIDDEN' });
  step('cross-tenant-refused', { code: 'FORBIDDEN' });

  // Rotation: new writes use a v2 DEK; v1 stays readable until its files are rewritten.
  await provision('acme', 2);
  acmeKeys[2] = await open('acme', 2);
  await writeFile('acme', acmeKeys[2], 2, 'notes-2026.db', 'written under v2');
  step('rotated', { v1: await readFile('acme', acmeKeys, 'notes.db'), v2: await readFile('acme', acmeKeys, 'notes-2026.db') });

  // A volume snapshot is taken, then globex leaves and its KMS key is destroyed. Locally that is a new
  // KEK; in production, `strongroom teardown aws|gcp --delete-key` schedules the KMS key's destruction.
  const snapshot = new Map(volume);
  await deployments.globex.stop();
  deployments.globex = await startDeployment('globex');
  await assert.rejects(open('globex', 1, snapshot), e => ['DECRYPT_FAILED', 'KMS_KEY_UNAVAILABLE'].includes(e.code));
  step('shredded', { globexSnapshotReadable: false, acmeStillReadable: await readFile('acme', { 1: await open('acme', 1, snapshot) }, 'notes.db', snapshot) });
} finally { await Promise.all(Object.values(deployments).map(d => d.stop())); }
