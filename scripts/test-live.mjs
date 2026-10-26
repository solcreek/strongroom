// Live KMS conformance: drives each provider adapter against the real API, checks every scenario's
// service error code, and compares the sanitized upstream response with tests/fixtures/kms/<provider>.json.
//   node scripts/test-live.mjs [--provider aws,gcp,openbao] [--record] [--mutate]
// --record rewrites fixtures from what was observed; --mutate also disables/re-enables dedicated test keys.
// Reads live.env from the live directory (scripts/live-dir.mjs) when present; scripts/live-env.mjs writes it. Prints one JSON report on stdout; exit 1 on any failure or drift.
import { spawn, execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { once } from 'node:events';
import { join } from 'node:path';
import { Miniflare } from 'miniflare';
import { liveDir } from './live-dir.mjs';
import { createProvider } from '../service/providers.ts';
import { capabilities } from '../service/contract.ts';
import { upstreamCode } from '../service/transport.ts';
import { sha256, utf8 } from '../service/encoding.ts';
import { Strongroom } from '../packages/strongroom/src/client.ts';

const args = process.argv.slice(2);
const flag = name => args.includes(name);
const option = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const liveEnv = join(liveDir(), 'live.env');
if (existsSync(liveEnv)) process.loadEnvFile(liveEnv);
const env = process.env;
const record = flag('--record'), mutate = flag('--mutate');
const today = new Date().toISOString().slice(0, 10);

// Only allowlisted machine-readable fields are kept; messages may contain account IDs or resource names.
export function sanitize(body) {
  if (!body || typeof body !== 'object') return null;
  if (typeof body.__type === 'string') return { __type: body.__type };
  if (body.error && typeof body.error === 'object') return { error: { code: body.error.code, status: body.error.status } };
  if (typeof body.error === 'string') return { error: body.error };
  // A Transit message is kept only when it is one of the fixed strings the adapter classifies.
  if (Array.isArray(body.errors)) return { errors: upstreamCode(body) ? body.errors : ['<redacted>'] };
  return { keys: Object.keys(body).sort() };
}
function recorder() {
  const calls = [];
  const fetcher = async (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    const response = await fetch(input, init);
    let body = null; try { body = JSON.parse(await response.clone().text()); } catch { /* non-JSON */ }
    calls.push({ endpoint: /oauth2|metadata/.test(url) ? 'token' : /\/v1\/credentials|169\.254\.170/.test(url) ? 'credentials' : 'kms', status: response.status, body: sanitize(body) });
    return response;
  };
  return { fetcher, calls };
}
const aad = utf8.encode('["strongroom-live",1]'), otherAad = utf8.encode('["strongroom-live",2]');
const dek = () => new Uint8Array(randomBytes(32));
async function outcome(run) {
  try { await run(); return { code: 'OK' }; } catch (e) { return { code: e.code ?? 'UNCLASSIFIED', status: e.status, retryable: e.retryable, upstream: e.upstream }; }
}
// Each scenario: a fresh provider with a recording fetch. `expect` is the service-level contract.
async function scenario(name, operation, config, expect, run, attempts = 1, ambient = {}) {
  let observed, calls;
  const started = Date.now();
  for (let i = 0; i < attempts; i++) {
    const r = recorder();
    observed = await outcome(() => run(createProvider(config, r.fetcher, ambient)));
    calls = r.calls;
    if ([expect].flat().includes(observed.code)) break;
    await new Promise(r => setTimeout(r, 3000)); // IAM and key-state changes are eventually consistent.
  }
  const last = calls.at(-1);
  // waitedMs: how long an eventually consistent change took to show (report only; never recorded in fixtures).
  return { name, operation, expect, observed: observed.code, upstream: last ? { endpoint: last.endpoint, status: last.status, body: last.body } : null, ...(attempts > 1 ? { waitedMs: Date.now() - started } : {}) };
}

async function aws() {
  const arn = env.STRONGROOM_LIVE_AWS_KEY_ARN, secondary = env.STRONGROOM_LIVE_AWS_SECONDARY_ARN;
  if (!arn || !secondary) return { skipped: 'Set STRONGROOM_LIVE_AWS_KEY_ARN and STRONGROOM_LIVE_AWS_SECONDARY_ARN: node scripts/live-env.mjs apply, then credentials.' };
  const region = arn.split(':')[3];
  const admin = JSON.parse(execFileSync('aws', ['configure', 'export-credentials', '--format', 'process'], { encoding: 'utf8' }));
  const adminCreds = { accessKeyId: admin.AccessKeyId, secretAccessKey: admin.SecretAccessKey, ...(admin.SessionToken ? { sessionToken: admin.SessionToken } : {}) };
  // Only the credential fields: the key configuration rejects anything else.
  const file = env.STRONGROOM_LIVE_AWS_CREDENTIALS_FILE && JSON.parse(readFileSync(env.STRONGROOM_LIVE_AWS_CREDENTIALS_FILE, 'utf8'));
  const service = file ? { accessKeyId: file.accessKeyId, secretAccessKey: file.secretAccessKey, ...(file.sessionToken ? { sessionToken: file.sessionToken } : {}) } : adminCreds;
  const key = (keyId, creds = service) => ({ provider: 'aws', region, keyId, ...creds });
  const missing = arn.replace(/key\/.+$/, 'key/00000000-0000-4000-8000-000000000000');
  const foreign = `arn:aws:kms:${region}:111122223333:key/00000000-0000-4000-8000-000000000000`;
  const secondaryBlob = await createProvider(key(secondary, adminCreds)).wrap(dek(), aad);
  const primary = createProvider(key(arn)); const blob = await primary.wrap(dek(), aad);
  const awsCli = (...a) => execFileSync('aws', ['kms', ...a, '--region', region, '--key-id', secondary], { stdio: 'ignore' });
  // Temporary credentials for the same principal: exercises the sessionToken (x-amz-security-token) path for real.
  const sts = JSON.parse(execFileSync('aws', ['sts', 'get-session-token', '--duration-seconds', '900', '--output', 'json'],
    { encoding: 'utf8', env: Object.fromEntries(Object.entries({ ...env, AWS_ACCESS_KEY_ID: service.accessKeyId, AWS_SECRET_ACCESS_KEY: service.secretAccessKey }).filter(([k]) => !['AWS_SESSION_TOKEN', 'AWS_PROFILE'].includes(k))) })).Credentials;
  const session = { accessKeyId: sts.AccessKeyId, secretAccessKey: sts.SecretAccessKey, sessionToken: sts.SessionToken };
  // A loopback stand-in for the ECS / EKS Pod Identity endpoint, serving the real STS session above.
  const endpoint = createHttpServer((req, res) => {
    const ok = req.headers.authorization === 'live-pod-token';
    res.writeHead(ok ? 200 : 403, { 'content-type': 'application/json' });
    res.end(JSON.stringify(ok ? { AccessKeyId: sts.AccessKeyId, SecretAccessKey: sts.SecretAccessKey, Token: sts.SessionToken, Expiration: sts.Expiration } : { message: 'denied' }));
  });
  endpoint.listen(0, '127.0.0.1'); await once(endpoint, 'listening');
  const container = { AWS_CONTAINER_CREDENTIALS_FULL_URI: `http://127.0.0.1:${endpoint.address().port}/v1/credentials`, AWS_CONTAINER_AUTHORIZATION_TOKEN: 'live-pod-token' };
  const results = [
    await scenario('roundtrip-session-token', 'wrap+unwrap', key(arn, session), 'OK', async p => { const k = dek(); if (Buffer.compare(await p.unwrap(await p.wrap(k, aad), aad), k)) throw new Error('mismatch'); }),
    await scenario('roundtrip-container-credentials', 'wrap+unwrap', { provider: 'aws', region, keyId: arn, containerCredentials: true }, 'OK', async p => { const k = dek(); if (Buffer.compare(await p.unwrap(await p.wrap(k, aad), aad), k)) throw new Error('mismatch'); }, 1, container),
    await scenario('container-credentials-rejected', 'wrap', { provider: 'aws', region, keyId: arn, containerCredentials: true }, 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad), 1, { ...container, AWS_CONTAINER_AUTHORIZATION_TOKEN: 'wrong' }),
    await scenario('session-token-wrong-secret', 'wrap', key(arn, { ...session, secretAccessKey: 'x'.repeat(40) }), 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
    await scenario('roundtrip', 'wrap+unwrap', key(arn), 'OK', async p => { const k = dek(); const w = await p.wrap(k, aad); if (Buffer.compare(await p.unwrap(w, aad), k)) throw new Error('mismatch'); }),
    await scenario('decrypt-wrong-context', 'unwrap', key(arn), 'DECRYPT_FAILED', p => p.unwrap(blob, otherAad)),
    await scenario('decrypt-malformed-ciphertext', 'unwrap', key(arn), 'DECRYPT_FAILED', p => p.unwrap(Buffer.alloc(64, 7).toString('base64'), aad)),
    // KMS authorizes against the key embedded in the ciphertext first: without a grant on it, AccessDenied wins.
    await scenario('decrypt-ciphertext-from-other-key', 'unwrap', key(arn, adminCreds), 'DECRYPT_FAILED', p => p.unwrap(secondaryBlob, aad)),
    await scenario('decrypt-ciphertext-from-other-key-without-grant', 'unwrap', key(arn), service === adminCreds ? 'DECRYPT_FAILED' : 'KMS_ACCESS_DENIED', p => p.unwrap(secondaryBlob, aad)),
    await scenario('encrypt-key-not-granted', 'wrap', key(secondary), service === adminCreds ? 'OK' : 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
    await scenario('decrypt-key-not-granted', 'unwrap', key(secondary), service === adminCreds ? 'OK' : 'KMS_ACCESS_DENIED', p => p.unwrap(secondaryBlob, aad)),
    await scenario('encrypt-key-not-found', 'wrap', key(missing, adminCreds), 'KMS_KEY_UNAVAILABLE', p => p.wrap(dek(), aad)),
    await scenario('encrypt-foreign-account-key', 'wrap', key(foreign), 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
    await scenario('unknown-access-key', 'wrap', key(arn, { accessKeyId: 'AKIA' + 'Z'.repeat(16), secretAccessKey: 'x'.repeat(40) }), 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
    await scenario('wrong-secret-key', 'unwrap', key(arn, { ...service, secretAccessKey: 'x'.repeat(40) }), 'KMS_ACCESS_DENIED', p => p.unwrap(blob, aad)),
    await scenario('invalid-session-token', 'wrap', key(arn, { ...service, sessionToken: 'invalid-session-token' }), 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
  ];
  endpoint.close();
  if (mutate) {
    try {
      awsCli('disable-key');
      // Observed 2026-10-13: Decrypt is refused at once, Encrypt kept succeeding for 30+ s (eventual consistency).
      results.push(await scenario('encrypt-disabled-key', 'wrap', key(secondary, adminCreds), ['KMS_KEY_UNAVAILABLE', 'OK'], p => p.wrap(dek(), aad)));
      results.push(await scenario('decrypt-disabled-key', 'unwrap', key(secondary, adminCreds), 'KMS_KEY_UNAVAILABLE', p => p.unwrap(secondaryBlob, aad), 60));
      execFileSync('aws', ['kms', 'schedule-key-deletion', '--region', region, '--key-id', secondary, '--pending-window-in-days', '7'], { stdio: 'ignore' });
      results.push(await scenario('decrypt-pending-deletion-key', 'unwrap', key(secondary, adminCreds), 'KMS_KEY_UNAVAILABLE', p => p.unwrap(secondaryBlob, aad), 60));
    } finally {
      try { awsCli('cancel-key-deletion'); } catch { /* not pending */ }
      awsCli('enable-key');
    }
  }
  return { results, e2e: { keys: { aws: key(arn), awsDenied: key(secondary) }, denied: service === adminCreds ? null : 'awsDenied' } };
}

async function gcp() {
  const keyId = env.STRONGROOM_LIVE_GCP_KEY, secondary = env.STRONGROOM_LIVE_GCP_SECONDARY;
  if (!keyId || !secondary) return { skipped: 'Set STRONGROOM_LIVE_GCP_KEY and STRONGROOM_LIVE_GCP_SECONDARY: node scripts/live-env.mjs apply --gcp-project P, then credentials.' };
  const adc = JSON.parse(readFileSync(env.GOOGLE_APPLICATION_CREDENTIALS ?? `${env.HOME}/.config/gcloud/application_default_credentials.json`, 'utf8'));
  if (adc.type !== 'authorized_user') return { skipped: 'Run gcloud auth application-default login; an authorized_user ADC file administers the test keys.' };
  const user = { clientId: adc.client_id, clientSecret: adc.client_secret, refreshToken: adc.refresh_token, quotaProject: adc.quota_project_id ?? keyId.split('/')[1] };
  const sa = env.STRONGROOM_LIVE_GCP_SA_FILE ? JSON.parse(readFileSync(env.STRONGROOM_LIVE_GCP_SA_FILE, 'utf8')) : undefined;
  const serviceAccount = sa && { clientEmail: sa.client_email, privateKey: sa.private_key };
  const asUser = id => ({ provider: 'gcp', keyId: id, authorizedUser: user });
  const asService = id => serviceAccount ? { provider: 'gcp', keyId: id, serviceAccount } : asUser(id);
  const blob = await createProvider(asService(keyId)).wrap(dek(), aad);
  const secondaryBlob = await createProvider(asUser(secondary)).wrap(dek(), aad);
  const missing = keyId.replace(/cryptoKeys\/.+$/, 'cryptoKeys/strongroom-live-missing');
  const strangerKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const results = [
    await scenario('roundtrip-service-account', 'wrap+unwrap', asService(keyId), 'OK', async p => { const k = dek(); if (Buffer.compare(await p.unwrap(await p.wrap(k, aad), aad), k)) throw new Error('mismatch'); }),
    await scenario('roundtrip-authorized-user', 'wrap+unwrap', asUser(keyId), 'OK', async p => { const k = dek(); if (Buffer.compare(await p.unwrap(await p.wrap(k, aad), aad), k)) throw new Error('mismatch'); }),
    await scenario('roundtrip-authorized-user-without-quota-project', 'wrap', { ...asUser(keyId), authorizedUser: { ...user, quotaProject: undefined } }, 'OK', p => p.wrap(dek(), aad)),
    await scenario('decrypt-wrong-context', 'unwrap', asService(keyId), 'DECRYPT_FAILED', p => p.unwrap(blob, otherAad)),
    await scenario('decrypt-malformed-ciphertext', 'unwrap', asService(keyId), 'DECRYPT_FAILED', p => p.unwrap(Buffer.alloc(64, 7).toString('base64'), aad)),
    await scenario('decrypt-ciphertext-from-other-key', 'unwrap', asService(keyId), 'DECRYPT_FAILED', p => p.unwrap(secondaryBlob, aad)),
    await scenario('encrypt-key-not-granted', 'wrap', asService(secondary), serviceAccount ? 'KMS_ACCESS_DENIED' : 'OK', p => p.wrap(dek(), aad)),
    await scenario('decrypt-key-not-granted', 'unwrap', asService(secondary), serviceAccount ? 'KMS_ACCESS_DENIED' : 'OK', p => p.unwrap(secondaryBlob, aad)),
    await scenario('encrypt-key-not-found', 'wrap', asUser(missing), 'KMS_KEY_UNAVAILABLE', p => p.wrap(dek(), aad)),
    await scenario('encrypt-key-not-found-without-access', 'wrap', asService(missing), serviceAccount ? 'KMS_ACCESS_DENIED' : 'KMS_KEY_UNAVAILABLE', p => p.wrap(dek(), aad)),
    await scenario('token-unregistered-service-account-key', 'wrap', { provider: 'gcp', keyId, serviceAccount: { clientEmail: serviceAccount?.clientEmail ?? 'unknown@example.iam.gserviceaccount.com', privateKey: strangerKey } }, 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
    await scenario('token-unknown-service-account', 'wrap', { provider: 'gcp', keyId, serviceAccount: { clientEmail: `missing-${randomBytes(4).toString('hex')}@${keyId.split('/')[1]}.iam.gserviceaccount.com`, privateKey: strangerKey } }, 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
    await scenario('token-invalid-refresh-token', 'wrap', { ...asUser(keyId), authorizedUser: { ...user, refreshToken: '1//invalid-refresh-token' } }, 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
    await scenario('token-invalid-client-secret', 'wrap', { ...asUser(keyId), authorizedUser: { ...user, clientSecret: 'invalid-client-secret' } }, 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
  ];
  if (mutate) {
    const admin = async (state) => {
      const token = execFileSync('gcloud', ['auth', 'application-default', 'print-access-token'], { encoding: 'utf8' }).trim();
      const r = await fetch(`https://cloudkms.googleapis.com/v1/${secondary}/cryptoKeyVersions/1?updateMask=state`, { method: 'PATCH', headers: { authorization: `Bearer ${token}`, 'x-goog-user-project': user.quotaProject, 'content-type': 'application/json' }, body: JSON.stringify({ state }) });
      if (!r.ok) throw new Error(`GCP admin ${state}: ${r.status}`);
    };
    try {
      await admin('DISABLED');
      // Google documents key-state changes as eventually consistent; Encrypt kept succeeding for 30+ s when observed.
      results.push(await scenario('encrypt-disabled-version', 'wrap', asUser(secondary), ['KMS_KEY_UNAVAILABLE', 'OK'], p => p.wrap(dek(), aad)));
      results.push(await scenario('decrypt-disabled-version', 'unwrap', asUser(secondary), 'KMS_KEY_UNAVAILABLE', p => p.unwrap(secondaryBlob, aad), 60));
    } finally { await admin('ENABLED'); }
  }
  return { results, e2e: { keys: { gcp: asService(keyId), gcpUser: asUser(keyId), ...(serviceAccount ? { gcpDenied: asService(secondary) } : {}) }, denied: serviceAccount ? 'gcpDenied' : null } };
}

async function freePort() {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; await new Promise(r => server.close(r)); return port;
}
// An ephemeral loopback OpenBao/Vault dev server; no account needed, so CI runs this provider.
async function openbao(cleanup) {
  const binary = env.TRANSIT_BIN ?? (existsSync('.cache/openbao-2.7.1/bao') ? '.cache/openbao-2.7.1/bao' : undefined);
  if (!binary) return { skipped: 'Set TRANSIT_BIN or run node scripts/install-transit.mjs.' };
  const port = await freePort(), root = randomBytes(32).toString('base64url'), address = `http://127.0.0.1:${port}`;
  // Dev output includes root credentials: deliberately discard it.
  const child = spawn(binary, ['server', '-dev', '-dev-no-store-token', `-dev-listen-address=127.0.0.1:${port}`],
    { env: { ...env, BAO_DEV_ROOT_TOKEN_ID: root, VAULT_DEV_ROOT_TOKEN_ID: root, BAO_LOG_LEVEL: 'error', VAULT_LOG_LEVEL: 'error' }, stdio: 'ignore' });
  cleanup.push(async () => { if (child.exitCode === null) { child.kill('SIGTERM'); await once(child, 'close'); } });
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error('Transit dev server could not start.');
    try { if ((await fetch(`${address}/v1/sys/health`)).ok) break; } catch { /* starting */ }
    await new Promise(r => setTimeout(r, 50));
  }
  const adminCall = async (path, body) => {
    const r = await fetch(`${address}/v1/${path}`, { method: 'POST', headers: { 'x-vault-token': root, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(`Transit setup ${path}: ${r.status}`); return r.status === 204 ? {} : r.json();
  };
  await adminCall('sys/mounts/transit', { type: 'transit' });
  for (const name of ['strongroom', 'other']) await adminCall(`transit/keys/${name}`, { type: 'aes256-gcm96', derived: true, exportable: false, allow_plaintext_backup: false });
  await adminCall('sys/policies/acl/strongroom', { policy: 'path "transit/encrypt/strongroom" { capabilities = ["update"] }\npath "transit/decrypt/strongroom" { capabilities = ["update"] }' });
  const scoped = async () => (await adminCall('auth/token/create', { policies: ['strongroom'], no_default_policy: true, ttl: '10m' })).auth.client_token;
  const token = await scoped();
  const key = (keyName = 'strongroom', t = token) => ({ provider: 'openbao', url: address, mount: 'transit', keyName, token: t });
  const blob = await createProvider(key()).wrap(dek(), aad);
  const otherBlob = await createProvider(key('other', root)).wrap(dek(), aad);
  const revoked = await scoped(); await adminCall('auth/token/revoke', { token: revoked });
  const results = [
    await scenario('roundtrip', 'wrap+unwrap', key(), 'OK', async p => { const k = dek(); if (Buffer.compare(await p.unwrap(await p.wrap(k, aad), aad), k)) throw new Error('mismatch'); }),
    await scenario('decrypt-wrong-context', 'unwrap', key(), 'DECRYPT_FAILED', p => p.unwrap(blob, otherAad)),
    await scenario('decrypt-malformed-ciphertext', 'unwrap', key(), 'DECRYPT_FAILED', p => p.unwrap('vault:v1:AAAA', aad)),
    await scenario('decrypt-ciphertext-from-other-key', 'unwrap', key(), 'DECRYPT_FAILED', p => p.unwrap(otherBlob, aad)),
    await scenario('decrypt-future-key-version', 'unwrap', key(), 'DECRYPT_FAILED', p => p.unwrap(blob.replace(/:v1:/, ':v9:'), aad)),
    await scenario('encrypt-key-not-granted', 'wrap', key('other'), 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
    await scenario('decrypt-key-not-granted', 'unwrap', key('other'), 'KMS_ACCESS_DENIED', p => p.unwrap(otherBlob, aad)),
    await scenario('decrypt-key-not-found', 'unwrap', key('missing', root), 'KMS_KEY_UNAVAILABLE', p => p.unwrap(blob, aad)),
    await scenario('revoked-token', 'unwrap', key('strongroom', revoked), 'KMS_ACCESS_DENIED', p => p.unwrap(blob, aad)),
    await scenario('invalid-token', 'wrap', key('strongroom', 'invalid-token'), 'KMS_ACCESS_DENIED', p => p.wrap(dek(), aad)),
  ];
  await adminCall('transit/keys/strongroom/rotate', {});
  await adminCall('transit/keys/strongroom/config', { min_decryption_version: 2 });
  results.push(await scenario('decrypt-version-below-minimum', 'unwrap', key(), 'KMS_KEY_UNAVAILABLE', p => p.unwrap(blob, aad)));
  results.push(await scenario('roundtrip-after-rotation', 'wrap+unwrap', key(), 'OK', async p => { const k = dek(); const w = await p.wrap(k, aad); if (!w.includes(':v2:') || Buffer.compare(await p.unwrap(w, aad), k)) throw new Error('not v2'); }));
  await adminCall('sys/seal', {});
  results.push(await scenario('sealed', 'wrap', key(), 'KMS_UNAVAILABLE', p => p.wrap(dek(), aad)));
  await cleanup.pop()();
  results.push(await scenario('connection-refused', 'wrap', key(), 'KMS_UNAVAILABLE', p => p.wrap(dek(), aad)));
  return { results, e2e: null };
}

// Through real workerd and the Node host: roundtrip both ways, context rejection, and a denied grant per provider.
async function endToEnd(keys, deniedKeys, cleanup) {
  const token = randomBytes(32).toString('base64url');
  const config = { tenantId: 'live', keys, principals: [{ tokenSha256: await sha256(token), permissions: ['encrypt', 'decrypt'], keys: Object.keys(keys) }] };
  const bindings = { STRONGROOM_CONFIG: JSON.stringify(config) };
  const mf = new Miniflare({ modules: true, scriptPath: 'dist/worker.js', modulesRoot: 'dist', modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }], compatibilityDate: '2026-07-01', host: '127.0.0.1', port: 0, bindings });
  cleanup.push(() => mf.dispose());
  const port = await freePort();
  const node = spawn(process.execPath, ['dist/server.js'], { env: { ...env, ...bindings, PORT: String(port) }, stdio: ['ignore', 'ignore', 'pipe'] });
  const logs = []; node.stderr.on('data', b => logs.push(...String(b).split('\n').filter(Boolean)));
  cleanup.push(async () => { if (node.exitCode === null) { node.kill('SIGTERM'); await once(node, 'close'); } });
  const nodeUrl = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) { try { if ((await fetch(`${nodeUrl}/readyz`)).ok) break; } catch { /* starting */ } await new Promise(r => setTimeout(r, 50)); }
  const worker = new Strongroom({ url: String(await mf.ready), token }), host = new Strongroom({ url: nodeUrl, token });
  const context = { tenantId: 'live', recordId: `record-${randomBytes(4).toString('hex')}`, purpose: 'live-test' };
  const results = [];
  for (const key of Object.keys(keys)) {
    const check = async (name, expect, run) => { const o = await outcome(run); results.push({ name: `${key}:${name}`, expect, observed: o.code }); };
    if (deniedKeys.includes(key)) { await check('worker-encrypt-denied', 'KMS_ACCESS_DENIED', () => worker.encrypt({ key, context, plaintext: 'x' })); continue; }
    let envelope;
    await check('worker-encrypt', 'OK', async () => { envelope = await worker.encrypt({ key, context, plaintext: `live-${key}-🔑` }); });
    await check('node-decrypt', 'OK', async () => { if (await host.decrypt({ envelope, context }) !== `live-${key}-🔑`) throw new Error('mismatch'); });
    await check('worker-decrypt-wrong-context', 'DECRYPT_FAILED', () => worker.decrypt({ envelope, context: { ...context, purpose: 'other' } }));
  }
  // The agent-facing CLI probe against the Worker, per provider: real KMS, token grants and context binding.
  for (const key of Object.keys(keys).filter(k => !deniedKeys.includes(k))) {
    const child = spawn(process.execPath, ['packages/strongroom/src/cli.ts', 'probe', '--key', key, '--tenant', 'live'], { env: { ...env, STRONGROOM_URL: String(await mf.ready), STRONGROOM_TOKEN: token }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; child.stdout.on('data', b => out += b); const [code] = await once(child, 'close');
    results.push({ name: `${key}:cli-probe`, expect: 'OK', observed: code === 0 && JSON.parse(out).ok ? 'OK' : `EXIT_${code}` });
  }
  // The Node host writes operator events to stderr: denied grants must be logged with sanitized upstream facts only.
  for (const key of deniedKeys) await outcome(() => host.encrypt({ key, context, plaintext: 'x' }));
  await new Promise(r => setTimeout(r, 100));
  const events = logs.flatMap(l => { try { return [JSON.parse(l)]; } catch { return []; } }).filter(e => e.event === 'kms_error');
  for (const key of deniedKeys) {
    const e = events.find(e => e.key === key);
    results.push({ name: `${key}:node-operator-log`, expect: 'KMS_ACCESS_DENIED', observed: e?.code ?? 'MISSING', upstream: e ? { status: e.upstreamStatus, code: e.upstreamCode } : null });
  }
  if (logs.some(l => l.includes(token) || l.includes('live-'))) results.push({ name: 'node-logs-free-of-secrets', expect: 'OK', observed: 'LEAKED' });
  return results;
}

// Drift: a recorded scenario whose live upstream status/code changed. Expected-code failures are reported separately.
function compare(provider, results) {
  const file = `tests/fixtures/kms/${provider}.json`;
  const scenarios = results.filter(r => r.observed !== 'OK' && r.upstream);
  if (record) {
    mkdirSync('tests/fixtures/kms', { recursive: true });
    // Merge by name: scenarios not run this time (for example --mutate ones) keep their earlier recording.
    const ran = new Set(results.map(r => r.name));
    const kept = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')).scenarios.filter(s => !ran.has(s.name)) : [];
    writeFileSync(file, JSON.stringify({ provider, verified: today, source: 'node scripts/test-live.mjs --record', scenarios: [...scenarios.map(r => {
      const e = capabilities.errors[r.observed];
      return { name: r.name, operation: r.operation, upstream: r.upstream, expect: { code: r.observed, status: e?.status, retryable: e?.retryable } };
    }), ...kept] }, null, 2) + '\n');
    return [];
  }
  if (!existsSync(file)) return [`${provider}: no fixture; run with --record`];
  const fixture = JSON.parse(readFileSync(file, 'utf8'));
  return scenarios.flatMap(r => {
    const f = fixture.scenarios.find(s => s.name === r.name);
    if (!f) return [`${provider}/${r.name}: not in fixture`];
    return JSON.stringify(f.upstream) === JSON.stringify(r.upstream) ? [] : [`${provider}/${r.name}: upstream ${JSON.stringify(f.upstream)} -> ${JSON.stringify(r.upstream)}`];
  });
}

const providers = (option('--provider') ?? 'aws,gcp,openbao').split(',');
const runners = { aws, gcp, openbao };
const report = { verified: today, record, mutate, providers: {}, failures: [], drift: [], warnings: [] };
const cleanup = [];
try {
  const e2eKeys = {}, denied = [];
  for (const name of providers) {
    if (!runners[name]) throw new Error(`Unknown provider ${name}`);
    const started = performance.now();
    let r;
    try { r = await runners[name](cleanup); } catch (e) { r = { error: e.message }; }
    report.providers[name] = { ...r, e2e: undefined, ms: Math.round(performance.now() - started) };
    if (r.error) { report.failures.push(`${name}: ${r.error}`); continue; }
    if (r.skipped) continue;
    report.failures.push(...r.results.filter(x => ![x.expect].flat().includes(x.observed)).map(x => `${name}/${x.name}: expected ${x.expect}, observed ${x.observed}`));
    report.drift.push(...compare(name, r.results));
    if (r.e2e) { Object.assign(e2eKeys, r.e2e.keys); if (r.e2e.denied) denied.push(r.e2e.denied); }
    // Passing as the administrator proves nothing about least privilege: say so instead of looking green.
    if (r.e2e && !r.e2e.denied) report.warnings.push(`${name}: no service credentials, so the service role ran as the administrator and "not granted" scenarios were not exercised. Run node scripts/live-env.mjs credentials.`);
  }
  if (Object.keys(e2eKeys).length) {
    if (!existsSync('dist/worker.js')) throw new Error('Run npm run build first.');
    const e2e = await endToEnd(e2eKeys, denied, cleanup);
    report.endToEnd = e2e;
    report.failures.push(...e2e.filter(x => x.observed !== x.expect).map(x => `e2e/${x.name}: expected ${x.expect}, observed ${x.observed}`));
  }
} finally { for (const f of cleanup.reverse()) await f().catch(() => {}); }
process.stdout.write(JSON.stringify(report, null, 2) + '\n');
process.exitCode = report.failures.length || report.drift.length ? 1 : 0;
