import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, stat, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { runCli } from './cli-helper.mjs';
import { parseConfig } from '../service/config.ts';
import { tenantName, tenantTag } from '../packages/strongroom/src/setup-common.ts';

// A stateful fake `gcloud`: a scenario maps a command to one response or a queue of responses, and every call is logged.
const fake = `#!/usr/bin/env node
const { readFileSync, writeFileSync, appendFileSync, existsSync } = require('node:fs');
const args = process.argv.slice(2);
const ops = ['config get-value', 'projects describe', 'services list', 'services enable', 'kms keyrings describe', 'kms keyrings create', 'kms keys describe', 'kms keys create',
  'kms keys add-iam-policy-binding', 'kms keys remove-iam-policy-binding', 'kms keys versions list', 'kms keys versions destroy', 'iam service-accounts list', 'iam service-accounts create',
  'iam service-accounts delete', 'iam service-accounts keys create'];
const op = ops.filter(o => args.join(' ').startsWith(o)).sort((a, b) => b.length - a.length)[0] ?? args.slice(0, 2).join(' ');
appendFileSync(process.env.FAKE_LOG, JSON.stringify(args) + '\\n');
const state = existsSync(process.env.FAKE_STATE) ? JSON.parse(readFileSync(process.env.FAKE_STATE, 'utf8')) : {};
let r = JSON.parse(readFileSync(process.env.FAKE_SCENARIO, 'utf8'))[op] ?? { stdout: {} };
if (Array.isArray(r)) { const i = state[op] ?? 0; state[op] = i + 1; writeFileSync(process.env.FAKE_STATE, JSON.stringify(state)); r = r[Math.min(i, r.length - 1)]; }
if (r.writeKey) writeFileSync(args[4], JSON.stringify(r.writeKey));
if (r.stderr) { process.stderr.write(r.stderr); process.exit(1); }
process.stdout.write(typeof r.stdout === 'string' ? r.stdout : JSON.stringify(r.stdout));
`;
const key = 'projects/demo-project/locations/global/keyRings/sr-ring/cryptoKeys/primary';
const email = 'sr-test@demo-project.iam.gserviceaccount.com';
const privateKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
const err = (code, command) => ({ stderr: `ERROR: (gcloud.${command}) ${code}: details naming projects/secret-project. This command is authenticated as someone@example.com\n` });
const ok = {
  'config get-value': { stdout: 'someone@example.com\n' },
  'projects describe': { stdout: { projectId: 'demo-project' } },
  'services list': { stdout: [{ config: { name: 'cloudkms.googleapis.com' } }] },
  'kms keyrings describe': err('NOT_FOUND', 'kms.keyrings.describe'),
  'iam service-accounts list': { stdout: [] },
  'kms keyrings create': { stdout: {} }, 'kms keys create': { stdout: {} }, 'iam service-accounts create': { stdout: {} },
  'kms keys add-iam-policy-binding': { stdout: { bindings: [] } },
  'iam service-accounts keys create': { stdout: '', writeKey: { type: 'service_account', client_email: email, private_key: privateKey, private_key_id: 'kid-1' } },
};
async function harness(t) {
  const dir = await mkdtemp(join(tmpdir(), 'strongroom-setup-gcp-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(join(dir, 'gcloud'), fake); await chmod(join(dir, 'gcloud'), 0o755);
  // A generous propagation window keeps retry tests independent of machine load; only never-recovering cases shorten it.
  const run = async (args, scenario, env = {}) => {
    await writeFile(join(dir, 'scenario.json'), JSON.stringify(scenario)); await writeFile(join(dir, 'calls.log'), ''); await rm(join(dir, 'state.json'), { force: true });
    const r = await runCli(args, { env: { PATH: `${dir}:${process.env.PATH}`, FAKE_SCENARIO: join(dir, 'scenario.json'), FAKE_LOG: join(dir, 'calls.log'), FAKE_STATE: join(dir, 'state.json'), STRONGROOM_SETUP_RETRY_MS: '5', STRONGROOM_SETUP_PROPAGATION_MS: '10000', ...env } });
    const calls = (await readFile(join(dir, 'calls.log'), 'utf8')).split('\n').filter(Boolean).map(l => JSON.parse(l));
    return { ...r, calls, ops: calls.map(c => c.slice(0, c[0] === 'kms' && c[1] === 'keys' && c[2] === 'versions' ? 4 : 3).filter(a => !a.startsWith('-') && !a.includes('/') && !a.includes('@') && a !== 'demo-project' && a !== 'sr-ring' && a !== 'primary').join(' ')) };
  };
  return { dir, run };
}
const base = ['setup', 'gcp', '--name', 'sr-test', '--keyring', 'sr-ring', '--tenant', 'acme', '--project', 'demo-project'];

test('setup gcp --dry-run plans key ring, key, account and grant without mutating', async t => {
  const { dir, run } = await harness(t);
  const r = await run([...base, '--directory', join(dir, 'out'), '--dry-run'], { ...ok, 'services list': { stdout: [] } });
  assert.equal(r.code, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.deepEqual(out.plan.map(p => p.action), ['enable-api', 'create-keyring', 'create-key', 'create-service-account', 'grant', 'create-service-account-key', 'write-files', 'verify']);
  assert.ok(out.requiredPermissions.includes('iam.serviceAccountKeys.create'));
  assert.ok(!r.ops.some(o => /create|enable|add-iam/.test(o)), r.ops.join());
  assert.ok(r.calls.filter(c => c[0] !== 'config').every(c => c.includes('--format=json') && c.includes('--quiet') && c.includes('demo-project')));
  await assert.rejects(stat(join(dir, 'out')));
});

test('setup gcp writes a service-account config, deletes the key file, and retries IAM propagation', async t => {
  const { dir, run } = await harness(t);
  const out = join(dir, 'out');
  const scenario = { ...ok, 'kms keys add-iam-policy-binding': [err('INVALID_ARGUMENT', 'kms.keys.add-iam-policy-binding'), err('INVALID_ARGUMENT', 'kms.keys.add-iam-policy-binding'), { stdout: { bindings: [] } }] };
  const r = await run([...base, '--directory', out, '--no-verify'], scenario);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(!r.stdout.includes('PRIVATE KEY'));
  assert.equal(r.calls.filter(c => c[2] === 'add-iam-policy-binding').length, 3);
  const config = JSON.parse(await readFile(join(out, 'config.json'), 'utf8'));
  assert.deepEqual(config.keys.primary, { provider: 'gcp', keyId: key, serviceAccount: { clientEmail: email, privateKey } });
  assert.equal(config.tenantId, 'acme'); assert.deepEqual(Object.keys(config.principals[0]).sort(), ['keys', 'permissions', 'tokenSha256']);
  assert.ok(parseConfig({ STRONGROOM_CONFIG: JSON.stringify(config) }));
  for (const f of ['config.json', 'token']) assert.equal((await stat(join(out, f))).mode & 0o777, 0o600);
  const keyPath = r.calls.find(c => c[2] === 'keys' && c[3] === 'create')[4];
  await assert.rejects(stat(keyPath), 'the gcloud key file is removed after reading');
  const grant = r.calls.find(c => c[2] === 'add-iam-policy-binding');
  assert.deepEqual(grant.slice(grant.indexOf('--member'), grant.indexOf('--member') + 4), ['--member', `serviceAccount:${email}`, '--role', 'roles/cloudkms.cryptoKeyEncrypterDecrypter']);
  const summary = JSON.parse(r.stdout);
  assert.match(summary.teardown, /--delete-key/); assert.ok(summary.next.some(n => n.includes('strongroom probe --key primary')));
});

test('setup gcp grants an existing workload identity and reuses this tenant\'s enabled key', async t => {
  const { dir, run } = await harness(t);
  const existing = { ...ok, 'kms keyrings describe': { stdout: {} }, 'kms keys describe': { stdout: { name: key, purpose: 'ENCRYPT_DECRYPT', primary: { state: 'ENABLED' }, labels: { app: 'strongroom', 'strongroom-tenant': tenantTag('acme') } } } };
  const r = await run([...base, '--directory', join(dir, 'w'), '--service-account', 'run@other-project.iam.gserviceaccount.com'], existing);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(!r.ops.some(o => /keyrings create|keys create|service-accounts create|service-accounts list/.test(o)), r.ops.join());
  assert.deepEqual(JSON.parse(await readFile(join(dir, 'w', 'config.json'), 'utf8')).keys.primary, { provider: 'gcp', keyId: key, metadataServer: true });
  assert.doesNotMatch(JSON.parse(r.stdout).teardown, /--delete-key/);
  const destroyed = { ...existing, 'kms keys describe': { stdout: { name: key, purpose: 'ENCRYPT_DECRYPT', primary: { state: 'DESTROY_SCHEDULED' } } } };
  assert.equal(JSON.parse((await run([...base, '--directory', join(dir, 'x')], destroyed)).stderr).error.code, 'KEY_UNUSABLE');
  // A key labelled for another tenant, or not created by setup, is never reused: that would share it across tenants.
  for (const labels of [{ app: 'strongroom', 'strongroom-tenant': tenantTag('globex') }, { app: 'strongroom' }, undefined]) {
    const foreign = await run([...base, '--directory', join(dir, `f${Object.keys(labels ?? {}).length}`), '--service-account', 'run@other-project.iam.gserviceaccount.com'],
      { ...existing, 'kms keys describe': { stdout: { name: key, purpose: 'ENCRYPT_DECRYPT', primary: { state: 'ENABLED' }, labels } } });
    assert.equal(foreign.code, 2); assert.equal(JSON.parse(foreign.stderr).error.code, 'NOT_OWNED'); assert.ok(!foreign.ops.some(o => /add-iam/.test(o)));
  }
  const sameProject = await run([...base, '--directory', join(dir, 'y'), '--service-account', 'gone@demo-project.iam.gserviceaccount.com'], existing);
  assert.equal(JSON.parse(sameProject.stderr).error.path, '--service-account');
});

test('setup gcp failures carry stable codes, next steps and created resources', async t => {
  const { dir, run } = await harness(t);
  const cases = [
    [{ ...ok, 'projects describe': { stderr: 'ERROR: (gcloud.projects.describe) There was a problem refreshing your current auth tokens: Reauthentication failed. cannot prompt during non-interactive execution.\nPlease run:\n\n  $ gcloud auth login\n' } }, 'GCP_NOT_AUTHENTICATED', 3],
    [{ ...ok, 'projects describe': err('PERMISSION_DENIED', 'projects.describe') }, 'GCP_PERMISSION_DENIED', 3],
    [{ ...ok, 'iam service-accounts list': { stdout: [{ email }] } }, 'RESOURCE_EXISTS', 2],
    [{ ...ok, 'iam service-accounts keys create': { stderr: 'ERROR: (gcloud.iam.service-accounts.keys.create) FAILED_PRECONDITION: Key creation is not allowed on this service account.\n- \'@type\': type.googleapis.com/google.rpc.PreconditionFailure\n  violations:\n  - type: constraints/iam.disableServiceAccountKeyCreation\n' } }, 'GCP_ORG_POLICY', 3],
    [{ ...ok, 'services list': { stdout: [] }, 'services enable': err('PERMISSION_DENIED', 'services.enable') }, 'GCP_PERMISSION_DENIED', 3],
    [{ ...ok, 'kms keyrings describe': { stderr: 'ERROR: (gcloud.kms.keyrings.describe) SERVICE_DISABLED: Cloud KMS API has not been used in project 1 before or it is disabled.\n' } }, 'GCP_API_DISABLED', 2],
  ];
  for (const [scenario, code, exit] of cases) {
    const r = await run([...base, '--directory', join(dir, code + exit), '--no-verify'], scenario);
    const e = JSON.parse(r.stderr).error;
    assert.equal(e.code, code, r.stderr); assert.equal(r.code, exit, code); assert.equal(r.stdout, '');
    assert.ok(!r.stderr.includes('secret-project') && !r.stderr.includes('someone@example.com'), 'gcloud stderr is never forwarded');
    if (code === 'GCP_ORG_POLICY') {
      assert.deepEqual(e.created.map(c => Object.keys(c)[0]), ['keyRing', 'cryptoKey', 'serviceAccount', 'keyBinding']);
      assert.match(e.cleanup, /^strongroom teardown gcp --name sr-test .* --delete-key$/);
      assert.match(e.next, /--service-account/);
    }
  }
  assert.equal(JSON.parse((await run([...base, '--directory', join(dir, 'z')], { ...ok, 'kms keys add-iam-policy-binding': err('INVALID_ARGUMENT', 'kms.keys.add-iam-policy-binding') }, { STRONGROOM_SETUP_PROPAGATION_MS: '100' })).stderr).error.gcpCode, 'INVALID_ARGUMENT');
  for (const args of [['setup', 'gcp', '--tenant', 'a', '--name', 'Bad_Name'], ['setup', 'gcp', '--name', 'sr-test'], ['setup', 'gcp', '--tenant', 'a', '--protection-level', 'external'], ['setup', 'gcp', '--tenant', 'a', '--service-account', 'nope'], ['setup', 'gcp', '--tenant', 'a', '--location', 'Bad Loc']])
    assert.equal((await run(args, ok)).code, 2, args.join(' '));
  assert.equal(JSON.parse((await run(['setup', 'gcp', '--tenant', 'a', '--directory', join(dir, 'np')], { 'config get-value': { stdout: '' } })).stderr).error.path, '--project');
});

test('teardown gcp removes the grant and account, destroys versions only on request, and is idempotent', async t => {
  const { run } = await harness(t);
  const present = { 'iam service-accounts list': { stdout: [{ email, description: `strongroom-tenant=${tenantTag('acme')}` }] },
    'kms keys describe': { stdout: { name: key, labels: { app: 'strongroom', 'strongroom-tenant': tenantTag('acme') } } },
    'kms keys versions list': { stdout: [{ name: `${key}/cryptoKeyVersions/1` }, { name: `${key}/cryptoKeyVersions/2` }] }, 'kms keys versions destroy': { stdout: { destroyTime: '2026-11-13T00:00:00Z' } } };
  const td = ['teardown', 'gcp', '--name', 'sr-test', '--keyring', 'sr-ring', '--project', 'demo-project'];
  const r = await run([...td, '--delete-key'], present);
  assert.equal(r.code, 0, r.stderr);
  const kinds = r.calls.map(c => c.slice(0, 3).join(' '));
  // Ownership is checked first; nothing changes until both the account and the key are confirmed.
  assert.deepEqual(kinds, ['iam service-accounts list', 'kms keys describe', 'kms keys remove-iam-policy-binding', 'iam service-accounts delete', 'kms keys versions', 'kms keys versions', 'kms keys versions']);
  const mutating = calls => calls.filter(c => /remove-iam|delete|destroy/.test(c.slice(0, 4).join(' ')));
  const foreignAccount = await run([...td, '--tenant', 'globex', '--delete-key'], present);
  assert.equal(foreignAccount.code, 2); assert.equal(JSON.parse(foreignAccount.stderr).error.code, 'NOT_OWNED'); assert.deepEqual(mutating(foreignAccount.calls), []);
  const foreignKey = await run([...td, '--tenant', 'acme', '--delete-key'], { ...present, 'kms keys describe': { stdout: { name: key, labels: { app: 'strongroom', 'strongroom-tenant': tenantTag('globex') } } } });
  assert.equal(foreignKey.code, 2); assert.deepEqual(mutating(foreignKey.calls), []);
  const unmarked = await run(td, { ...present, 'iam service-accounts list': { stdout: [{ email, description: 'someone else' }] } });
  assert.equal(unmarked.code, 2); assert.deepEqual(mutating(unmarked.calls), []);
  assert.deepEqual(r.calls.filter(c => c[3] === 'destroy').map(c => c[4]), ['1', '2']);
  const kept = await run(td, present);
  assert.ok(!kept.calls.some(c => c[2] === 'versions') && JSON.parse(kept.stdout).keptKey);
  const absent = await run([...td, '--delete-key'], { 'kms keys remove-iam-policy-binding': { stderr: 'ERROR: Policy binding with the specified principal, role, and condition not found!\n' }, 'iam service-accounts list': { stdout: [] }, 'kms keys describe': err('NOT_FOUND', 'kms.keys.describe'), 'kms keys versions list': err('NOT_FOUND', 'kms.keys.versions.list') });
  assert.equal(absent.code, 0, absent.stderr); assert.deepEqual(JSON.parse(absent.stdout).absent, ['keyBinding', 'serviceAccount', 'cryptoKey']);
  // A workload's binding is removed only from a key setup created (for this tenant, with --tenant).
  const workload = await run([...td, '--service-account', 'run@other.iam.gserviceaccount.com'], { 'kms keys describe': present['kms keys describe'] });
  assert.deepEqual(workload.calls.map(c => c[2]), ['describe', 'remove-iam-policy-binding']);
  const otherWorkload = await run([...td, '--tenant', 'globex', '--service-account', 'run@other.iam.gserviceaccount.com'], { 'kms keys describe': present['kms keys describe'] });
  assert.equal(otherWorkload.code, 2); assert.deepEqual(mutating(otherWorkload.calls), []);
  // A 0.1.0 account (no description yet, setup's display name) can still be torn down by --name.
  const legacy = await run(td, { ...present, 'iam service-accounts list': { stdout: [{ email, displayName: 'Strongroom (sr-test)' }] } });
  assert.equal(legacy.code, 0, legacy.stderr); assert.ok(legacy.calls.some(c => c[2] === 'delete'));
});
test('setup gcp names resources after the tenant and fixes the destroy-scheduled duration at creation', async t => {
  const { dir, run } = await harness(t);
  // No --name or --keyring: both follow the tenant, so a second tenant in the same project does not collide.
  const r = await run(['setup', 'gcp', '--tenant', 'acme', '--project', 'demo-project', '--directory', join(dir, 'acme'), '--no-verify'], ok);
  assert.equal(r.code, 0, r.stderr);
  const acme = tenantName('acme');
  const created = r.calls.find(c => c[0] === 'kms' && c[1] === 'keys' && c[2] === 'create');
  assert.equal(created[created.indexOf('--keyring') + 1], acme);
  assert.equal(created[created.indexOf('--destroy-scheduled-duration') + 1], '7d');
  // Both resources carry the tenant's ownership marker, which later reuse and teardown check.
  assert.equal(created[created.indexOf('--labels') + 1], `app=strongroom,strongroom-tenant=${tenantTag('acme')}`);
  const account = r.calls.find(c => c[1] === 'service-accounts' && c[2] === 'create');
  assert.equal(account[3], acme); assert.equal(account[account.indexOf('--description') + 1], `strongroom-tenant=${tenantTag('acme')}`);
  assert.equal(JSON.parse(r.stdout).identity.serviceAccount, `${acme}@demo-project.iam.gserviceaccount.com`);
  const custom = await run([...base, '--directory', join(dir, 'custom'), '--no-verify', '--destroy-scheduled-duration', '30d'], ok);
  const createdCustom = custom.calls.find(c => c[0] === 'kms' && c[1] === 'keys' && c[2] === 'create');
  assert.equal(createdCustom[createdCustom.indexOf('--destroy-scheduled-duration') + 1], '30d');
  // Cloud KMS accepts 24 hours to 120 days; anything else is refused before gcloud is called.
  for (const value of ['23h', '121d', '7', '1w', '-1d']) {
    const bad = await run([...base, '--directory', join(dir, `bad${value}`), '--destroy-scheduled-duration', value], ok);
    assert.equal(bad.code, 2, value); assert.equal(JSON.parse(bad.stderr).error.path, '--destroy-scheduled-duration'); assert.deepEqual(bad.calls, []);
  }
  // Teardown finds the same resources from the tenant alone, and needs one of --tenant or --name.
  const td = await run(['teardown', 'gcp', '--tenant', 'acme', '--project', 'demo-project'], { 'iam service-accounts list': { stdout: [] }, 'kms keys describe': { stdout: { labels: { 'strongroom-tenant': tenantTag('acme') } } } });
  assert.equal(td.code, 0, td.stderr);
  const unbound = td.calls.find(c => c[2] === 'remove-iam-policy-binding');
  assert.equal(unbound[unbound.indexOf('--keyring') + 1], acme); assert.ok(unbound.includes(`serviceAccount:${acme}@demo-project.iam.gserviceaccount.com`));
  const neither = await run(['teardown', 'gcp', '--project', 'demo-project'], ok);
  assert.equal(neither.code, 2); assert.equal(JSON.parse(neither.stderr).error.path, '--tenant');
});
