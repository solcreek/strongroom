import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, stat, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from './cli-helper.mjs';
import { parseConfig } from '../service/config.ts';
import { tenantName, tenantTag } from '../packages/strongroom/src/setup-common.ts';
import { kmsPolicy } from '../packages/strongroom/src/setup-aws.ts';

// A fake `aws` on PATH: answers from a scenario file and records every call, so setup runs offline and deterministically.
const fake = `#!/usr/bin/env node
const { readFileSync, appendFileSync } = require('node:fs');
const args = process.argv.slice(2), op = args[0] + ' ' + args[1];
appendFileSync(process.env.FAKE_AWS_LOG, JSON.stringify(args) + '\\n');
const r = JSON.parse(readFileSync(process.env.FAKE_AWS_SCENARIO, 'utf8'))[op] ?? { stdout: {} };
if (r.stderr) { process.stderr.write(r.stderr); process.exit(254); }
process.stdout.write(typeof r.stdout === 'string' ? r.stdout : JSON.stringify(r.stdout));
`;
const arn = 'arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555';
const err = (code, operation) => ({ stderr: `\nAn error occurred (${code}) when calling the ${operation} operation: details with arn:aws:secret\n` });
const ok = {
  'sts get-caller-identity': { stdout: { Account: '123456789012', Arn: 'arn:aws:iam::123456789012:user/admin' } },
  'kms describe-key': err('NotFoundException', 'DescribeKey'),
  'iam get-user': err('NoSuchEntity', 'GetUser'),
  'kms create-key': { stdout: { KeyMetadata: { Arn: arn } } },
  'kms create-alias': { stdout: '' },
  'iam create-user': { stdout: { User: {} } },
  'iam put-user-policy': { stdout: '' },
  'iam create-access-key': { stdout: { AccessKey: { AccessKeyId: 'AKIAFAKEFAKEFAKE0000', SecretAccessKey: 'fake-secret-access-key-never-printed' } } },
};
async function harness(t) {
  const dir = await mkdtemp(join(tmpdir(), 'strongroom-setup-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(join(dir, 'aws'), fake); await chmod(join(dir, 'aws'), 0o755);
  const run = async (args, scenario) => {
    await writeFile(join(dir, 'scenario.json'), JSON.stringify(scenario)); await writeFile(join(dir, 'calls.log'), '');
    const r = await runCli(args, { env: { PATH: `${dir}:${process.env.PATH}`, FAKE_AWS_SCENARIO: join(dir, 'scenario.json'), FAKE_AWS_LOG: join(dir, 'calls.log') } });
    const calls = (await readFile(join(dir, 'calls.log'), 'utf8')).split('\n').filter(Boolean).map(l => JSON.parse(l));
    return { ...r, calls, ops: calls.map(c => `${c[0]} ${c[1]}`) };
  };
  return { dir, run };
}
const base = ['setup', 'aws', '--name', 'sr-test', '--tenant', 'acme', '--region', 'us-east-1'];

test('setup aws --dry-run reports the plan and required permissions without mutating AWS', async t => {
  const { dir, run } = await harness(t);
  const r = await run([...base, '--directory', join(dir, 'out'), '--dry-run'], ok);
  assert.equal(r.code, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.deepEqual(out.plan.map(p => p.action), ['create-key', 'create-iam-user', 'write-files', 'verify']);
  assert.ok(out.requiredPermissions.includes('iam:CreateAccessKey'));
  assert.deepEqual(r.ops, ['sts get-caller-identity', 'kms describe-key', 'iam get-user']);
  assert.ok(r.calls.every(c => c.includes('--region') && c.includes('--output')));
  await assert.rejects(stat(join(dir, 'out')));
  // Without --region the profile's region is used; with neither, setup stops before touching AWS.
  const profileRegion = await run(['setup', 'aws', '--tenant', 'acme', '--directory', join(dir, 'p'), '--dry-run'], { ...ok, 'configure get': { stdout: 'eu-west-1\n' } });
  assert.equal(JSON.parse(profileRegion.stdout).region, 'eu-west-1');
  const none = await run(['setup', 'aws', '--tenant', 'acme', '--directory', join(dir, 'n'), '--dry-run'], { ...ok, 'configure get': { stderr: '' } });
  assert.equal(JSON.parse(none.stderr).error.path, '--region'); assert.deepEqual(none.ops, ['configure get']);
});

test('setup aws writes a valid private config, keeps the secret off stdout, and grants only Strongroom context', async t => {
  const { dir, run } = await harness(t);
  const out = join(dir, 'out');
  const r = await run([...base, '--directory', out, '--no-verify', '--key', 'vault'], ok);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(!r.stdout.includes('fake-secret-access-key') && !r.stderr.includes('fake-secret'));
  const summary = JSON.parse(r.stdout), config = JSON.parse(await readFile(join(out, 'config.json'), 'utf8'));
  assert.deepEqual(config.keys.vault, { provider: 'aws', region: 'us-east-1', keyId: arn, accessKeyId: 'AKIAFAKEFAKEFAKE0000', secretAccessKey: 'fake-secret-access-key-never-printed' });
  assert.ok(parseConfig({ STRONGROOM_CONFIG: JSON.stringify(config) }));
  assert.equal(config.principals[0].tokenSha256, summary.principal.tokenSha256);
  // --tenant names the one tenant this deployment serves; principals carry none.
  assert.equal(config.tenantId, 'acme'); assert.equal(summary.tenantId, 'acme'); assert.equal(Object.hasOwn(config.principals[0], 'tenantId'), false);
  for (const f of ['config.json', 'token']) assert.equal((await stat(join(out, f))).mode & 0o777, 0o600);
  assert.equal((await stat(out)).mode & 0o777, 0o700);
  const policy = JSON.parse(r.calls.find(c => c[1] === 'put-user-policy')[r.calls.find(c => c[1] === 'put-user-policy').indexOf('--policy-document') + 1]);
  assert.equal(policy.Statement[0].Resource, arn);
  assert.deepEqual(policy.Statement[0].Condition['ForAllValues:StringEquals'], { 'kms:EncryptionContextKeys': ['strongroom'] });
  assert.match(summary.teardown, /--delete-key/);
  assert.ok(summary.next.some(n => n.includes('strongroom probe')));
  // Rerunning never overwrites secrets.
  assert.equal((await run([...base, '--directory', out, '--no-verify'], ok)).code, 2);
});

test('setup aws reuses this tenant\'s existing key and grants a role instead of creating a user', async t => {
  const { dir, run } = await harness(t);
  const scenario = { ...ok, 'kms describe-key': { stdout: { KeyMetadata: { Arn: arn, KeyState: 'Enabled', KeySpec: 'SYMMETRIC_DEFAULT', KeyUsage: 'ENCRYPT_DECRYPT' } } },
    'kms list-resource-tags': { stdout: { Tags: [{ TagKey: 'strongroom-tenant', TagValue: tenantTag('acme') }] } }, 'iam get-role': { stdout: { Role: {} } },
    'iam get-role-policy': err('NoSuchEntity', 'GetRolePolicy'), 'iam put-role-policy': { stdout: '' } };
  const r = await run([...base, '--directory', join(dir, 'out'), '--role-name', 'task'], scenario);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(!r.ops.includes('kms create-key') && !r.ops.includes('iam create-user'));
  // Named per deployment, so a role shared by several tenants never has one tenant's grant overwritten.
  assert.ok(r.calls.find(c => c[1] === 'put-role-policy').includes('strongroom-kms-sr-test'));
  assert.deepEqual(JSON.parse(await readFile(join(dir, 'out', 'config.json'), 'utf8')).keys.primary, { provider: 'aws', region: 'us-east-1', keyId: arn, containerCredentials: true });
  assert.equal(JSON.parse(r.stdout).verified.ok, false);
  assert.doesNotMatch(JSON.parse(r.stdout).teardown, /--delete-key/);
  const disabled = { ...scenario, 'kms describe-key': { stdout: { KeyMetadata: { Arn: arn, KeyState: 'Disabled', KeySpec: 'SYMMETRIC_DEFAULT', KeyUsage: 'ENCRYPT_DECRYPT' } } } };
  assert.equal(JSON.parse((await run([...base, '--directory', join(dir, 'x'), '--role-name', 'task'], disabled)).stderr).error.code, 'KEY_UNUSABLE');
  // An alias whose key is tagged for another tenant, or not tagged at all, is never reused: that would share a key across tenants.
  for (const tags of [[{ TagKey: 'strongroom-tenant', TagValue: tenantTag('globex') }], [{ TagKey: 'app', TagValue: 'strongroom' }], []]) {
    const foreign = await run([...base, '--directory', join(dir, `f${tags.length}${tags[0]?.TagKey ?? ''}`), '--role-name', 'task'], { ...scenario, 'kms list-resource-tags': { stdout: { Tags: tags } } });
    assert.equal(foreign.code, 2); assert.equal(JSON.parse(foreign.stderr).error.code, 'NOT_OWNED'); assert.ok(!foreign.ops.includes('iam put-role-policy'));
  }
  // IAM is global, aliases are regional: an existing grant for another key (the same name set up in another
  // region, say) is never overwritten. Re-running against the same key is fine.
  const otherKey = arn.replace('us-east-1', 'eu-west-1');
  const overwrite = await run([...base, '--directory', join(dir, 'ow'), '--role-name', 'task'], { ...scenario, 'iam get-role-policy': { stdout: { PolicyDocument: kmsPolicy(otherKey) } } });
  assert.equal(overwrite.code, 2); assert.equal(JSON.parse(overwrite.stderr).error.code, 'NOT_OWNED'); assert.ok(!overwrite.ops.includes('iam put-role-policy'));
  const rerun = await run([...base, '--directory', join(dir, 'rr'), '--role-name', 'task'], { ...scenario, 'iam get-role-policy': { stdout: { PolicyDocument: kmsPolicy(arn) } } });
  assert.equal(rerun.code, 0, rerun.stderr);
  // The cross-region case itself: no alias here, but the role already grants this name's key elsewhere.
  const otherRegion = await run([...base, '--directory', join(dir, 'or'), '--role-name', 'task'],
    { ...scenario, 'kms describe-key': err('NotFoundException', 'DescribeKey'), 'iam get-role-policy': { stdout: { PolicyDocument: kmsPolicy(otherKey) } } });
  assert.equal(otherRegion.code, 2); assert.equal(JSON.parse(otherRegion.stderr).error.code, 'NOT_OWNED');
  assert.ok(!otherRegion.ops.includes('iam put-role-policy') && !otherRegion.ops.includes('kms create-key'));
});

test('setup aws failures carry a stable code, a next step and the resources created so far', async t => {
  const { dir, run } = await harness(t);
  const cases = [
    [{ ...ok, 'sts get-caller-identity': { stderr: 'Unable to locate credentials. You can configure credentials by running "aws configure".' } }, 'AWS_NOT_AUTHENTICATED', 3],
    [{ ...ok, 'sts get-caller-identity': { stderr: 'Error when retrieving token from sso: Token has expired and refresh failed' } }, 'AWS_NOT_AUTHENTICATED', 3],
    [{ ...ok, 'iam get-user': { stdout: { User: {} } }, 'iam list-user-tags': { stdout: { Tags: [{ Key: 'strongroom-tenant', Value: tenantTag('acme') }] } } }, 'RESOURCE_EXISTS', 2],
    // The same name held by another tenant's user is not "yours to tear down": no teardown is suggested.
    [{ ...ok, 'iam get-user': { stdout: { User: {} } }, 'iam list-user-tags': { stdout: { Tags: [{ Key: 'strongroom-tenant', Value: tenantTag('globex') }] } } }, 'NOT_OWNED', 2],
    [{ ...ok, 'iam create-user': err('AccessDenied', 'CreateUser') }, 'AWS_PERMISSION_DENIED', 3],
    [{ ...ok, 'kms create-alias': err('LimitExceededException', 'CreateAlias') }, 'AWS_ERROR', 1],
  ];
  for (const [scenario, code, exit] of cases) {
    const r = await run([...base, '--directory', join(dir, code), '--no-verify'], scenario);
    const e = JSON.parse(r.stderr).error;
    assert.equal(e.code, code); assert.equal(r.code, exit, code); assert.equal(r.stdout, '');
    assert.ok(!r.stderr.includes('arn:aws:secret'), 'aws stderr text is never forwarded');
    if (code === 'AWS_PERMISSION_DENIED') {
      assert.deepEqual(e.created, [{ kmsKey: arn }, { alias: 'alias/sr-test' }]);
      // Every command setup prints is tenant-scoped, so following it can only touch this tenant's resources.
      assert.match(e.cleanup, /^strongroom teardown aws --tenant acme --name sr-test .*--delete-key$/);
      assert.ok(e.requiredPermissions.user.includes('iam:CreateUser'));
    } else if (code !== 'AWS_ERROR') assert.ok(e.next);
    if (code === 'RESOURCE_EXISTS') assert.match(e.next, /teardown aws --tenant acme /);
    if (code === 'NOT_OWNED') assert.doesNotMatch(e.next, /teardown/);
  }
  // A tenant id that needs quoting is quoted in the printed command.
  const quoted = await run(['setup', 'aws', '--tenant', "o'brien & co", '--region', 'us-east-1', '--directory', join(dir, 'q'), '--no-verify'], { ...ok, 'iam create-user': err('AccessDenied', 'CreateUser') });
  assert.match(JSON.parse(quoted.stderr).error.cleanup, /--tenant 'o'\\''brien & co' /);
  assert.equal(JSON.parse((await run(['setup', 'aws', '--tenant', 'a', '--profile', 'nope', '--region', 'us-east-1'], { 'sts get-caller-identity': { stderr: 'The config profile (nope) could not be found' } })).stderr).error.code, 'AWS_PROFILE_NOT_FOUND');
  // Only the fake aws is on PATH here; gcp input errors are covered against a fake gcloud in setup-gcp.test.mjs.
  for (const args of [['setup', 'aws', '--name', 'sr-test'], ['setup', 'aws', '--tenant', 'a', '--name', 'bad name'], ['teardown', 'aws']])
    assert.equal((await run(args, ok)).code, 2, args.join(' '));
  assert.equal(JSON.parse((await run(['teardown', 'aws'], ok)).stderr).error.path, '--tenant');
});

test('resource names follow the tenant, so tenants can share an account without --name', async t => {
  for (const [tenant, name] of [['acme', /^sr-acme-[0-9a-f]{10}$/], ['Acme', /^sr-acme-[0-9a-f]{10}$/], ['ab', /^sr-ab-[0-9a-f]{10}$/], ['日本', /^sr-[0-9a-f]{10}$/], ['x'.repeat(40), /^sr-x{16}-[0-9a-f]{10}$/]]) {
    const derived = tenantName(tenant);
    assert.match(derived, name);
    // Valid as a KMS alias and IAM user, and as a GCP key ring and service account id.
    assert.match(derived, /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/); assert.match(derived, /^[A-Za-z0-9_-]{1,32}$/);
  }
  // Every name carries the hash, so a tenant id shaped like another tenant's derived name cannot claim it.
  assert.notEqual(tenantName('Acme'), tenantName('acme'));
  assert.notEqual(tenantName('ab'), tenantName(tenantName('ab').slice(3)));
  const acme = tenantName('acme');
  const { dir, run } = await harness(t);
  const setup = await run(['setup', 'aws', '--tenant', 'acme', '--region', 'us-east-1', '--directory', join(dir, 'acme'), '--dry-run'], ok);
  assert.equal(setup.code, 0, setup.stderr); assert.equal(JSON.parse(setup.stdout).name, acme);
  assert.ok(setup.calls.some(c => c.includes(`alias/${acme}`)) && setup.calls.some(c => c.includes(acme) && c[1] === 'get-user'));
  // Teardown derives the same names from the tenant alone.
  const teardown = await run(['teardown', 'aws', '--tenant', 'acme', '--region', 'us-east-1'], ok);
  assert.ok(teardown.calls.every(c => !c.includes('--user-name') || c.includes(acme)));
  assert.ok(teardown.calls.some(c => c.includes(acme)));
});

test('teardown aws removes exactly what setup created and is idempotent', async t => {
  const { run } = await harness(t);
  const present = { 'iam list-user-tags': { stdout: { Tags: [{ Key: 'app', Value: 'strongroom' }, { Key: 'strongroom-tenant', Value: tenantTag('acme') }] } },
    'iam list-access-keys': { stdout: { AccessKeyMetadata: [{ AccessKeyId: 'AKIA1' }, { AccessKeyId: 'AKIA2' }] } }, 'kms describe-key': { stdout: { KeyMetadata: { Arn: arn } } },
    'kms list-resource-tags': { stdout: { Tags: [{ TagKey: 'app', TagValue: 'strongroom' }, { TagKey: 'strongroom-tenant', TagValue: tenantTag('acme') }] } }, 'kms schedule-key-deletion': { stdout: { DeletionDate: '2026-10-20' } } };
  const r = await run(['teardown', 'aws', '--tenant', 'acme', '--name', 'sr-test', '--region', 'us-east-1', '--delete-key'], present);
  assert.equal(r.code, 0, r.stderr);
  // Every ownership check (user, then key) runs before the first deletion.
  assert.deepEqual(r.ops, ['iam list-user-tags', 'kms describe-key', 'kms list-resource-tags', 'iam list-access-keys', 'iam delete-access-key', 'iam delete-access-key', 'iam delete-user-policy', 'iam delete-user', 'kms delete-alias', 'kms schedule-key-deletion']);
  // Resources tagged for another tenant, or not created by setup, are refused before anything is deleted.
  const mutating = ops => ops.filter(o => /delete|schedule/.test(o));
  const foreignUser = await run(['teardown', 'aws', '--tenant', 'globex', '--name', 'sr-test', '--region', 'us-east-1', '--delete-key'], present);
  assert.equal(foreignUser.code, 2); assert.equal(JSON.parse(foreignUser.stderr).error.code, 'NOT_OWNED'); assert.deepEqual(mutating(foreignUser.ops), []);
  // setup's app=strongroom tag alone proves nothing about the tenant.
  const untagged = await run(['teardown', 'aws', '--tenant', 'acme', '--name', 'sr-test', '--region', 'us-east-1'], { ...present, 'iam list-user-tags': { stdout: { Tags: [{ Key: 'app', Value: 'strongroom' }] } } });
  assert.equal(untagged.code, 2); assert.deepEqual(mutating(untagged.ops), []);
  // A name alone is never enough: teardown is always tenant-scoped.
  const nameOnly = await run(['teardown', 'aws', '--name', 'sr-test', '--region', 'us-east-1'], present);
  assert.equal(nameOnly.code, 2); assert.equal(JSON.parse(nameOnly.stderr).error.path, '--tenant'); assert.deepEqual(nameOnly.ops, []);
  const foreignKey = await run(['teardown', 'aws', '--tenant', 'acme', '--name', 'sr-test', '--region', 'us-east-1', '--delete-key'],
    { ...present, 'kms list-resource-tags': { stdout: { Tags: [{ TagKey: 'strongroom-tenant', TagValue: tenantTag('globex') }] } } });
  // A foreign key with --delete-key stops the whole teardown: the user is not deleted either.
  assert.equal(foreignKey.code, 2); assert.deepEqual(mutating(foreignKey.ops), []);
  assert.ok(r.calls.find(c => c[1] === 'schedule-key-deletion').includes('7'));
  const kept = await run(['teardown', 'aws', '--tenant', 'acme', '--name', 'sr-test', '--region', 'us-east-1'], present);
  assert.ok(!kept.ops.some(o => o.startsWith('kms')) && JSON.parse(kept.stdout).keptKey);
  const absent = await run(['teardown', 'aws', '--tenant', 'acme', '--name', 'sr-test', '--region', 'us-east-1', '--delete-key'], { 'iam list-user-tags': err('NoSuchEntity', 'ListUserTags'), 'kms describe-key': err('NotFoundException', 'DescribeKey') });
  assert.equal(absent.code, 0); assert.deepEqual(JSON.parse(absent.stdout).absent, ['iamUser', 'kmsKey']);
  // A key not found in this region was not deleted, and the result must say so rather than report a crypto-shred.
  const absentOut = JSON.parse(absent.stdout);
  assert.equal(absentOut.keyScheduledForDeletion, false); assert.equal(absentOut.keptKey, true); assert.match(absentOut.note, /nothing was scheduled/);
  assert.equal(JSON.parse(r.stdout).keyScheduledForDeletion, true);
  // A shared role keeps one policy per deployment; teardown removes this one only if its key is this tenant's.
  const granted = { 'iam get-role-policy': { stdout: { PolicyDocument: kmsPolicy(arn) } }, 'kms list-resource-tags': present['kms list-resource-tags'] };
  const roleArgs = tenant => ['teardown', 'aws', '--tenant', tenant, '--name', 'sr-test', '--region', 'us-east-1', '--role-name', 'task'];
  const role = await run(roleArgs('acme'), granted);
  assert.equal(role.code, 0, role.stderr); assert.deepEqual(role.ops, ['iam get-role-policy', 'kms list-resource-tags', 'iam delete-role-policy']);
  assert.ok(role.calls.find(c => c[1] === 'delete-role-policy').includes('strongroom-kms-sr-test'));
  // Fail closed: another tenant's key, an untagged key, or a policy that is not setup's exact shape is refused.
  const { Statement: [statement] } = kmsPolicy(arn);
  for (const [why, tenant, scenario] of [
    ['other tenant', 'globex', granted],
    ['untagged key', 'acme', { ...granted, 'kms list-resource-tags': { stdout: { Tags: [] } } }],
    ['NotResource', 'acme', { ...granted, 'iam get-role-policy': { stdout: { PolicyDocument: { ...kmsPolicy(arn), Statement: [{ ...statement, Resource: undefined, NotResource: arn }] } } } }],
    ['two statements', 'acme', { ...granted, 'iam get-role-policy': { stdout: { PolicyDocument: { ...kmsPolicy(arn), Statement: [statement, statement] } } } }],
    ['wider actions', 'acme', { ...granted, 'iam get-role-policy': { stdout: { PolicyDocument: { ...kmsPolicy(arn), Statement: [{ ...statement, Action: ['kms:*'] }] } } } }],
    ['no document', 'acme', { ...granted, 'iam get-role-policy': { stdout: {} } }],
  ]) {
    const refused = await run(roleArgs(tenant), scenario);
    assert.equal(refused.code, 2, why); assert.equal(JSON.parse(refused.stderr).error.code, 'NOT_OWNED', why); assert.deepEqual(mutating(refused.ops), [], why);
  }
  // The granted key is looked up in its own region, so a different --region cannot make a live key look gone.
  const euKey = arn.replace('us-east-1', 'eu-west-1');
  const crossRegion = await run(roleArgs('acme'), { ...granted, 'iam get-role-policy': { stdout: { PolicyDocument: kmsPolicy(euKey) } } });
  assert.equal(crossRegion.code, 0, crossRegion.stderr);
  const lookup = crossRegion.calls.find(c => c[1] === 'list-resource-tags');
  assert.equal(lookup[lookup.indexOf('--region') + 1], 'eu-west-1');
  // A grant on a key that no longer exists is no one's, so it is removed.
  const keyGone = await run(roleArgs('acme'), { ...granted, 'kms list-resource-tags': err('NotFoundException', 'ListResourceTags') });
  assert.equal(keyGone.code, 0, keyGone.stderr); assert.ok(keyGone.ops.includes('iam delete-role-policy'));
});
