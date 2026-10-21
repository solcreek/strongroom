import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, stat, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from './cli-helper.mjs';
import { parseConfig } from '../service/config.ts';

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

test('setup aws reuses an existing key and grants a role instead of creating a user', async t => {
  const { dir, run } = await harness(t);
  const scenario = { ...ok, 'kms describe-key': { stdout: { KeyMetadata: { Arn: arn, KeyState: 'Enabled', KeySpec: 'SYMMETRIC_DEFAULT', KeyUsage: 'ENCRYPT_DECRYPT' } } }, 'iam get-role': { stdout: { Role: {} } }, 'iam put-role-policy': { stdout: '' } };
  const r = await run([...base, '--directory', join(dir, 'out'), '--role-name', 'task'], scenario);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(!r.ops.includes('kms create-key') && !r.ops.includes('iam create-user'));
  assert.deepEqual(JSON.parse(await readFile(join(dir, 'out', 'config.json'), 'utf8')).keys.primary, { provider: 'aws', region: 'us-east-1', keyId: arn, containerCredentials: true });
  assert.equal(JSON.parse(r.stdout).verified.ok, false);
  assert.doesNotMatch(JSON.parse(r.stdout).teardown, /--delete-key/);
  const disabled = { ...scenario, 'kms describe-key': { stdout: { KeyMetadata: { Arn: arn, KeyState: 'Disabled', KeySpec: 'SYMMETRIC_DEFAULT', KeyUsage: 'ENCRYPT_DECRYPT' } } } };
  assert.equal(JSON.parse((await run([...base, '--directory', join(dir, 'x'), '--role-name', 'task'], disabled)).stderr).error.code, 'KEY_UNUSABLE');
});

test('setup aws failures carry a stable code, a next step and the resources created so far', async t => {
  const { dir, run } = await harness(t);
  const cases = [
    [{ ...ok, 'sts get-caller-identity': { stderr: 'Unable to locate credentials. You can configure credentials by running "aws configure".' } }, 'AWS_NOT_AUTHENTICATED', 3],
    [{ ...ok, 'sts get-caller-identity': { stderr: 'Error when retrieving token from sso: Token has expired and refresh failed' } }, 'AWS_NOT_AUTHENTICATED', 3],
    [{ ...ok, 'iam get-user': { stdout: { User: {} } } }, 'RESOURCE_EXISTS', 2],
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
      assert.match(e.cleanup, /^strongroom teardown aws --name sr-test --delete-key/);
      assert.ok(e.requiredPermissions.user.includes('iam:CreateUser'));
    } else if (code !== 'AWS_ERROR') assert.ok(e.next);
  }
  assert.equal(JSON.parse((await run(['setup', 'aws', '--tenant', 'a', '--profile', 'nope', '--region', 'us-east-1'], { 'sts get-caller-identity': { stderr: 'The config profile (nope) could not be found' } })).stderr).error.code, 'AWS_PROFILE_NOT_FOUND');
  // Only the fake aws is on PATH here; gcp input errors are covered against a fake gcloud in setup-gcp.test.mjs.
  for (const args of [['setup', 'aws', '--name', 'sr-test'], ['setup', 'aws', '--tenant', 'a', '--name', 'bad name'], ['teardown', 'aws', '--tenant', 'a']])
    assert.equal((await run(args, ok)).code, 2, args.join(' '));
});

test('teardown aws removes exactly what setup created and is idempotent', async t => {
  const { run } = await harness(t);
  const present = { 'iam list-access-keys': { stdout: { AccessKeyMetadata: [{ AccessKeyId: 'AKIA1' }, { AccessKeyId: 'AKIA2' }] } }, 'kms describe-key': { stdout: { KeyMetadata: { Arn: arn } } }, 'kms schedule-key-deletion': { stdout: { DeletionDate: '2026-10-20' } } };
  const r = await run(['teardown', 'aws', '--name', 'sr-test', '--region', 'us-east-1', '--delete-key'], present);
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(r.ops, ['iam list-access-keys', 'iam delete-access-key', 'iam delete-access-key', 'iam delete-user-policy', 'iam delete-user', 'kms describe-key', 'kms delete-alias', 'kms schedule-key-deletion']);
  assert.ok(r.calls.find(c => c[1] === 'schedule-key-deletion').includes('7'));
  const kept = await run(['teardown', 'aws', '--name', 'sr-test', '--region', 'us-east-1'], present);
  assert.ok(!kept.ops.some(o => o.startsWith('kms')) && JSON.parse(kept.stdout).keptKey);
  const absent = await run(['teardown', 'aws', '--name', 'sr-test', '--region', 'us-east-1', '--delete-key'], { 'iam list-access-keys': err('NoSuchEntity', 'ListAccessKeys'), 'kms describe-key': err('NotFoundException', 'DescribeKey') });
  assert.equal(absent.code, 0); assert.deepEqual(JSON.parse(absent.stdout).absent, ['iamUser', 'kmsKey']);
  const role = await run(['teardown', 'aws', '--name', 'sr-test', '--region', 'us-east-1', '--role-name', 'task'], {});
  assert.deepEqual(role.ops, ['iam delete-role-policy']);
});
