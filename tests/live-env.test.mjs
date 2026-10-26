import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adopt, renderLiveEnv, parseArgs, nextAfterStatus, LiveError } from '../scripts/live-env.mjs';

test('live-env adoption is all or nothing and never adopts an unmarked resource', async () => {
  const imported = [];
  const importer = async (address, id) => { imported.push([address, id]); };
  const found = [
    { address: 'aws_kms_key.primary', id: 'k1', owned: true, resource: 'alias/strongroom-dev' },
    { address: 'aws_iam_user.service', id: 'strongroom-dev-live', owned: true, resource: 'IAM user strongroom-dev-live' },
  ];
  // Already in state: skipped; the rest imported in order.
  assert.deepEqual(await adopt(found, new Set(['aws_kms_key.primary']), importer), ['aws_iam_user.service']);
  assert.deepEqual(imported, [['aws_iam_user.service', 'strongroom-dev-live']]);
  // One unmarked candidate refuses the whole adoption before any import.
  imported.length = 0;
  const foreign = [...found, { address: 'aws_kms_key.secondary', id: 'k2', owned: false, resource: 'alias/strongroom-dev-secondary' }];
  await assert.rejects(adopt(foreign, new Set(), importer), e => e instanceof LiveError && e.code === 'NOT_OWNED' && e.exit === 2 && e.details.resources[0] === 'alias/strongroom-dev-secondary');
  assert.deepEqual(imported, []);
  // An unmarked resource already in state was adopted earlier on purpose: no refusal.
  assert.deepEqual(await adopt(foreign, new Set(found.concat(foreign).map(f => f.address)), importer), []);
});

test('live.env lists key IDs, and credential files only when they exist', () => {
  const outputs = { aws: { live_env: { value: { STRONGROOM_LIVE_AWS_KEY_ARN: 'arn:1', STRONGROOM_LIVE_AWS_SECONDARY_ARN: 'arn:2' } } }, gcp: {} };
  const bare = renderLiveEnv(outputs, { aws: false, gcp: false });
  assert.match(bare, /^# Written by scripts\/live-env\.mjs/);
  assert.match(bare, /\nSTRONGROOM_LIVE_AWS_KEY_ARN=arn:1\nSTRONGROOM_LIVE_AWS_SECONDARY_ARN=arn:2\n$/);
  assert.doesNotMatch(bare, /CREDENTIALS_FILE|SA_FILE|GCP_KEY/);
  const issued = renderLiveEnv(outputs, { aws: '/live/aws-service-credentials.json', gcp: '/live/gcp-sa.json' });
  assert.match(issued, /\nSTRONGROOM_LIVE_AWS_CREDENTIALS_FILE=\/live\/aws-service-credentials\.json\nSTRONGROOM_LIVE_GCP_SA_FILE=\/live\/gcp-sa\.json\n$/);
});

test('live-env arguments are validated before anything runs', () => {
  assert.deepEqual(parseArgs(['apply', '--cloud', 'aws', '--yes']), { command: 'apply', yes: true, cloud: 'aws' });
  assert.equal(parseArgs(['status', '--gcp-project', 'p', '--aws-region', 'eu-west-1']).gcpProject, 'p');
  for (const argv of [[], ['destroy'], ['apply', '--cloud', 'azure'], ['apply', '--cloud'], ['apply', '--force']])
    assert.throws(() => parseArgs(argv), e => e instanceof LiveError && e.exit === 2, JSON.stringify(argv));
});

test('status names the next step from what it saw', () => {
  const resources = n => Array.from({ length: n }, (_, i) => ({ address: `r${i}`, inState: true }));
  const cloud = (r, live = []) => ({ resources: r, credentials: { live } });
  assert.match(nextAfterStatus({ aws: cloud(resources(4)) }), /^node scripts\/live-env\.mjs apply/);
  assert.match(nextAfterStatus({ aws: cloud([...resources(5), { address: 'x', inState: false }]) }), /apply/);
  assert.match(nextAfterStatus({ aws: cloud(resources(6), [{ id: 'AKIA' }]) }), /revoke when done/);
  assert.match(nextAfterStatus({ aws: cloud(resources(6)), gcp: cloud(resources(6)) }), /^node scripts\/live-env\.mjs credentials/);
});
