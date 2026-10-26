// The live test environment: the cloud resources scripts/test-live.mjs runs against, as OpenTofu stacks in
// infra/live-test/<cloud>, plus service credentials that are issued for a run and revoked after it. No credential
// ever enters OpenTofu state, and a missing state is rebuilt by adopting the resources already in the cloud.
//   node scripts/live-env.mjs status|plan|apply|credentials|revoke [--cloud aws,gcp] [--aws-region R] [--gcp-project P] [--yes]
// One JSON object on stdout; tofu's own output goes to stderr. Exit 0 success, 2 usage or ownership refusal, 1 failure.
import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, rmSync, chmodSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { liveDir } from './live-dir.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// Must match the defaults in infra/live-test/<cloud>/variables.tf.
const AWS = { name: 'strongroom-dev', user: 'strongroom-dev-live', policy: 'strongroom-kms-primary' };
const GCP = { location: 'global', keyring: 'strongroom-dev', account: 'strongroom-dev', displayName: 'strongroom live KMS tests (dev only)' };
const MARKER = 'integration-test';
const ROLE = 'roles/cloudkms.cryptoKeyEncrypterDecrypter';

export class LiveError extends Error {
  constructor(code, message, exit = 1, details = {}) { super(message); Object.assign(this, { code, exit, details }); }
}

const exec = (cmd, args, env = {}) => new Promise((done, reject) =>
  execFile(cmd, args, { cwd: repo, env: { ...process.env, ...env }, maxBuffer: 16 << 20, timeout: 300000 }, (error, stdout, stderr) => {
    if (!error) return done(stdout);
    if (error.code === 'ENOENT') return reject(new LiveError('TOOL_MISSING', `${cmd} is not installed or not on PATH.`, 2));
    reject(Object.assign(new LiveError('TOOL_FAILED', `${cmd} ${args.slice(0, 3).join(' ')} failed.`), { stderr }));
  }));
// Only "it does not exist" becomes null; every other failure stops the run, so an outage never reads as absence.
const missing = /NoSuchEntity|NotFoundException|NOT_FOUND|was not found|does not exist/;
const maybe = promise => promise.catch(e => { if (missing.test(e.stderr ?? '')) return null; throw e; });
const tail = s => (s ?? '').trim().split('\n').slice(-3).join(' ').slice(0, 400);

function tools(s) {
  const aws = async args => { const out = await exec('aws', [...args, '--region', s.awsRegion, '--output', 'json'], { AWS_PAGER: '' }); return out.trim() ? JSON.parse(out) : {}; };
  const gcloud = async args => { const out = await exec('gcloud', [...args, '--project', s.gcpProject, '--format', 'json']); return out.trim() ? JSON.parse(out) : {}; };
  return { aws, gcloud };
}

// --- where things live ---------------------------------------------------------------------------------------------
export const paths = dir => ({
  settings: join(dir, 'settings.json'), liveEnv: join(dir, 'live.env'),
  awsCredentials: join(dir, 'aws-service-credentials.json'), gcpCredentials: join(dir, 'gcp-sa.json'),
  state: cloud => join(dir, 'tofu', cloud, 'terraform.tfstate'), data: cloud => join(dir, 'tofu', cloud, '.terraform'),
});
function writePrivate(file, text) {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 }); renameSync(tmp, file); chmodSync(file, 0o600);
}

// --- OpenTofu -------------------------------------------------------------------------------------------------------
function tofu(p, s, cloud) {
  const env = { TF_DATA_DIR: p.data(cloud), TF_IN_AUTOMATION: '1' };
  const chdir = `-chdir=infra/live-test/${cloud}`;
  const vars = cloud === 'aws' ? ['-var', `region=${s.awsRegion}`] : ['-var', `project_id=${s.gcpProject}`];
  // Streamed commands write to stderr, keeping stdout for the one JSON result.
  const stream = args => new Promise((done, reject) => {
    const child = spawn('tofu', [chdir, ...args], { cwd: repo, env: { ...process.env, ...env }, stdio: ['ignore', 2, 2] });
    child.on('error', e => reject(e.code === 'ENOENT' ? new LiveError('TOOL_MISSING', 'tofu (OpenTofu) is not installed or not on PATH.', 2) : e));
    child.on('close', done);
  });
  const capture = args => exec('tofu', [chdir, ...args], env);
  return {
    init: async () => { if (await stream(['init', '-input=false', '-no-color', '-reconfigure', `-backend-config=path=${p.state(cloud)}`]) !== 0) throw new LiveError('TOFU_INIT_FAILED', `tofu init failed for ${cloud}; see stderr.`); },
    stateList: async () => existsSync(p.state(cloud)) ? new Set((await capture(['state', 'list'])).split('\n').filter(Boolean)) : new Set(),
    import: async (address, id) => { if (await stream(['import', '-input=false', '-no-color', ...vars, address, id]) !== 0) throw new LiveError('TOFU_IMPORT_FAILED', `tofu import ${address} failed; see stderr.`); },
    plan: async file => {
      const code = await stream(['plan', '-input=false', '-no-color', '-detailed-exitcode', `-out=${file}`, ...vars]);
      if (code !== 0 && code !== 2) throw new LiveError('TOFU_PLAN_FAILED', `tofu plan failed for ${cloud}; see stderr.`);
      const plan = JSON.parse(await capture(['show', '-json', file]));
      return (plan.resource_changes ?? []).filter(c => !c.change.actions.every(a => a === 'no-op' || a === 'read')).map(c => ({ address: c.address, actions: c.change.actions }));
    },
    apply: async file => { if (await stream(['apply', '-input=false', '-no-color', file]) !== 0) throw new LiveError('TOFU_APPLY_FAILED', `tofu apply failed for ${cloud}; see stderr.`); },
    output: async () => existsSync(p.state(cloud)) ? JSON.parse(await capture(['output', '-json'])) : {},
  };
}

// --- what already exists in the cloud ------------------------------------------------------------------------------
// Each entry is an OpenTofu address, its import ID, and whether it carries the test marker. Adoption refuses an
// unmarked resource: a name collision must never pull someone else's key or identity into this stack.
async function findAws(s) {
  const { aws } = tools(s); const out = [];
  for (const [which, alias] of [['primary', `alias/${AWS.name}`], ['secondary', `alias/${AWS.name}-secondary`]]) {
    const key = await maybe(aws(['kms', 'describe-key', '--key-id', alias]));
    if (!key) continue;
    const tags = await aws(['kms', 'list-resource-tags', '--key-id', key.KeyMetadata.KeyId]);
    const owned = (tags.Tags ?? []).some(t => t.TagKey === 'purpose' && t.TagValue === MARKER);
    out.push({ address: `aws_kms_key.${which}`, id: key.KeyMetadata.KeyId, owned, resource: alias, state: key.KeyMetadata.KeyState },
      { address: `aws_kms_alias.${which}`, id: alias, owned, resource: alias });
  }
  const tags = await maybe(aws(['iam', 'list-user-tags', '--user-name', AWS.user]));
  if (tags) {
    const owned = (tags.Tags ?? []).some(t => t.Key === 'purpose' && t.Value === MARKER);
    out.push({ address: 'aws_iam_user.service', id: AWS.user, owned, resource: `IAM user ${AWS.user}` });
    if (await maybe(aws(['iam', 'get-user-policy', '--user-name', AWS.user, '--policy-name', AWS.policy])))
      out.push({ address: 'aws_iam_user_policy.service', id: `${AWS.user}:${AWS.policy}`, owned, resource: `IAM user policy ${AWS.policy}` });
  }
  return out;
}

async function findGcp(s) {
  const { gcloud } = tools(s); const out = [];
  const ring = `projects/${s.gcpProject}/locations/${GCP.location}/keyRings/${GCP.keyring}`;
  const email = `${GCP.account}@${s.gcpProject}.iam.gserviceaccount.com`;
  const enabled = await gcloud(['services', 'list', '--enabled', '--filter=config.name=cloudkms.googleapis.com']);
  if (enabled.length) out.push({ address: 'google_project_service.kms', id: `${s.gcpProject}/cloudkms.googleapis.com`, owned: true, resource: 'cloudkms.googleapis.com' });
  if (!enabled.length) return out;
  // Key rings carry no labels; the keys inside are what adoption checks.
  if (await maybe(gcloud(['kms', 'keyrings', 'describe', ring]))) out.push({ address: 'google_kms_key_ring.this', id: ring, owned: true, resource: ring });
  let primaryOwned = false;
  for (const which of ['primary', 'secondary']) {
    const key = await maybe(gcloud(['kms', 'keys', 'describe', `${ring}/cryptoKeys/${which}`]));
    if (!key) continue;
    const owned = key.labels?.purpose === MARKER;
    if (which === 'primary') primaryOwned = owned;
    out.push({ address: `google_kms_crypto_key.${which}`, id: `${ring}/cryptoKeys/${which}`, owned, resource: `${ring}/cryptoKeys/${which}` });
  }
  const account = await maybe(gcloud(['iam', 'service-accounts', 'describe', email]));
  if (account) out.push({ address: 'google_service_account.service', id: `projects/${s.gcpProject}/serviceAccounts/${email}`, owned: (account.description ?? '').includes(`purpose=${MARKER}`) || account.displayName === GCP.displayName, resource: email });
  if (out.some(f => f.address === 'google_kms_crypto_key.primary')) {
    const policy = await gcloud(['kms', 'keys', 'get-iam-policy', `${ring}/cryptoKeys/primary`]);
    if ((policy.bindings ?? []).some(b => b.role === ROLE && b.members?.includes(`serviceAccount:${email}`)))
      out.push({ address: 'google_kms_crypto_key_iam_member.service', id: `${ring}/cryptoKeys/primary ${ROLE} serviceAccount:${email}`, owned: primaryOwned, resource: `${ROLE} on primary` });
  }
  return out;
}

// Imports what exists but is missing from state, after checking every candidate first: all or nothing.
export async function adopt(found, inState, importer) {
  const todo = found.filter(f => !inState.has(f.address));
  const foreign = todo.filter(f => !f.owned);
  if (foreign.length) throw new LiveError('NOT_OWNED', `Refusing to adopt resources without the purpose=${MARKER} marker; nothing was imported.`, 2,
    { resources: foreign.map(f => f.resource), next: 'Check the region/project, or rename the stack in infra/live-test/<cloud>/variables.tf and scripts/live-env.mjs.' });
  for (const f of todo) await importer(f.address, f.id);
  return todo.map(f => f.address);
}

// --- live.env: what test-live.mjs reads ----------------------------------------------------------------------------
export function renderLiveEnv(outputs, files) {
  const lines = ['# Written by scripts/live-env.mjs. Rerun it instead of editing; it holds no secret, only paths and key IDs.'];
  for (const cloud of ['aws', 'gcp']) for (const [k, v] of Object.entries(outputs[cloud]?.live_env?.value ?? {})) lines.push(`${k}=${v}`);
  if (files.aws) lines.push(`STRONGROOM_LIVE_AWS_CREDENTIALS_FILE=${files.aws}`);
  if (files.gcp) lines.push(`STRONGROOM_LIVE_GCP_SA_FILE=${files.gcp}`);
  return `${lines.join('\n')}\n`;
}
async function writeLiveEnv(p, s) {
  const outputs = {};
  for (const cloud of ['aws', 'gcp']) if (existsSync(p.state(cloud)) && (cloud === 'aws' || s.gcpProject)) { const t = tofu(p, s, cloud); await t.init(); outputs[cloud] = await t.output(); }
  writePrivate(p.liveEnv, renderLiveEnv(outputs, { aws: existsSync(p.awsCredentials) && p.awsCredentials, gcp: existsSync(p.gcpCredentials) && p.gcpCredentials }));
  return p.liveEnv;
}

// --- credentials ---------------------------------------------------------------------------------------------------
const age = iso => Math.round((Date.now() - Date.parse(iso)) / 36e5 * 10) / 10;
async function awsKeys(s) { const r = await maybe(tools(s).aws(['iam', 'list-access-keys', '--user-name', AWS.user])); return (r?.AccessKeyMetadata ?? []).map(k => ({ id: k.AccessKeyId, created: k.CreateDate, ageHours: age(k.CreateDate) })); }
async function gcpKeys(s) { const r = await maybe(tools(s).gcloud(['iam', 'service-accounts', 'keys', 'list', '--iam-account', `${GCP.account}@${s.gcpProject}.iam.gserviceaccount.com`, '--managed-by', 'user'])); return (r ?? []).map(k => ({ id: k.name.split('/').at(-1), created: k.validAfterTime, ageHours: age(k.validAfterTime) })); }

async function revokeCloud(p, s, cloud) {
  const revoked = [];
  if (cloud === 'aws') for (const k of await awsKeys(s)) { await tools(s).aws(['iam', 'delete-access-key', '--user-name', AWS.user, '--access-key-id', k.id]); revoked.push(k.id); }
  else for (const k of await gcpKeys(s)) { await exec('gcloud', ['iam', 'service-accounts', 'keys', 'delete', k.id, '--iam-account', `${GCP.account}@${s.gcpProject}.iam.gserviceaccount.com`, '--project', s.gcpProject, '--quiet']); revoked.push(k.id); }
  const file = cloud === 'aws' ? p.awsCredentials : p.gcpCredentials;
  const removedFile = existsSync(file); rmSync(file, { force: true });
  return { revoked, removedFile: removedFile ? file : null };
}

async function issueCloud(p, s, cloud) {
  const state = await tofu(p, s, cloud).stateList();
  if (!state.has(cloud === 'aws' ? 'aws_iam_user.service' : 'google_service_account.service'))
    throw new LiveError('NOT_APPLIED', `The ${cloud} stack is not applied here; there is no service identity to issue a credential for.`, 2, { next: `node scripts/live-env.mjs apply --cloud ${cloud} --yes` });
  // At most one live credential per identity: issuing revokes every older one first.
  const { revoked } = await revokeCloud(p, s, cloud);
  if (cloud === 'aws') {
    const r = await tools(s).aws(['iam', 'create-access-key', '--user-name', AWS.user]);
    writePrivate(p.awsCredentials, JSON.stringify({ accessKeyId: r.AccessKey.AccessKeyId, secretAccessKey: r.AccessKey.SecretAccessKey }, null, 2));
    return { issued: r.AccessKey.AccessKeyId, revoked, file: p.awsCredentials, note: 'A new IAM access key can take about 10 s to work everywhere.' };
  }
  mkdirSync(dirname(p.gcpCredentials), { recursive: true, mode: 0o700 });
  await exec('gcloud', ['iam', 'service-accounts', 'keys', 'create', p.gcpCredentials, '--iam-account', `${GCP.account}@${s.gcpProject}.iam.gserviceaccount.com`, '--project', s.gcpProject]);
  chmodSync(p.gcpCredentials, 0o600);
  return { issued: JSON.parse(readFileSync(p.gcpCredentials, 'utf8')).private_key_id, revoked, file: p.gcpCredentials };
}

// --- commands ------------------------------------------------------------------------------------------------------
async function planCloud(p, s, cloud) {
  const t = tofu(p, s, cloud);
  await t.init();
  const adopted = await adopt(cloud === 'aws' ? await findAws(s) : await findGcp(s), await t.stateList(), t.import);
  const file = join(p.data(cloud), 'live.tfplan');
  return { t, file, adopted, changes: await t.plan(file) };
}

const commands = {
  async status(p, s, cloud) {
    const found = cloud === 'aws' ? await findAws(s) : await findGcp(s);
    const inState = await tofu(p, s, cloud).stateList();
    return { where: cloud === 'aws' ? { region: s.awsRegion } : { project: s.gcpProject },
      resources: found.map(f => ({ address: f.address, resource: f.resource, marked: f.owned, inState: inState.has(f.address), ...(f.state ? { keyState: f.state } : {}) })),
      credentials: { live: await (cloud === 'aws' ? awsKeys(s) : gcpKeys(s)), localFile: existsSync(cloud === 'aws' ? p.awsCredentials : p.gcpCredentials) } };
  },
  async plan(p, s, cloud) { const { adopted, changes } = await planCloud(p, s, cloud); return { adopted, changes }; },
  async apply(p, s, cloud, o) {
    const { t, file, adopted, changes } = await planCloud(p, s, cloud);
    if (changes.length && !o.yes) return { adopted, changes, applied: false, next: `Review the changes, then rerun with --yes: node scripts/live-env.mjs apply --cloud ${cloud} --yes` };
    if (changes.length) await t.apply(file);
    return { adopted, changes, applied: changes.length > 0 };
  },
  credentials: (p, s, cloud) => issueCloud(p, s, cloud),
  revoke: (p, s, cloud) => revokeCloud(p, s, cloud),
};

// The next step follows from what status saw: missing or unadopted resources, then credentials, then the run.
export function nextAfterStatus(clouds) {
  const all = Object.values(clouds);
  if (all.some(c => c.resources.length < 6 || c.resources.some(r => !r.inState))) return 'node scripts/live-env.mjs apply (creates what is missing and adopts what exists; review, then --yes)';
  if (all.some(c => c.credentials.live.length)) return 'Credentials are live: npm run test:live, and node scripts/live-env.mjs revoke when done.';
  return 'node scripts/live-env.mjs credentials, then npm run test:live, then node scripts/live-env.mjs revoke';
}

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  const o = { command, yes: false };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--yes') o.yes = true;
    else if (['--cloud', '--aws-region', '--gcp-project'].includes(a) && rest[i + 1] && !rest[i + 1].startsWith('--')) o[a.slice(2).replace(/-(.)/g, (_, c) => c.toUpperCase())] = rest[++i];
    else throw new LiveError('INVALID_INPUT', `Unknown or incomplete argument ${a}.`, 2);
  }
  if (!Object.hasOwn(commands, command ?? '')) throw new LiveError('INVALID_INPUT', `Command must be one of ${Object.keys(commands).join(', ')}.`, 2);
  if (o.cloud && !o.cloud.split(',').every(c => c === 'aws' || c === 'gcp')) throw new LiveError('INVALID_INPUT', '--cloud takes aws, gcp or aws,gcp.', 2, { path: '--cloud' });
  return o;
}

export async function main(argv) {
  const o = parseArgs(argv);
  const dir = liveDir(); const p = paths(dir);
  const saved = existsSync(p.settings) ? JSON.parse(readFileSync(p.settings, 'utf8')) : {};
  // Remembered per clone, so later commands need no flags. The GCP project has no default on purpose.
  const s = { awsRegion: o.awsRegion ?? saved.awsRegion ?? 'us-east-1', gcpProject: o.gcpProject ?? saved.gcpProject ?? process.env.STRONGROOM_LIVE_GCP_PROJECT };
  const clouds = o.cloud ? o.cloud.split(',') : ['aws', ...(s.gcpProject ? ['gcp'] : [])];
  if (clouds.includes('gcp') && !s.gcpProject) throw new LiveError('INVALID_INPUT', 'GCP needs --gcp-project once; it is remembered afterwards.', 2, { path: '--gcp-project' });
  writePrivate(p.settings, JSON.stringify({ awsRegion: s.awsRegion, ...(s.gcpProject ? { gcpProject: s.gcpProject } : {}) }, null, 2));
  const result = { command: o.command, liveDir: dir, clouds: {} };
  if (!clouds.includes('gcp') && !o.cloud) result.skipped = { gcp: 'No GCP project known; pass --gcp-project P once.' };
  for (const cloud of clouds) result.clouds[cloud] = await commands[o.command](p, s, cloud, o);
  if (o.command !== 'status' && o.command !== 'plan') result.liveEnv = await writeLiveEnv(p, s);
  result.next = {
    status: nextAfterStatus(result.clouds),
    plan: 'node scripts/live-env.mjs apply',
    apply: 'node scripts/live-env.mjs credentials',
    credentials: 'npm run test:live, then node scripts/live-env.mjs revoke',
    revoke: 'Done. Issue new credentials before the next live run.',
  }[o.command];
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.umask(0o077);
  main(process.argv.slice(2)).then(r => console.log(JSON.stringify(r, null, 2)), e => {
    const error = e instanceof LiveError ? { code: e.code, message: e.message, ...e.details, ...(e.stderr ? { detail: tail(e.stderr) } : {}) } : { code: 'INTERNAL', message: String(e?.message ?? e) };
    console.error(JSON.stringify({ error }));
    process.exit(e instanceof LiveError ? e.exit : 1);
  });
}
