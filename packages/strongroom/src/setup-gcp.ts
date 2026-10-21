// `strongroom setup gcp` / `strongroom teardown gcp`: provision a Cloud KMS key and a least-privilege service account with
// the operator's own gcloud session, then write a complete STRONGROOM_CONFIG. Same agent contract as setup aws.
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { SetupError, assertNewDirectory, writeSetup, nextSteps, verifyKey, resourceName } from './setup-common.ts';

const role = 'roles/cloudkms.cryptoKeyEncrypterDecrypter';
// IAM permissions the operator needs; roles/cloudkms.admin plus roles/iam.serviceAccountAdmin and serviceAccountKeyAdmin cover them.
export const requiredGcpPermissions = {
  serviceAccountKey: ['resourcemanager.projects.get', 'serviceusage.services.list', 'serviceusage.services.enable', 'cloudkms.keyRings.get', 'cloudkms.keyRings.create', 'cloudkms.cryptoKeys.get', 'cloudkms.cryptoKeys.create', 'cloudkms.cryptoKeys.getIamPolicy', 'cloudkms.cryptoKeys.setIamPolicy', 'iam.serviceAccounts.list', 'iam.serviceAccounts.create', 'iam.serviceAccountKeys.create'],
  workload: ['resourcemanager.projects.get', 'serviceusage.services.list', 'serviceusage.services.enable', 'cloudkms.keyRings.get', 'cloudkms.keyRings.create', 'cloudkms.cryptoKeys.get', 'cloudkms.cryptoKeys.create', 'cloudkms.cryptoKeys.getIamPolicy', 'cloudkms.cryptoKeys.setIamPolicy', 'iam.serviceAccounts.list'],
  teardown: ['cloudkms.cryptoKeys.getIamPolicy', 'cloudkms.cryptoKeys.setIamPolicy', 'iam.serviceAccounts.list', 'iam.serviceAccounts.delete', 'cloudkms.cryptoKeyVersions.list', 'cloudkms.cryptoKeyVersions.destroy'],
};
type Gcloud = (args: string[]) => Promise<any>;

function cli(project?: string): Gcloud {
  return args => new Promise((done, reject) => {
    const full = [...args, '--format=json', '--quiet', ...(project ? ['--project', project] : [])];
    execFile('gcloud', full, { env: { ...process.env, CLOUDSDK_CORE_DISABLE_PROMPTS: '1' }, maxBuffer: 1 << 20, timeout: 120000 }, (error, stdout, stderr) => {
      if (!error) { try { return done(stdout.trim() ? JSON.parse(stdout) : {}); } catch { return reject(gcloudError(args, 'INVALID_OUTPUT', '')); } }
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return reject(new SetupError('GCP_CLI_MISSING', 'The gcloud CLI is not installed or not on PATH.', 0, { next: 'Install the Google Cloud CLI: https://cloud.google.com/sdk/docs/install' }));
      reject(gcloudError(args, stderr.match(/\(gcloud\.[\w.-]+\) ([A-Z_]+):/)?.[1] ?? '', stderr));
    });
  });
}
// Only gcloud's canonical status code and the command are surfaced; stderr text is never forwarded.
function gcloudError(args: string[], code: string, stderr: string): SetupError {
  const operation = args.slice(0, 3).join(' ');
  if (/Reauthentication failed|do not currently have an active account|problem refreshing your current auth tokens|gcloud auth login|UNAUTHENTICATED/.test(stderr + code))
    return new SetupError('GCP_NOT_AUTHENTICATED', 'The gcloud CLI has no valid credentials.', 401, { operation, gcpCode: code || null, next: 'Run `gcloud auth login`, confirm with `gcloud auth print-access-token`, then retry.' });
  if (/iam\.disableServiceAccountKeyCreation|iam\.managed\.disableServiceAccountKeyCreation/.test(stderr))
    return new SetupError('GCP_ORG_POLICY', 'An organization policy forbids creating service account keys.', 403, { operation, next: 'Use --service-account with a Cloud Run or GKE workload identity (metadataServer), or ask an organization admin for a policy exception.' });
  if (code === 'SERVICE_DISABLED' || /has not been used in project|is disabled/.test(stderr))
    return new SetupError('GCP_API_DISABLED', 'A required Google Cloud API is disabled in the project.', 0, { operation, next: 'Run `gcloud services enable cloudkms.googleapis.com --project PROJECT` (setup does this when it has serviceusage permission).' });
  if (code === 'PERMISSION_DENIED')
    return new SetupError('GCP_PERMISSION_DENIED', `The gcloud identity may not run ${operation}.`, 403, { operation, gcpCode: code, requiredPermissions: requiredGcpPermissions });
  return new SetupError('GCP_ERROR', `gcloud ${operation} failed.`, 0, { operation, gcpCode: code || null });
}
const notFound = (e: unknown) => e instanceof SetupError && e.details.gcpCode === 'NOT_FOUND';
// Observed 2026-10-13: binding a service account seconds after creating it fails with INVALID_ARGUMENT until IAM
// propagates. Retry only those propagation-shaped codes, briefly.
async function propagated<T>(run: () => Promise<T>, timeoutMs = Number(process.env.STRONGROOM_SETUP_PROPAGATION_MS ?? 90000)): Promise<T> {
  const started = Date.now();
  for (;;) {
    try { return await run(); }
    catch (e) {
      if (!(e instanceof SetupError && ['INVALID_ARGUMENT', 'NOT_FOUND'].includes(String(e.details.gcpCode))) || Date.now() - started > timeoutMs) throw e;
      await new Promise(r => setTimeout(r, propagationDelayMs));
    }
  }
}
const propagationDelayMs = Number(process.env.STRONGROOM_SETUP_RETRY_MS ?? 3000);
// describe/delete on a recently deleted account answer PERMISSION_DENIED, not NOT_FOUND (observed 2026-10-13); list is exact.
const accountExists = async (gcloud: Gcloud, email: string) => (await gcloud(['iam', 'service-accounts', 'list', `--filter=email=${email}`])).length > 0;
const raw = (args: string[]) => new Promise<string>(r => execFile('gcloud', args, (e, out) => r(e ? '' : out.trim())));

function inputs(options: Record<string, string>, command: string) {
  const name = resourceName(options, command);
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(name)) throw new SetupError('INVALID_INPUT', '--name must be 6-30 lowercase letters, digits or hyphens, starting with a letter; it names the key ring and the service account.', 0, { path: '--name' });
  const keyRing = options['--keyring'] ?? name, keyRef = options['--key'] ?? 'primary', location = options['--location'] ?? 'global';
  if (!/^[A-Za-z0-9_-]{1,63}$/.test(keyRing)) throw new SetupError('INVALID_INPUT', '--keyring must match ^[A-Za-z0-9_-]{1,63}$.', 0, { path: '--keyring' });
  if (!/^[A-Za-z0-9_-]{1,63}$/.test(keyRef)) throw new SetupError('INVALID_INPUT', '--key must match ^[A-Za-z0-9_-]{1,63}$; it is both the CryptoKey name and the key reference.', 0, { path: '--key' });
  if (!/^[a-z0-9-]+$/.test(location)) throw new SetupError('INVALID_INPUT', '--location must be a Cloud KMS location such as global or us-central1.', 0, { path: '--location' });
  const workload = options['--service-account'];
  if (workload !== undefined && !/^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$/.test(workload)) throw new SetupError('INVALID_INPUT', '--service-account must be a service account email.', 0, { path: '--service-account' });
  return { name, keyRing, keyRef, location, workload };
}
async function project(options: Record<string, string>) {
  const p = options['--project'] ?? await raw(['config', 'get-value', 'project']);
  if (!p || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(p)) throw new SetupError('INVALID_INPUT', 'No valid Google Cloud project: pass --project or run `gcloud config set project PROJECT`.', 0, { path: '--project' });
  return p;
}

export async function setupGcp(options: Record<string, string>) {
  const tenantId = options['--tenant'], protection = options['--protection-level'] ?? 'software';
  if (!tenantId) throw new SetupError('INVALID_INPUT', 'setup gcp requires --tenant TENANT: the one tenant the new deployment serves.', 0, { path: '--tenant' });
  const { name, keyRing, keyRef, location, workload } = inputs(options, 'setup gcp');
  if (!['software', 'hsm'].includes(protection)) throw new SetupError('INVALID_INPUT', '--protection-level must be software or hsm.', 0, { path: '--protection-level' });
  // Settable only when the key is created, so choose it explicitly: how long a destroyed key stays restorable.
  // 7 days matches the shortest AWS deletion window; Cloud KMS allows 24 hours to 120 days.
  const destroyAfter = options['--destroy-scheduled-duration'] ?? '7d';
  const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 }, match = /^(\d+)([smhd])$/.exec(destroyAfter);
  const seconds = match ? Number(match[1]) * units[match[2]] : NaN;
  if (!(seconds >= 86400 && seconds <= 120 * 86400)) throw new SetupError('INVALID_INPUT', '--destroy-scheduled-duration must be INTEGER[s|m|h|d] between 24h and 120d, e.g. 7d.', 0, { path: '--destroy-scheduled-duration' });
  const directory = resolve(options['--directory'] ?? `.strongroom/gcp-${name}`), dryRun = options['--dry-run'] === 'true', skipVerify = options['--no-verify'] === 'true';
  await assertNewDirectory(directory);
  const p = await project(options), gcloud = cli(p);
  const loc = ['--location', location], ring = [...loc, '--keyring', keyRing];
  const account = await raw(['config', 'get-value', 'account']);
  await gcloud(['projects', 'describe', p]);
  const apiEnabled = (await gcloud(['services', 'list', '--enabled', '--filter=config.name=cloudkms.googleapis.com'])).length > 0;
  const ringExists = apiEnabled && await gcloud(['kms', 'keyrings', 'describe', keyRing, ...loc]).then(() => true, e => { if (notFound(e)) return false; throw e; });
  const existing = ringExists ? await gcloud(['kms', 'keys', 'describe', keyRef, ...ring]).catch(e => { if (notFound(e)) return undefined; throw e; }) : undefined;
  if (existing && (existing.purpose !== 'ENCRYPT_DECRYPT' || existing.primary?.state !== 'ENABLED'))
    throw new SetupError('KEY_UNUSABLE', `${existing.name} exists but is not an ENCRYPT_DECRYPT key with an enabled primary version.`, 0, { keyId: existing.name, next: 'Choose another --key.' });
  const email = workload ?? `${name}@${p}.iam.gserviceaccount.com`;
  // A workload account may live in another project (a central key project); then the IAM binding itself validates it.
  const saExists = !workload || email.endsWith(`@${p}.iam.gserviceaccount.com`) ? await accountExists(gcloud, email) : true;
  if (workload && !saExists) throw new SetupError('INVALID_INPUT', `Service account ${workload} does not exist.`, 0, { path: '--service-account' });
  if (!workload && saExists) throw new SetupError('RESOURCE_EXISTS', `Service account ${email} already exists.`, 0, { next: `Choose another --name, or remove it with: strongroom teardown gcp --name ${name} --project ${p}` });
  const keyId = `projects/${p}/locations/${location}/keyRings/${keyRing}/cryptoKeys/${keyRef}`;
  const plan = [
    ...(apiEnabled ? [] : [{ action: 'enable-api', api: 'cloudkms.googleapis.com' }]),
    ringExists ? { action: 'reuse-keyring', keyRing } : { action: 'create-keyring', keyRing, location, note: 'Key rings cannot be deleted.' },
    existing ? { action: 'reuse-key', keyId, note: 'Its destroy-scheduled duration was fixed when it was created.' }
      : { action: 'create-key', keyId, purpose: 'ENCRYPT_DECRYPT', protectionLevel: protection.toUpperCase(), destroyScheduledDuration: destroyAfter },
    workload ? { action: 'grant', member: `serviceAccount:${email}`, role, on: keyId } : { action: 'create-service-account', email },
    ...(workload ? [] : [{ action: 'grant', member: `serviceAccount:${email}`, role, on: keyId }, { action: 'create-service-account-key', note: 'written to config.json only' }]),
    { action: 'write-files', directory, files: ['config.json', 'token'] },
    workload ? { action: 'verify', skipped: 'workload credentials exist only on Cloud Run/GKE' } : { action: 'verify', detail: 'real encrypt/decrypt with the new key file' },
  ];
  const base = { project: p, caller: account || null, location, plan, requiredPermissions: workload ? requiredGcpPermissions.workload : requiredGcpPermissions.serviceAccountKey };
  if (dryRun) return { dryRun: true, ...base, next: 'Run the same command without --dry-run to apply.' };

  const created: Record<string, string>[] = [];
  const cleanup = `strongroom teardown gcp --name ${name} --project ${p} --location ${location} --keyring ${keyRing} --key ${keyRef}${workload ? ` --service-account ${workload}` : ''}${existing ? '' : ' --delete-key'}`;
  try {
    if (!apiEnabled) { await gcloud(['services', 'enable', 'cloudkms.googleapis.com']); created.push({ enabledApi: 'cloudkms.googleapis.com' }); }
    if (!ringExists) { await gcloud(['kms', 'keyrings', 'create', keyRing, ...loc]); created.push({ keyRing }); }
    if (!existing) { await gcloud(['kms', 'keys', 'create', keyRef, ...ring, '--purpose', 'encryption', '--protection-level', protection, '--destroy-scheduled-duration', destroyAfter, '--labels', 'app=strongroom']); created.push({ cryptoKey: keyId }); }
    if (!workload) { await gcloud(['iam', 'service-accounts', 'create', name, '--display-name', `Strongroom (${name})`]); created.push({ serviceAccount: email }); }
    await propagated(() => gcloud(['kms', 'keys', 'add-iam-policy-binding', keyRef, ...ring, '--member', `serviceAccount:${email}`, '--role', role])); created.push({ keyBinding: email });
    let key: Record<string, unknown> = { provider: 'gcp', keyId, metadataServer: true };
    if (!workload) {
      // gcloud writes the key file itself; keep it in a private temporary directory only long enough to read it.
      const scratch = await mkdtemp(join(tmpdir(), 'strongroom-gcp-'));
      try {
        await propagated(() => gcloud(['iam', 'service-accounts', 'keys', 'create', join(scratch, 'key.json'), '--iam-account', email]));
        const file = JSON.parse(await readFile(join(scratch, 'key.json'), 'utf8'));
        created.push({ serviceAccountKey: file.private_key_id });
        key = { provider: 'gcp', keyId, serviceAccount: { clientEmail: file.client_email, privateKey: file.private_key } };
      } finally { await rm(scratch, { recursive: true, force: true }); }
    }
    const { files, principal } = await writeSetup(directory, keyRef, key, tenantId);
    const verified = workload ? { ok: false, skipped: 'workload credentials exist only on Cloud Run/GKE; run strongroom probe after deploying' }
      : skipVerify ? { ok: false, skipped: '--no-verify' } : await verifyKey(key, 180000);
    return { ...base, plan: undefined, keyId, identity: workload ? { type: 'workload', serviceAccount: email } : { type: 'service-account-key', serviceAccount: email },
      tenantId, files, principal, verified, next: nextSteps(files, keyRef, tenantId), teardown: cleanup };
  } catch (e) {
    const error = e instanceof SetupError ? e : new SetupError('SETUP_FAILED', 'Setup failed after creating resources.', 0);
    error.details = { ...error.details, created, cleanup: created.length ? cleanup : undefined };
    throw error;
  }
}

export async function teardownGcp(options: Record<string, string>) {
  const { name, keyRing, keyRef, location, workload } = inputs(options, 'teardown gcp');
  const p = await project(options), gcloud = cli(p), ring = ['--location', location, '--keyring', keyRing];
  const email = workload ?? `${name}@${p}.iam.gserviceaccount.com`, removed: Record<string, string>[] = [], absent: string[] = [];
  const binding = await gcloud(['kms', 'keys', 'remove-iam-policy-binding', keyRef, ...ring, '--member', `serviceAccount:${email}`, '--role', role])
    .then(() => true, e => { if (notFound(e) || (e instanceof SetupError && e.code === 'GCP_ERROR' && !e.details.gcpCode)) return false; throw e; });
  if (binding) removed.push({ keyBinding: email }); else absent.push('keyBinding');
  if (!workload) {
    if (await accountExists(gcloud, email)) {
      await gcloud(['iam', 'service-accounts', 'delete', email]); removed.push({ serviceAccount: email });
    } else absent.push('serviceAccount');
  }
  // Destroying every version makes all envelopes wrapped by the key unrecoverable. (A destroyed key could then be
  // deleted, but a deleted CryptoKey name can never be reused, so teardown keeps the key and its name.)
  if (options['--delete-key'] === 'true') {
    const versions = await gcloud(['kms', 'keys', 'versions', 'list', '--key', keyRef, ...ring, '--filter=state=ENABLED OR state=DISABLED']).catch(e => { if (notFound(e)) return undefined; throw e; });
    if (!versions) absent.push('cryptoKey');
    for (const v of versions ?? []) {
      const r = await gcloud(['kms', 'keys', 'versions', 'destroy', v.name.split('/').pop(), '--key', keyRef, ...ring]);
      removed.push({ cryptoKeyVersionScheduledForDestruction: v.name, destroyTime: r.destroyTime });
    }
  }
  return { removed, absent, keptKey: options['--delete-key'] !== 'true',
    note: options['--delete-key'] === 'true' ? 'Decrypts fail now. Each version becomes unrecoverable at its destroyTime (the key\'s destroy-scheduled duration, 7 days when setup created it); until then gcloud kms keys versions restore undoes it. Key material can take up to 45 more days to leave Google\'s backups.' : 'The CryptoKey was kept; pass --delete-key to schedule destruction of its versions.' };
}
