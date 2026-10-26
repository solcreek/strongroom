// `strongroom setup aws` / `strongroom teardown aws`: provision a KMS key and a least-privilege identity with the
// operator's own AWS CLI session, then write a complete STRONGROOM_CONFIG. Built for agents: a --dry-run plan,
// stable error codes with a `next` command, `created` resources on partial failure, and an exact inverse.
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { SetupError, assertNewDirectory, writeSetup, nextSteps, verifyKey, resourceName, tenantTag, shellQuote, reportPartial } from './setup-common.ts';
export { SetupError } from './setup-common.ts';

// What the operator running setup needs; printed by --dry-run and on AWS_PERMISSION_DENIED.
export const requiredPermissions = {
  user: ['sts:GetCallerIdentity', 'kms:DescribeKey', 'kms:ListResourceTags', 'kms:CreateKey', 'kms:CreateAlias', 'kms:TagResource', 'iam:GetUser', 'iam:ListUserTags', 'iam:CreateUser', 'iam:TagUser', 'iam:PutUserPolicy', 'iam:CreateAccessKey'],
  role: ['sts:GetCallerIdentity', 'kms:DescribeKey', 'kms:ListResourceTags', 'kms:CreateKey', 'kms:CreateAlias', 'kms:TagResource', 'iam:GetRole', 'iam:GetRolePolicy', 'iam:ListRolePolicies', 'iam:PutRolePolicy'],
  teardown: ['iam:ListUserTags', 'iam:GetRolePolicy', 'iam:ListAccessKeys', 'iam:DeleteAccessKey', 'iam:DeleteUserPolicy', 'iam:DeleteUser', 'iam:DeleteRolePolicy', 'kms:DescribeKey', 'kms:ListResourceTags', 'kms:DeleteAlias', 'kms:ScheduleKeyDeletion'],
};
// Same grant as deploy/terraform/aws-ecs-express: the key only, and only with Strongroom's encryption context.
export function kmsPolicy(keyArn: string) {
  return { Version: '2012-10-17', Statement: [{ Sid: 'StrongroomEnvelope', Effect: 'Allow', Action: ['kms:Encrypt', 'kms:Decrypt'], Resource: keyArn,
    Condition: { Null: { 'kms:EncryptionContext:strongroom': 'false' }, 'ForAllValues:StringEquals': { 'kms:EncryptionContextKeys': ['strongroom'] } } }] };
}
// Key order does not matter when comparing a policy IAM returns with the one setup writes.
const canonical = (v: unknown): string => Array.isArray(v) ? `[${v.map(canonical).join(',')}]`
  : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(',')}}` : JSON.stringify(v);
interface Options { name: string; region?: string; profile?: string; role?: string }
type Aws = (args: string[]) => Promise<any>;

function cli(o: Options): Aws {
  return args => new Promise((done, reject) => {
    const full = [...args, '--output', 'json', ...(o.region ? ['--region', o.region] : []), ...(o.profile ? ['--profile', o.profile] : [])];
    execFile('aws', full, { env: { ...process.env, AWS_PAGER: '' }, maxBuffer: 1 << 20, timeout: 60000 }, (error, stdout, stderr) => {
      if (!error) { try { return done(stdout.trim() ? JSON.parse(stdout) : {}); } catch { return reject(awsError(args, 'INVALID_OUTPUT', '')); } }
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return reject(new SetupError('AWS_CLI_MISSING', 'The aws CLI is not installed or not on PATH.', 0, { next: 'Install AWS CLI v2: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html' }));
      reject(awsError(args, stderr.match(/An error occurred \(([A-Za-z0-9.]+)\)/)?.[1] ?? '', stderr));
    });
  });
}
// Only the AWS error code and operation are surfaced; stderr text is never forwarded.
function awsError(args: string[], code: string, stderr: string): SetupError {
  const operation = `${args[0]} ${args[1]}`;
  if (/config profile \(.*\) could not be found/i.test(stderr))
    return new SetupError('AWS_PROFILE_NOT_FOUND', 'The --profile does not exist in the aws CLI configuration.', 0, { path: '--profile', next: 'List profiles with `aws configure list-profiles`.' });
  if (/Unable to locate credentials|SSO session|Token has expired|ExpiredToken|InvalidClientTokenId|UnrecognizedClient|SignatureDoesNotMatch|security token included in the request is invalid/i.test(stderr + code))
    return new SetupError('AWS_NOT_AUTHENTICATED', 'The aws CLI has no valid credentials for this profile.', 401, { operation, awsCode: code || null, next: 'Run `aws sso login` (or `aws configure`), confirm with `aws sts get-caller-identity`, then retry.' });
  if (/AccessDenied|UnauthorizedOperation|NotAuthorized/.test(code))
    return new SetupError('AWS_PERMISSION_DENIED', `The AWS identity may not call ${operation}.`, 403, { operation, awsCode: code, requiredPermissions });
  return new SetupError('AWS_ERROR', `aws ${operation} failed.`, 0, { operation, awsCode: code || null });
}
const notFound = (e: unknown) => e instanceof SetupError && ['NotFoundException', 'NoSuchEntity', 'NoSuchEntityException'].includes(String(e.details.awsCode));
// The aws CLI prints timestamps in an offset of its own choosing (seen live: -06:00 from a UTC+8 machine); report UTC.
const utc = (v: unknown): string => { const t = typeof v === 'string' || typeof v === 'number' ? new Date(typeof v === 'number' ? v * 1000 : v) : null; return t && !Number.isNaN(t.getTime()) ? t.toISOString() : typeof v === 'string' ? v : 'unknown'; };

export async function setupAws(options: Record<string, string>) {
  const tenantId = options['--tenant'], keyRef = options['--key'] ?? 'primary';
  if (!tenantId) throw new SetupError('INVALID_INPUT', 'setup aws requires --tenant TENANT: the one tenant the new deployment serves.', 0, { path: '--tenant' });
  const name = resourceName(options, 'setup aws');
  const o: Options = { name, region: options['--region'], profile: options['--profile'], role: options['--role-name'] };
  const directory = resolve(options['--directory'] ?? `.strongroom/aws-${name}`), dryRun = options['--dry-run'] === 'true', skipVerify = options['--no-verify'] === 'true';
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) throw new SetupError('INVALID_INPUT', '--name must match ^[A-Za-z0-9_-]{1,32}$; it names the KMS alias and IAM user.', 0, { path: '--name' });
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(keyRef)) throw new SetupError('INVALID_INPUT', '--key must match ^[A-Za-z0-9_-]{1,64}$.', 0, { path: '--key' });
  await assertNewDirectory(directory);
  const aws = cli(o);
  if (!o.region) {
    o.region = await new Promise<string>(r => execFile('aws', ['configure', 'get', 'region', ...(o.profile ? ['--profile', o.profile] : [])], (e, out) => r(e ? '' : out.trim())));
    if (!o.region) throw new SetupError('INVALID_INPUT', 'No AWS region: pass --region or set one in the profile.', 0, { path: '--region' });
  }
  const identity = await aws(['sts', 'get-caller-identity']);
  const alias = `alias/${name}`;
  const existing = await aws(['kms', 'describe-key', '--key-id', alias]).catch(e => { if (notFound(e)) return undefined; throw e; });
  if (existing) {
    const m = existing.KeyMetadata;
    if (m.KeyState !== 'Enabled' || m.KeySpec !== 'SYMMETRIC_DEFAULT' || m.KeyUsage !== 'ENCRYPT_DECRYPT')
      throw new SetupError('KEY_UNUSABLE', `${alias} exists but is not an enabled symmetric ENCRYPT_DECRYPT key.`, 0, { keyArn: m.Arn, keyState: m.KeyState, next: 'Choose another --name.' });
    // Reuse only this tenant's own key: an alias that resolves to another tenant's key would share it.
    const tags: { TagKey: string; TagValue: string }[] = (await aws(['kms', 'list-resource-tags', '--key-id', m.Arn])).Tags ?? [];
    if (!tags.some(t => t.TagKey === 'strongroom-tenant' && t.TagValue === tenantTag(tenantId)))
      throw new SetupError('NOT_OWNED', `${alias} exists but is not tagged as this tenant's key; setup never reuses another tenant's key.`, 0, { keyArn: m.Arn, next: 'Choose another --name, or omit it to use the name derived from --tenant.' });
  }
  const teardownCommand = `strongroom teardown aws --tenant ${shellQuote(tenantId)} --name ${name}${o.role ? ` --role-name ${o.role}` : ''} --region ${o.region}${o.profile ? ` --profile ${o.profile}` : ''}`;
  if (o.role) {
    await aws(['iam', 'get-role', '--role-name', o.role]).catch(e => { throw notFound(e) ? new SetupError('INVALID_INPUT', `IAM role ${o.role} does not exist.`, 0, { path: '--role-name' }) : e; });
    // IAM is global while aliases are per region: the same name in another region must not overwrite this grant.
    const current = await aws(['iam', 'get-role-policy', '--role-name', o.role, '--policy-name', `strongroom-kms-${name}`]).catch(e => { if (notFound(e)) return undefined; throw e; });
    if (current && !(existing && canonical(current.PolicyDocument) === canonical(kmsPolicy(existing.KeyMetadata.Arn))))
      throw new SetupError('NOT_OWNED', `Role ${o.role} already has strongroom-kms-${name} for another key; setup never overwrites a grant.`, 0, { next: 'Choose another --name, or remove that deployment first with its own teardown.' });
    // One deployment, one KMS identity: a role that already grants another deployment's key would let one
    // compromised credential reach two tenants.
    const others = ((await aws(['iam', 'list-role-policies', '--role-name', o.role])).PolicyNames ?? []).filter((p: string) => p.startsWith('strongroom-kms') && p !== `strongroom-kms-${name}`);
    if (others.length) throw new SetupError('NOT_OWNED', `Role ${o.role} already serves another Strongroom deployment (${others.join(', ')}); each tenant needs its own role.`, 0, { next: 'Create a role for this tenant\'s deployment and pass it with --role-name.' });
  } else if (await aws(['iam', 'get-user', '--user-name', name]).then(() => true, e => { if (notFound(e)) return false; throw e; })) {
    const tags = (await aws(['iam', 'list-user-tags', '--user-name', name])).Tags ?? [];
    if (!tags.some((t: { Key: string; Value: string }) => t.Key === 'strongroom-tenant' && t.Value === tenantTag(tenantId)))
      throw new SetupError('NOT_OWNED', `IAM user ${name} already exists and is not this tenant's.`, 0, { next: 'Choose another --name, or omit it to use the name derived from --tenant.' });
    throw new SetupError('RESOURCE_EXISTS', `IAM user ${name} already exists for this tenant.`, 0, { next: `Remove it first with: ${teardownCommand}` });
  }
  const plan = [
    existing ? { action: 'reuse-key', keyArn: existing.KeyMetadata.Arn, alias } : { action: 'create-key', alias, spec: 'SYMMETRIC_DEFAULT', usage: 'ENCRYPT_DECRYPT' },
    o.role ? { action: 'put-role-policy', role: o.role, policy: `strongroom-kms-${name}` } : { action: 'create-iam-user', user: name, policy: 'strongroom-kms', accessKey: 'written to config.json only' },
    { action: 'write-files', directory, files: ['config.json', 'token'] },
    o.role ? { action: 'verify', skipped: 'role credentials are only available inside the workload' } : { action: 'verify', detail: 'real Encrypt/Decrypt with the new credentials' },
  ];
  const base = { name, directory, account: identity.Account, caller: identity.Arn, region: o.region, plan, requiredPermissions: o.role ? requiredPermissions.role : requiredPermissions.user };
  if (dryRun) return { dryRun: true, ...base, next: `Run the same command without --dry-run to apply.` };

  const created: Record<string, string>[] = [];
  const cleanup = `${teardownCommand}${existing ? '' : ' --delete-key'}`;
  try {
    const tags = ['--tags', 'TagKey=app,TagValue=strongroom', `TagKey=strongroom-name,TagValue=${name}`, `TagKey=strongroom-tenant,TagValue=${tenantTag(tenantId)}`];
    let keyArn: string = existing?.KeyMetadata.Arn;
    if (!keyArn) {
      keyArn = (await aws(['kms', 'create-key', '--description', `Strongroom envelope key (${name})`, '--key-spec', 'SYMMETRIC_DEFAULT', '--key-usage', 'ENCRYPT_DECRYPT', ...tags])).KeyMetadata.Arn;
      created.push({ kmsKey: keyArn });
      await aws(['kms', 'create-alias', '--alias-name', alias, '--target-key-id', keyArn]); created.push({ alias });
    }
    const policy = JSON.stringify(kmsPolicy(keyArn));
    let key: Record<string, unknown>;
    if (o.role) {
      // The preflight refused a role serving another deployment, but IAM has no compare-and-set: two setups
      // racing on one role could both pass it. Re-check after writing, and withdraw this grant if another
      // deployment's appeared, so a race fails closed (both may fail) instead of leaving a two-tenant role.
      await aws(['iam', 'put-role-policy', '--role-name', o.role, '--policy-name', `strongroom-kms-${name}`, '--policy-document', policy]); created.push({ rolePolicy: `${o.role}/strongroom-kms-${name}` });
      const after = ((await aws(['iam', 'list-role-policies', '--role-name', o.role])).PolicyNames ?? []).filter((p: string) => p.startsWith('strongroom-kms') && p !== `strongroom-kms-${name}`);
      if (after.length) {
        await aws(['iam', 'delete-role-policy', '--role-name', o.role, '--policy-name', `strongroom-kms-${name}`]); created.pop();
        throw new SetupError('NOT_OWNED', `Role ${o.role} gained another Strongroom deployment's grant (${after.join(', ')}) during setup; this grant was withdrawn.`, 0, { next: 'Use a role dedicated to this tenant; never run setup for two tenants on one role.' });
      }
      key = { provider: 'aws', region: o.region, keyId: keyArn, containerCredentials: true };
    } else {
      await aws(['iam', 'create-user', '--user-name', name, '--tags', 'Key=app,Value=strongroom', `Key=strongroom-tenant,Value=${tenantTag(tenantId)}`]); created.push({ iamUser: name });
      await aws(['iam', 'put-user-policy', '--user-name', name, '--policy-name', 'strongroom-kms', '--policy-document', policy]);
      const access = (await aws(['iam', 'create-access-key', '--user-name', name])).AccessKey;
      created.push({ accessKeyId: access.AccessKeyId });
      key = { provider: 'aws', region: o.region, keyId: keyArn, accessKeyId: access.AccessKeyId, secretAccessKey: access.SecretAccessKey };
    }
    const { files, principal } = await writeSetup(directory, keyRef, key, tenantId);
    const verified = o.role ? { ok: false, skipped: 'role credentials exist only inside ECS/EKS; run strongroom probe after deploying' }
      : skipVerify ? { ok: false, skipped: '--no-verify' } : await verifyKey(key, 60000);
    return { ...base, plan: undefined, keyArn, alias, identity: o.role ? { type: 'iam-role', role: o.role } : { type: 'iam-user', user: name, accessKeyId: (key as { accessKeyId: string }).accessKeyId },
      tenantId, files, principal, verified, next: nextSteps(files, keyRef, tenantId), teardown: cleanup };
  } catch (e) {
    const error = e instanceof SetupError ? e : new SetupError('SETUP_FAILED', 'Setup failed after creating resources.', 0);
    error.details = { ...error.details, created, cleanup: created.length ? cleanup : undefined };
    throw error;
  }
}
export async function teardownAws(options: Record<string, string>) {
  // Always tenant-scoped: a name alone cannot prove which tenant a resource belongs to.
  const tenant = options['--tenant'];
  if (!tenant) throw new SetupError('INVALID_INPUT', 'teardown aws requires --tenant TENANT; it removes only resources setup marked for that tenant.', 0, { path: '--tenant' });
  const name = resourceName(options, 'teardown aws'), role = options['--role-name'];
  const o: Options = { name, region: options['--region'], profile: options['--profile'], role };
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) throw new SetupError('INVALID_INPUT', '--name must match ^[A-Za-z0-9_-]{1,32}$.', 0, { path: '--name' });
  const aws = cli(o), removed: Record<string, string>[] = [], absent: string[] = [];
  const gone = (what: string) => (e: unknown) => { if (notFound(e)) { absent.push(what); return undefined; } throw e; };
  // Remove only what setup marked for this tenant. Every check runs before the first change, so a refusal
  // leaves everything as it was.
  const deleteKey = options['--delete-key'] === 'true', policyName = `strongroom-kms-${name}`;
  const owned = (tags: { key: string; value: string }[], what: string) => {
    if (!tags.some(t => t.key === 'strongroom-tenant' && t.value === tenantTag(tenant)))
      throw new SetupError('NOT_OWNED', `${what} is not marked as this tenant's; teardown changed nothing.`, 0, { resource: what, next: 'Check --tenant and --name.' });
  };
  // Look a key up in its own region (from its ARN or the alias's region), so a wrong --region cannot turn
  // "not in this region" into "gone".
  const keyTags = async (keyId: string) => {
    const region = keyId.startsWith('arn:') ? keyId.split(':')[3] : o.region;
    return ((await cli({ ...o, region })(['kms', 'list-resource-tags', '--key-id', keyId])).Tags ?? []).map((t: { TagKey: string; TagValue: string }) => ({ key: t.TagKey, value: t.TagValue }));
  };
  // aws CLI JSON, read in the check phase and used in the change phase.
  let userTags: any, rolePolicy: any, key: any;
  if (role) {
    // The role is the operator's; teardown may remove only the grant setup wrote on this tenant's key. Fail
    // closed: the policy must have setup's exact shape (one statement on one key ARN), and that key must carry
    // the marker or be gone. Anything else is refused rather than guessed at.
    rolePolicy = await aws(['iam', 'get-role-policy', '--role-name', role, '--policy-name', policyName]).catch(gone('rolePolicy'));
    if (rolePolicy) {
      const what = `${role}/${policyName}`, statements = rolePolicy.PolicyDocument?.Statement;
      const granted = Array.isArray(statements) && statements.length === 1 ? statements[0].Resource : undefined;
      if (typeof granted !== 'string' || !/^arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:\d{12}:key\/[a-zA-Z0-9-]+$/.test(granted) || canonical(rolePolicy.PolicyDocument) !== canonical(kmsPolicy(granted)))
        throw new SetupError('NOT_OWNED', `${what} is not the policy setup writes; teardown changed nothing.`, 0, { resource: what, next: `Inspect it with aws iam get-role-policy --role-name ${role} --policy-name ${policyName}.` });
      const tags = await keyTags(granted).catch(e => { if (notFound(e)) return undefined; throw e; });
      if (tags) owned(tags, `KMS key ${granted} granted by ${what}`); // a key that no longer exists cannot be anyone's
    }
  } else {
    userTags = await aws(['iam', 'list-user-tags', '--user-name', name]).catch(gone('iamUser'));
    if (userTags) owned((userTags.Tags ?? []).map((t: { Key: string; Value: string }) => ({ key: t.Key, value: t.Value })), `IAM user ${name}`);
  }
  if (deleteKey) {
    key = await aws(['kms', 'describe-key', '--key-id', `alias/${name}`]).catch(gone('kmsKey'));
    if (key) owned(await keyTags(key.KeyMetadata.Arn), `KMS key alias/${name}`);
  }
  let scheduled = false;
  await reportPartial(removed, async () => {
    if (rolePolicy) { await aws(['iam', 'delete-role-policy', '--role-name', role!, '--policy-name', policyName]); removed.push({ rolePolicy: `${role}/${policyName}` }); }
    if (userTags) {
      const keys = await aws(['iam', 'list-access-keys', '--user-name', name]);
      for (const k of keys.AccessKeyMetadata ?? []) { await aws(['iam', 'delete-access-key', '--user-name', name, '--access-key-id', k.AccessKeyId]); removed.push({ accessKeyId: k.AccessKeyId }); }
      await aws(['iam', 'delete-user-policy', '--user-name', name, '--policy-name', 'strongroom-kms']).catch(gone('userPolicy'));
      await aws(['iam', 'delete-user', '--user-name', name]); removed.push({ iamUser: name });
    }
    // Deleting the key makes every envelope wrapped by it unrecoverable after the waiting period; it is opt-in.
    // Schedule first and remove the alias last: if scheduling fails, the alias still leads a rerun to the key.
    if (deleteKey && key) {
      const m = key.KeyMetadata;
      if (m.KeyState === 'PendingDeletion') removed.push({ kmsKeyAlreadyScheduledForDeletion: m.Arn, deletionDate: utc(m.DeletionDate) });
      else {
        const r = await aws(['kms', 'schedule-key-deletion', '--key-id', m.Arn, '--pending-window-in-days', '7']);
        removed.push({ kmsKeyScheduledForDeletion: m.Arn, deletionDate: utc(r.DeletionDate) });
      }
      scheduled = true;
      await aws(['kms', 'delete-alias', '--alias-name', `alias/${name}`]); removed.push({ alias: `alias/${name}` });
    }
  });
  // Report the key's state, not what was asked: true kept, false scheduled for deletion (now or earlier),
  // null not found. "Not found here" must never read as a completed crypto-shred.
  return { removed, absent, keptKey: !deleteKey ? true : scheduled ? false : null, keyScheduledForDeletion: scheduled,
    note: scheduled ? 'Decrypts start failing once AWS KMS applies the pending-deletion state: observed within seconds, but allow a short propagation delay before treating them as refused. The key is deleted at the deletionDate in removed, whatever waiting period it was scheduled with. Until then, aws kms cancel-key-deletion undoes it.'
      : deleteKey ? `No key found at alias/${name} in ${o.region ?? 'the profile region'}, so nothing was scheduled now. An earlier teardown may already have scheduled the key and removed its alias, or the key is in another --region or under another --name. Find it by its strongroom-tenant tag (${tenantTag(tenant)}) with aws kms list-keys and aws kms list-resource-tags.`
      : 'The KMS key was kept; pass --delete-key to schedule its deletion.' };
}
