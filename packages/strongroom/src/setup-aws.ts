// `strongroom setup aws` / `strongroom teardown aws`: provision a KMS key and a least-privilege identity with the
// operator's own AWS CLI session, then write a complete STRONGROOM_CONFIG. Built for agents: a --dry-run plan,
// stable error codes with a `next` command, `created` resources on partial failure, and an exact inverse.
import { execFile } from 'node:child_process';
import { mkdir, writeFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { StrongroomError } from './client.ts';
import { parseConfig } from '../../../service/config.ts';
import { createProvider } from '../../../service/providers.ts';

export class SetupError extends StrongroomError {
  details: Record<string, unknown>;
  constructor(code: string, message: string, status: number, details: Record<string, unknown> = {}) { super(code, message, status); this.details = details; }
  toJSON() { return { ...super.toJSON(), ...this.details }; }
}
// What the operator running setup needs; printed by --dry-run and on AWS_PERMISSION_DENIED.
export const requiredPermissions = {
  user: ['sts:GetCallerIdentity', 'kms:DescribeKey', 'kms:CreateKey', 'kms:CreateAlias', 'kms:TagResource', 'iam:GetUser', 'iam:CreateUser', 'iam:TagUser', 'iam:PutUserPolicy', 'iam:CreateAccessKey'],
  role: ['sts:GetCallerIdentity', 'kms:DescribeKey', 'kms:CreateKey', 'kms:CreateAlias', 'kms:TagResource', 'iam:GetRole', 'iam:PutRolePolicy'],
  teardown: ['iam:ListAccessKeys', 'iam:DeleteAccessKey', 'iam:DeleteUserPolicy', 'iam:DeleteUser', 'iam:DeleteRolePolicy', 'kms:DescribeKey', 'kms:DeleteAlias', 'kms:ScheduleKeyDeletion'],
};
// Same grant as deploy/terraform/aws-ecs-express: the key only, and only with Strongroom's encryption context.
export function kmsPolicy(keyArn: string) {
  return { Version: '2012-10-17', Statement: [{ Sid: 'StrongroomEnvelope', Effect: 'Allow', Action: ['kms:Encrypt', 'kms:Decrypt'], Resource: keyArn,
    Condition: { Null: { 'kms:EncryptionContext:strongroom': 'false' }, 'ForAllValues:StringEquals': { 'kms:EncryptionContextKeys': ['strongroom'] } } }] };
}
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

export async function setupAws(options: Record<string, string>) {
  const name = options['--name'] ?? 'strongroom', tenantId = options['--tenant'], keyRef = options['--key'] ?? 'primary';
  const o: Options = { name, region: options['--region'], profile: options['--profile'], role: options['--role-name'] };
  const directory = resolve(options['--directory'] ?? `.strongroom/aws-${name}`), dryRun = options['--dry-run'] === 'true', skipVerify = options['--no-verify'] === 'true';
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) throw new SetupError('INVALID_INPUT', '--name must match ^[A-Za-z0-9_-]{1,32}$; it names the KMS alias and IAM user.', 0, { path: '--name' });
  if (!tenantId) throw new SetupError('INVALID_INPUT', 'setup aws requires --tenant TENANT for the first principal.', 0, { path: '--tenant' });
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(keyRef)) throw new SetupError('INVALID_INPUT', '--key must match ^[A-Za-z0-9_-]{1,64}$.', 0, { path: '--key' });
  if (await stat(directory).then(() => true, () => false)) throw new SetupError('INVALID_INPUT', 'The output directory already exists; secrets are never overwritten.', 0, { path: '--directory', next: 'Choose a new --directory.' });
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
  }
  if (o.role) await aws(['iam', 'get-role', '--role-name', o.role]).catch(e => { throw notFound(e) ? new SetupError('INVALID_INPUT', `IAM role ${o.role} does not exist.`, 0, { path: '--role-name' }) : e; });
  else if (await aws(['iam', 'get-user', '--user-name', name]).then(() => true, e => { if (notFound(e)) return false; throw e; }))
    throw new SetupError('RESOURCE_EXISTS', `IAM user ${name} already exists.`, 0, { next: `Choose another --name, or remove it with: strongroom teardown aws --name ${name}` });
  const plan = [
    existing ? { action: 'reuse-key', keyArn: existing.KeyMetadata.Arn, alias } : { action: 'create-key', alias, spec: 'SYMMETRIC_DEFAULT', usage: 'ENCRYPT_DECRYPT' },
    o.role ? { action: 'put-role-policy', role: o.role, policy: 'strongroom-kms' } : { action: 'create-iam-user', user: name, policy: 'strongroom-kms', accessKey: 'written to config.json only' },
    { action: 'write-files', directory, files: ['config.json', 'token'] },
    o.role ? { action: 'verify', skipped: 'role credentials are only available inside the workload' } : { action: 'verify', detail: 'real Encrypt/Decrypt with the new credentials' },
  ];
  const base = { account: identity.Account, caller: identity.Arn, region: o.region, plan, requiredPermissions: o.role ? requiredPermissions.role : requiredPermissions.user };
  if (dryRun) return { dryRun: true, ...base, next: `Run the same command without --dry-run to apply.` };

  const created: Record<string, string>[] = [];
  const cleanup = `strongroom teardown aws --name ${name}${o.role ? ` --role-name ${o.role}` : ''}${existing ? '' : ' --delete-key'} --region ${o.region}${o.profile ? ` --profile ${o.profile}` : ''}`;
  try {
    const tags = ['--tags', 'TagKey=app,TagValue=strongroom', `TagKey=strongroom-name,TagValue=${name}`];
    let keyArn: string = existing?.KeyMetadata.Arn;
    if (!keyArn) {
      keyArn = (await aws(['kms', 'create-key', '--description', `Strongroom envelope key (${name})`, '--key-spec', 'SYMMETRIC_DEFAULT', '--key-usage', 'ENCRYPT_DECRYPT', ...tags])).KeyMetadata.Arn;
      created.push({ kmsKey: keyArn });
      await aws(['kms', 'create-alias', '--alias-name', alias, '--target-key-id', keyArn]); created.push({ alias });
    }
    const policy = JSON.stringify(kmsPolicy(keyArn));
    let key: Record<string, unknown>;
    if (o.role) {
      await aws(['iam', 'put-role-policy', '--role-name', o.role, '--policy-name', 'strongroom-kms', '--policy-document', policy]); created.push({ rolePolicy: `${o.role}/strongroom-kms` });
      key = { provider: 'aws', region: o.region, keyId: keyArn, containerCredentials: true };
    } else {
      await aws(['iam', 'create-user', '--user-name', name, '--tags', 'Key=app,Value=strongroom']); created.push({ iamUser: name });
      await aws(['iam', 'put-user-policy', '--user-name', name, '--policy-name', 'strongroom-kms', '--policy-document', policy]);
      const access = (await aws(['iam', 'create-access-key', '--user-name', name])).AccessKey;
      created.push({ accessKeyId: access.AccessKeyId });
      key = { provider: 'aws', region: o.region, keyId: keyArn, accessKeyId: access.AccessKeyId, secretAccessKey: access.SecretAccessKey };
    }
    const token = randomBytes(32).toString('base64url'), tokenSha256 = createHash('sha256').update(token).digest('hex');
    const config = { keys: { [keyRef]: key }, principals: [{ tokenSha256, tenantId, permissions: ['encrypt', 'decrypt'], keys: [keyRef] }] };
    parseConfig({ STRONGROOM_CONFIG: JSON.stringify(config) });
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const secret = { mode: 0o600, flag: 'wx' } as const;
    await writeFile(resolve(directory, 'config.json'), JSON.stringify(config, null, 2) + '\n', secret);
    await writeFile(resolve(directory, 'token'), token + '\n', secret);
    await writeFile(resolve(directory, '.gitignore'), '*\n', secret);
    const verified = o.role ? { ok: false, skipped: 'role credentials exist only inside ECS/EKS; run strongroom probe after deploying' }
      : skipVerify ? { ok: false, skipped: '--no-verify' } : await verify(key);
    return { ...base, plan: undefined, keyArn, alias, identity: o.role ? { type: 'iam-role', role: o.role } : { type: 'iam-user', user: name, accessKeyId: (key as { accessKeyId: string }).accessKeyId },
      files: { config: resolve(directory, 'config.json'), token: resolve(directory, 'token') }, principal: { tenantId, keys: [keyRef], tokenSha256 }, verified,
      next: [
        `strongroom config-check --input ${resolve(directory, 'config.json')}`,
        `Workers: npx wrangler secret put STRONGROOM_CONFIG < ${resolve(directory, 'config.json')}`,
        `Local: STRONGROOM_CONFIG="$(cat ${resolve(directory, 'config.json')})" node dist/server.js`,
        `Then: STRONGROOM_URL=<service origin> STRONGROOM_TOKEN_FILE=${resolve(directory, 'token')} strongroom probe --key ${keyRef} --tenant ${tenantId}`,
      ], teardown: cleanup };
  } catch (e) {
    const error = e instanceof SetupError ? e : new SetupError('SETUP_FAILED', 'Setup failed after creating resources.', 0);
    error.details = { ...error.details, created, cleanup: created.length ? cleanup : undefined };
    throw error;
  }
}
// New IAM credentials take seconds to propagate; retry only denial-shaped failures, for up to a minute.
async function verify(key: Record<string, unknown>) {
  const provider = createProvider(key as never), started = Date.now();
  const aad = new TextEncoder().encode('["strongroom-setup",1]');
  for (let attempt = 1; ; attempt++) {
    try {
      const dek = crypto.getRandomValues(new Uint8Array(32));
      const back = await provider.unwrap(await provider.wrap(dek, aad), aad);
      if (back.some((b, i) => b !== dek[i])) throw new SetupError('VERIFY_FAILED', 'Decrypted key differs.', 0);
      return { ok: true, attempts: attempt, ms: Date.now() - started };
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code !== 'KMS_ACCESS_DENIED' || Date.now() - started > 60000) {
        return { ok: false, attempts: attempt, ms: Date.now() - started, code: code ?? 'VERIFY_FAILED', next: 'Files were written; retry later with strongroom probe after deploying, or inspect the key policy.' };
      }
      await new Promise(r => setTimeout(r, 3000));
    }
  }
}

export async function teardownAws(options: Record<string, string>) {
  const name = options['--name'] ?? 'strongroom', role = options['--role-name'];
  const o: Options = { name, region: options['--region'], profile: options['--profile'], role };
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) throw new SetupError('INVALID_INPUT', '--name must match ^[A-Za-z0-9_-]{1,32}$.', 0, { path: '--name' });
  const aws = cli(o), removed: Record<string, string>[] = [], absent: string[] = [];
  const gone = (what: string) => (e: unknown) => { if (notFound(e)) { absent.push(what); return undefined; } throw e; };
  if (role) {
    if (await aws(['iam', 'delete-role-policy', '--role-name', role, '--policy-name', 'strongroom-kms']).catch(gone('rolePolicy')) !== undefined) removed.push({ rolePolicy: `${role}/strongroom-kms` });
  } else {
    const keys = await aws(['iam', 'list-access-keys', '--user-name', name]).catch(gone('iamUser'));
    if (keys) {
      for (const k of keys.AccessKeyMetadata) { await aws(['iam', 'delete-access-key', '--user-name', name, '--access-key-id', k.AccessKeyId]); removed.push({ accessKeyId: k.AccessKeyId }); }
      await aws(['iam', 'delete-user-policy', '--user-name', name, '--policy-name', 'strongroom-kms']).catch(gone('userPolicy'));
      await aws(['iam', 'delete-user', '--user-name', name]); removed.push({ iamUser: name });
    }
  }
  // Deleting the key makes every envelope wrapped by it unrecoverable after the waiting period; it is opt-in.
  if (options['--delete-key'] === 'true') {
    const key = await aws(['kms', 'describe-key', '--key-id', `alias/${name}`]).catch(gone('kmsKey'));
    if (key) {
      await aws(['kms', 'delete-alias', '--alias-name', `alias/${name}`]); removed.push({ alias: `alias/${name}` });
      const r = await aws(['kms', 'schedule-key-deletion', '--key-id', key.KeyMetadata.Arn, '--pending-window-in-days', '7']);
      removed.push({ kmsKeyScheduledForDeletion: key.KeyMetadata.Arn, deletionDate: r.DeletionDate });
    }
  }
  return { removed, absent, keptKey: options['--delete-key'] !== 'true',
    note: options['--delete-key'] === 'true' ? 'The KMS key is deleted after 7 days; cancel with aws kms cancel-key-deletion if envelopes still need it.' : 'The KMS key was kept; pass --delete-key to schedule its deletion.' };
}
