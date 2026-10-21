// Shared by the provider setup commands: the agent-facing error shape, private output files and live verification.
import { mkdir, writeFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { StrongroomError } from './client.ts';
import { parseConfig } from '../../../service/config.ts';
import { createProvider } from '../../../service/providers.ts';

// Error details (next, path, created, cleanup, requiredPermissions) are flattened into the JSON error for agents.
export class SetupError extends StrongroomError {
  details: Record<string, unknown>;
  constructor(code: string, message: string, status: number, details: Record<string, unknown> = {}) { super(code, message, status); this.details = details; }
  toJSON() { return { ...super.toJSON(), ...this.details }; }
}
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
// Default cloud resource names follow the tenant, so several tenants' deployments can share an account or
// project without --name. Always readable slug + hash: a plain form would share a namespace with the hashed
// one ("ab" vs "ab-fb8e20"), letting a chosen tenant id land on another tenant's name. 40 bits of hash keep
// accidental collisions negligible; ownership tags (tenantTag) catch the rest. The result fits both AWS
// (KMS alias, IAM user) and GCP (key ring, service account: ^[a-z][a-z0-9-]{4,28}[a-z0-9]$).
export function tenantName(tenantId: string): string {
  const head = tenantId.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 16).replace(/-+$/, '');
  return `sr-${head}${head ? '-' : ''}${sha256(tenantId).slice(0, 10)}`;
}
// Written on every resource setup creates (AWS tag, GCP label, service account description) and checked
// before setup reuses or teardown removes one, so a name that points at another tenant's resource is refused
// rather than shared or destroyed. A hash, because tag and label values cannot hold arbitrary tenant ids.
export const tenantTag = (tenantId: string) => sha256(tenantId).slice(0, 32);
// For commands setup prints for an agent or operator to run: the tenant id is arbitrary text.
export const shellQuote = (s: string) => /^[A-Za-z0-9._@%+=:,/-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
// --name wins; otherwise the name follows --tenant. Teardown accepts either, so an agent can undo a setup
// knowing only the tenant.
export function resourceName(options: Record<string, string>, command: string): string {
  if (options['--name']) return options['--name'];
  if (options['--tenant']) return tenantName(options['--tenant']);
  throw new SetupError('INVALID_INPUT', `${command} needs --tenant TENANT (resource names follow it) or an explicit --name.`, 0, { path: '--tenant' });
}
// Teardown's change phase: a failure partway must still say what was already removed or scheduled (a key
// pending deletion is irreversible in days), and that rerunning the same command resumes.
export async function reportPartial(removed: Record<string, string>[], change: () => Promise<void>) {
  try { await change(); } catch (e) {
    const error = e instanceof SetupError ? e : new SetupError('TEARDOWN_FAILED', 'Teardown failed partway.', 0);
    error.details = { ...error.details, removed: [...removed], next: 'Rerun the same teardown command; it resumes from what is left.' };
    throw error;
  }
}
export async function assertNewDirectory(directory: string) {
  if (await stat(directory).then(() => true, () => false)) throw new SetupError('INVALID_INPUT', 'The output directory already exists; secrets are never overwritten.', 0, { path: '--directory', next: 'Choose a new --directory.' });
}
// Writes config.json (complete STRONGROOM_CONFIG for the one tenant, with one principal) and the caller token, both 0600, in a new 0700 directory.
export async function writeSetup(directory: string, keyRef: string, key: Record<string, unknown>, tenantId: string) {
  const token = randomBytes(32).toString('base64url'), tokenSha256 = createHash('sha256').update(token).digest('hex');
  const config = { tenantId, keys: { [keyRef]: key }, principals: [{ tokenSha256, permissions: ['encrypt', 'decrypt'], keys: [keyRef] }] };
  parseConfig({ STRONGROOM_CONFIG: JSON.stringify(config) });
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const secret = { mode: 0o600, flag: 'wx' } as const;
  await writeFile(resolve(directory, 'config.json'), JSON.stringify(config, null, 2) + '\n', secret);
  await writeFile(resolve(directory, 'token'), token + '\n', secret);
  await writeFile(resolve(directory, '.gitignore'), '*\n', secret).catch(() => {});
  return { files: { config: resolve(directory, 'config.json'), token: resolve(directory, 'token') }, principal: { keys: [keyRef], tokenSha256 } };
}
export function nextSteps(files: { config: string; token: string }, keyRef: string, tenantId: string) {
  return [
    `strongroom config-check --input ${files.config}`,
    `Workers: npx wrangler secret put STRONGROOM_CONFIG < ${files.config}`,
    `Local: STRONGROOM_CONFIG="$(cat ${files.config})" node dist/server.js`,
    `Then: STRONGROOM_URL=<service origin> STRONGROOM_TOKEN_FILE=${files.token} strongroom probe --key ${keyRef} --tenant ${tenantId}`,
  ];
}
// New credentials and IAM bindings propagate in seconds (AWS) to about a minute (GCP); retry only denial-shaped failures.
export async function verifyKey(key: Record<string, unknown>, timeoutMs: number) {
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
      if (code !== 'KMS_ACCESS_DENIED' || Date.now() - started > timeoutMs)
        return { ok: false, attempts: attempt, ms: Date.now() - started, code: code ?? 'VERIFY_FAILED', next: 'Files were written; retry later with strongroom probe after deploying, or inspect the key IAM policy.' };
      await new Promise(r => setTimeout(r, 3000));
    }
  }
}
