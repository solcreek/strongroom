import { unbase64url, utf8 } from './encoding.ts';

export type KeyConfig =
  | { provider: 'local'; kek: string }
  | { provider: 'aws'; region: string; keyId: string; accessKeyId: string; secretAccessKey: string; sessionToken?: string }
  | ({ provider: 'gcp'; keyId: string } & ({ serviceAccount: { clientEmail: string; privateKey: string } } |
      { authorizedUser: { clientId: string; clientSecret: string; refreshToken: string; quotaProject?: string } } | { metadataServer: true }))
  | { provider: 'vault' | 'openbao'; url: string; mount: string; keyName: string; token: string; namespace?: string };
export interface Principal { tokenSha256: string; tenantId: string; permissions: ('encrypt' | 'decrypt')[]; keys: string[] }
export interface Config { keys: Record<string, KeyConfig>; principals: Principal[] }
export interface Bindings { STRONGROOM_CONFIG?: string; STRONGROOM_ALLOW_LOCAL?: string }
export const keyPattern = /^[A-Za-z0-9_-]{1,64}$/;
export function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
export function fields(value: unknown, required: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  if (!object(value) || required.some(k => !Object.hasOwn(value, k)) || Object.keys(value).some(k => !required.includes(k) && !optional.includes(k))) throw new Error(`Invalid fields. Required: ${required.join(', ')}. Optional: ${optional.join(', ') || 'none'}.`);
}
export function text(value: unknown, max = 8192): value is string {
  return typeof value === 'string' && value.length > 0 && value.isWellFormed() && utf8.encode(value).length <= max;
}
// Diagnostics name the JSON path and the rule, never the supplied value.
export class ConfigError extends Error { path: string; constructor(path: string, rule: string) { super(`${path}: ${rule}`); this.name = 'ConfigError'; this.path = path; } }
function shape(value: unknown, path: string, required: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  if (!object(value)) throw new ConfigError(path, 'must be a JSON object.');
  const missing = required.filter(k => !Object.hasOwn(value, k)), unknown = Object.keys(value).filter(k => !required.includes(k) && !optional.includes(k));
  if (missing.length) throw new ConfigError(path, `missing required field(s): ${missing.join(', ')}.`);
  if (unknown.length) throw new ConfigError(path, `unknown field(s): ${unknown.map(k => k.length > 64 ? `${k.slice(0, 64)}…` : k).join(', ')}. Allowed: ${[...required, ...optional].join(', ')}.`);
}
function check(ok: boolean, path: string, rule: string) { if (!ok) throw new ConfigError(path, rule); }
const gcpCredentials = ['serviceAccount', 'authorizedUser', 'metadataServer'];
export function parseConfig(env: Bindings): Config {
  let config: unknown;
  try { config = JSON.parse(env.STRONGROOM_CONFIG ?? 'null'); } catch { throw new ConfigError('$', 'STRONGROOM_CONFIG must contain valid JSON.'); }
  shape(config, '$', ['keys', 'principals']);
  check(object(config.keys) && Object.keys(config.keys).length > 0 && Object.keys(config.keys).length <= 100, '$.keys', 'must be an object with 1-100 key references.');
  for (const [alias, k] of Object.entries(config.keys as Record<string, unknown>)) {
    const at = `$.keys.${alias}`;
    check(keyPattern.test(alias) && !['__proto__', 'constructor', 'prototype'].includes(alias), '$.keys', 'reference names must match ^[A-Za-z0-9_-]{1,64}$.');
    check(object(k), at, 'must be a JSON object.');
    const provider = (k as Record<string, unknown>).provider;
    switch (provider) {
      case 'local':
        shape(k, at, ['provider', 'kek']);
        check(env.STRONGROOM_ALLOW_LOCAL === 'true', `${at}.provider`, 'local requires STRONGROOM_ALLOW_LOCAL=true and is for development only.');
        check(text(k.kek) && (() => { try { return unbase64url(k.kek as string).length === 32; } catch { return false; } })(), `${at}.kek`, 'must be 32 random bytes, base64url without padding.');
        break;
      case 'aws':
        shape(k, at, ['provider', 'region', 'keyId', 'accessKeyId', 'secretAccessKey'], ['sessionToken']);
        check(text(k.region, 32) && /^[a-z]{2}(?:-[a-z]+)+-\d$/.test(k.region), `${at}.region`, 'must be an AWS region such as us-east-1.');
        check(text(k.keyId) && /^arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:\d{12}:key\/[a-zA-Z0-9-]+$/.test(k.keyId), `${at}.keyId`, 'must be a full key ARN (arn:aws:kms:REGION:ACCOUNT:key/ID); aliases are rejected. Resolve one with: aws kms describe-key --key-id alias/NAME --query KeyMetadata.Arn');
        check((k.keyId as string).split(':')[3] === k.region, `${at}.keyId`, 'ARN region must equal region.');
        for (const f of ['accessKeyId', 'secretAccessKey', 'sessionToken']) check(f === 'sessionToken' && k[f] === undefined || text(k[f]), `${at}.${f}`, 'must be a non-empty string.');
        break;
      case 'gcp': {
        const credential = gcpCredentials.filter(f => Object.hasOwn(k as object, f));
        check(credential.length === 1, at, `needs exactly one credential: ${gcpCredentials.join(' | ')}.`);
        shape(k, at, ['provider', 'keyId', credential[0]]);
        check(text(k.keyId) && /^projects\/[A-Za-z0-9_-]+\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+$/.test(k.keyId), `${at}.keyId`, 'must be projects/P/locations/L/keyRings/R/cryptoKeys/K (no cryptoKeyVersions suffix).');
        const c = k[credential[0]], cat = `${at}.${credential[0]}`;
        if (credential[0] === 'serviceAccount') {
          shape(c, cat, ['clientEmail', 'privateKey']);
          check(text(c.clientEmail, 256) && /^[^@\s]+@[^@\s]+$/.test(c.clientEmail), `${cat}.clientEmail`, 'must be the service account client_email.');
          check(text(c.privateKey, 16384) && c.privateKey.startsWith('-----BEGIN PRIVATE KEY-----'), `${cat}.privateKey`, 'must be the PKCS#8 PEM private_key from the downloaded key file.');
        } else if (credential[0] === 'authorizedUser') {
          shape(c, cat, ['clientId', 'clientSecret', 'refreshToken'], ['quotaProject']);
          for (const f of ['clientId', 'clientSecret', 'refreshToken', 'quotaProject']) check(f === 'quotaProject' && c[f] === undefined || text(c[f], 2048), `${cat}.${f}`, 'must be a non-empty string.');
        } else check(c === true, cat, 'must be true; uses the GCP metadata server (Cloud Run, GKE, Compute Engine).');
        break;
      }
      case 'vault': case 'openbao': {
        shape(k, at, ['provider', 'url', 'mount', 'keyName', 'token'], ['namespace']);
        check(text(k.mount, 128) && /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(k.mount), `${at}.mount`, 'must be a mount path such as transit.');
        check(text(k.keyName, 128) && /^[A-Za-z0-9_-]+$/.test(k.keyName), `${at}.keyName`, 'must match ^[A-Za-z0-9_-]+$.');
        check(text(k.token), `${at}.token`, 'must be a non-empty string.');
        check(k.namespace === undefined || text(k.namespace), `${at}.namespace`, 'must be a non-empty string when present.');
        let url: URL | undefined;
        try { url = new URL(k.url as string); } catch { /* reported below */ }
        check(!!url && text(k.url) && !url.username && !url.password && !url.search && !url.hash && url.pathname === '/', `${at}.url`, 'must be an origin with no credentials, path, query or fragment.');
        check(url!.protocol === 'https:' || (env.STRONGROOM_ALLOW_LOCAL === 'true' && url!.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url!.hostname)), `${at}.url`, 'requires HTTPS; HTTP is allowed only for loopback with STRONGROOM_ALLOW_LOCAL=true.');
        break;
      }
      default: throw new ConfigError(`${at}.provider`, 'must be one of aws, gcp, vault, openbao, local.');
    }
  }
  check(Array.isArray(config.principals) && config.principals.length > 0 && config.principals.length <= 1000, '$.principals', 'must be an array of 1-1000 principals.');
  const hashes = new Set<string>();
  (config.principals as unknown[]).forEach((p, i) => {
    const at = `$.principals[${i}]`;
    shape(p, at, ['tokenSha256', 'tenantId', 'permissions', 'keys']);
    check(text(p.tokenSha256) && /^[a-f0-9]{64}$/.test(p.tokenSha256), `${at}.tokenSha256`, 'must be the lowercase SHA-256 hex digest of the bearer token.');
    check(!hashes.has(p.tokenSha256 as string), `${at}.tokenSha256`, 'duplicates another principal.');
    check(text(p.tenantId, 256), `${at}.tenantId`, 'must be 1-256 UTF-8 bytes.');
    check(Array.isArray(p.permissions) && p.permissions.length > 0 && p.permissions.every(v => ['encrypt', 'decrypt'].includes(v)), `${at}.permissions`, 'must be a non-empty subset of ["encrypt","decrypt"].');
    check(Array.isArray(p.keys) && p.keys.length > 0 && p.keys.every(v => typeof v === 'string' && Object.hasOwn(config.keys as object, v)), `${at}.keys`, 'must list only key references defined in $.keys.');
    hashes.add(p.tokenSha256 as string);
  });
  return config as unknown as Config;
}
