import { unbase64url, utf8 } from './encoding.ts';

export type KeyConfig =
  | { provider: 'local'; kek: string }
  | { provider: 'aws'; region: string; keyId: string; accessKeyId: string; secretAccessKey: string; sessionToken?: string }
  | { provider: 'gcp'; keyId: string; serviceAccount: { clientEmail: string; privateKey: string } }
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
export function parseConfig(env: Bindings): Config {
  let config: unknown;
  try { config = JSON.parse(env.STRONGROOM_CONFIG ?? 'null'); } catch { throw new Error('STRONGROOM_CONFIG must contain valid JSON.'); }
  fields(config, ['keys', 'principals']);
  if (!object(config.keys) || !Object.keys(config.keys).length || Object.keys(config.keys).length > 100) throw new Error('Invalid keys');
  for (const [alias, k] of Object.entries(config.keys)) {
    if (!keyPattern.test(alias) || ['__proto__', 'constructor', 'prototype'].includes(alias) || !object(k)) throw new Error('Invalid key');
    switch (k.provider) {
      case 'local':
        fields(k, ['provider', 'kek']);
        if (env.STRONGROOM_ALLOW_LOCAL !== 'true' || !text(k.kek) || unbase64url(k.kek).length !== 32) throw new Error('Local provider requires explicit opt-in and a 32-byte key');
        break;
      case 'aws':
        fields(k, ['provider', 'region', 'keyId', 'accessKeyId', 'secretAccessKey'], ['sessionToken']);
        if (!text(k.region, 32) || !/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(k.region) ||
            !text(k.keyId) || !/^arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:\d{12}:key\/[a-zA-Z0-9-]+$/.test(k.keyId) ||
            k.keyId.split(':')[3] !== k.region || !text(k.accessKeyId) || !text(k.secretAccessKey) ||
            (k.sessionToken !== undefined && !text(k.sessionToken))) throw new Error('Invalid AWS key');
        break;
      case 'gcp':
        fields(k, ['provider', 'keyId', 'serviceAccount']);
        fields(k.serviceAccount, ['clientEmail', 'privateKey']);
        if (!text(k.keyId) || !/^projects\/[A-Za-z0-9_-]+\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+$/.test(k.keyId) ||
            !text(k.serviceAccount.clientEmail) || !text(k.serviceAccount.privateKey, 16384) || !k.serviceAccount.privateKey.startsWith('-----BEGIN PRIVATE KEY-----')) throw new Error('Invalid GCP key');
        break;
      case 'vault': case 'openbao': {
        fields(k, ['provider', 'url', 'mount', 'keyName', 'token'], ['namespace']);
        if (!text(k.url) || !text(k.mount, 128) || !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(k.mount) ||
            !text(k.keyName, 128) || !/^[A-Za-z0-9_-]+$/.test(k.keyName) || !text(k.token) ||
            (k.namespace !== undefined && !text(k.namespace))) throw new Error('Invalid Transit key');
        const url = new URL(k.url);
        if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
            (url.protocol !== 'https:' && !(env.STRONGROOM_ALLOW_LOCAL === 'true' && url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) throw new Error('Transit URL requires HTTPS');
        break;
      }
      default: throw new Error('Unsupported provider');
    }
  }
  if (!Array.isArray(config.principals) || !config.principals.length || config.principals.length > 1000) throw new Error('Invalid principals');
  const hashes = new Set<string>();
  for (const p of config.principals) {
    fields(p, ['tokenSha256', 'tenantId', 'permissions', 'keys']);
    if (!text(p.tokenSha256) || !/^[a-f0-9]{64}$/.test(p.tokenSha256) || hashes.has(p.tokenSha256) || !text(p.tenantId, 256) ||
        !Array.isArray(p.permissions) || !p.permissions.length || p.permissions.some(v => !['encrypt', 'decrypt'].includes(v)) ||
        !Array.isArray(p.keys) || !p.keys.length || p.keys.some(v => typeof v !== 'string' || !Object.hasOwn(config.keys as object, v))) throw new Error('Invalid principal');
    hashes.add(p.tokenSha256);
  }
  return config as unknown as Config;
}
