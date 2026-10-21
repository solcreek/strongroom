import { readFile } from 'node:fs/promises';
import init, { execute } from '../crates/core/pkg/strongroom_core.js';
import { sha256, base64url } from '../service/encoding.ts';
import { createApp } from '../service/app.ts';
await init({ module_or_path: await readFile(new URL('../crates/core/pkg/strongroom_core_bg.wasm', import.meta.url)) });
export const token = 'test-token-'.padEnd(43, 'a');
export const encryptToken = 'encrypt-only-'.padEnd(43, 'c');
export const context = { tenantId: 'a', recordId: 'credential-1', purpose: 'provider-api-key' };
export const keyConfig = { provider: 'local', kek: base64url(new Uint8Array(32).fill(9)) };
export const config = { tenantId: 'a', keys: { primary: keyConfig, restricted: keyConfig }, principals: [
  { tokenSha256: await sha256(token), permissions: ['encrypt', 'decrypt'], keys: ['primary'] },
  { tokenSha256: await sha256(encryptToken), permissions: ['encrypt'], keys: ['primary'] },
] };
export const env = { STRONGROOM_CONFIG: JSON.stringify(config), STRONGROOM_ALLOW_LOCAL: 'true' };
// Tenant b's own deployment, deliberately miswired to the same KEK and token as tenant a.
export const tenantBEnv = { STRONGROOM_CONFIG: JSON.stringify({ ...config, tenantId: 'b' }) };
export function appWith(overrides = {}, fetcher, log = () => {}) { return createApp({ ...env, ...overrides }, execute, fetcher, log); }
export function request(path, body, auth = token, options = {}) {
  return new Request(`http://localhost${path}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${auth}` }, body: JSON.stringify(body), ...options });
}
export async function encrypt(app, plaintext = 'fake-user-api-key') {
  const response = await app.fetch(request('/v1/encrypt', { plaintext, context, key: 'primary' }));
  if (response.status !== 200) throw new Error(await response.text());
  return (await response.json()).envelope;
}
