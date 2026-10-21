// A local stand-in for real deployments: one Strongroom per tenant (the only supported model), each with
// its own key, running the same Node host as production with the development-only local provider.
// In production each tenant's deployment comes from `strongroom setup aws|gcp --tenant T` instead.
import { spawn } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const server = fileURLToPath(new URL('../../dist/server.js', import.meta.url));
const sha256 = s => createHash('sha256').update(s).digest('hex');
const random = () => randomBytes(32).toString('base64url');

async function freePort() {
  const probe = createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
  const { port } = probe.address(); await new Promise(r => probe.close(r)); return port;
}

// Three callers per deployment, so each example can show least privilege:
// `ingest` may only encrypt, `use` may only decrypt, `both` is for flows that rewrite a secret.
export async function startDeployment(tenantId, { kek = random() } = {}) {
  const tokens = { ingest: random(), use: random(), both: random() };
  const config = { tenantId, keys: { primary: { provider: 'local', kek } }, principals: [
    { tokenSha256: sha256(tokens.ingest), permissions: ['encrypt'], keys: ['primary'] },
    { tokenSha256: sha256(tokens.use), permissions: ['decrypt'], keys: ['primary'] },
    { tokenSha256: sha256(tokens.both), permissions: ['encrypt', 'decrypt'], keys: ['primary'] },
  ] };
  const port = await freePort();
  // Pin HOST as well as PORT: an inherited HOST would bind elsewhere while the probe below waits on 127.0.0.1.
  const child = spawn(process.execPath, [server], { stdio: 'ignore',
    env: { ...process.env, STRONGROOM_CONFIG: JSON.stringify(config), STRONGROOM_ALLOW_LOCAL: 'true', HOST: '127.0.0.1', PORT: String(port) } });
  const url = `http://127.0.0.1:${port}`;
  for (let attempt = 0; ; attempt++) {
    if (child.exitCode !== null || attempt > 200) {
      if (child.exitCode === null) { child.kill('SIGTERM'); await once(child, 'close'); }
      throw new Error('Strongroom did not start. Run `npm run build` first.');
    }
    try { if ((await fetch(`${url}/readyz`)).ok) break; } catch { /* starting */ }
    await new Promise(r => setTimeout(r, 25));
  }
  return {
    tenantId, url, tokens, kek,
    async stop() { if (child.exitCode === null) { child.kill('SIGTERM'); await once(child, 'close'); } },
  };
}

// Each step prints one JSON line, so a run reads as a transcript and can be checked by tests.
export const step = (name, details = {}) => console.log(JSON.stringify({ step: name, ...details }));
