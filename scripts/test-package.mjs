import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
const root = resolve('.');
const dir = await mkdtemp(join(tmpdir(), 'strongroom-package-'));
function run(command, args, cwd = dir) {
  const r = spawnSync(command, args, { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`${command} failed: ${r.stderr || r.stdout}`);
  return r.stdout;
}
try {
  const [packed] = JSON.parse(run('npm', ['pack', resolve('packages/strongroom'), '--json', '--pack-destination', dir]));
  assert.ok(packed.files.some(f => f.path === 'dist/client.d.ts'));
  assert.ok(packed.files.every(f => f.path.startsWith('dist/') || ['README.md', 'LICENSE', 'package.json'].includes(f.path)));
  assert.ok(packed.files.some(f => f.path === 'LICENSE'));
  await writeFile(join(dir, 'package.json'), '{"private":true,"type":"module"}');
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', join(dir, packed.filename)]);
  const schema = JSON.parse(run(process.execPath, ['node_modules/strongroom/dist/cli.js', 'schema', 'encrypt']));
  assert.deepEqual(schema.required, ['context', 'key']);
  assert.deepEqual(schema.oneOf, [{ required: ['plaintext'] }, { required: ['plaintextBase64url'] }]);
  run(process.execPath, ['--input-type=module', '-e', 'import { Strongroom, StrongroomError } from "strongroom"; if (typeof Strongroom !== "function" || typeof StrongroomError !== "function") process.exit(1)']);
  await writeFile(join(dir, 'consumer.ts'), 'import { Strongroom, type Context, type Envelope } from "strongroom"; const c: Context = {tenantId:"t",recordId:"r",purpose:"p"}; const client = new Strongroom({url:"https://example.com",token:"a".repeat(43)}); const e: Promise<Envelope> = client.encrypt({plaintext:"test",context:c,key:"primary"}); const b: Promise<Envelope> = client.encrypt({plaintext:new Uint8Array(32),context:c,key:"primary"}); const k = async (envelope: Envelope) => { const bytes: Uint8Array = await client.decryptBytes({envelope,context:c}); bytes.fill(0); }; void e; void b; void k;');
  run(join(root, 'node_modules/.bin/tsc'), ['--noEmit', '--strict', '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', 'consumer.ts']);
  console.log(`Package ${packed.name}@${packed.version}: tarball allowlist, installed SDK, TypeScript declarations and CLI passed.`);
} finally { await rm(dir, { recursive: true, force: true }); }
