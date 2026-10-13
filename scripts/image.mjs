// Builds the runtime container image without a Docker daemon and pushes it to one or more registries.
//   node scripts/image.mjs --repository REGISTRY/PATH/strongroom [--repository ...] [--tag TAG] [--platforms linux/amd64,linux/arm64]
// Uses the locally verified dist/ (npm run build) as one deterministic layer on a digest-pinned node:24-bookworm-slim,
// matching the Dockerfile's runtime stage. Requires `crane`; registry login is the caller's (crane auth login / docker config).
// Prints one JSON object: the pushed image references, pinned by digest, for IaC.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const args = process.argv.slice(2);
const all = name => args.flatMap((a, i) => a === name ? [args[i + 1]] : []);
const one = (name, fallback) => all(name).at(-1) ?? fallback;
const repositories = all('--repository');
if (!repositories.length) throw new Error('Give at least one --repository REGISTRY/PATH/NAME.');
const version = JSON.parse(readFileSync('packages/strongroom/package.json', 'utf8')).version;
const commit = execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], { encoding: 'utf8' }).trim();
const tag = one('--tag', `${version}-${commit}`);
const platforms = one('--platforms', 'linux/amd64,linux/arm64').split(',');
const crane = (...a) => execFileSync('crane', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
const base = one('--base', 'node:24-bookworm-slim');
const baseRef = base.includes('@sha256:') ? base : `${base.split(':')[0]}@${crane('digest', base)}`;

// Minimal ustar writer: fixed owners, modes and mtime make the layer byte-identical for the same commit.
const mtime = Number(execFileSync('git', ['log', '-1', '--format=%ct'], { encoding: 'utf8' }));
function entry(name, body, { mode, uid, gid, uname, gname, type = '0' }) {
  const h = Buffer.alloc(512);
  const field = (value, offset, length) => h.write(value, offset, length, 'utf8');
  const octal = (value, offset, length) => field(value.toString(8).padStart(length - 1, '0') + '\0', offset, length);
  field(name, 0, 100); octal(mode, 100, 8); octal(uid, 108, 8); octal(gid, 116, 8); octal(body.length, 124, 12); octal(mtime, 136, 12);
  field(' '.repeat(8), 148, 8); field(type, 156, 1); field('ustar\0', 257, 6); field('00', 263, 2); field(uname, 265, 32); field(gname, 297, 32);
  octal(h.reduce((s, b) => s + b, 0), 148, 7);
  return Buffer.concat([h, body, Buffer.alloc((512 - body.length % 512) % 512)]);
}
const node = { mode: 0o644, uid: 1000, gid: 1000, uname: 'node', gname: 'node' };
const layer = Buffer.concat([
  entry('app/', Buffer.alloc(0), { mode: 0o755, uid: 0, gid: 0, uname: 'root', gname: 'root', type: '5' }),
  entry('app/package.json', readFileSync('deploy/runtime-package.json'), node),
  entry('app/server.js', readFileSync('dist/server.js'), node),
  entry('app/strongroom_core_bg.wasm', readFileSync('dist/strongroom_core_bg.wasm'), node),
  Buffer.alloc(1024),
]);
const dir = mkdtempSync(join(tmpdir(), 'strongroom-image-'));
try {
  const layerFile = join(dir, 'layer.tar'); writeFileSync(layerFile, layer);
  const [primary, ...mirrors] = repositories;
  const manifests = platforms.map(platform => {
    const ref = `${primary}:${tag}-${platform.replace('/', '-')}`;
    crane('append', '--platform', platform, '-b', baseRef, '-f', layerFile, '-t', ref);
    // Same runtime settings as the Dockerfile runtime stage; ECS and Cloud Run use their own health checks.
    return crane('mutate', ref, '-t', ref, '--workdir', '/app', '--user', 'node', '--exposed-ports', '8080/tcp',
      '--env', 'NODE_ENV=production', '--env', 'HOST=0.0.0.0', '--env', 'PORT=8080', '--cmd', 'node,server.js',
      '--label', `org.opencontainers.image.revision=${commit}`, '--label', `org.opencontainers.image.version=${version}`);
  });
  crane('index', 'append', ...manifests.flatMap(m => ['-m', m]), '-t', `${primary}:${tag}`);
  const digest = crane('digest', `${primary}:${tag}`);
  for (const mirror of mirrors) crane('copy', `${primary}:${tag}`, `${mirror}:${tag}`);
  process.stdout.write(JSON.stringify({ tag, digest, base: baseRef, platforms, layerSha256: createHash('sha256').update(layer).digest('hex'),
    images: repositories.map(r => `${r}@${digest}`) }, null, 2) + '\n');
} finally { rmSync(dir, { recursive: true, force: true }); }
