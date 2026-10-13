import { mkdir, readFile, writeFile, chmod } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
const version = '2.7.1';
const platform = `${process.platform}_${process.arch === 'x64' ? 'amd64' : process.arch}`;
const hashes = {
  darwin_arm64: '15625b5f69aee5bb4578b4e76e856a2141647342b0f8e5969a8875b44e0fbf91',
  linux_amd64: '0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243',
  linux_arm64: '2b3807d90f224df05d4fe1fdede7f052d2227596c648a56bd291381f8fd01840',
};
if (!hashes[platform]) throw new Error('Unsupported platform; install OpenBao and set TRANSIT_BIN manually.');
const directory = resolve(`.cache/openbao-${version}`);
await mkdir(directory, { recursive: true });
const archive = resolve(directory, `openbao_${version}_${platform}.tar.gz`);
let bytes;
try { bytes = await readFile(archive); } catch {
  const response = await fetch(`https://github.com/openbao/openbao/releases/download/v${version}/openbao_${version}_${platform}.tar.gz`, { signal: AbortSignal.timeout(120000) });
  if (!response.ok) throw new Error(`OpenBao download failed: ${response.status}`);
  bytes = Buffer.from(await response.arrayBuffer()); await writeFile(archive, bytes);
}
if (createHash('sha256').update(bytes).digest('hex') !== hashes[platform]) throw new Error('OpenBao checksum mismatch.');
const result = spawnSync('tar', ['-xzf', archive, '-C', directory, 'bao'], { encoding: 'utf8' });
if (result.status !== 0) throw new Error('OpenBao extraction failed.');
await chmod(resolve(directory, 'bao'), 0o755);
console.log(resolve(directory, 'bao'));
