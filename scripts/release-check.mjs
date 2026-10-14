// Release gate: the tag, npm package, API capabilities and Rust crate must name one version.
//   node scripts/release-check.mjs v0.1.0-alpha.1
// Prints {"version","distTag"}; prereleases publish under their identifier (alpha, beta, rc), never latest.
import { readFileSync } from 'node:fs';
import { capabilities } from '../service/contract.ts';
const tag = process.argv[2] ?? process.env.GITHUB_REF_NAME;
const pkg = JSON.parse(readFileSync('packages/strongroom/package.json', 'utf8')).version;
const crate = readFileSync('crates/core/Cargo.toml', 'utf8').match(/^version = "([^"]+)"/m)?.[1];
const versions = { tag: tag?.replace(/^v/, ''), package: pkg, capabilities: capabilities.version, crate };
if (!tag?.startsWith('v') || new Set(Object.values(versions)).size !== 1) {
  process.stderr.write(JSON.stringify({ error: { code: 'VERSION_MISMATCH', message: 'Tag vN.N.N must equal packages/strongroom/package.json, service/contract.ts capabilities.version and crates/core/Cargo.toml.', versions } }) + '\n');
  process.exit(2);
}
const prerelease = pkg.match(/^\d+\.\d+\.\d+-([0-9A-Za-z]+)/)?.[1];
process.stdout.write(JSON.stringify({ version: pkg, distTag: prerelease ?? 'latest' }) + '\n');
