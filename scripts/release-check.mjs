// Release gate: the tag, npm package, API capabilities, Rust crate and lockfile must name one version, and CHANGELOG.md must have it.
//   node scripts/release-check.mjs v0.1.0
// Prints {"version","distTag"}; prereleases publish under their identifier (alpha, beta, rc), never latest.
import { readFileSync } from 'node:fs';
import { capabilities } from '../service/contract.ts';
const tag = process.argv[2] ?? process.env.GITHUB_REF_NAME;
const pkg = JSON.parse(readFileSync('packages/strongroom/package.json', 'utf8')).version;
const crate = readFileSync('crates/core/Cargo.toml', 'utf8').match(/^version = "([^"]+)"/m)?.[1];
const lock = readFileSync('Cargo.lock', 'utf8').match(/name = "strongroom-core"\nversion = "([^"]+)"/)?.[1];
// Keep a Changelog: the release needs its own dated heading, e.g. "## [0.1.0] - 2026-10-13".
const changelog = readFileSync('CHANGELOG.md', 'utf8').match(new RegExp(`^## \\[${pkg.replace(/\./g, '\\.')}\\] - (\\d{4}-\\d{2}-\\d{2})$`, 'm')) ? pkg : null;
const versions = { tag: tag?.replace(/^v/, ''), package: pkg, capabilities: capabilities.version, crate, cargoLock: lock, changelog };
if (!tag?.startsWith('v') || new Set(Object.values(versions)).size !== 1) {
  process.stderr.write(JSON.stringify({ error: { code: 'VERSION_MISMATCH', message: 'Tag vN.N.N must equal packages/strongroom/package.json, service/contract.ts capabilities.version, crates/core/Cargo.toml and Cargo.lock, and CHANGELOG.md needs a "## [N.N.N] - YYYY-MM-DD" heading.', versions } }) + '\n');
  process.exit(2);
}
const prerelease = pkg.match(/^\d+\.\d+\.\d+-([0-9A-Za-z]+)/)?.[1];
process.stdout.write(JSON.stringify({ version: pkg, distTag: prerelease ?? 'latest' }) + '\n');
