# Releasing the npm package

`strongroom` is published to npm by `.github/workflows/release.yml` with [npm trusted publishing](https://docs.npmjs.com/trusted-publishers): GitHub Actions presents an OIDC token, npm exchanges it for a short-lived publish credential, and the package gets a provenance attestation linking it to the exact commit and workflow run. No npm token exists in the repository, in GitHub secrets or on any machine.

## What is trusted

| Layer | Setting |
| --- | --- |
| npmjs.com | Package `strongroom` trusts repository `solcreek/strongroom`, workflow file `release.yml`, environment `npm`; permissions `publish, stage publish` (created 2026-10-13, `npm trust list strongroom`) |
| GitHub environment `npm` | Deployments only from tags matching `v*` |
| Tag ruleset "release tags are immutable" | `v*` tags cannot be moved or deleted after they are pushed |
| Workflow | `id-token: write` only on the publish job; version gate, full `npm run verify` and `npm run test:package` before `npm publish` |

Renaming `release.yml`, the environment or the repository breaks publishing until the npm trust is updated.

## One-time setup (owner, interactive)

Trusted publisher configuration requires an npm account owner with 2FA. A non-interactive shell cannot complete the browser flow (`EOTP`); pass a one-time password with `--otp`, for example from 1Password: `--otp="$(op item get ITEM --otp)"`.

```sh
npm trust github strongroom --file release.yml --repository solcreek/strongroom --environment npm --allow-publish --yes
npm trust list strongroom
```

After the first successful trusted publish, set the package to **Require two-factor authentication and disallow tokens** under the package's Settings → Publishing access on npmjs.com, so a leaked token cannot publish. Trusted publishing keeps working with that setting.

## Cutting a release

1. Bump the version in all three places in one commit: `packages/strongroom/package.json`, `capabilities.version` in `service/contract.ts`, and `crates/core/Cargo.toml` (then `cargo check` to refresh `Cargo.lock`).
2. Check locally: `npm run release:check -- vX.Y.Z[-pre.N]` prints the version and the npm dist-tag.
3. Merge to `main`, wait for CI, then tag that commit and push the tag:

```sh
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

A prerelease (`-alpha.N`, `-beta.N`, `-rc.N`) publishes under that identifier as its dist-tag (`alpha`, `beta`, `rc`) and never moves `latest`. Install one with `npm install strongroom@alpha`. A plain `X.Y.Z` publishes to `latest`.

A tag whose version disagrees with any of the three files fails the version gate with `VERSION_MISMATCH` before anything is built. npm versions are immutable: a failed or bad release is fixed by publishing the next version, never by moving the tag.
