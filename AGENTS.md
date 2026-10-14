# Strongroom development

Strongroom encrypts recoverable API credentials, not account login passwords. The public service is stateless; callers store envelopes in their own database.

- Read `README.md`, `docs/architecture.md` and `docs/security.md` before changing cryptography or authorization.
- `crates/core` owns the envelope format and AES-GCM. `service` owns auth, KMS and HTTP. `packages/strongroom` owns the SDK/CLI. `poc` is historical comparison code and must never be used by the service.
- Keep Workers and the Node/container host on the same handler. Do not add Node-specific APIs to shared service modules.
- Run `npm run verify` before committing a complete change. Run `npm run deploy:check` after Worker build/config changes. `npm run test:fast` is useful during iteration after the initial build.
- Add meaningful negative tests for auth, tenant binding, envelope validation and provider failures. Coverage gates apply to shared service and SDK/CLI; actual workerd and Node hosts have separate integration tests.
- Provider error mapping is pinned by live-recorded fixtures (`tests/fixtures/kms/`). When changing an adapter or classifier, run `npm run test:live` if credentials are configured; use `--record` only for an intentional change and review the fixture diff. See `docs/testing.md`.
- Do not log plaintext, tokens, DEKs, configuration, upstream bodies or exception stacks. JSON error codes and schemas are part of the agent-facing API contract.
- Keep secrets off CLI arguments. Use stdin/files/environment. Preserve JSON-only stdout, JSON errors on stderr, documented exit codes and bounded inputs.
- Context is authenticated metadata, not authorization. Check tenant, operation and configured key grants before KMS access. Never resolve provider URLs or KMS key IDs from caller input.
- Each envelope gets a fresh host CSPRNG DEK and nonce. No caller-supplied entropy, hardcoded wrapping keys, or automatic fallback from KMS to local mode.
- Provisioning commands (`setup aws`, `teardown aws`) must stay non-interactive: plan with `--dry-run`, stable error codes with `next`, `created`/`cleanup` on partial failure, secrets only in new 0600 files. Test them offline with the fake `aws` / `gcloud` in `tests/setup.test.mjs` and `tests/setup-gcp.test.mjs`; never make those tests depend on wall-clock timing.
- Releases are tag-driven npm trusted publishing (`docs/releasing.md`); never add an npm token. Version bumps touch package.json, `capabilities.version`, the crate and Cargo.lock together, with a dated CHANGELOG.md section (Keep a Changelog 1.1.0); `npm run release:check -- vX.Y.Z` enforces it. Record user-visible changes under `[Unreleased]` as you go.
- Keep commits small and atomic. Update relevant docs and tests in the same change. Commit often. Publishing or deployment is separate from local verification.
- Do not commit `.strongroom`, `.env*`, `.dev.vars*`, credential files, generated Wasm, coverage or `node_modules`.
