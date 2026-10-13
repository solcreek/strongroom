# Strongroom development

Strongroom encrypts recoverable API credentials, not account login passwords. The public service is stateless; callers store envelopes in their own database.

- Read `README.md`, `docs/architecture.md` and `docs/security.md` before changing cryptography or authorization.
- `crates/core` owns the envelope format and AES-GCM. `service` owns auth, KMS and HTTP. `packages/strongroom` owns the SDK/CLI. `poc` is historical comparison code and must never be used by the service.
- Keep Workers and the Node/container host on the same handler. Do not add Node-specific APIs to shared service modules.
- Run `npm run verify` before committing a complete change. Run `npm run deploy:check` after Worker build/config changes. `npm run test:fast` is useful during iteration after the initial build.
- Add meaningful negative tests for auth, tenant binding, envelope validation and provider failures. Coverage gates apply to shared service and SDK/CLI; actual workerd and Node hosts have separate integration tests.
- Do not log plaintext, tokens, DEKs, configuration, upstream bodies or exception stacks. JSON error codes and schemas are part of the agent-facing API contract.
- Keep secrets off CLI arguments. Use stdin/files/environment. Preserve JSON-only stdout, JSON errors on stderr, documented exit codes and bounded inputs.
- Context is authenticated metadata, not authorization. Check tenant, operation and configured key grants before KMS access. Never resolve provider URLs or KMS key IDs from caller input.
- Each envelope gets a fresh host CSPRNG DEK and nonce. No caller-supplied entropy, hardcoded wrapping keys, or automatic fallback from KMS to local mode.
- Keep commits small and atomic. Update relevant docs and tests in the same change. Commit often. Publishing or deployment is separate from local verification.
- Do not commit `.strongroom`, `.env*`, `.dev.vars*`, credential files, generated Wasm, coverage or `node_modules`.
