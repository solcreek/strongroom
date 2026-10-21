# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0.0, a minor version may change the HTTP API, CLI or configuration; the envelope format changes only with a new envelope `version`.

## [Unreleased]

### Added

- Binary plaintext, for secrets such as data keys. `POST /v1/encrypt` accepts `plaintextBase64url` instead of `plaintext`. `POST /v1/decrypt` returns the raw bytes as `application/octet-stream` when asked with `Accept`. The envelope format is unchanged, and text envelopes can be read either way.
- `PLAINTEXT_NOT_TEXT` (406): a binary envelope was decrypted as JSON text.
- SDK: `encrypt` takes a `Uint8Array` plaintext. `decryptBytes` returns a `Uint8Array` read without ever becoming a string, and wipes the transport chunks.
- CLI: `encrypt --plaintext-file` and `decrypt --plaintext-file` move raw bytes through files; a decrypted file is new and mode 0600.

## [0.1.0] - 2026-10-13

### Added

- `strongroom setup gcp` provisions Cloud KMS with the operator's `gcloud` session: it enables the API if needed, creates or reuses a key ring and CryptoKey, and either creates a service account granted only that key (with a key file, for Workers and other hosts) or grants an existing Cloud Run/GKE identity using `metadataServer`. It writes a complete `STRONGROOM_CONFIG` and caller token and verifies with real encrypt/decrypt.
- `strongroom teardown gcp` removes the grant and service account; `--delete-key` schedules destruction of every key version.

### Changed

- The README shipped to npm documents `setup`, `teardown`, `probe`, `token`, error paths, exit code 6 and Cloud Run ID tokens.
- Documentation describes Strongroom as a pre-1.0 release instead of an alpha.

### Fixed

- `setup gcp` retries the IAM grant while a newly created service account propagates (`INVALID_ARGUMENT` for a few seconds), and `teardown gcp` detects deleted service accounts with `list`, because `describe` and `delete` answer `PERMISSION_DENIED` for them.
- The package's `bin` path is written as npm normalizes it, removing a misleading "script name was invalid and removed" warning at publish time. The 0.1.0-alpha.1 executable was not affected.

## [0.1.0-alpha.1] - 2026-10-13

First public release.

### Added

- Rust AES-256-GCM envelope core (envelope version 1) compiled to Wasm, with a fresh CSPRNG data key and nonce per envelope and tenant, record and purpose bound as authenticated data.
- Stateless HTTP API (`/v1/encrypt`, `/v1/decrypt`, `/v1/capabilities`, `/openapi.json`, `/healthz`, `/readyz`) running unchanged on Cloudflare Workers and a Node container host, with bearer tokens bound to one tenant, explicit operations and key references.
- KMS providers: AWS KMS (static, temporary, or ECS/EKS role credentials via `containerCredentials`), Google Cloud KMS (service account, metadata server, or local ADC), Vault and OpenBao Transit.
- Stable error contract: `DECRYPT_FAILED`, `KMS_ACCESS_DENIED`, `KMS_KEY_UNAVAILABLE`, retryable `KMS_UNAVAILABLE` and `GATEWAY_REJECTED`, classified from allowlisted upstream codes; `INVALID_REQUEST` and configuration errors name the offending JSON path; sanitized `kms_error` operator events with severity.
- TypeScript SDK and non-interactive JSON CLI: `encrypt`, `decrypt --envelope`, `schema`, `capabilities`, `doctor`, `probe`, `token`, `config-check`, `init`, and `setup aws` / `teardown aws`.
- Live KMS conformance suite (`npm run test:live`) against real AWS, Google Cloud and OpenBao, with recorded fixtures replayed offline and drift detection.
- OpenTofu/Terraform modules for Cloud Run and ECS Express Mode using workload identity, a daemonless reproducible container image builder, and Docker, Kubernetes, Render and Railway templates.
- npm releases through trusted publishing (OIDC) with provenance.

[Unreleased]: https://github.com/solcreek/strongroom/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/solcreek/strongroom/compare/v0.1.0-alpha.1...v0.1.0
[0.1.0-alpha.1]: https://github.com/solcreek/strongroom/releases/tag/v0.1.0-alpha.1
