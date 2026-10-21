# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0.0, a minor version may change the HTTP API, CLI or configuration; the envelope format changes only with a new envelope `version`.

## [Unreleased]

### Added

- Binary plaintext, for secrets such as data keys. `POST /v1/encrypt` accepts `plaintextBase64url` instead of `plaintext`. `POST /v1/decrypt` returns the raw bytes as `application/octet-stream` when asked with `Accept`. The envelope format is unchanged, and text envelopes can be read either way.
- `PLAINTEXT_NOT_TEXT` (406): a plaintext that is not valid UTF-8 was decrypted as JSON text.
- SDK: `encrypt` takes a `Uint8Array` plaintext. `decryptBytes` returns a `Uint8Array` read without ever becoming a string, and wipes the transport chunks.
- CLI: `encrypt --plaintext-file` and `decrypt --plaintext-file` move raw bytes through files; a decrypted file is new and mode 0600.
- `examples/`: four runnable apps, each running one local deployment per tenant: bring-your-own API keys, rotating OAuth tokens, per-tenant data keys with crypto-shredding, and agent tools. Each lists common designs. A comparison covers using Strongroom versus calling AWS KMS or Cloud KMS yourself, including when to do the latter. `tests/examples.test.mjs` runs them all.
- CLI: `init --tenant T --port P` creates one local development deployment for that tenant. `server.env` sets `PORT`, `client.env` points at it, and the output names the `url` and the `next` command. Run it once per tenant for a local multi-tenant setup. The local tenant is limited to `^[A-Za-z0-9._-]{1,64}$` because it is written into an env file.
- SDK: `ErrorCode`, a union of every code `StrongroomError.code` can carry, and the runtime lists `serviceErrorCodes` and `clientErrorCodes`. A test keeps them equal to the service's `capabilities.errors` and to the codes the SDK raises.

### Changed

- **Breaking:** one deployment serves exactly one tenant. `STRONGROOM_CONFIG` takes a top-level `tenantId`, and principals no longer have one; a principal that still carries a `tenantId` is rejected at `$.principals[N].tenantId`, with a message pointing to `$.tenantId`. Every request's `context.tenantId` must equal the deployment's tenant, or it gets `FORBIDDEN`. To serve many tenants, run one deployment per tenant, each with its own KMS key and identity (see `docs/security.md`, "Tenant isolation"). Migrate by moving the principals' common `tenantId` to the top level. A configuration that mixed tenants becomes one configuration per tenant.
- **Breaking:** `strongroom token` no longer takes `--tenant`, and its `principal` has no `tenantId`. `setup aws|gcp --tenant` sets the configuration's `tenantId` and reports it as `tenantId`. `config-check` reports `tenantId`.
- **Breaking:** the Terraform modules take a `tenant_id` variable, and `principals` entries drop `tenant_id`. Apply a module once per tenant. `plan` fails on a principal that still has a `tenant_id` (Terraform would otherwise drop it silently and authorize that token for this tenant), and on a `tenant_id` over 256 UTF-8 bytes. Offline `tofu test` suites with mock providers cover both and run in CI.
- `FORBIDDEN` now says which check refused. `error.path` is `$.context.tenantId` (another tenant's deployment is needed), `$.key` or `$.envelope.key` (the token is not granted that key reference), or absent (the token may not perform the operation), and the message gives the next step. An unknown key reference reads the same as an ungranted one.
- **Breaking:** CLI `decrypt` no longer prints plaintext by default. It needs exactly one destination: `--output FILE`, `--plaintext-file FILE`, or `--reveal` for stdout. Without one it exits 2 before reading input or calling the service, so a secret never lands in an agent's transcript by accident.
- **Breaking:** setup and teardown are tenant-scoped end to end, so tenants can share an AWS account or GCP project.
  - **Names.** `setup aws|gcp` names the KMS alias or key ring, the IAM identity and the output directory `sr-<slug>-<10 hex of sha256(tenant)>`. The hash is always present, so no tenant id can be chosen to land on another tenant's name. `--name` still overrides it, and `--dry-run` shows it.
  - **Markers.** Every key, IAM user and service account setup creates carries the tenant's ownership marker: an AWS tag, a GCP label, or the service account's description.
  - **Setup checks.** Setup reuses an existing key only if it is marked for the tenant. An existing identity of the same name belongs to this tenant (`RESOURCE_EXISTS`) or to another (`NOT_OWNED`). A role shared by several tenants gets one inline policy per deployment (`strongroom-kms-<name>`), and setup refuses to overwrite one that grants another key, such as the same name set up in another region.
  - **Teardown checks.** `teardown aws|gcp` requires `--tenant` and changes nothing unless it can prove every resource it touches is marked for that tenant (`NOT_OWNED`, exit 2). That covers the IAM user or service account, the key it would delete or unbind, and the key a role policy grants. Role grants are checked fail-closed: the policy must be exactly the one setup writes, on a key marked for the tenant (looked up in the key's own region) or no longer present. Every command setup prints includes `--tenant`.
  - **Teardown output** reports the key's state, not the request. `keptKey` is `true` (kept), `false` (scheduled for deletion or destruction, by this run or an earlier one) or `null` (not found, so nothing is claimed). AWS adds `keyScheduledForDeletion` and GCP adds `versionsScheduledForDestruction`, and the note explains a missing key instead of claiming a deletion. AWS schedules the key before removing its alias, so a failed schedule can be rerun. GCP stops on any gcloud failure without a status code, except gcloud's explicit binding-not-found message, instead of treating it as an absent binding.
  - **0.1.0 deployments.** Their resources carry no marker, so remove them by hand: the IAM user or service account, and the `strongroom-kms` role policy (`aws iam delete-role-policy --role-name ROLE --policy-name strongroom-kms`).
- `setup gcp` sets the key's destroy-scheduled duration explicitly (`--destroy-scheduled-duration`, default `7d`, 24h–120d), since Cloud KMS fixes it at creation. `teardown gcp --delete-key` reports each version's `destroyTime` and no longer claims a 30-day default.
- `KMS_KEY_UNAVAILABLE`'s action now covers destroyed keys too. Providers report disabled, pending-deletion and destroyed keys alike (AWS `DisabledException` for a key pending deletion, as recorded live; GCP `FAILED_PRECONDITION`). After `teardown --delete-key`, the error is the intended result.

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
