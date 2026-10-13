# Security boundaries

Strongroom protects recoverable third-party credentials against a **database-only disclosure** when the attacker cannot also obtain service authorization and KMS access. This is not a password hashing system. Hash account login passwords with a dedicated password hashing function in the application.

The application and Strongroom handle plaintext at use time. Compromise of an application with decrypt permission, the running service, its credentials, or its memory can expose secrets. Managed KMS does not prevent an authorized or compromised caller from requesting decryption.

The implementation uses RustCrypto AES-GCM, host CSPRNG entropy, authenticated metadata, tenant-bound principals and explicit grants. It has automated tests but has not received an independent cryptographic/security audit. Treat this alpha as development software until your deployment and trust boundaries have been reviewed.

## Authorization

A bearer token authorizes exactly one tenant, an explicit operation set, and explicit key references. Configuration stores a SHA-256 digest, not the raw bearer token. Generate at least 32 random bytes and encode as base64url. A digest is appropriate for these high-entropy random tokens; it is not appropriate for human passwords.

An application must still authorize which of its users may access a record. A principal allowed to decrypt for a tenant can decrypt any envelope for that tenant and granted key if it knows the original context. Record-level authorization is the application's responsibility. Use distinct principals for ingestion (`encrypt` only) and workloads that require decryption, where possible.

Service configuration is trusted and is stored as a platform secret. Callers cannot choose provider URLs or KMS key IDs. The alpha supports static AWS credentials (including session tokens), a GCP service account private key with automatic OAuth refresh, and a Vault/OpenBao token. It does **not** yet implement AWS role credentials, GCP workload identity federation, Vault auth login/renewal, token expiry on the Strongroom side, or per-request identity federation. Rotate external credentials before expiry and update the service secret; restarts are required for Node environment changes.

## Deployment responsibilities

- Terminate TLS before exposing the HTTP host. Node binds loopback by default; Docker binds all interfaces for the platform ingress. Keep internal traffic on a trusted private network or protected transport.
- Configure ingress rate limits, authentication-aware quotas and network exposure for your deployment. The stateless alpha has no distributed rate limiter.
- Grant KMS encrypt/decrypt only on selected keys. Never grant key creation/deletion or administrative permissions to the service. Transit requires precreated, non-exportable `aes256-gcm96` derived keys and `update` permissions only on the selected encrypt/decrypt endpoints.
- Keep platform request/body tracing disabled or redacted. Strongroom does not log request bodies, plaintext, bearer tokens, DEKs, upstream bodies, or exception stacks. Integrations and proxies must preserve this property.
- Context can appear in KMS audit records. Use nonsecret opaque identifiers. Do not place API keys, passwords or personal details in tenant/record/purpose values.
- Back up envelopes and retain KMS key versions. Losing or disabling an old KMS key can make stored credentials unrecoverable. Do not remap an existing reference to a different KMS key.

Rust zeroizes owned DEK/entropy buffers, and the host wipes mutable DEK/entropy arrays after use. JSON strings, JavaScript strings, Wasm linear memory, allocator copies and plaintext returned to the application cannot be guaranteed erased. Do not claim full memory zeroization.

The local provider uses an explicitly configured random KEK and requires `STRONGROOM_ALLOW_LOCAL=true`. It is only for local development. Anyone with that KEK and the original context can decrypt the envelopes. The POC's public fixed key is isolated in `poc/` and is never accepted by this service.
