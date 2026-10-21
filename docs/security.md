# Security boundaries

Strongroom protects recoverable third-party credentials against a **database-only disclosure** when the attacker cannot also obtain service authorization and KMS access. This is not a password hashing system. Hash account login passwords with a dedicated password hashing function in the application.

The application and Strongroom handle plaintext at use time. Compromise of an application with decrypt permission, the running service, its credentials, or its memory can expose secrets. Managed KMS does not prevent an authorized or compromised caller from requesting decryption.

The implementation uses RustCrypto AES-GCM, host CSPRNG entropy, authenticated metadata, single-tenant deployments and explicit grants. It has automated tests but has not received an independent cryptographic/security audit. Review your deployment and trust boundaries before protecting production credentials with it.

## Tenant isolation

One deployment serves exactly one tenant (`$.tenantId`); serving many tenants means one deployment per tenant. This is enforced by the configuration schema, not left to operators. Give each deployment its own KMS key and its own KMS identity, ideally in its own GCP project or AWS account.

The reason is blast radius. A shared service whose identity can reach every tenant's keys exposes all of them when that identity, or the process holding it, is compromised. Giving each tenant its own key would add crypto-shredding but would not shrink that radius. Neither would credentials that Strongroom narrowed to one tenant per request, because Strongroom would still hold the right to mint any tenant's credential.

| Threat | Shared deployment, per-tenant keys | One deployment per tenant |
| --- | --- | --- |
| Authorization bug in Strongroom crosses tenants | KMS allows it | No other tenant's key is reachable |
| Strongroom process or its KMS credential compromised | Every tenant | That tenant only |
| KMS quota contention (AWS: per account and Region; GCP: per key project) | Shared | Isolated with a project or account per tenant |

`context.tenantId` must equal the deployment's tenant, and it stays in the AAD, so even a deployment miswired to another tenant's key cannot open that tenant's envelopes. This isolation pays off only if the caller does not collapse it again. An application that holds every tenant's Strongroom token in one process is the shared component, and its own isolation decides the outcome.

## Authorization

A bearer token authorizes one deployment's tenant, an explicit operation set, and explicit key references. Configuration stores a SHA-256 digest, not the raw bearer token. Generate at least 32 random bytes and encode as base64url. A digest is appropriate for these high-entropy random tokens; it is not appropriate for human passwords.

An application must still authorize which of its users may access a record. A principal allowed to decrypt for a tenant can decrypt any envelope for that tenant and granted key if it knows the original context. Record-level authorization is the application's responsibility. Use distinct principals for ingestion (`encrypt` only) and workloads that require decryption, where possible.

Service configuration is trusted and is stored as a platform secret. Callers cannot choose provider URLs or KMS key IDs. Strongroom supports static AWS credentials (including session tokens), a GCP service account private key with automatic OAuth refresh, the GCP metadata server (Cloud Run, GKE Workload Identity), a local-development ADC refresh token, and a Vault/OpenBao token. AWS keys can also use the ECS task role or EKS Pod Identity (`containerCredentials`). It does **not** yet implement EC2 instance profiles, AWS `AssumeRoleWithWebIdentity`, GCP external workload identity federation, Vault auth login/renewal, token expiry on the Strongroom side, or per-request identity federation. Rotate external credentials before expiry and update the service secret; restarts are required for Node environment changes.

## Deployment responsibilities

- Terminate TLS before exposing the HTTP host. Node binds loopback by default; Docker binds all interfaces for the platform ingress. Keep internal traffic on a trusted private network or protected transport.
- Configure ingress rate limits, authentication-aware quotas and network exposure for your deployment. The stateless service has no distributed rate limiter.
- Grant KMS encrypt/decrypt only on selected keys. Never grant key creation/deletion or administrative permissions to the service. Transit requires precreated, non-exportable `aes256-gcm96` derived keys and `update` permissions only on the selected encrypt/decrypt endpoints.
- Keep platform request/body tracing disabled or redacted. Strongroom does not log request bodies, plaintext, bearer tokens, DEKs, upstream bodies, or exception stacks. Integrations and proxies must preserve this property.
- Context can appear in KMS audit records. Use nonsecret opaque identifiers. Do not place API keys, passwords or personal details in tenant/record/purpose values.
- Back up envelopes and retain KMS key versions. Losing or disabling an old KMS key can make stored credentials unrecoverable. Do not remap an existing reference to a different KMS key.

Rust zeroizes owned DEK/entropy buffers, and the host wipes mutable DEK/entropy arrays after use. JSON strings, JavaScript strings, Wasm linear memory, allocator copies and plaintext returned to the application cannot be guaranteed erased. Do not claim full memory zeroization.

Binary plaintext narrows this on the caller's side only. `decryptBytes` reads `application/octet-stream` into a `Uint8Array`, wipes the transport chunks and never makes a string, so the caller can `fill(0)` the one copy it gets. Encrypting bytes still sends them as base64url text, and the service still passes plaintext through the Wasm bridge as JSON strings.

The local provider uses an explicitly configured random KEK and requires `STRONGROOM_ALLOW_LOCAL=true`. It is only for local development. Anyone with that KEK and the original context can decrypt the envelopes. The POC's public fixed key is isolated in `poc/` and is never accepted by this service.
