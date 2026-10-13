# Architecture

```mermaid
sequenceDiagram
  participant App as Application / Agent
  participant SR as Strongroom HTTP
  participant Core as Rust core (Wasm)
  participant KMS as Managed KMS / Transit
  participant DB as Application DB
  App->>SR: encrypt(plaintext, context, key reference)
  SR->>SR: Authenticate token; check tenant, operation, key
  SR->>Core: Fresh CSPRNG DEK + nonce; seal plaintext
  Core-->>SR: Ciphertext + canonical AAD
  SR->>KMS: Wrap 32-byte DEK with AAD
  KMS-->>SR: Wrapped DEK
  SR-->>App: Versioned envelope
  App->>DB: Store envelope
  App->>SR: decrypt(envelope, trusted context)
  SR->>SR: Authenticate and authorize again
  SR->>Core: Validate envelope; derive AAD
  SR->>KMS: Unwrap DEK with AAD and configured KMS key
  KMS-->>SR: DEK
  SR->>Core: Authenticate and decrypt ciphertext
  SR-->>App: Plaintext for immediate use
```

`crates/core` is the shared Rust library. Its internal JSON/Wasm bridge is **not a public API**: it accepts entropy and DEKs only from the trusted host. The HTTP layer rejects these fields. No POC module is imported by the service.

`service/app.ts` uses Web Request/Response and Web Crypto, with no Node APIs. The Worker and Node host load the same Rust Wasm and handler. Containers currently use Node + Wasm; there is no native Rust HTTP executable yet. A native host would need to pass these same cross-runtime tests before replacing the container path. Prior native benchmark numbers do not describe this container's performance.

Every encryption uses a fresh 32-byte DEK and 12-byte nonce from the host CSPRNG. AES-256-GCM ciphertext includes a 16-byte tag. Data keys are wrapped by the configured KMS, never persisted by Strongroom. No plaintext or unwrapped-key cache exists. Only OAuth access tokens and provider clients are cached in memory.

## Envelope v1

```json
{"version":1,"algorithm":"A256GCM","key":"primary","nonce":"base64url-no-padding","ciphertext":"base64url-no-padding","wrappedKey":"provider-opaque-value"}
```

Canonical AAD is Rust's compact JSON serialization of:

```json
["strongroom",1,"A256GCM","primary","tenant-id","record-id","purpose"]
```

The key reference and context are authenticated for both the ciphertext and wrapped key. AWS uses `EncryptionContext.strongroom = base64(AAD)`, GCP uses `additionalAuthenticatedData`, Transit uses both derivation `context` and `associated_data`. Context must be regenerated from trusted application identifiers for decryption. Renaming a key reference or changing context makes an existing envelope undecryptable under the new values.

`key` is a stable server-configured reference, never an arbitrary provider URL or KMS identifier from the caller. AWS pins an immutable key ARN and validates the response ARN. GCP pins a CryptoKey and verifies returned encryption version ancestry and CRC32C. Rotation within the same KMS key retains access to old versions. To migrate to a different KMS key/provider, create a new reference, retain the old mapping, decrypt with the original context, encrypt using the new reference, then replace the database envelope transactionally. Rewrap-only migration is not implemented.

## Contracts

- `POST /v1/encrypt`: `{plaintext, context, key}` → `{envelope}`.
- `POST /v1/decrypt`: `{envelope, context}` → `{plaintext}`.
- `GET /v1/capabilities`: limits, operations, error codes and API version.
- `GET /openapi.json`: OpenAPI 3.1 and JSON Schemas.
- `GET /healthz`: liveness; does not require configuration or KMS access in Workers.
- `GET /readyz`: configuration validity; **does not test credentials or KMS connectivity**.

All responses use `Cache-Control: no-store`. Each response has a server-generated request ID. Errors return `{error:{code,message,retryable,requestId}}`; provider responses and exception stacks are not forwarded. `GET /v1/capabilities` lists every error code with its status, retryability and next action. Provider failures are classified from allowlisted upstream codes (see [configuration](configuration.md#provider-error-mapping)) and logged once per request as a sanitized `kms_error` event. Public metadata endpoints disclose no configured key identities or principals. There is no CORS opt-in; this is a backend-to-backend API.

Inputs are bounded to 512 KiB, plaintext to 64 KiB UTF-8, and each context field to 256 UTF-8 bytes. Request bodies and each upstream request have an 8-second deadline. SDK defaults to 20 seconds to allow OAuth refresh plus KMS. Redirects are handled manually and rejected: Workers does not implement Fetch's `redirect: "error"` mode. No automatic retries occur; retryable failures may be retried with bounded backoff, recognizing that each encrypt attempt creates a different envelope.
