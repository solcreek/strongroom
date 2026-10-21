# Strongroom

TypeScript SDK and non-interactive JSON CLI for [Strongroom](https://github.com/solcreek/strongroom), a stateless service that protects user-supplied API keys with envelope encryption and a managed KMS (AWS KMS, Google Cloud KMS, Vault or OpenBao Transit). Your database stores only envelopes; the service decrypts them when an authorized caller needs to use a key.

This package talks to a deployed Strongroom service. It holds no KMS credentials and performs no local encryption. Strongroom is pre-1.0 and has not had an independent security audit.

## Provision a key (agents welcome)

With a signed-in `aws` or `gcloud` CLI, one command creates the KMS key and a least-privilege identity, writes a complete service configuration and a caller token to a new private directory, and verifies them with a real encrypt/decrypt:

```sh
npx strongroom setup aws --tenant acme --dry-run     # plan and required IAM permissions
npx strongroom setup aws --tenant acme
npx strongroom setup gcp --tenant acme --project my-project
npx strongroom teardown aws                          # exact inverse; the key survives unless --delete-key
```

Each Strongroom deployment serves exactly one tenant, the `--tenant` given to setup. For many tenants, run one deployment per tenant and route each tenant to its own URL and token.

## SDK

```ts
import { Strongroom } from 'strongroom';

const client = new Strongroom({ url: process.env.STRONGROOM_URL!, token: process.env.STRONGROOM_TOKEN! });
const context = { tenantId: 'your-tenant', recordId: 'credential-id', purpose: 'provider-api-key' };
const envelope = await client.encrypt({ key: 'primary', plaintext: userSuppliedApiKey, context });
// Persist the envelope; rebuild the context from trusted application metadata at use time.
const apiKey = await client.decrypt({ envelope, context });

// Binary secrets (e.g. a 32-byte data key): a Uint8Array in, a Uint8Array out, never a string.
const sealed = await client.encrypt({ key: 'primary', plaintext: dataKey, context });
const key = await client.decryptBytes({ envelope: sealed, context });
try { useKey(key); } finally { key.fill(0); }
```

Always read data keys with `decryptBytes`. `decrypt` returns any plaintext that happens to be valid UTF-8 as a string, and fails with `PLAINTEXT_NOT_TEXT` only for bytes that are not.

`StrongroomError` exposes `code`, `status`, `retryable`, `requestId`, `path` (the offending or refused input field) and `toJSON()`. `code` is typed as `ErrorCode`. `serviceErrorCodes` and `clientErrorCodes` list every code at runtime; each service code's status, retryability and next action are in `capabilities().errors`. Calls accept `{signal}`; the default deadline is 20 seconds; redirects are rejected; HTTP is allowed only on loopback; nothing is retried automatically. For a Cloud Run service with invoker IAM, pass `cloudRunIdToken`. Provide a custom `fetch` for Worker service bindings or other platform authentication.

## CLI

```sh
strongroom --help                     # JSON description of every command, flag and exit code
strongroom schema encrypt             # offline JSON Schema
strongroom encrypt --input request.json --output envelope.json
strongroom decrypt --envelope envelope.json --output plaintext.json < context.json
strongroom encrypt --plaintext-file dek.bin < key-and-context.json   # raw bytes in
strongroom decrypt --envelope dek.json --plaintext-file out.bin < context.json   # raw bytes out, new 0600 file
strongroom decrypt --envelope envelope.json --reveal < context.json   # only when stdout is where it must go
strongroom doctor                     # readiness and API version
strongroom probe --key primary --tenant acme   # real KMS roundtrip through the service
strongroom token --token-file app-token --keys primary   # principal for this tenant's deployment
strongroom config-check --input config.json
```

Set `STRONGROOM_URL` and `STRONGROOM_TOKEN` or `STRONGROOM_TOKEN_FILE` (plus `STRONGROOM_CLOUD_RUN_ID_TOKEN` for Cloud Run invoker IAM). Input is JSON on stdin or `--input FILE`. Success is one JSON value on stdout; errors are one JSON object on stderr with a stable `code` and, where useful, `path` and `next`. There are no prompts, and secrets never go in arguments. `--output` creates a new mode-0600 file and never overwrites.

Exit codes: 0 success, 2 input/config/file error, 3 authentication or authorization, 4 request or decryption rejected, 5 retryable network/provider error, 6 the service's KMS credentials or key need an operator, 1 other.

Strongroom protects recoverable credentials against database-only disclosure. It is not for login passwords, and an application with decrypt access still handles plaintext. Packages are published with npm provenance; verify with `npm audit signatures`.
