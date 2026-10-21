# Examples

Four common ways applications hold other people's secrets, each as a small runnable app. Every app starts its own local Strongroom deployments, one per tenant as in production, with the development-only local provider. They need no cloud account and no network.

```sh
npm run build                              # the Node host and SDK the examples use
node examples/byok-api-keys/main.mjs       # users bring their own provider API keys
node examples/oauth-integrations/main.mjs  # rotating OAuth refresh tokens from background workers
node examples/tenant-data-keys/main.mjs    # per-tenant data keys for files at rest, and crypto-shredding
node examples/agent-tools/main.mjs         # an AI agent uses a credential it never sees
```

Each run prints one JSON line per step and exits non-zero if any property it demonstrates fails. `tests/examples.test.mjs` runs all four.

| Example | Secret | What it shows |
| --- | --- | --- |
| [byok-api-keys](byok-api-keys/) | A user's API key for a third-party service | Encrypt-only and decrypt-only callers; a context that stops envelopes being swapped between records; rotation by overwrite |
| [oauth-integrations](oauth-integrations/) | OAuth access and refresh tokens | Refresh-token rotation done exactly once across concurrent workers; separate purposes per token type |
| [tenant-data-keys](tenant-data-keys/) | A tenant's 32-byte data encryption key | Bulk data encrypted locally; the key wrapped by the tenant's own deployment; binary plaintext you can wipe; DEK rotation; destroying one tenant's data, including snapshots |
| [agent-tools](agent-tools/) | A credential an AI agent's tools use | Credential handles instead of secrets in the model's context; redacting tool output; record-level authorization in the tool runtime |

To run an example against real deployments, provision and deploy one per tenant. Give each its own `--name` and `--directory`, because setup's names do not yet derive from the tenant:

```sh
strongroom setup aws --tenant acme   --name sr-acme   --directory .strongroom/acme
strongroom setup aws --tenant globex --name sr-globex --directory .strongroom/globex
```

Deploy each directory's `config.json` as its own service. Keep each `--name` for the matching `teardown`. Then replace `startDeployment()` with each deployment's URL and tokens.

## Strongroom or your cloud's KMS directly?

Strongroom does not replace KMS: AWS KMS, Cloud KMS, Vault or OpenBao still hold the root keys and do every wrap and unwrap. What changes is who talks to KMS and how much of the envelope-encryption work each application rebuilds.

| | Calling AWS KMS / Cloud KMS yourself | Through Strongroom |
| --- | --- | --- |
| Credentials in your apps | Every service that reads a secret needs cloud IAM credentials and the cloud SDK. | Apps hold a bearer token for one tenant's deployment, limited to `encrypt` and/or `decrypt` on named keys. Apps carry no cloud SDK and no KMS permission. |
| Envelope encryption | You build it: data key generation, AES-GCM, nonces, an encoding, a version field. Calling KMS `Encrypt` directly caps plaintext at 4 KiB on AWS and 64 KiB on Cloud KMS. | A versioned envelope format from one tested Rust core: a fresh key and nonce per envelope, and up to 64 KiB of text or bytes. |
| Binding a secret to its record | Optional. You must pass the same encryption context (AWS) or additional authenticated data (GCP) on every call, and decide what goes in it. | Always on. Tenant, record and purpose authenticate both the ciphertext and the wrapped key, so an envelope copied to another row does not open ([byok](byok-api-keys/)). |
| Least privilege per caller | IAM policies per service, with conditions on the encryption context. | Encrypt-only and decrypt-only tokens per caller, in one reviewed JSON configuration. |
| Tenant isolation | Your design. Shared keys, shared identities and ad hoc checks are the easy default. | One deployment per tenant, each with its own key and identity. The schema cannot express a second tenant ([why](../docs/security.md#tenant-isolation)). |
| More than one provider | Different APIs, identifiers and integrity checks per cloud: key ARNs and encryption context on AWS, resource names, AAD and CRC32C on GCP. | One HTTP API and SDK across AWS KMS, Cloud KMS, Vault and OpenBao. Moving providers means a new key reference and re-encrypting the stored envelopes, not new application code. |
| Errors | Provider-specific. AWS reports rejected credentials as HTTP 400. | Stable codes with `retryable` and a next action: `DECRYPT_FAILED` (never overwrite the record), `KMS_ACCESS_DENIED` and `KMS_KEY_UNAVAILABLE` (operator), `KMS_UNAVAILABLE` (retry). |
| Local development and tests | A cloud account, an emulator, or mocks that drift from the real API. | The local provider behind the same API, as in these examples. Real-KMS behaviour is pinned by recorded fixtures. |
| Provisioning | Key, key policy or IAM binding, identity and configuration, written by hand or in Terraform. | `strongroom setup aws\|gcp --tenant T`: one command with a dry-run plan and a live check. Terraform modules for Cloud Run and ECS. |
| Agents and scripts | SDK code. | A JSON CLI with schemas, exit codes and no prompts. Secrets stay off arguments, and off stdout when you decrypt with `--plaintext-file` or `--output` (a plain `decrypt` prints the plaintext). |

### What it costs, and when to call KMS yourself

- **One more service and one more hop.** Strongroom is stateless and runs on Workers, Cloud Run, ECS or any container host, but it is still a dependency: if it is down, decrypts fail just as they would if KMS were down. Each encrypt or decrypt is one HTTP call plus one KMS call.
- **No data-key caching.** Every operation reaches KMS, which is right for credentials used occasionally. For bulk or hot-path data, encrypt locally with a data key that Strongroom wraps once, as [tenant-data-keys](tenant-data-keys/) does. If you need thousands of KMS-backed operations per second in an AWS-only stack, the AWS Encryption SDK's hierarchical keyring fits better.
- **The deployment holds the tenant's KMS permission.** Your applications no longer do. A compromised Strongroom deployment exposes the secrets of the one tenant it serves, and of no other.
- **Pre-1.0 and not independently audited.** Review it against your own threat model ([security](../docs/security.md)).
- **Call KMS directly** when one AWS-only service owns its own secrets and the team already runs IAM well, or when you need KMS features Strongroom does not expose, such as asymmetric signing or HMAC. Symmetric keys held in an external key store (AWS XKS, Cloud EKM) work through Strongroom like any other key, though `setup` does not provision them.
