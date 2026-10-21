# Bring-your-own API keys

A SaaS lets each user paste a key for a third-party service (OpenAI, Stripe, a mail provider) and calls that service on the user's behalf. The database holds only envelopes, and a key exists in plaintext only for the duration of the call.

```sh
npm run build && node examples/byok-api-keys/main.mjs
```

The run stores Alice's key and uses it for a chat call. It then shows three refusals:

- the settings service cannot read the key back;
- Alice's envelope copied into Mallory's row does not open;
- after rotation, the new key works and the old one is gone.

## Common designs

1. **Split callers by job.** The settings page gets an `encrypt`-only token; the worker that calls the provider gets a `decrypt`-only token. A breach of the public-facing settings service then leaks nothing. Both tokens belong to the same tenant's deployment.
2. **Context from trusted identifiers.** `recordId` is built from the authenticated user and the provider name (`user/alice/provider/openai`), never from the request body. Envelopes are bound to that record, so someone with write access to the database cannot move one user's key into another user's row.
3. **Store a non-secret hint.** Keep `last4` (or a fingerprint) beside the envelope so the UI can show "sk-…1234" without a decrypt. Every decrypt should correspond to a real use.
4. **Decrypt per use; cache only deliberately.** Strongroom itself never caches plaintext. If one key serves many calls per second, cache the plaintext in the worker for seconds, keyed by the envelope, and accept that the key then lives in that process's memory.
5. **Rotate by overwrite.** A new key is a new envelope written over the old one. No other data is encrypted under it, so nothing else needs re-encrypting.
6. **Delete by deleting the row.** For data that must also be unrecoverable from backups, encrypt it under a per-tenant key you can destroy ([tenant-data-keys](../tenant-data-keys/)).

## Why Strongroom here

Without Strongroom, both the settings service and the worker need KMS permissions and the cloud SDK, and each must build envelopes and pass the right encryption context on every call. Here they get one token each, and the context binding is not optional. Provisioning and local development are the same everywhere: `strongroom setup aws|gcp --tenant T` and `npm run dev:init`. See the [comparison](../README.md#strongroom-or-your-clouds-kms-directly).
