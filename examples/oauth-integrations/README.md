# OAuth integrations with rotating refresh tokens

An integration platform stores each customer's OAuth tokens (Slack, GitHub, Google…) and refreshes them from background workers. Refresh tokens rotate on every use. Many identity providers treat a replayed refresh token as theft and revoke the whole grant. A refresh must therefore happen once, and its result must be written back exactly once.

```sh
npm run build && node examples/oauth-integrations/main.mjs
```

Three workers ask for an expired token at the same moment. One refreshes, and all three get the same new access token. The run then shows what happens without coordination: replaying the rotated refresh token makes the provider revoke the grant. Then a worker dies between the provider call and the write-back. The next worker sees the expired lease and marks the connection for reconnection instead of replaying the consumed token. Last, a retryable failure on the decrypt, before the provider call, releases the lease, and the next attempt refreshes normally.

## Common designs

1. **One refresh per connection, enforced in the database.** A worker takes a lease with a compare-and-set on a version column, and the others wait for the new version instead of reusing the old refresh token. An in-process mutex is not enough once there is more than one worker process.
2. **A lost lease means reconnect, never retry.** A lease that expired without being cleared means a refresh may have reached the provider and then been lost, so the stored refresh token may already be consumed. Retrying would replay it and revoke the grant, and no lease length rules that out. Mark the connection `reconnect-required` and ask the customer to authorize again. For that to mean something, release the lease on any failure before the provider call, such as a retryable `KMS_UNAVAILABLE` on the decrypt: nothing was consumed yet, so a retry is safe and must not cost a reconnect. The run simulates both cases.
3. **Encrypt before you write, and write both tokens in one update.** The new access and refresh envelopes go into the same row update as the version bump, so the stored tokens never disagree. A crash after the provider call but before the write is the one window that loses a grant; keep it short, and design 2 turns it into a reconnect rather than a revocation.
4. **A purpose per token type.** `oauth-access-token` and `oauth-refresh-token` are different contexts, so an access-token envelope can never be decrypted as a refresh token.
5. **The callback only encrypts.** The OAuth redirect handler is internet-facing and only stores tokens, so it gets an `encrypt`-only token. The refresher, which rewrites tokens, gets `encrypt` and `decrypt`.
6. **Act on error codes, not messages.** Retry `retryable` errors (`KMS_UNAVAILABLE`, `NETWORK_ERROR`, `TIMEOUT`) with backoff. On `DECRYPT_FAILED`, mark the connection broken for a person: never overwrite it with empty values. `KMS_ACCESS_DENIED` and `KMS_KEY_UNAVAILABLE` page an operator.

## Why Strongroom here

Every worker would otherwise hold KMS permissions and the cloud SDK. Here a worker holds a token that can touch only this tenant's envelopes. Error handling needs no provider-specific parsing: each code says whether to retry, page an operator or stop. See the [comparison](../README.md#strongroom-or-your-clouds-kms-directly).
