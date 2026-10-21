# Per-tenant data keys and crypto-shredding

A multi-tenant app keeps each tenant's files encrypted at rest under that tenant's own key: SQLite databases, uploads, search indexes. Destroying one KMS key must make that tenant's data unrecoverable, including in backups and volume snapshots. Strongroom never sees the bulk data. It wraps one 32-byte data encryption key (DEK) per tenant, under the tenant's own deployment and KMS key.

```sh
npm run build && node examples/tenant-data-keys/main.mjs
```

The run proceeds in this order:

1. Two tenants write encrypted files.
2. Acme reads its file back.
3. Globex's deployment refuses Acme's wrapped DEK.
4. Acme rotates to a v2 DEK while v1 files stay readable.
5. Globex leaves after a snapshot was taken. Its key is destroyed, and the snapshot's copy of its data no longer opens. Acme's copy still does.

## Common designs

1. **Strongroom wraps keys, not data.** Generate the DEK locally, encrypt it with Strongroom as bytes (`plaintext: Uint8Array`), and store only the envelope. Encrypt files locally with AES-GCM under the DEK. One KMS call per process start, not per read.
2. **Never hold the DEK as a string.** `decryptBytes()` returns a `Uint8Array`. Import it as a non-extractable `CryptoKey`, then `fill(0)` the bytes. Wipe the freshly generated DEK the same way once it is wrapped.
3. **One deployment per tenant.** A routing table in the control plane maps each tenant to its deployment's URL and token. A tenant's envelope sent to another tenant's deployment is refused (`FORBIDDEN`). Even a deployment miswired to the wrong key cannot open it, because the tenant is in the authenticated data.
4. **Version the DEK.** `recordId: storage/dek/v<n>`, with the version stored in each file's header. New writes use the newest DEK. Old versions stay readable until their files are rewritten, and only then is the old envelope deleted.
5. **Bind each file to its place.** Use the tenant and path as AES-GCM additional data, so a file moved to another path or tenant fails to decrypt.
6. **Isolate callers too, not only deployments.** Per-tenant deployments keep each tenant's KMS permission apart, so a compromised Strongroom deployment exposes one tenant. This example's single process still holds every tenant's token, though, so compromising the app exposes every tenant's DEK. To bound that as well, give each tenant (or each group of tenants) its own app process or worker pool. Each one should get only its own tenants' tokens, for example from a per-tenant secret, rather than one process that loads them all.
7. **Shred by destroying the tenant's KMS key.** Deleting the envelope is not enough: snapshots keep copies of everything on the volume, the envelope included. Destroying the KMS key makes every copy of the wrapped DEK useless. `strongroom teardown aws|gcp --delete-key` schedules destruction. AWS waits 7–30 days; Cloud KMS waits 24 hours to 120 days, and material can take 45 more days to leave Google's backups. Decrypts fail as soon as destruction is scheduled. Evict DEKs that running processes already unwrapped.

Two practical limits:

- With random 96-bit nonces, keep each DEK under about 2³² encryptions: rotate long before that.
- Locally, a destroyed key shows up as `DECRYPT_FAILED`. Real KMS answers `KMS_KEY_UNAVAILABLE`.

## Why Strongroom here

Doing this directly against KMS means every app process holds KMS permissions for every tenant's key, which is exactly the shared blast radius per-tenant keys are meant to avoid. With Strongroom, each tenant's KMS permission lives in that tenant's deployment. The app holds one token per tenant, which design 6 can split across processes, and binary plaintext lets it handle DEKs without string copies. Provisioning a tenant is `strongroom setup aws|gcp --tenant T`, and offboarding is the matching teardown. See the [comparison](../README.md#strongroom-or-your-clouds-kms-directly).
