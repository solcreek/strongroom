# Configuration

Store one JSON object in the secret environment binding `STRONGROOM_CONFIG`. Keep `STRONGROOM_ALLOW_LOCAL=false` for managed deployments. Node reads configuration at startup; Workers rebuilds its cached service when bindings change. Unknown fields and unsupported providers fail closed.

```json
{
  "keys": {
    "primary": {
      "provider": "aws",
      "region": "us-east-1",
      "keyId": "arn:aws:kms:us-east-1:123456789012:key/REPLACE-WITH-KEY-ID",
      "accessKeyId": "REPLACE",
      "secretAccessKey": "REPLACE"
    }
  },
  "principals": [{
    "tokenSha256": "REPLACE-WITH-SHA256-HEX-OF-RANDOM-TOKEN",
    "tenantId": "your-tenant-id",
    "permissions": ["encrypt", "decrypt"],
    "keys": ["primary"]
  }]
}
```

Replace placeholders before use. Put the file under an ignored private directory such as `.strongroom/production.json`, mode 0600. Run `node packages/strongroom/dist/cli.js config-check --input .strongroom/production.json`. Diagnostics describe expected fields without echoing supplied values; validation makes no KMS calls.

The SDK/CLI receives the original random token via `STRONGROOM_TOKEN` or `STRONGROOM_TOKEN_FILE`, plus `STRONGROOM_URL`. The service receives only its digest. Generate token material without displaying it:

```sh
node --input-type=module <<'JS'
import { randomBytes, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const token = randomBytes(32).toString('base64url');
writeFileSync('.strongroom/production-token', token + '\n', { mode: 0o600, flag: 'wx' });
writeFileSync('.strongroom/production-token.sha256', createHash('sha256').update(token).digest('hex') + '\n', { mode: 0o600, flag: 'wx' });
JS
```

Read the digest into the principal configuration; distribute the original token only to the intended application. Rotate Strongroom tokens by adding a second principal with the new digest, migrating callers, then removing the old digest. Duplicate digests are rejected. Principals are bounded to 1000 and keys to 100 per service instance; use separate deployments when appropriate.

## AWS KMS

Use the AWS object above. Optional `sessionToken` supports preissued temporary credentials. `keyId` must be a full symmetric key ARN matching `region`; aliases are rejected. The service signs requests with SigV4 and only wraps 32-byte DEKs. Supply the least privilege `kms:Encrypt` and/or `kms:Decrypt` policy on the exact ARN. Automatic AWS credential discovery/renewal is not implemented.

Reference: [AWS Encrypt API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) and [AWS Decrypt API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html).

## Google Cloud KMS

```json
{
  "provider": "gcp",
  "keyId": "projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY",
  "serviceAccount": {
    "clientEmail": "ACCOUNT@PROJECT.iam.gserviceaccount.com",
    "privateKey": "-----BEGIN PRIVATE KEY-----\nREPLACE\n-----END PRIVATE KEY-----\n"
  }
}
```

Use a symmetric `ENCRYPT_DECRYPT` CryptoKey. Map the downloaded service account's `client_email` and `private_key` into these camelCase fields. The service signs an OAuth JWT, caches short-lived access tokens, refreshes before expiry and validates KMS CRC32C responses. Grant the service account encrypt/decrypt access on the exact CryptoKey. This alpha uses service-account credentials even on GCP; Workload Identity/ADC is not yet implemented.

Reference: [GCP encrypt API](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt) and [service account OAuth](https://developers.google.com/identity/protocols/oauth2/service-account).

## Vault and OpenBao

```json
{
  "provider": "openbao",
  "url": "https://bao.example.com",
  "mount": "transit",
  "keyName": "strongroom",
  "token": "REPLACE"
}
```

Use `provider: "vault"` for Vault. Both use Transit; `namespace` is optional. The URL must be an HTTPS origin, with no credentials, path, query or fragment. HTTP loopback is accepted only with the explicit local-development opt-in. Workers must be able to reach the configured endpoint; a private cluster endpoint needs networking/proxy setup outside this package.

Provision a non-exportable derived `aes256-gcm96` key in Transit, with convergence disabled. Example for OpenBao (admin provisioning only):

```sh
bao secrets enable transit
bao write transit/keys/strongroom type=aes256-gcm96 derived=true exportable=false allow_plaintext_backup=false
```

Service token policy:

```hcl
path "transit/encrypt/strongroom" { capabilities = ["update"] }
path "transit/decrypt/strongroom" { capabilities = ["update"] }
```

Use `vault` in place of `bao` for Vault. Tokens must be renewed or replaced externally.

## Provider error mapping

Upstream failures map to four stable codes; upstream messages are never forwarded.

| Code | HTTP | Retryable | Upstream evidence |
| --- | --- | --- | --- |
| `DECRYPT_FAILED` | 400 | no | AWS `InvalidCiphertextException` / `IncorrectKeyException`; GCP decrypt `INVALID_ARGUMENT`; Transit decrypt 400 |
| `KMS_ACCESS_DENIED` | 502 | no | AWS `AccessDeniedException`, `UnrecognizedClientException`, `InvalidSignatureException`; GCP 401/403; OAuth `invalid_grant`/`invalid_client`; Transit 401/403 |
| `KMS_KEY_UNAVAILABLE` | 502 | no | AWS `NotFoundException`, `DisabledException`, `KMSInvalidStateException`; GCP 404 or `FAILED_PRECONDITION`; Transit missing key or version below `min_decryption_version` |
| `KMS_UNAVAILABLE` | 503 | yes | throttling, 5xx, network, timeout, redirects, malformed or unrecognized responses |

AWS KMS reports every client error, including rejected credentials, as HTTP 400 with a `__type`; never infer meaning from the status alone. With least-privilege credentials, decrypting a ciphertext produced by a different AWS key returns `AccessDeniedException` (KMS authorizes the embedded key first), so it surfaces as `KMS_ACCESS_DENIED`, not `DECRYPT_FAILED`.

Each KMS failure writes one JSON line to stderr (Node) or the Workers log: `{"event":"kms_error","requestId","operation","key","provider","code","upstreamStatus","upstreamCode"}`. `upstreamCode` is an allowlisted machine code (`__type`, Google `error.status`, OAuth `error`), never a message. Match the response's `x-request-id` to find it.

References: [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit), [OpenBao Transit](https://openbao.org/docs/secrets/transit/).
