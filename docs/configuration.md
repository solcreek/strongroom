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

Replace placeholders before use. Put the file under an ignored private directory such as `.strongroom/production.json`, mode 0600. Run `node packages/strongroom/dist/cli.js config-check --input .strongroom/production.json`. Failures exit 2 with `error.path` naming the field (for example `$.keys.primary.keyId`) and a message stating the rule; supplied values are never echoed. Validation makes no KMS calls.

The SDK/CLI receives the original random token via `STRONGROOM_TOKEN` or `STRONGROOM_TOKEN_FILE`, plus `STRONGROOM_URL`. The service receives only its digest. Generate a token without displaying it:

```sh
node packages/strongroom/dist/cli.js token --token-file .strongroom/production-token --tenant your-tenant-id --keys primary --permissions encrypt,decrypt
```

The token goes only to the new 0600 file (an existing path is refused). Stdout returns `tokenSha256` and, with `--tenant` and `--keys`, a complete `principal` object to append to `principals`. Distribute the original token only to the intended application. Rotate Strongroom tokens by adding a second principal with the new digest, migrating callers, then removing the old digest. Duplicate digests are rejected. Principals are bounded to 1000 and keys to 100 per service instance; use separate deployments when appropriate.

## AWS KMS

Use the AWS object above. Optional `sessionToken` supports preissued temporary credentials. On ECS/Fargate or EKS Pod Identity, replace `accessKeyId`/`secretAccessKey` with `"containerCredentials": true`: the service then fetches the task or pod role's temporary credentials from `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `AWS_CONTAINER_CREDENTIALS_FULL_URI` (+ `AWS_CONTAINER_AUTHORIZATION_TOKEN`), caches them until five minutes before `Expiration`, and refetches after a rejection. A plain-HTTP full URI must be link-local or loopback. Not available in Cloudflare Workers. `keyId` must be a full symmetric key ARN matching `region`; aliases are rejected. The service signs requests with SigV4 and only wraps 32-byte DEKs. Supply the least privilege `kms:Encrypt` and/or `kms:Decrypt` policy on the exact ARN. EC2 instance profiles (IMDS), `AssumeRoleWithWebIdentity` and shared credential files are not implemented.

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

Use a symmetric `ENCRYPT_DECRYPT` CryptoKey. Each GCP key takes exactly one credential:

| Field | Use | Token source |
| --- | --- | --- |
| `serviceAccount: {clientEmail, privateKey}` | Workers, any host | Signed OAuth JWT. Map the downloaded key file's `client_email` / `private_key`. |
| `metadataServer: true` | Cloud Run, GKE Workload Identity, Compute Engine — no key file | Metadata server; unreachable from Cloudflare Workers. |
| `authorizedUser: {clientId, clientSecret, refreshToken, quotaProject?}` | Local development with `gcloud auth application-default login` | OAuth refresh token from the ADC file (`client_id`, `client_secret`, `refresh_token`, `quota_project_id`). Not for production. |

Access tokens are cached until 60 s before expiry and dropped on the first 401/403, then refreshed. KMS CRC32C fields are verified in both directions. Grant only `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the exact CryptoKey.

Verified live 2026-10-13 against Cloud KMS: `serviceAccount` and `authorizedUser` (with and without `quotaProject`) in workerd and Node. `metadataServer` ran on Cloud Run against a CryptoKey in another project (see [deploy/terraform](../deploy/terraform/README.md)).

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

Upstream failures map to four stable codes; upstream messages are never forwarded. The mapping is pinned by live-recorded fixtures in `tests/fixtures/kms/` ([testing](testing.md)).

| Code | HTTP | Retryable | Upstream evidence |
| --- | --- | --- | --- |
| `DECRYPT_FAILED` | 400 | no | AWS `InvalidCiphertextException` / `IncorrectKeyException`; GCP decrypt `INVALID_ARGUMENT`; Transit decrypt 400 |
| `KMS_ACCESS_DENIED` | 502 | no | AWS `AccessDeniedException`, `UnrecognizedClientException`, `InvalidSignatureException`; GCP 401/403; OAuth `invalid_grant`/`invalid_client`; Transit 401/403 |
| `KMS_KEY_UNAVAILABLE` | 502 | no | AWS `NotFoundException`, `DisabledException`, `KMSInvalidStateException`; GCP 404 or `FAILED_PRECONDITION`; Transit missing key or version below `min_decryption_version` |
| `KMS_UNAVAILABLE` | 503 | yes | throttling, 5xx, network, timeout, redirects, malformed or unrecognized responses |

AWS KMS reports every client error, including rejected credentials, as HTTP 400 with a `__type`; never infer meaning from the status alone. With least-privilege credentials, decrypting a ciphertext produced by a different AWS key returns `AccessDeniedException` (KMS authorizes the embedded key first), so it surfaces as `KMS_ACCESS_DENIED`, not `DECRYPT_FAILED`.

Each KMS failure writes one JSON line to stderr (Node) or the Workers log: `{"severity","event":"kms_error","requestId","operation","key","provider","code","upstreamStatus","upstreamCode"}`. `upstreamCode` is an allowlisted machine code (`__type`, Google `error.status`, OAuth `error`), never a message. Match the response's `x-request-id` to find it. `severity` is `ERROR` for `KMS_ACCESS_DENIED` / `KMS_KEY_UNAVAILABLE` and `WARNING` otherwise; Cloud Logging uses it as the entry's level (query `jsonPayload.event="kms_error"`), and CloudWatch Logs Insights can filter on it.

References: [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit), [OpenBao Transit](https://openbao.org/docs/secrets/transit/).
