# Testing KMS providers

Three layers, cheapest first. Each provider adapter takes an injected `fetch`, so no global interception (MSW, nock) is needed.

| Layer | Command | Network | Proves |
| --- | --- | --- | --- |
| Unit | `npm run test:fast` | none | Request signing, AAD binding, CRC32C, token caching, sanitization, deadlines |
| Replay | `npm run test:fast` (`tests/providers.test.mjs`) | none | Every live-recorded upstream failure maps to the documented code, status and retryability |
| Live conformance | `npm run test:live` | real AWS, GCP, local OpenBao | The real APIs still behave as recorded; end-to-end through workerd and the Node host |

## Why recorded fixtures, not VCR cassettes

Byte-level record/replay does not fit KMS: SigV4 signatures embed timestamps, every DEK and ciphertext is random, and decrypt responses contain key material. `scripts/test-live.mjs --record` instead stores a **semantic** fixture per scenario in `tests/fixtures/kms/<provider>.json`: the HTTP status and only allowlisted machine fields (AWS `__type`, Google `error.code`/`error.status`, OAuth `error`, the fixed Transit messages the adapter classifies). Messages, ARNs, project IDs and emails are never written. Each fixture records the date it was verified.

Without `--record`, the live run compares every observed upstream failure against the fixture and reports **drift** — a provider changing its error shape fails the run instead of silently changing the error code callers see.

## Running live

```sh
npm run build
npm run test:live                               # aws, gcp, openbao — skips any provider without configuration
npm run test:live -- --provider openbao         # no account needed; runs in CI
npm run test:live -- --record                   # rewrite fixtures after an intentional change; review the diff
npm run test:live -- --mutate                   # also disable/re-enable the dedicated secondary keys
```

Output is one JSON report on stdout (`providers.*.results`, `endToEnd`, `failures`, `drift`); exit 1 on any failure or drift. Configuration comes from the environment or `.strongroom/live/live.env` (git-ignored, mode 0600):

```sh
STRONGROOM_LIVE_AWS_KEY_ARN=arn:aws:kms:us-east-1:ACCOUNT:key/...        # service user may Encrypt/Decrypt
STRONGROOM_LIVE_AWS_SECONDARY_ARN=arn:aws:kms:us-east-1:ACCOUNT:key/...  # service user has no grant
STRONGROOM_LIVE_AWS_CREDENTIALS_FILE=.strongroom/live/aws-service-credentials.json  # {"accessKeyId","secretAccessKey"}
STRONGROOM_LIVE_GCP_KEY=projects/P/locations/global/keyRings/R/cryptoKeys/primary
STRONGROOM_LIVE_GCP_SECONDARY=projects/P/locations/global/keyRings/R/cryptoKeys/secondary
STRONGROOM_LIVE_GCP_SA_FILE=.strongroom/live/gcp-sa.json                  # downloaded key; granted on primary only
```

The AWS CLI's default credentials (`aws configure export-credentials`) act as the administrator that produces cross-key ciphertexts and, with `--mutate`, disables keys. GCP administration uses the `authorized_user` ADC file from `gcloud auth application-default login`. The service credentials are deliberately least-privilege so that "not granted" scenarios exercise real IAM denials.

## Provisioning the test resources

AWS (run 2026-10-13):

```sh
aws kms create-key --region us-east-1 --description "strongroom live test" --query KeyMetadata.Arn --output text   # primary, then again for secondary
aws kms create-alias --region us-east-1 --alias-name alias/strongroom-dev --target-key-id PRIMARY_ARN
aws iam create-user --user-name strongroom-dev-live
aws iam put-user-policy --user-name strongroom-dev-live --policy-name strongroom-kms-primary \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kms:Encrypt","kms:Decrypt"],"Resource":"PRIMARY_ARN"}]}'
aws iam create-access-key --user-name strongroom-dev-live   # write AccessKeyId/SecretAccessKey to the 0600 credentials file
```

GCP (2026-10-13 these ran as the equivalent Cloud KMS and IAM REST calls with an ADC token, because the `gcloud` session needed reauthentication):

```sh
gcloud kms keyrings create strongroom-dev --location global
gcloud kms keys create primary --keyring strongroom-dev --location global --purpose encryption
gcloud kms keys create secondary --keyring strongroom-dev --location global --purpose encryption
gcloud iam service-accounts create strongroom-dev
gcloud kms keys add-iam-policy-binding primary --keyring strongroom-dev --location global \
  --member serviceAccount:strongroom-dev@PROJECT.iam.gserviceaccount.com --role roles/cloudkms.cryptoKeyEncrypterDecrypter
gcloud iam service-accounts keys create .strongroom/live/gcp-sa.json --iam-account strongroom-dev@PROJECT.iam.gserviceaccount.com
```

Cloud KMS can delete a key ring only once its keys are destroyed and deleted, and a deleted CryptoKey name can never be reused, so reuse these names across runs. Cost: AWS charges per KMS key per month; Cloud KMS charges per active key version.

## Live setup and teardown (Google Cloud, 2026-10-21)

The silo flow was run end to end against Cloud KMS in a fresh project (`strongroom-e2e-1021`), with two tenants (`acme`, `globex`) sharing it. Results:

| Step | Result |
| --- | --- |
| `setup gcp --tenant acme --dry-run` | name `sr-acme-822b33ad87`, plan includes `destroyScheduledDuration: 7d` |
| `setup gcp --tenant acme` | about 25 s; live verify passed. Key labelled `app=strongroom`, `strongroom-tenant=<hash>`; `destroyScheduledDuration: 604800s`; service account description `strongroom-tenant=<hash>`; no private key on stdout; files 0600 in a 0700 directory |
| local host with that config, `probe` | encrypt 390 ms, decrypt 189 ms, changed context rejected |
| 32-byte key via `--plaintext-file` | round-trips byte for byte |
| `decrypt` without a destination | exit 2 before any request |
| context for another tenant | `FORBIDDEN`, `path: $.context.tenantId` |
| `setup gcp --tenant globex` in the same project | `sr-globex-5bc1a08d28`; no collision |
| acme's envelope sent to globex's deployment | as acme: `FORBIDDEN`; relabelled as globex: `DECRYPT_FAILED` (globex's key cannot unwrap it) |
| `setup gcp --tenant globex --name <acme's name>` | `NOT_OWNED` (acme's key is not labelled for globex) |
| `teardown gcp --tenant globex --name <acme's name> --delete-key` | `NOT_OWNED`; acme's key, binding and account untouched |
| acme's printed teardown (`--tenant acme ... --delete-key`) | binding and account removed; version 1 `DESTROY_SCHEDULED`, `destroyTime` 7 days out; `keptKey: false` |
| decrypt through acme's running host afterwards | `KMS_ACCESS_DENIED` (upstream 401): the deleted account's cached token is revoked first |
| direct Cloud KMS unwrap with the owner's identity | still succeeded 47 s after scheduling, then `FAILED_PRECONDITION` (`KMS_KEY_UNAVAILABLE`) about a minute after |
| acme's teardown rerun | `keptKey: false`, 0 versions newly scheduled, note says an earlier teardown scheduled them |
| globex `probe` after acme's shred | unaffected |

**Destruction is not instant on Cloud KMS.** Google's pages do not state how quickly a version's state change reaches cryptographic requests; this run observed under about a minute. Allow for that before treating a tenant as shredded.

## Live setup and teardown (AWS, 2026-10-26)

The same flow against AWS KMS in `ap-northeast-1`, in one shared account, with tenants `acme` and `globex` on IAM users and `initech` on an IAM role. Results:

| Step | Result |
| --- | --- |
| `setup aws --tenant acme --dry-run` | name `sr-acme-822b33ad87` (the same derivation as on GCP) |
| `setup aws --tenant acme` | about 23 s; live verify passed on the 5th attempt (13 s) while the new IAM user propagated. Key tagged `app`, `strongroom-name`, `strongroom-tenant=<hash>`; user tagged `app`, `strongroom-tenant`; policy grants `kms:Encrypt`/`kms:Decrypt` on that key only, with the `strongroom` encryption context required; files 0600 in a 0700 directory |
| local host with that config, `probe` | encrypt 932 ms (first call, Taiwan to Tokyo), decrypt 164 ms, changed context rejected |
| 32-byte key via `--plaintext-file` | round-trips byte for byte; output file 0600 |
| `decrypt` without a destination | exit 2 before any request |
| context for another tenant | `FORBIDDEN`, `path: $.context.tenantId` |
| changed `recordId` on decrypt | `DECRYPT_FAILED` |
| `setup aws --tenant globex` in the same account | `sr-globex-5bc1a08d28`; no collision |
| acme's envelope sent to globex's deployment | as acme: `FORBIDDEN`; relabelled as globex: `KMS_ACCESS_DENIED` (exit 6), since globex's IAM user has no grant on acme's key. GCP answers `DECRYPT_FAILED` here |
| `setup aws --tenant globex --name <acme's name>` | `NOT_OWNED`; no key created |
| `teardown aws --tenant globex --name <acme's name> --delete-key` | `NOT_OWNED`; acme's key `Enabled`, access key `Active`, probe still passes |
| `setup aws --tenant initech --role-name R --no-verify` | role gets one inline policy, `strongroom-kms-sr-initech-4cdc1a4207` |
| `setup aws --tenant umbrella --role-name R` (same role) | `NOT_OWNED`: the role already serves another deployment; no key created |
| `setup aws --tenant initech --region us-east-1 --role-name R` | `NOT_OWNED`: the role's grant for that name is on another key; no key created in `us-east-1` |
| `teardown aws --tenant umbrella --name <initech's name> --role-name R` | `NOT_OWNED`; the policy stays |
| acme's printed teardown (`--delete-key`) | access key, user, then key scheduled (`deletionDate` 7 days out), then alias; `keptKey: false`; 11 s |
| decrypt through acme's running host afterwards | `KMS_KEY_UNAVAILABLE` at the first poll (2 s after teardown), then `KMS_ACCESS_DENIED` from 10 s on, once the deleted IAM user stopped authenticating |
| direct AWS KMS unwrap with the owner's identity | `KMSInvalidStateException` at the first poll (`KMS_KEY_UNAVAILABLE`) |
| acme's teardown rerun | `keptKey: null`: the alias is gone, so the key is not found; the note says an earlier teardown may have scheduled it and gives the tag to search by |
| globex `probe` after acme's shred | unaffected |
| initech's printed teardown (`--role-name`) | role policy removed, key scheduled, alias removed; the role is left with no policies |

**Pending deletion took effect within seconds on AWS**, unlike Cloud KMS. A key scheduled for deletion without being disabled first answers `KMSInvalidStateException`; one disabled first answers `DisabledException` (2026-10-13). Both map to `KMS_KEY_UNAVAILABLE`.

The aws CLI printed `DeletionDate` in a `-06:00` offset on a UTC+8 machine; teardown now reports it in UTC.

## Observed provider behaviour (2026-10-13)

- `containerCredentials` is exercised against real KMS through a loopback stand-in for the ECS/EKS credential endpoint that serves a real STS session; the endpoint itself is emulated there. On 2026-10-13 the same path also ran on real ECS Fargate (task role) through `deploy/terraform/aws-ecs-express`.
- AWS temporary credentials from `sts get-session-token` roundtrip through the `sessionToken` path; a wrong secret with a valid session token is `InvalidSignatureException`.
- AWS KMS returns HTTP 400 for every client error, including `AccessDeniedException`, `UnrecognizedClientException` (unknown key ID or invalid session token), `InvalidSignatureException` (wrong secret), `NotFoundException` and `DisabledException`. A key pending deletion that was disabled first reports `DisabledException`.
- With least-privilege credentials, AWS decrypting a ciphertext from another key returns `AccessDeniedException`; with a grant on both keys it returns `IncorrectKeyException`.
- GCP returns 403 `PERMISSION_DENIED` for an ungranted key, and also for a **nonexistent** key when the caller lacks access; 404 only when the caller could see it. Wrong AAD, malformed ciphertext and ciphertext from another key are all 400 `INVALID_ARGUMENT`. A disabled version is 400 `FAILED_PRECONDITION`.
- Disabling a key is not immediate for encryption: on both AWS and GCP, Decrypt was refused at once while Encrypt kept succeeding for 30+ seconds. The live suite accepts either outcome for `encrypt-disabled-*`.
- OAuth: an unregistered key, unknown service account or invalid refresh token is 400 `invalid_grant`; a wrong client secret is 401 `invalid_client`.
- OpenBao 2.7.1 Transit: wrong context, malformed or future-version ciphertext and other-key ciphertext are 400; a missing key on decrypt is 400 `encryption key not found`; a version below `min_decryption_version` is 400; denied, revoked or invalid tokens are 403; sealed is 503.
- Latency from Taiwan to `us-east-1` through workerd: about 230 ms for the first Encrypt (connection setup) and 55 ms for a following Decrypt.
