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

Key rings cannot be deleted. Cost: AWS charges per KMS key per month; Cloud KMS charges per active key version.

## Observed provider behaviour (2026-10-13)

- AWS KMS returns HTTP 400 for every client error, including `AccessDeniedException`, `UnrecognizedClientException` (unknown key ID or invalid session token), `InvalidSignatureException` (wrong secret), `NotFoundException` and `DisabledException`. A key pending deletion that was disabled first reports `DisabledException`.
- With least-privilege credentials, AWS decrypting a ciphertext from another key returns `AccessDeniedException`; with a grant on both keys it returns `IncorrectKeyException`.
- GCP returns 403 `PERMISSION_DENIED` for an ungranted key, and also for a **nonexistent** key when the caller lacks access; 404 only when the caller could see it. Wrong AAD, malformed ciphertext and ciphertext from another key are all 400 `INVALID_ARGUMENT`. A disabled version is 400 `FAILED_PRECONDITION`.
- Disabling a key is not immediate for encryption: on both AWS and GCP, Decrypt was refused at once while Encrypt kept succeeding for 30+ seconds. The live suite accepts either outcome for `encrypt-disabled-*`.
- OAuth: an unregistered key, unknown service account or invalid refresh token is 400 `invalid_grant`; a wrong client secret is 401 `invalid_client`.
- OpenBao 2.7.1 Transit: wrong context, malformed or future-version ciphertext and other-key ciphertext are 400; a missing key on decrypt is 400 `encryption key not found`; a version below `min_decryption_version` is 400; denied, revoked or invalid tokens are 403; sealed is 503.
- Latency from Taiwan to `us-east-1` through workerd: about 230 ms for the first Encrypt (connection setup) and 55 ms for a following Decrypt.
