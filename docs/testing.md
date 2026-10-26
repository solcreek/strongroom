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

## The live environment

The cloud resources the suite runs against are code: `infra/live-test/aws` and `infra/live-test/gcp` (OpenTofu). `scripts/live-env.mjs` (`npm run live:env --`) drives them and issues the service credentials each run needs. Credentials never enter OpenTofu state or the repository, and they do not outlive a run: each is issued for a run and revoked after it.

| Stack | Resources | Marker |
| --- | --- | --- |
| AWS (default `us-east-1`) | KMS keys `alias/strongroom-dev` (primary) and `alias/strongroom-dev-secondary`. IAM user `strongroom-dev-live`, with one inline policy granting `kms:Encrypt`/`kms:Decrypt` on the primary key only, with the `strongroom` encryption context required, as `setup aws` grants a deployment | tags `project=strongroom`, `purpose=integration-test`, `managed-by=opentofu` |
| GCP (project given once) | Key ring `strongroom-dev`, with keys `primary` and `secondary`. Service account `strongroom-dev`, granted `roles/cloudkms.cryptoKeyEncrypterDecrypter` on `primary` only | labels as above; the service account's description says `purpose=integration-test` |

The service identities have no grant on the secondary keys, so "not granted" scenarios exercise real IAM denials. `--mutate` disables the secondary keys and restores them. The keys have `prevent_destroy`: recorded ciphertexts depend on them, and a deleted CryptoKey name can never be reused.

### Run the suite

```sh
npm run build
npm run live:env -- status --gcp-project P        # once per clone: the project is remembered; AWS defaults to us-east-1
npm run live:env -- apply                         # adopts what exists, plans, and stops; review the changes
npm run live:env -- apply --yes                   # applies exactly the reviewed plan
npm run live:env -- credentials                   # a fresh AWS access key and GCP service account key, 0600; older ones are revoked
npm run test:live                                 # aws, gcp, openbao; skips any provider without configuration
npm run test:live -- --mutate                     # also disable/re-enable the secondary keys (about 2 more minutes)
npm run test:live -- --record                     # rewrite fixtures after an intentional change; review the diff
npm run live:env -- revoke                        # delete both credentials in the cloud and locally
```

Every command prints one JSON object with a `next` step. `status` lists each resource, with whether it carries the marker and whether it is in state, plus every live credential and its age. Add `--cloud aws` or `--cloud gcp` to act on one stack. `npm run test:live -- --provider openbao` needs no account and runs in CI.

`test:live` prints one JSON report on stdout (`providers.*.results`, `endToEnd`, `failures`, `drift`) and exits 1 on any failure or drift. Administration runs as you:
- AWS: the AWS CLI's default credentials produce the cross-key ciphertexts and, with `--mutate`, disable keys.
- GCP: the `authorized_user` ADC file from `gcloud auth application-default login`.

Without issued credentials, the suite also runs the service role as the administrator, and the "not granted" scenarios then expect success.

### Local files

The files live in `.strongroom/live/` at the root of the main checkout. Every worktree of the clone shares this directory, so a credential issued in one worktree can be seen and revoked from any other. `STRONGROOM_LIVE_DIR` overrides the location. The directory is ignored by version control and has mode 0700; every file in it is 0600.

| File | Holds |
| --- | --- |
| `settings.json` | the AWS region and GCP project |
| `tofu/<cloud>/` | OpenTofu state and providers. No secret: names, ARNs and IDs |
| `live.env` | key IDs, and the credential paths while credentials are issued. Read by `test:live` |
| `aws-service-credentials.json`, `gcp-sa.json` | the issued credentials, present only between `credentials` and `revoke` |

### New machine, lost state, or a fresh account

State is a cache, not the source of truth. When it is missing, `plan` and `apply` find the resources by name, check that each carries the `purpose=integration-test` marker, and import them. One unmarked resource refuses the whole adoption with `NOT_OWNED` before anything is imported, so a name collision never pulls someone else's key into the stack.

After an adoption, the plan shows only attributes the providers keep in state alone (`deletion_window_in_days`, `terraform_labels`). Applying them changes nothing in the cloud (verified 2026-10-26). In an account or project without the resources, `apply` creates them.

### Checks

`tofu -chdir=infra/live-test/<cloud> test` runs offline with mock providers. It asserts that each service identity reaches the primary key only, and for GCP that a project must be given. CI runs it with `fmt` and `validate`. `tests/live-env.test.mjs` covers adoption, `live.env` and argument handling.

Cost: AWS charges per KMS key per month; Cloud KMS charges per active key version.

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
- Disabling a key is not immediate.
  - On 2026-10-13, Decrypt was refused at once on both AWS and GCP, while Encrypt kept succeeding for 30+ seconds.
  - On 2026-10-26, Decrypt kept succeeding after the disable: for 58 s on AWS and for 60 s on GCP.
  - The suite now waits up to 3 minutes for `decrypt-disabled-*` and reports the wait as `waitedMs`. It accepts either outcome for `encrypt-disabled-*`.
  - Scheduling the AWS key's deletion after the disable has taken effect answers `DisabledException`; before that, it answers `KMSInvalidStateException`.
- OAuth: an unregistered key, unknown service account or invalid refresh token is 400 `invalid_grant`; a wrong client secret is 401 `invalid_client`.
- OpenBao 2.7.1 Transit: wrong context, malformed or future-version ciphertext and other-key ciphertext are 400; a missing key on decrypt is 400 `encryption key not found`; a version below `min_decryption_version` is 400; denied, revoked or invalid tokens are 403; sealed is 503.
- Latency from Taiwan to `us-east-1` through workerd: about 230 ms for the first Encrypt (connection setup) and 55 ms for a following Decrypt.
