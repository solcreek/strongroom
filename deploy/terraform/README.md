# Strongroom infrastructure as code

Two OpenTofu/Terraform modules, each a complete deployment that runs without long-lived KMS credentials:

| Module | Runs on | KMS identity | HTTPS endpoint |
| --- | --- | --- | --- |
| `gcp-cloud-run/` | Cloud Run (scale to zero) | Runtime service account via the metadata server (`metadataServer`) | `*.run.app`, optional invoker IAM |
| `aws-ecs-express/` | ECS Express Mode on Fargate | Task role via the container credential endpoint (`containerCredentials`) | Managed ALB, `*.ecs.REGION.on.aws` |

Both were applied, probed, updated and destroyed end to end on 2026-10-13 with OpenTofu 1.12.6 (google provider 8.7.0, aws provider 6.68.0). See [Verified run](#verified-run-2026-10-13).

## Design

- **No secret in the configuration.** With workload identity, `STRONGROOM_CONFIG` contains only key IDs, the tenant ID and token *digests*. The modules generate it from variables and pass it as a plain environment variable, so there is no Secret Manager step and nothing to rotate in the platform. Callers' raw tokens never enter Terraform state.
- **Least privilege.** GCP grants `roles/cloudkms.cryptoKeyEncrypterDecrypter` on each listed CryptoKey only, to a dedicated runtime service account. AWS grants `kms:Encrypt`/`kms:Decrypt` on each listed key ARN only, and only when the request carries Strongroom's `strongroom` encryption context, so the task role cannot decrypt other data protected by the same key.
- **Images pinned by digest.** `npm run image` prints `REPO@sha256:…`; that string is the `image` variable. Promote the same digest between environments instead of rebuilding.
- **Two-phase first apply.** The registry must exist before an image can be pushed, so the service is created only once `image` is set. Later deploys are one apply.

## Recommendations

1. **Keep KMS keys out of the service stack.** Destroying or recreating a service must never touch the keys, or every stored envelope becomes unrecoverable. Create keys in a separate, long-lived stack (or by hand) with `lifecycle { prevent_destroy = true }`, then pass their IDs to `kms_keys`. A central key project or account works: on 2026-10-13 the Cloud Run service used a key in a different project.
2. **Use remote state with locking**: a GCS bucket backend, or S3 with `use_lockfile = true`. State holds the generated configuration (no secrets, but the tenant ID and key IDs), so restrict who can read it.
3. **Run applies from CI with federated identity** (GitHub OIDC to an AWS role, or GCP Workload Identity Federation) instead of personal credentials. Plan on pull requests, apply on merge. *Not yet exercised here.*
4. **Pick `public` deliberately on Cloud Run.** `public = false` adds Google IAM as a second gate: callers need `roles/run.invoker` and send an ID token in `X-Serverless-Authorization` (SDK `cloudRunIdToken`, CLI `STRONGROOM_CLOUD_RUN_ID_TOKEN`). `public = true` matches the Workers deployment, where the Strongroom bearer token is the only gate.
5. **Keep `deletion_protection = true`** (Cloud Run) and `force_delete_registry = false` (ECR) in production; the verification run turned them off only so it could be torn down.

## Runbook

Prerequisites: OpenTofu ≥ 1.6 (or Terraform ≥ 1.6), `crane`, the AWS CLI and/or `gcloud`, Node 24, and a local `npm run build`. Docker is not required.

### 1. Caller token (both platforms)

```sh
node packages/strongroom/dist/cli.js token --token-file .strongroom/app-token --keys primary
```

Set `tenant_id` to the one tenant this deployment serves. For more tenants, apply the module once per tenant (a separate state, KMS key and identity each); a deployment never serves a second tenant.

Copy `principal.token_sha256` (the `tokenSha256` value) into `principals` in your tfvars. Hand `.strongroom/app-token` to the calling application through its own secret store.

### 2a. Google Cloud Run

```sh
# New project only: Terraform cannot enable APIs until these two are on.
gcloud services enable serviceusage.googleapis.com cloudresourcemanager.googleapis.com --project PROJECT

cd deploy/terraform/gcp-cloud-run
cp terraform.tfvars.example terraform.tfvars   # edit project_id, kms_keys, principals
tofu init
tofu apply                                      # phase 1: APIs, Artifact Registry, runtime SA, KMS grants

cd ../../..
gcloud auth print-access-token | crane auth login REGION-docker.pkg.dev -u oauth2accesstoken --password-stdin
npm run image -- --repository "$(tofu -chdir=deploy/terraform/gcp-cloud-run output -raw repository)"

cd deploy/terraform/gcp-cloud-run
tofu apply -var image=REPO@sha256:...           # phase 2: the Cloud Run service
```

Verify, from the repository root:

```sh
cd ../../..
export STRONGROOM_URL="$(tofu -chdir=deploy/terraform/gcp-cloud-run output -raw url)" STRONGROOM_TOKEN_FILE=.strongroom/app-token
export STRONGROOM_CLOUD_RUN_ID_TOKEN="$(gcloud auth print-identity-token)"   # only when public = false
node packages/strongroom/dist/cli.js probe --key primary --tenant acme
gcloud logging read 'resource.type="cloud_run_revision" AND jsonPayload.event="kms_error"' --project PROJECT --limit 5
```

### 2b. AWS ECS Express Mode

```sh
cd deploy/terraform/aws-ecs-express
cp terraform.tfvars.example terraform.tfvars   # edit region, kms_keys, principals
tofu init
tofu apply                                      # phase 1: ECR, IAM roles, log group, cluster

cd ../../..
aws ecr get-login-password --region REGION | crane auth login ACCOUNT.dkr.ecr.REGION.amazonaws.com -u AWS --password-stdin
npm run image -- --repository "$(tofu -chdir=deploy/terraform/aws-ecs-express output -raw repository_url)"

cd deploy/terraform/aws-ecs-express
tofu apply -var image=REPO@sha256:...           # phase 2: Express service, ALB, HTTPS URL
```

Verify, from the repository root:

```sh
cd ../../..
export STRONGROOM_URL="$(tofu -chdir=deploy/terraform/aws-ecs-express output -raw url)" STRONGROOM_TOKEN_FILE=.strongroom/app-token
node packages/strongroom/dist/cli.js probe --key primary --tenant acme
aws logs filter-log-events --log-group-name "$(tofu -chdir=deploy/terraform/aws-ecs-express output -raw log_group)" --filter-pattern '{ $.event = "kms_error" }'
```

### Both clouds from one build

Repeat `--repository` to push one image to several registries; every copy has the same digest:

```sh
npm run image -- --repository ACCOUNT.dkr.ecr.REGION.amazonaws.com/strongroom --repository REGION-docker.pkg.dev/PROJECT/strongroom/strongroom
```

### Update and tear down

A new release is `npm run build`, `npm run image`, then `tofu apply -var image=NEW_DIGEST` per platform. Changing `principals` or `kms_keys` is an apply without a new image. `tofu destroy` removes the service stack; it does not touch KMS keys passed in by ID, and removes only the IAM bindings it added to them.

## Platform behaviour to know

- **Cloud Run reserves `/healthz`.** Google's front end answers it with its own 404 HTML before the request reaches the container. Use `/readyz` for external checks; the container's own liveness probe still reaches `/healthz`.
- **A new GCP project** needs `serviceusage` and `cloudresourcemanager` enabled before Terraform can enable anything else (it fails with `accessNotConfigured`).
- **Cloud Run with invoker IAM** rejects unauthenticated calls with non-JSON responses (403, and 401 for POST). The SDK and CLI report them as `GATEWAY_REJECTED`, exit 3.
- **Cloud Run parses JSON stderr into `jsonPayload`.** Query `jsonPayload.event="kms_error"`, not `textPayload`.
- **ECS Express timing**: creating the service took 5 min; replacing the image took 9 min (load balancer drain and steady state). Cloud Run took 22 s and 27 s.
- **ECS Express** returns its endpoint already prefixed with `https://`.

## Verified run (2026-10-13)

A throwaway GCP project (us-central1) with a KMS key in a different project; a sandbox AWS account (us-east-1). On both: phase 1 and phase 2 applies, `doctor`, `probe` (encrypt, decrypt, context binding), a 401 without a Strongroom token, `kms_error` events with `severity` in Cloud Logging and CloudWatch, a rolling image update, then `tofu destroy`. Cloud Run ran with `public = false` (probe without an ID token: `GATEWAY_REJECTED`; with one: success) and with `public = true`. An envelope written by ECS decrypted in a local workerd host with the same key, and the reverse.
