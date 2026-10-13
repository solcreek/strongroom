# Deployment

The same HTTP contract and Rust Wasm core run on Workers and Node containers. Strongroom has no database, migrations, volumes or background jobs. Supply `STRONGROOM_CONFIG` as a platform secret; never bake it into an image or commit it. See [configuration](configuration.md) for the complete provider and principal setup.

## Cloudflare Workers

```sh
npm ci
npm run build
npm run verify
npm run deploy:check
```

`wrangler.jsonc` packages the Wasm module, disables automatic workers.dev/preview exposure, and leaves local mode off. Add a custom domain/route for your account, then deploy and provision the secret:

```sh
npx wrangler deploy --config wrangler.jsonc
npx wrangler secret put STRONGROOM_CONFIG --config wrangler.jsonc < .strongroom/production.json
```

Until the secret is installed, cryptographic endpoints return `503 NOT_CONFIGURED`. Alternatively provision secrets through your deployment pipeline before routing traffic. Choose your URL explicitly; do not enable a public development URL accidentally. The repository's automated workflow only runs a dry-run and does not deploy.

Outbound KMS calls require reachable HTTPS endpoints. AWS/GCP use their fixed service endpoints; Vault/OpenBao use the configured origin. No Node compatibility flag is needed. [Wrangler documentation](https://developers.cloudflare.com/workers/wrangler/commands/) describes account login, routes and secrets.

## Docker

```sh
docker build -t strongroom:alpha .
docker run --rm -p 127.0.0.1:8787:8080 --env-file .strongroom/container.env strongroom:alpha
```

`container.env` must use Docker env-file syntax: `STRONGROOM_CONFIG=` followed by **unquoted, one-line JSON**, plus `STRONGROOM_ALLOW_LOCAL=false`. The generated `server.env` uses Node env-file quoting and is not a Docker env-file. Prefer your platform's secret injection for real deployments. The runtime image contains only Node, the bundled host and Wasm; it runs as UID 1000, defaults to port 8080, and needs no writable filesystem.

Node loads config once at startup and refuses to listen if it is invalid. `/readyz` checks configuration, not KMS connectivity. Termination stops accepting requests and allows up to 10 seconds to finish in-flight work. Adjust ingress request deadlines to allow OAuth refresh plus an 8-second KMS deadline.

## Cloud Run / GCP

Build and push the Docker image to your Artifact Registry. Create a Secret Manager secret containing the raw JSON configuration, grant the Cloud Run runtime identity access to that secret, and deploy with it mapped to `STRONGROOM_CONFIG`:

```sh
gcloud run deploy strongroom \
  --image REGION-docker.pkg.dev/PROJECT/REPOSITORY/strongroom:VERSION \
  --region REGION --port 8080 \
  --set-secrets STRONGROOM_CONFIG=strongroom-config:latest \
  --set-env-vars STRONGROOM_ALLOW_LOCAL=false \
  --no-allow-unauthenticated
```

Cloud Run IAM authentication is a second boundary in addition to Strongroom tokens. Its identity token must be supplied using `X-Serverless-Authorization` so `Authorization` remains the Strongroom bearer. The SDK supports a custom `fetch` for adding this header; the CLI does not obtain Google identity tokens automatically. Alternatively place the service behind a trusted ingress that performs platform authentication. For KMS, prefer `metadataServer: true` on Cloud Run and GKE Workload Identity: the service then uses the attached service account and holds no key file. Grant that account `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the CryptoKey only. See [Cloud Run service authentication](https://docs.cloud.google.com/run/docs/authenticating/service-to-service).

## GKE / Kubernetes

Push the image and replace `YOUR_REGISTRY/strongroom:YOUR_VERSION` in `deploy/kubernetes.yaml`. Create the secret from the private config file, then apply:

```sh
kubectl create secret generic strongroom --from-file=config=.strongroom/production.json
kubectl apply -f deploy/kubernetes.yaml
```

The template uses two replicas, a private ClusterIP service, probes, resource limits, a non-root UID, a read-only filesystem and no service-account token mount. Add your own TLS ingress and network policy. Configuration secret changes require a rollout restart because they are consumed through environment variables.

## AWS

Push the same image to ECR and run it in ECS Fargate or App Runner on port 8080. Map an AWS Secrets Manager secret to `STRONGROOM_CONFIG`, use `/readyz` for health checks, and terminate TLS at the platform/load balancer. For ECS use an execution role that can retrieve the config secret. Give the task role `kms:Encrypt`/`kms:Decrypt` on the key ARN and set `"containerCredentials": true` on the key, so the config holds no AWS secret. App Runner instance roles have not been verified with this path. Set ingress rate limits and network rules appropriate to the application.

## Render / Railway

`render.yaml` and `railway.json` use the root Dockerfile and `/readyz`. Supply the raw JSON `STRONGROOM_CONFIG` in the platform's secret environment settings. Render's Blueprint prompts for it; Railway requires you to add the variable. `STRONGROOM_ALLOW_LOCAL` stays false or unset. Both platforms can override `PORT`. Attach the platform's HTTPS domain and set that origin as `STRONGROOM_URL` in callers. References: [Render Blueprint](https://render.com/docs/blueprint-spec), [Railway config as code](https://docs.railway.com/config-as-code).

Templates are included for these platforms; no remote deployment was performed. The Node host is tested locally over HTTP. The local Docker daemon was unavailable during this implementation; the CI workflow includes a Docker build to validate the image on a runner with Docker.
