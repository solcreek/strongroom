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

## Container image without Docker

```sh
npm run build
npm run image -- --repository REGISTRY/PATH/strongroom [--repository MIRROR/strongroom]
```

`scripts/image.mjs` needs only [`crane`](https://github.com/google/go-containerregistry/tree/main/cmd/crane) and a registry login (`crane auth login`). It adds the locally verified `dist/` as one deterministic layer to a digest-pinned `node:24-bookworm-slim`, with the Dockerfile runtime stage's user, workdir, environment and command, for `linux/amd64` and `linux/arm64`. The same commit always yields the same digest. It prints JSON with `images` pinned by digest for IaC. The Dockerfile remains the CI build; the daemonless path is for machines without Docker and for multi-registry pushes.

## Docker

```sh
docker build -t strongroom:local .
docker run --rm -p 127.0.0.1:8787:8080 --env-file .strongroom/container.env strongroom:local
```

`container.env` must use Docker env-file syntax: `STRONGROOM_CONFIG=` followed by **unquoted, one-line JSON**, plus `STRONGROOM_ALLOW_LOCAL=false`. The generated `server.env` uses Node env-file quoting and is not a Docker env-file. Prefer your platform's secret injection for real deployments. The runtime image contains only Node, the bundled host and Wasm; it runs as UID 1000, defaults to port 8080, and needs no writable filesystem.

Node loads config once at startup and refuses to listen if it is invalid. `/readyz` checks configuration, not KMS connectivity. Termination stops accepting requests and allows up to 10 seconds to finish in-flight work. Adjust ingress request deadlines to allow OAuth refresh plus an 8-second KMS deadline.

## Cloud Run / GCP

Use `deploy/terraform/gcp-cloud-run`: Artifact Registry, a runtime service account with encrypt/decrypt on the listed CryptoKeys only, and a Cloud Run service whose KMS access uses `metadataServer` (no key file, no secret). Step-by-step runbook, IaC recommendations and platform caveats: [deploy/terraform/README.md](../deploy/terraform/README.md). Verified end to end on 2026-10-13.

With invoker IAM (`public = false`), callers send a Google ID token in `X-Serverless-Authorization` so `Authorization` remains the Strongroom bearer: SDK option `cloudRunIdToken`, CLI `STRONGROOM_CLOUD_RUN_ID_TOKEN`. Cloud Run's front end reserves `/healthz`; use `/readyz` for external checks. See [Cloud Run service authentication](https://docs.cloud.google.com/run/docs/authenticating/service-to-service).

## GKE / Kubernetes

Push the image and replace `YOUR_REGISTRY/strongroom:YOUR_VERSION` in `deploy/kubernetes.yaml`. Create the secret from the private config file, then apply:

```sh
kubectl create secret generic strongroom --from-file=config=.strongroom/production.json
kubectl apply -f deploy/kubernetes.yaml
```

The template uses two replicas, a private ClusterIP service, probes, resource limits, a non-root UID, a read-only filesystem and no service-account token mount. Add your own TLS ingress and network policy. Configuration secret changes require a rollout restart because they are consumed through environment variables.

## AWS

Use `deploy/terraform/aws-ecs-express`: ECR, a task role allowed `kms:Encrypt`/`kms:Decrypt` on the listed key ARNs only and only with Strongroom's encryption context, and an ECS Express Mode service that provisions the HTTPS load balancer. KMS access uses `containerCredentials` (no AWS secret in the configuration). Runbook: [deploy/terraform/README.md](../deploy/terraform/README.md). Verified end to end on 2026-10-13. App Runner has not been verified.

## Render / Railway

`render.yaml` and `railway.json` use the root Dockerfile and `/readyz`. Supply the raw JSON `STRONGROOM_CONFIG` in the platform's secret environment settings. Render's Blueprint prompts for it; Railway requires you to add the variable. `STRONGROOM_ALLOW_LOCAL` stays false or unset. Both platforms can override `PORT`. Attach the platform's HTTPS domain and set that origin as `STRONGROOM_URL` in callers. References: [Render Blueprint](https://render.com/docs/blueprint-spec), [Railway config as code](https://docs.railway.com/config-as-code).

Render and Railway templates have not been deployed; Cloud Run and ECS were (see above). The Node host is also tested locally over HTTP. The local Docker daemon was unavailable during this implementation; the CI workflow includes a Docker build to validate the image on a runner with Docker.
