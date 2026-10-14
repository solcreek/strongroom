# Strongroom

[![CI](https://github.com/solcreek/strongroom/actions/workflows/ci.yml/badge.svg)](https://github.com/solcreek/strongroom/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Protect user-supplied API keys with a managed KMS. Your database stores only encrypted envelopes; when you need to call a third-party service, an authorized Strongroom service decrypts them.

This is the **0.1.0-alpha.1 development release**. Rust owns AES-256-GCM and the ciphertext format, and Cloudflare Workers is the primary target; containers run the same Rust Wasm and HTTP handler on a Node 24 host. The public npm version is still the name-reserving `0.0.0`; the commands below use a local build and neither publish nor deploy anything.

- KMS: AWS KMS, Google Cloud KMS, Vault, OpenBao Transit.
- HTTP: `POST /v1/encrypt`, `POST /v1/decrypt`, with fixed tenant, operation and key authorization.
- Agent interface: TypeScript SDK, JSON CLI, OpenAPI 3.1, offline JSON Schema, explicit error codes and a retryable field.
- Deployment: Workers, Docker, Cloud Run / GKE, AWS ECS / App Runner, Render, Railway. Cloud Run and ECS Express have ready-to-apply OpenTofu/Terraform modules that use workload identity and keep secrets out of the configuration; both were deployed and verified on 2026-10-13: [deployment runbook](deploy/terraform/README.md).

## Run locally

Requires Node 24, Rust 1.98.1, the Wasm target, and the wasm-bindgen CLI at the same version as the wasm-bindgen crate in `Cargo.lock` (the build checks this).

```sh
rustup toolchain install 1.98.1 --profile minimal --target wasm32-unknown-unknown
cargo install wasm-bindgen-cli --locked --version "$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/[^0-9.]/, ""); print }' Cargo.lock)"
npm ci
npm run build
npm run dev:init
npm run dev
```

`dev:init` creates `.strongroom/` and generates a local KEK and API token from the CSPRNG; the directory is mode 0700, files are 0600, and existing configuration is never overwritten. `dev` starts a real workerd on `127.0.0.1:8787` and rebuilds and reloads on TypeScript changes. After Rust changes, run `npm run build` and restart dev. Start the Node host with `npm run dev:node`.

In another terminal, run the complete SDK example:

```sh
node --env-file=.strongroom/client.env examples/byok.mjs
```

Or let an agent read the schema first, then use the CLI through stdin:

```sh
node packages/strongroom/dist/cli.js schema encrypt
printf '%s' '{"key":"primary","plaintext":"demo-api-key","context":{"tenantId":"development","recordId":"user-123/openai","purpose":"provider-api-key"}}' |
  node --env-file=.strongroom/client.env packages/strongroom/dist/cli.js encrypt --output .strongroom/envelope.json
```

Plaintext and tokens never need to appear in CLI flags. `--output` creates a 0600 file and refuses to overwrite; without it, one JSON value goes to stdout. Errors are one JSON value on stderr, and exit codes distinguish input, authorization, rejection and transient failures.

## Application integration

```ts
import { Strongroom } from 'strongroom'; // the package produced by a local npm pack

const strongroom = new Strongroom({
  url: process.env.STRONGROOM_URL!,
  token: process.env.STRONGROOM_TOKEN!,
});
const context = {
  tenantId: authenticatedTenant.id,
  recordId: credential.id,
  purpose: 'provider-api-key',
};
const envelope = await strongroom.encrypt({ key: 'primary', plaintext: userSuppliedApiKey, context });
await database.credentials.update(credential.id, { envelope });

// At use time, rebuild the context from trusted authorization data.
const stored = await database.credentials.find(credential.id);
const apiKey = await strongroom.decrypt({ envelope: stored.envelope, context });
// Pass apiKey to the third-party API; never log it.
```

One Strongroom token is bound to one tenant. Your application must still verify that the user may access the given credential. Context is not a password and not a substitute for authorization; never put an API key in the context.

## Development and verification

```sh
npm run verify           # build, TypeScript, Rust tests, service/SDK/CLI/runtime tests, coverage gate
npm run test:fast        # fast tests after the first build
npm run build:host       # rebuild only the HTTP host and SDK/CLI
npm run deploy:check     # Wrangler dry-run, no deployment
npm run test:package     # really pack, install and verify the SDK types and CLI
TRANSIT_BIN=/path/to/bao npm run test:transit
npm run test:live        # real AWS/GCP/OpenBao conformance and fixture drift check (see docs/testing.md)
```

Coverage gate: lines, statements and functions ≥90% and branches ≥80% for the shared service and the SDK/CLI. Rust has its own tests; the Workers and Node hosts are verified with the real runtimes over loopback HTTP and do not count toward the shared code's coverage percentage.

On 2026-10-13, AWS KMS (least-privilege IAM user), Google Cloud KMS (service account and ADC) and a local OpenBao 2.7.1 were verified with real accounts: roundtrips, context rejection, permission denial, missing or disabled keys and bad credentials all ran through workerd and the Node host. Real error responses are recorded in `tests/fixtures/kms/` and replayed one by one by the offline tests; `npm run test:live` detects provider behaviour drift. See [KMS testing](docs/testing.md). The Docker daemon is not running in this environment, so the image build has not completed locally; CI runs the Docker build.

Documentation: [architecture](docs/architecture.md), [configuration](docs/configuration.md), [KMS testing](docs/testing.md), [deployment](docs/deployment.md), [security boundaries](docs/security.md), [agent guide](docs/agents.md). The historical POC is kept in `poc/` with its [benchmark report](results/REPORT.md); its fixed mock key and ciphertext format are incompatible with the production core.

## License and security

[MIT](LICENSE). Not yet independently audited; report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
