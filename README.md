# Strongroom: Rust / TypeScript POC

Compares envelope encryption of BYOK API keys across TypeScript / Web Crypto, Rust / Wasm, and a native executable built from the same Rust core.

**This is a performance and compatibility POC, not a service that can store real API keys.** The "KMS" that wraps data keys uses a public, fixed local test key. There is no integration with AWS KMS, Google Cloud KMS, Vault or OpenBao, and no real tenant authorization, credential management or audit facility. The HTTP entry point is off by default; use it only locally, with synthetic data.

## Contents

| Implementation | Encryption and ciphertext format | Runs on |
|---|---|---|
| TypeScript | Web Crypto AES-256-GCM | Node.js; Cloudflare Workers |
| Rust / Wasm | RustCrypto AES-256-GCM; Rust handles JSON, validation, encryption and base64 | Small JS HTTP host + Wasm; Node.js and local workerd |
| Rust native | The same Rust core as Wasm; the ARM native build enables AES / PMULL hardware acceleration | CLI, as a baseline for core performance and whole-process memory |

The Rust / Wasm POC is not a complete workers-rs server. A shared JS host handles HTTP, request limits, the POC token, CSPRNG and simulated network waits; the Rust core handles ciphertext. The split deliberately keeps HTTP behaviour identical so framework differences do not leak into the core comparison. The native build has no HTTP server or container deployment test yet.

## Reproduce

Requirements: Node.js 24+, Rust 1.98.1, the `wasm32-unknown-unknown` target, wasm-bindgen CLI 0.2.105.

```sh
rustup toolchain install 1.98.1 --profile minimal --target wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.105 --locked
npm ci
npm run build
npm run check
npm test
npm run bench
npm run bench:workerd
npm run report
# Where local TCP listeners are allowed, also run:
npm run bench:workers
```

Do not run several benchmarks at once; they interfere with each other. The build first runs Rust's standard test vectors and tampering tests. The Node tests check all nine cross-decryption combinations of the three engines, plus Unicode, the empty string, the 64 KiB limit, a wrong context, ciphertext tampering and HTTP protections. This environment forbade TCP listen, so the HTTP load test did not complete; workerd's socketless test entry point verified real-runtime compatibility and handler performance instead.

This workspace originally had only Homebrew Rust and no Wasm target, so `.cache/` also holds the official Rust toolchain, wasm-bindgen and the Cargo download cache. `scripts/build.mjs` uses them when present; a normal rustup installation does not need these local caches. The global toolchain is untouched. Cargo.lock and package-lock.json record dependency versions.

## Run the POC

The TypeScript Node HTTP server binds loopback only:

```sh
POC_ONLY=true POC_TOKEN=synthetic-local-token-at-least-24-chars npm run start:ts
```

```sh
curl http://127.0.0.1:8787/encrypt \
  -H 'Authorization: Bearer synthetic-local-token-at-least-24-chars' \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"synthetic-api-key","context":{"tenantId":"t1","recordId":"r1","purpose":"api-key"}}'
```

Send the whole returned envelope with the same context to `POST /decrypt` to get `{"plaintext":"synthetic-api-key"}`. The HTTP API does not accept caller-supplied entropy.

There are two Workers configurations: `wrangler.ts.jsonc` and `wrangler.rust.jsonc`. To run locally:

```sh
npx wrangler dev --config wrangler.ts.jsonc --local \
  --var POC_ONLY:true --var POC_TOKEN:synthetic-local-token-at-least-24-chars
# or use wrangler.rust.jsonc as the config (run npm run build first)
```

Defaults are `workers_dev: false` and `POC_ONLY: false`; nothing has been published to any account. A Workers deployment needs the compiled Wasm, JS glue and a Worker entry point; it cannot take an arbitrary WASI executable. General container platforms should use a native Rust HTTP program or a Node.js service; Wasm does not by itself remove each platform's networking, authentication and deployment differences.

## Ciphertext contract

Each encryption draws 56 bytes from the CSPRNG: a 32-byte DEK, a 12-byte data nonce and a 12-byte wrapping nonce. AES-256-GCM uses a 128-bit tag. Every write gets a fresh DEK; there is no plaintext DEK cache.

The AAD is a UTF-8 JSON array: `["strongroom-poc",1,tenantId,recordId,purpose]`. Data encryption and DEK wrapping bind the same AAD; a decrypting caller must supply the expected context and must not trust only the tenant column in the database. Context is integrity binding, not caller authorization, and must not contain secrets.

The envelope contains `version`, `algorithm`, `keyId`, `nonce`, `wrappedKey` and `ciphertext`. Binary fields use canonical base64url without padding; the GCM tag is appended to the ciphertext; wrappedKey is wrapping nonce + encrypted DEK + tag. The format is for the POC only and is not an existing public standard.

Rust protects the temporary DEK with Zeroizing, and TS clears the byte buffers it controls; both still have JSON strings, host/Wasm data copies and runtime-managed memory, so they cannot guarantee that every plaintext copy is erased immediately.

## Method and limitations

- Core tests: 128 B, 1 KiB, 16 KiB; each sample is one encrypt + decrypt, including RNG, JSON, base64 and two simulated KMS wrap/unwrap calls. Three independent process runs, rotating test order.
- The no-delay scenario warms up 100 times; scenarios where each simulated KMS call waits 10 ms or 50 ms warm up 5 times. The delay is a timer, with no DNS, TLS, cloud authentication, rate limiting or real KMS cost.
- Local workerd: socketless handler tests completed. Each roundtrip includes the encrypt / decrypt Request/Response, and each batch measurement includes a final 1 ms timer to match the Workers clock behaviour. There is no HTTP transport; the numbers are batch averages, not per-request p50/p95.
- Additional HTTP script: Miniflare/workerd, loopback HTTP, 128 B, concurrency 1 and 8; each roundtrip is two HTTP requests. This run did not complete because the sandbox forbade listen.
- Latency reports p50/p95 per run; the report tables take the median of three runs and are not a global service SLO.
- Memory is whole-process peak RSS: Wasm is measured inside Node, including V8; the native Rust CLI needs no V8. This does not prove a Workers isolate saves memory in the same proportion. Wasm linear memory is listed separately as raw data and cannot stand in for total memory.
- CPU is process resource accounting, including startup and warmup; it is not Cloudflare billed CPU time. Module initialization inside Node and starting a local workerd are not production cold starts either.
- These results compare these two implementations and their libraries. Web Crypto is implemented by the host; the Wasm RustCrypto build uses a portable implementation. Rust / Wasm could instead call the host's Web Crypto; that is a different design still to be measured.
- Artifact sizes list the JS bundle, Wasm and native binary separately, and do not compare compressed Wasm with uncompressed JS.
- No deployment or cross-cloud networking was tested on production Cloudflare, GCP, GKE, AWS, Render or Railway, and there is no end-to-end validation against a real KMS.

Results: [POC comparison report](results/REPORT.md), [core raw data](results/benchmark.json), [workerd raw data](results/workerd.json), [HTTP test status](results/workers.json). Both Workers configurations passed Wrangler deploy --dry-run.

## Next steps toward a product

Keep the shareable Rust domain core, but abstract KMS as an asynchronous wrap/unwrap provider, then implement AWS SigV4, Google OAuth / workload identity, Vault / OpenBao authentication and HTTP transport separately. Native and Workers differ in HTTP, timers and credential acquisition; a cloud SDK that compiles for native Rust does not necessarily work on `wasm32-unknown-unknown`.

Production acceptance also needs: tenant authorization, rotatable service identities, no sensitive data in logs, KMS timeout / retry / rate limiting, durable auditing, versioned key routing, recovery for old data and backups, and real integration tests for every deployment platform and KMS combination. Complete one real flow with an AWS sandbox KMS first, then add providers.

References: [Workers Rust](https://developers.cloudflare.com/workers/languages/rust/), [workers-rs](https://github.com/cloudflare/workers-rs), [Workers Wasm](https://developers.cloudflare.com/workers/runtime-apis/webassembly/javascript/), [Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/), [RustCrypto AES-GCM](https://docs.rs/aes-gcm/0.10.3/aes_gcm/), [envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption).
