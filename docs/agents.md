# Agent interface

Use the CLI for shell-based workflows and the SDK for application code. Both are noninteractive and use the same versioned HTTP API. The service requires a trusted application's authorization; never infer tenant or record access from user-provided context alone.

Discover the contract without a service or credentials:

```sh
strongroom --help
strongroom capabilities
strongroom schema
strongroom schema encrypt
strongroom schema decrypt
```

During development substitute `node packages/strongroom/dist/cli.js` for `strongroom`. The npm alpha is not published automatically. Install a local tarball using `npm pack ./packages/strongroom --pack-destination .cache`, then install that tarball into your consuming project.

The CLI accepts `STRONGROOM_URL` plus `STRONGROOM_TOKEN` or `STRONGROOM_TOKEN_FILE`. Input is JSON from stdin or `--input FILE`; secrets are never CLI flags. No interactive prompt, login redirect, or automatic browser launch occurs. Responses are one JSON value on stdout. Errors are one JSON object on stderr, with a stable code, status and retryability. `--output FILE` creates a private file and refuses to overwrite any existing path, including a symlink.

```json
{"error":{"code":"FORBIDDEN","message":"Tenant or key is not permitted.","status":403,"retryable":false,"requestId":"server-generated-id"}}
```

`INVALID_REQUEST` and `INVALID_CONFIG` errors add `path`, the JSON path of the field to fix, and the message states the rule (`$.context.recordId: must be a well-formed string of 1-256 UTF-8 bytes.`). Messages never echo supplied values.

| Exit code | Meaning | Action |
| --- | --- | --- |
| 0 | Success | Parse stdout or the output file |
| 2 | Input, config, or file error | Read schema/help; correct input or configuration |
| 3 | Authentication / authorization | Obtain the correct grant; do not retry unchanged |
| 4 | Request/decryption rejected | Verify context and envelope; never replace data with an empty fallback |
| 5 | Retryable network/provider failure | Bounded backoff; preserve the stored envelope |
| 6 | Service KMS credentials or key rejected (`KMS_ACCESS_DENIED`, `KMS_KEY_UNAVAILABLE`, `NOT_CONFIGURED`) | Escalate to the operator with the `requestId`; do not retry unchanged; the envelope is not at fault |
| 1 | Other failure | Report the structured error |

`strongroom doctor` checks configuration readiness and API version. It explicitly reports that token permissions and KMS connectivity are unchecked. To test those, perform an encrypt/decrypt roundtrip with a disposable synthetic value and a dedicated test record. `config-check` validates local server configuration without printing credentials or making network calls.

## Decrypt an existing CLI result

An encryption result is `{envelope}`. Decryption requires `{envelope, context}`. Keep context in trusted application metadata and assemble the request explicitly:

```sh
node --input-type=module <<'JS' | node --env-file=.strongroom/client.env packages/strongroom/dist/cli.js decrypt --output .strongroom/plaintext.json
import { readFileSync } from 'node:fs';
const { envelope } = JSON.parse(readFileSync('.strongroom/envelope.json', 'utf8'));
process.stdout.write(JSON.stringify({ envelope, context: {
  tenantId: 'development', recordId: 'user-123/openai', purpose: 'provider-api-key'
}}));
JS
```

The output file contains plaintext. Do not include it in agent transcripts, logs or commits. Remove it when no longer needed. A decrypt operation returns a secret by design; use only the information the authorized workflow needs.

## SDK

`Strongroom.encrypt` returns an `Envelope`; `Strongroom.decrypt` returns a string. Calls accept `{signal}` for cancellation. `StrongroomError` has `code`, `status`, `retryable`, `requestId` and `toJSON()`. The client has a 20-second default timeout and does not automatically retry encryption. Supply a custom `fetch` for Worker service bindings, tracing that excludes bodies, or platform authentication.

The service does not offer autonomous agent execution or MCP in this alpha. Agent compatibility comes from explicit schemas, bounded noninteractive commands, predictable outputs and stable authorization. Adding more tools must preserve these contracts.
