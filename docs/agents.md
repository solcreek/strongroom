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

The CLI accepts `STRONGROOM_URL` plus `STRONGROOM_TOKEN` or `STRONGROOM_TOKEN_FILE`. For a Cloud Run service with invoker IAM, also set `STRONGROOM_CLOUD_RUN_ID_TOKEN=$(gcloud auth print-identity-token)` (SDK: `cloudRunIdToken`); it travels in `X-Serverless-Authorization` so `Authorization` stays the Strongroom bearer. A non-JSON 401/403/404 from a platform in front of the service (Cloud Run IAM, a load balancer, a WAF) surfaces as `GATEWAY_REJECTED`, exit 3. Input is JSON from stdin or `--input FILE`; secrets are never CLI flags. No interactive prompt, login redirect, or automatic browser launch occurs. Responses are one JSON value on stdout. Errors are one JSON object on stderr, with a stable code, status and retryability. `--output FILE` creates a private file and refuses to overwrite any existing path, including a symlink.

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

`strongroom doctor` checks configuration readiness and API version only. `strongroom probe --key KEY --tenant TENANT` exercises the token's grants and the real KMS: it encrypts a random synthetic value, decrypts it, and confirms that a changed context is rejected, reporting per-step latency. Nothing is stored. A failing step keeps the service's error code and exit code (`probe step decrypt failed: …`), so `KMS_ACCESS_DENIED` exits 6 and an encrypt-only token exits 3 at the decrypt step. `config-check` validates local server configuration without printing credentials or making network calls.

## Install Strongroom on AWS (agent runbook)

`strongroom setup aws` turns the operator's existing `aws` CLI session into a working configuration in one non-interactive command: it creates (or reuses) the KMS key `alias/NAME`, creates a least-privilege IAM user (or grants an existing ECS task / EKS pod role with `--role-name`), writes a complete `STRONGROOM_CONFIG` plus a caller token to a new private directory, and proves the result with a real Encrypt/Decrypt. Verified against AWS on 2026-10-13 (about 20 s, of which about 12 s is IAM propagation).

1. Plan. Nothing changes; the output lists every action and the IAM permissions the operator needs.
   ```sh
   strongroom setup aws --tenant acme --dry-run
   ```
2. On an error, follow `error.next` (for example `aws sso login`) or report `error.requiredPermissions` to the operator, then repeat step 1.
3. Apply, and check `verified.ok`:
   ```sh
   strongroom setup aws --tenant acme
   ```
4. Deploy with the files named in `files` and the commands in `next` (Workers secret, container env, or the IaC modules), then run `strongroom probe --key primary --tenant acme` against the service.
5. Undo with the `teardown` command printed by setup. The KMS key survives unless `--delete-key`, which schedules deletion after 7 days.

Defaults: `--name strongroom`, `--key primary`, region from the profile, directory `.strongroom/aws-NAME`. The access key secret is written only to `config.json` (0600); stdout never contains it. AWS error text is never echoed, only its error code. Re-running never overwrites files and stops with `RESOURCE_EXISTS` if the IAM user exists; the key behind an existing alias is reused.

| `error.code` | Exit | Meaning and next step |
| --- | --- | --- |
| `AWS_CLI_MISSING` | 2 | Install AWS CLI v2 |
| `AWS_PROFILE_NOT_FOUND` | 2 | Fix `--profile` (`aws configure list-profiles`) |
| `AWS_NOT_AUTHENTICATED` | 3 | `aws sso login` or `aws configure`; check `aws sts get-caller-identity` |
| `AWS_PERMISSION_DENIED` | 3 | The operator lacks `error.requiredPermissions`; `error.created` and `error.cleanup` list anything already made |
| `RESOURCE_EXISTS` | 2 | Choose another `--name`, or run the suggested teardown |
| `KEY_UNUSABLE` | 2 | `alias/NAME` points at a disabled or non-symmetric key; choose another `--name` |
| `INVALID_INPUT` | 2 | `error.path` names the flag to fix |
| `AWS_ERROR` | 1 | Unexpected AWS failure; `error.awsCode` and `error.operation` identify it |

## Decrypt an existing CLI result

An encryption result is `{envelope}`. Decryption requires that envelope plus the context, which must come from trusted application metadata. Pass the stored file with `--envelope` and only the context on stdin:

```sh
printf '%s' '{"context":{"tenantId":"development","recordId":"user-123/openai","purpose":"provider-api-key"}}' |
  node --env-file=.strongroom/client.env packages/strongroom/dist/cli.js decrypt --envelope .strongroom/envelope.json --output .strongroom/plaintext.json
```

`--envelope` accepts an encrypt result (`{envelope}`) or a bare envelope. Without it, stdin carries the full `{envelope, context}` DecryptInput.

The output file contains plaintext. Do not include it in agent transcripts, logs or commits. Remove it when no longer needed. A decrypt operation returns a secret by design; use only the information the authorized workflow needs.

## SDK

`Strongroom.encrypt` returns an `Envelope`; `Strongroom.decrypt` returns a string. Calls accept `{signal}` for cancellation. `StrongroomError` has `code`, `status`, `retryable`, `requestId` and `toJSON()`. The client has a 20-second default timeout and does not automatically retry encryption. Supply a custom `fetch` for Worker service bindings, tracing that excludes bodies, or platform authentication.

The service does not offer autonomous agent execution or MCP in this alpha. Agent compatibility comes from explicit schemas, bounded noninteractive commands, predictable outputs and stable authorization. Adding more tools must preserve these contracts.
