# Strongroom

TypeScript SDK and noninteractive JSON CLI for the Strongroom HTTP encryption service.
This is an alpha implementation. A separately configured Strongroom service is required;
this package contains no KMS credentials and performs no local encryption by itself.

```ts
import { Strongroom } from 'strongroom';
const client = new Strongroom({ url: process.env.STRONGROOM_URL!, token: process.env.STRONGROOM_TOKEN! });
const context = { tenantId: 'your-tenant', recordId: 'credential-id', purpose: 'provider-api-key' };
const envelope = await client.encrypt({ key: 'primary', plaintext: 'demo-key', context });
// Persist envelope in your database; reconstruct context from trusted application metadata.
const apiKey = await client.decrypt({ envelope, context });
```

`StrongroomError` exposes `code`, `status`, `retryable`, `requestId` and `toJSON()`.
Calls support `{signal}` cancellation. The client defaults to a 20-second deadline,
rejects redirects and permits HTTP only on loopback. It does not automatically retry.
Provide a custom `fetch` for platform authentication or Worker service bindings.

```sh
strongroom --help
strongroom schema encrypt
strongroom schema decrypt
strongroom capabilities
strongroom doctor
strongroom encrypt --input request.json --output envelope.json
strongroom decrypt --input decrypt-request.json --output plaintext.json
```

Set `STRONGROOM_URL` and `STRONGROOM_TOKEN` (or `STRONGROOM_TOKEN_FILE`). JSON stdin
is the default input. Success is JSON on stdout; errors are JSON on stderr. There are
no interactive prompts. `--output` creates a mode-0600 file and refuses to overwrite
existing files. Never place secrets in shell arguments, logs, or agent transcripts.

Exit codes: 0 success, 2 input/config/file error, 3 auth denied, 4 rejected request/decryption,
5 retryable network/provider error, 1 other failure. `doctor` checks readiness and API
version, not token permissions or KMS connectivity. `schema` works offline.

`strongroom init` generates private local-development configuration and credentials
in `.strongroom/`; it does not start a server. `config-check` validates the server's
`STRONGROOM_CONFIG` or `--input FILE` without exposing values.

Strongroom protects recoverable credentials against database-only disclosure. It is
not a login password hashing system. An application or service with decrypt access
still handles plaintext. The alpha has not received an independent security audit.
