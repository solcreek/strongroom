# Agent tools that use credentials they never see

An AI agent acts for a user through tools (send an email, open a ticket, query an API) that need the user's own credential. Anything that reaches the model can end up in a transcript, a log, a trace, or a prompt-injected reply. So the model must be able to use the credential without ever seeing it.

```sh
npm run build && node examples/agent-tools/main.mjs
```

The run has three outcomes:

- Alice's agent sends one mail.
- Her second mail fails with a provider error that echoes her key; the error reaches the model with the key redacted.
- Mallory's agent, prompt-injected with Alice's credential handle, is refused.

The transcript never contains the secret.

## Common designs

1. **Handles, not secrets.** The model passes an opaque credential id (`cred_1`). The envelope and the key stay in the tool runtime.
2. **Decrypt is a runtime capability, not a tool.** No tool returns a secret, so no prompt can ask for one. Only the tool runtime holds a `decrypt` token; the code that stores credentials holds an `encrypt`-only one.
3. **Authorize the record in the runtime.** Check that the session's user owns the credential before decrypting. Strongroom's context binds an envelope to its record but does not decide who may use it.
4. **Scrub tool output.** Provider errors and debug payloads sometimes echo the credential. Replace it before anything goes back to the model.
5. **Shell-based agents keep secrets in files.** With the CLI, use `decrypt --plaintext-file FILE` or `--output FILE` (new 0600 files) so plaintext never lands on stdout or in the agent's transcript ([agent guide](../../docs/agents.md)).

## Why Strongroom here

The tool runtime needs a token that can decrypt one tenant's credentials, not cloud KMS permissions, so a compromised agent host is limited to that tenant. Stable error codes and a non-interactive JSON CLI make Strongroom usable from agents and scripts without provider SDKs. See the [comparison](../README.md#strongroom-or-your-clouds-kms-directly).
