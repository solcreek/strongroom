// Scenario: an AI agent acts for a user through tools (send email, open a ticket...) that need the user's
// own credential. The model must be able to use the credential without ever seeing it: anything that
// reaches the model can end up in a transcript, a log, a trace or a prompt-injected reply.
import assert from 'node:assert/strict';
import { Strongroom } from '../../packages/strongroom/dist/index.js';
import { startDeployment, step } from '../shared/stack.mjs';

const acme = await startDeployment('acme');
try {
  const ingest = new Strongroom({ url: acme.url, token: acme.tokens.ingest });
  const tools = new Strongroom({ url: acme.url, token: acme.tokens.use }); // only the tool runtime can decrypt
  const context = (credentialId) => ({ tenantId: 'acme', recordId: `credential/${credentialId}`, purpose: 'agent-tool-credential' });

  // Credentials are stored as envelopes and addressed by an opaque handle owned by one user.
  const credentials = new Map();
  const secret = 'mail-api-key-DO-NOT-LEAK-7f3a';
  credentials.set('cred_1', { owner: 'alice', service: 'mail', envelope: await ingest.encrypt({ key: 'primary', context: context('cred_1'), plaintext: secret }) });

  // Stand-in mail API. Its error messages echo the key, as real APIs sometimes do.
  const mailApi = { send: async (apiKey, to) => to.endsWith('@example.com') ? { id: 'msg_42', to } : Promise.reject(new Error(`rejected recipient ${to} for key ${apiKey}`)) };

  // The tool runtime: authorize, decrypt just in time, call, scrub. The model only ever passes the handle.
  async function runTool(session, call) {
    const credential = credentials.get(call.args.credential);
    // Record-level authorization is the application's job; the Strongroom context is not authorization.
    if (!credential || credential.owner !== session.user) return { error: 'credential not available to this user' };
    const apiKey = await tools.decrypt({ envelope: credential.envelope, context: context(call.args.credential) });
    try { return { result: await mailApi.send(apiKey, call.args.to) }; }
    catch (e) { return { error: String(e.message).replaceAll(apiKey, '[redacted]') }; } // never hand a secret back to the model
  }

  // A scripted "model": Alice's agent sends one mail and fails another; Mallory's agent, prompt-injected
  // with Alice's handle, tries to use her credential.
  const transcript = [];
  for (const [session, call] of [
    [{ user: 'alice' }, { tool: 'send_email', args: { credential: 'cred_1', to: 'bob@example.com' } }],
    [{ user: 'alice' }, { tool: 'send_email', args: { credential: 'cred_1', to: 'eve@elsewhere.test' } }],
    [{ user: 'mallory' }, { tool: 'send_email', args: { credential: 'cred_1', to: 'x@example.com' } }],
  ]) transcript.push({ user: session.user, call, output: await runTool(session, call) });

  assert.ok(!JSON.stringify(transcript).includes(secret));
  step('transcript', { entries: transcript.map(t => t.output.error ?? `sent ${t.output.result.id}`), secretInTranscript: false });
  // There is no "read secret" tool: decrypt is a capability of the runtime, not something the model can ask for.
  step('model-visible', { tools: ['send_email'], argument: 'credential handle only' });
} finally { await acme.stop(); }
