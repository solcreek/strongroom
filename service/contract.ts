const context = { type: 'object', additionalProperties: false, required: ['tenantId', 'recordId', 'purpose'], properties: {
  tenantId: { type: 'string', minLength: 1, maxLength: 256, description: 'Must equal the tenant this deployment serves; at most 256 UTF-8 bytes.' },
  recordId: { type: 'string', minLength: 1, maxLength: 256, description: 'At most 256 UTF-8 bytes.' },
  purpose: { type: 'string', minLength: 1, maxLength: 256, description: 'At most 256 UTF-8 bytes.' },
} };
const key = { type: 'string', pattern: '^[A-Za-z0-9_-]{1,64}$' };
const b64 = { type: 'string', pattern: '^[A-Za-z0-9_-]*$' };
const envelope = { type: 'object', additionalProperties: false, required: ['version', 'algorithm', 'key', 'nonce', 'ciphertext', 'wrappedKey'], properties: {
  version: { const: 1 }, algorithm: { const: 'A256GCM' }, key, nonce: { ...b64, minLength: 16, maxLength: 16 },
  ciphertext: { ...b64, minLength: 22, maxLength: 87403 }, wrappedKey: { type: 'string', minLength: 1, maxLength: 16384 },
} };
export const schemas = {
  Context: context, Envelope: envelope,
  EncryptInput: { type: 'object', additionalProperties: false, required: ['context', 'key'], oneOf: [{ required: ['plaintext'] }, { required: ['plaintextBase64url'] }], properties: {
    plaintext: { type: 'string', maxLength: 65536, description: 'Well-formed UTF-8 text, at most 65536 bytes.' },
    plaintextBase64url: { ...b64, maxLength: 87382, description: 'Binary plaintext (for example a data key), canonical base64url without padding, at most 65536 bytes decoded.' }, context, key,
  } },
  DecryptInput: { type: 'object', additionalProperties: false, required: ['envelope', 'context'], properties: { envelope, context } },
  EncryptOutput: { type: 'object', additionalProperties: false, required: ['envelope'], properties: { envelope } },
  DecryptOutput: { type: 'object', additionalProperties: false, required: ['plaintext'], properties: { plaintext: { type: 'string' } } },
  Error: { type: 'object', required: ['error'], properties: { error: { type: 'object', required: ['code', 'message', 'retryable', 'requestId'], properties: {
    code: { type: 'string' }, message: { type: 'string' }, retryable: { type: 'boolean' }, requestId: { type: 'string' },
    path: { type: 'string', description: 'JSON path of the offending request field, for INVALID_REQUEST only.' },
  } } } },
};
export const capabilities = {
  name: 'strongroom', version: '0.1.0', apiVersion: 'v1', envelopeVersion: 1,
  operations: ['encrypt', 'decrypt'], providers: ['aws', 'gcp', 'vault', 'openbao', 'local'],
  maxPlaintextBytes: 65536, maxRequestBytes: 524288, openapi: '/openapi.json',
  // Decrypt returns {plaintext} JSON by default, or the raw bytes for Accept: application/octet-stream.
  decryptMediaTypes: ['application/json', 'application/octet-stream'],
  // Every code the service emits. `action` is the next step for a caller or agent.
  errors: {
    INVALID_REQUEST: { status: 400, retryable: false, action: 'Fix the field named by error.path; see schema.' },
    DECRYPT_FAILED: { status: 400, retryable: false, action: 'The envelope does not open with this context and key. Rebuild context from trusted identifiers; never overwrite the stored envelope.' },
    UNAUTHENTICATED: { status: 401, retryable: false, action: 'Supply a valid bearer token.' },
    FORBIDDEN: { status: 403, retryable: false, action: 'This deployment serves another tenant, or the token lacks this operation or key reference. Each tenant has its own deployment and URL.' },
    NOT_FOUND: { status: 404, retryable: false, action: 'Use a documented endpoint.' },
    METHOD_NOT_ALLOWED: { status: 405, retryable: false, action: 'Use the documented method.' },
    PLAINTEXT_NOT_TEXT: { status: 406, retryable: false, action: 'The envelope opened but holds bytes that are not UTF-8 text. Decrypt with Accept: application/octet-stream (SDK decryptBytes, CLI decrypt --plaintext-file FILE).' },
    REQUEST_TIMEOUT: { status: 408, retryable: false, action: 'Send the complete request body promptly.' },
    PAYLOAD_TOO_LARGE: { status: 413, retryable: false, action: 'Reduce the request size.' },
    UNSUPPORTED_MEDIA_TYPE: { status: 415, retryable: false, action: 'Send Content-Type: application/json.' },
    INTERNAL_ERROR: { status: 500, retryable: false, action: 'Report the requestId to the operator.' },
    KMS_ACCESS_DENIED: { status: 502, retryable: false, action: 'Operator: the service KMS credentials or IAM grant were rejected. Fix credentials or permissions; retrying unchanged will not succeed.' },
    KMS_KEY_UNAVAILABLE: { status: 502, retryable: false, action: 'Operator: the configured KMS key is missing, disabled or pending deletion. Re-enable it; never remap the key reference.' },
    KMS_UNAVAILABLE: { status: 503, retryable: true, action: 'Retry with bounded exponential backoff; preserve the stored envelope.' },
    NOT_CONFIGURED: { status: 503, retryable: false, action: 'Operator: run strongroom config-check against the service configuration.' },
  },
  retry: 'Only retry errors marked retryable, with bounded exponential backoff. Encryption generates a new envelope on every attempt.',
};
function operation(name: 'encrypt' | 'decrypt') {
  const type = name === 'encrypt' ? 'Encrypt' : 'Decrypt';
  const bytes = name === 'decrypt' ? { 'application/octet-stream': { schema: { type: 'string', contentMediaType: 'application/octet-stream', description: 'The raw plaintext bytes, when the request sends Accept: application/octet-stream.' } } } : {};
  return { operationId: name, security: [{ bearerAuth: [] }], requestBody: { required: true, content: { 'application/json': { schema: { $ref: `#/components/schemas/${type}Input` } } } },
    responses: { '200': { description: 'Success; Cache-Control: no-store', content: { 'application/json': { schema: { $ref: `#/components/schemas/${type}Output` } }, ...bytes } },
      default: { description: 'Stable error code and retryability. No upstream details or secret values.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } } } };
}
export const openapi = { openapi: '3.1.0', info: { title: 'Strongroom', version: capabilities.version, description: 'Stateless envelope encryption for recoverable BYOK credentials. Context identifiers are metadata, not secrets.' },
  paths: { '/v1/encrypt': { post: operation('encrypt') }, '/v1/decrypt': { post: operation('decrypt') },
    '/healthz': { get: { operationId: 'health', responses: { '200': { description: 'Process is alive.' } } } },
    '/readyz': { get: { operationId: 'ready', responses: { '200': { description: 'Configuration is valid; does not probe KMS.' }, '503': { description: 'Configuration is invalid.' } } } },
    '/v1/capabilities': { get: { operationId: 'capabilities', responses: { '200': { description: 'Machine-readable API capabilities.' } } } },
  }, components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } }, schemas } };
