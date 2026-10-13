const context = { type: 'object', additionalProperties: false, required: ['tenantId', 'recordId', 'purpose'], properties: {
  tenantId: { type: 'string', minLength: 1, maxLength: 256, description: 'Must match the authenticated principal; at most 256 UTF-8 bytes.' },
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
  EncryptInput: { type: 'object', additionalProperties: false, required: ['plaintext', 'context', 'key'], properties: {
    plaintext: { type: 'string', maxLength: 65536, description: 'Well-formed UTF-8 text, at most 65536 bytes.' }, context, key,
  } },
  DecryptInput: { type: 'object', additionalProperties: false, required: ['envelope', 'context'], properties: { envelope, context } },
  EncryptOutput: { type: 'object', additionalProperties: false, required: ['envelope'], properties: { envelope } },
  DecryptOutput: { type: 'object', additionalProperties: false, required: ['plaintext'], properties: { plaintext: { type: 'string' } } },
  Error: { type: 'object', required: ['error'], properties: { error: { type: 'object', required: ['code', 'message', 'retryable', 'requestId'], properties: {
    code: { type: 'string' }, message: { type: 'string' }, retryable: { type: 'boolean' }, requestId: { type: 'string' },
  } } } },
};
export const capabilities = {
  name: 'strongroom', version: '0.1.0-alpha.1', apiVersion: 'v1', envelopeVersion: 1,
  operations: ['encrypt', 'decrypt'], providers: ['aws', 'gcp', 'vault', 'openbao', 'local'],
  maxPlaintextBytes: 65536, maxRequestBytes: 524288, openapi: '/openapi.json',
  errors: { INVALID_REQUEST: 400, DECRYPT_FAILED: 400, UNAUTHENTICATED: 401, FORBIDDEN: 403, NOT_FOUND: 404, METHOD_NOT_ALLOWED: 405, REQUEST_TIMEOUT: 408, PAYLOAD_TOO_LARGE: 413, UNSUPPORTED_MEDIA_TYPE: 415, KMS_UNAVAILABLE: 503, NOT_CONFIGURED: 503, INTERNAL_ERROR: 500 },
  retry: 'Only retry errors marked retryable, with bounded exponential backoff. Encryption generates a new envelope on every attempt.',
};
function operation(name: 'encrypt' | 'decrypt') {
  const type = name === 'encrypt' ? 'Encrypt' : 'Decrypt';
  return { operationId: name, security: [{ bearerAuth: [] }], requestBody: { required: true, content: { 'application/json': { schema: { $ref: `#/components/schemas/${type}Input` } } } },
    responses: { '200': { description: 'Success; Cache-Control: no-store', content: { 'application/json': { schema: { $ref: `#/components/schemas/${type}Output` } } } },
      default: { description: 'Stable error code and retryability. No upstream details or secret values.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } } } };
}
export const openapi = { openapi: '3.1.0', info: { title: 'Strongroom', version: capabilities.version, description: 'Stateless envelope encryption for recoverable BYOK credentials. Context identifiers are metadata, not secrets.' },
  paths: { '/v1/encrypt': { post: operation('encrypt') }, '/v1/decrypt': { post: operation('decrypt') },
    '/healthz': { get: { operationId: 'health', responses: { '200': { description: 'Process is alive.' } } } },
    '/readyz': { get: { operationId: 'ready', responses: { '200': { description: 'Configuration is valid; does not probe KMS.' }, '503': { description: 'Configuration is invalid.' } } } },
    '/v1/capabilities': { get: { operationId: 'capabilities', responses: { '200': { description: 'Machine-readable API capabilities.' } } } },
  }, components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } }, schemas } };
