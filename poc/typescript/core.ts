/** POC ONLY: this public, fixed key simulates KMS wrapping. Never use real secrets. */
export type Context = { tenantId: string; recordId: string; purpose: string };
export type Envelope = { version: number; algorithm: string; keyId: string; nonce: string; wrappedKey: string; ciphertext: string };
export const MAX_PLAINTEXT = 65536;
const KEY_ID = 'INSECURE-POC-LOCAL-KEY';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export function encode(bytes: Uint8Array): string {
  let value = '';
  for (let i = 0; i < bytes.length; i += 8192) value += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(value).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
export function decode(value: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('invalid base64url');
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
  if (encode(bytes) !== value) throw new Error('noncanonical base64url');
  return bytes;
}
function keys(value: unknown, expected: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== expected.sort().join(',')) throw new Error('invalid fields');
}
function aad(context: Context): Uint8Array<ArrayBuffer> {
  keys(context, ['tenantId', 'recordId', 'purpose']);
  for (const value of Object.values(context)) {
    if (typeof value !== 'string' || !value || encoder.encode(value).length > 256 || !value.isWellFormed()) throw new Error('invalid context');
  }
  return encoder.encode(JSON.stringify(['strongroom-poc', 1, context.tenantId, context.recordId, context.purpose]));
}
async function key(bytes: Uint8Array<ArrayBuffer>, usage: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, [usage]);
}
async function seal(raw: Uint8Array<ArrayBuffer>, nonce: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>, additionalData: Uint8Array<ArrayBuffer>) {
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 }, await key(raw, 'encrypt'), data));
}
async function open(raw: Uint8Array<ArrayBuffer>, nonce: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>, additionalData: Uint8Array<ArrayBuffer>) {
  if (raw.length !== 32 || nonce.length !== 12) throw new Error('invalid key or nonce');
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 }, await key(raw, 'decrypt'), data));
}
export async function encrypt(plaintext: string, context: Context, entropy: Uint8Array<ArrayBuffer>): Promise<Envelope> {
  if (typeof plaintext !== 'string' || !plaintext.isWellFormed()) throw new Error('invalid plaintext');
  const bytes = encoder.encode(plaintext);
  if (bytes.length > MAX_PLAINTEXT || entropy.length !== 56) throw new Error('invalid input size');
  const additionalData = aad(context);
  const dek = entropy.slice(0, 32);
  try {
    const nonce = entropy.slice(32, 44);
    const wrappingNonce = entropy.slice(44, 56);
    const ciphertext = await seal(dek, nonce, bytes, additionalData);
    const wrapped = await seal(new Uint8Array(32).fill(0x42), wrappingNonce, dek, additionalData);
    const wrappedKey = new Uint8Array(60);
    wrappedKey.set(wrappingNonce);
    wrappedKey.set(wrapped, 12);
    return { version: 1, algorithm: 'A256GCM', keyId: KEY_ID, nonce: encode(nonce), wrappedKey: encode(wrappedKey), ciphertext: encode(ciphertext) };
  } finally { dek.fill(0); bytes.fill(0); }
}
export async function decrypt(envelope: Envelope, context: Context): Promise<string> {
  keys(envelope, ['version', 'algorithm', 'keyId', 'nonce', 'wrappedKey', 'ciphertext']);
  if (envelope.version !== 1 || envelope.algorithm !== 'A256GCM' || envelope.keyId !== KEY_ID) throw new Error('unsupported envelope');
  if (typeof envelope.ciphertext !== 'string' || envelope.ciphertext.length > 87403) throw new Error('invalid ciphertext size');
  const additionalData = aad(context);
  const wrapped = decode(envelope.wrappedKey);
  if (wrapped.length !== 60) throw new Error('invalid wrapped key');
  const dek = await open(new Uint8Array(32).fill(0x42), wrapped.slice(0, 12), wrapped.slice(12), additionalData);
  try {
    const ciphertext = decode(envelope.ciphertext);
    if (ciphertext.length < 16 || ciphertext.length > MAX_PLAINTEXT + 16) throw new Error('invalid ciphertext size');
    const plaintext = await open(dek, decode(envelope.nonce), ciphertext, additionalData);
    try { return decoder.decode(plaintext); } finally { plaintext.fill(0); }
  } finally { dek.fill(0); }
}
export async function execute(input: string): Promise<string> {
  if (encoder.encode(input).length > 524288) throw new Error('request too large');
  const command = JSON.parse(input);
  if (command.op === 'encrypt') {
    keys(command, ['op', 'plaintext', 'context', 'entropy']);
    const entropy = decode(command.entropy as string);
    try { return JSON.stringify(await encrypt(command.plaintext as string, command.context as Context, entropy)); }
    finally { entropy.fill(0); }
  }
  if (command.op === 'decrypt') {
    keys(command, ['op', 'envelope', 'context']);
    return JSON.stringify({ plaintext: await decrypt(command.envelope as Envelope, command.context as Context) });
  }
  throw new Error('invalid operation');
}
