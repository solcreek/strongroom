export interface Context { tenantId: string; recordId: string; purpose: string }
export interface Envelope {
  version: 1;
  algorithm: 'A256GCM';
  key: string;
  nonce: string;
  ciphertext: string;
  wrappedKey: string;
}
// A Uint8Array is sent as binary plaintext; decrypt it with decryptBytes.
export interface EncryptInput { plaintext: string | Uint8Array; context: Context; key: string }
export interface DecryptInput { envelope: Envelope; context: Context }
export interface ErrorBody { error: { code: string; message: string; retryable: boolean; requestId: string; path?: string } }
