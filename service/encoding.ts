export const utf8 = new TextEncoder();
export function base64(bytes: Uint8Array): string {
  let result = '';
  for (const b of bytes) result += String.fromCharCode(b);
  return btoa(result);
}
export function unbase64(s: string): Uint8Array<ArrayBuffer> {
  if (typeof s !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) throw new Error('Invalid base64');
  const result = Uint8Array.from(atob(s), c => c.charCodeAt(0));
  if (base64(result) !== s) throw new Error('Noncanonical base64');
  return result;
}
export const base64url = (b: Uint8Array) => base64(b).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
export function unbase64url(s: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('Invalid base64url');
  return unbase64(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4));
}
export async function sha256(s: string): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
}
export function equalHash(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  for (let i = 0; i < 64; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
export function crc32c(bytes: Uint8Array): string {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
  }
  return String((crc ^ 0xffffffff) >>> 0);
}
