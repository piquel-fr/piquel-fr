/**
 * Unpadded base64url (RFC 4648 §5), as JOSE and PKCE use it. Decoding is strict, as
 * the Rust SDK's: no padding, no other alphabet, and no stray trailing bits, so each
 * value has exactly one encoding.
 */

/** Encodes bytes. */
export function encode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes canonical unpadded base64url, or returns `undefined`. */
export function decode(text: string): Uint8Array<ArrayBuffer> | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return undefined;
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  // `atob` ignores trailing bits; a value that does not round-trip set some.
  return encode(bytes) === text ? bytes : undefined;
}
