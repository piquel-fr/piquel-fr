/**
 * Sealing: AES-256-GCM under keys derived with HKDF-SHA256 from the app's
 * {@link CookieKey}, for the session and pending-login cookies the browser keeps. The
 * format is the Rust SDK's, so a cookie one seals opens in the other.
 */
import * as base64 from './base64.ts';
import * as json from './json.ts';

/** Bytes in a cookie key, and in the AES-256 keys derived from it. */
const SECRET_BYTES = 32;
/** Bytes in an AES-GCM nonce. */
const NONCE_BYTES = 12;

/**
 * How a cookie key may be written, each decoding to its bytes or `undefined`:
 * `openssl rand -base64 32` prints padded standard base64, and piqueld generates
 * secrets as hex or unpadded base64url. They are tried in this order, the Rust SDK's:
 * hex first, since hex text is also base64.
 */
const ENCODINGS: readonly ((text: string) => Uint8Array<ArrayBuffer> | undefined)[] = [
  (text) =>
    /^(?:[0-9a-fA-F]{2})*$/.test(text)
      ? Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16))
      : undefined,
  (text) =>
    /^[A-Za-z0-9+/]*=*$/.test(text)
      ? paddingOptional(text.replace(/\+/g, '-').replace(/\//g, '_'))
      : undefined,
  (text) => (/^[A-Za-z0-9_-]*=*$/.test(text) ? paddingOptional(text) : undefined)
];

/** Decodes canonical base64url, with no more padding than it needs, or none. */
function paddingOptional(text: string): Uint8Array<ArrayBuffer> | undefined {
  const unpadded = text.replace(/=+$/, '');
  const padding = text.length - unpadded.length;
  return padding <= (4 - (unpadded.length % 4)) % 4 ? base64.decode(unpadded) : undefined;
}

/**
 * What each sealing key is for, as its HKDF `info`, so the keys derived from one
 * secret for two purposes are unrelated. Each names the format version: a new format
 * gets a new `info`, so cookies of the old one no longer open. Every SDK uses the
 * same, so their cookies interoperate.
 */
const PURPOSES = {
  session: 'sourceorigin-auth session v1',
  pending: 'sourceorigin-auth pending login v1'
} as const;

/**
 * An AES-256-GCM key for one purpose, with a random nonce per seal. Its
 * output binds a context, the cookie's client and name, so a value sealed under one
 * name does not open under another.
 */
class SealingKey {
  readonly #key: CryptoKey;

  private constructor(key: CryptoKey) {
    this.#key = key;
  }

  /** The key for `info` derived from `secret`, which holds 256 random bits: HKDF needs no salt then. */
  static async derive(secret: Uint8Array<ArrayBuffer>, info: string): Promise<SealingKey> {
    const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(),
        info: new TextEncoder().encode(info)
      },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return new SealingKey(key);
  }

  /** `value` as JSON, sealed for `context`: base64url of the nonce, the ciphertext and the tag. */
  async seal(value: unknown, context: string): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(context) },
      this.#key,
      new TextEncoder().encode(JSON.stringify(value))
    );
    const framed = new Uint8Array(NONCE_BYTES + sealed.byteLength);
    framed.set(iv);
    framed.set(new Uint8Array(sealed), NONCE_BYTES);
    return base64.encode(framed);
  }

  /**
   * The value sealed for `context`, if `sealed` opens with this key and `decoder`
   * reads it. Anything else, tampered with, sealed for another context or by another
   * key, is `undefined`.
   */
  async open<T>(sealed: string, context: string, decoder: json.Decoder<T>): Promise<T | undefined> {
    const framed = base64.decode(sealed);
    if (framed === undefined || framed.length < NONCE_BYTES) return undefined;
    let plain: ArrayBuffer;
    try {
      plain = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: framed.subarray(0, NONCE_BYTES),
          additionalData: new TextEncoder().encode(context)
        },
        this.#key,
        framed.subarray(NONCE_BYTES)
      );
    } catch {
      return undefined;
    }
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(plain);
      return decoder(json.parse(text), 'cookie');
    } catch {
      // Not UTF-8, not JSON, or not the expected shape.
      return undefined;
    }
  }
}

/** @internal The keys a {@link CookieKey} derives, one per purpose. */
export type SealingKeys = { [P in keyof typeof PURPOSES]: SealingKey };

/**
 * The secret sealing the cookies the browser keeps: the session, with the user's
 * tokens, and each login waiting at auth, with its PKCE verifier and `nonce`. Every
 * replica needs the same key: keep it like any other secret, and generate it with
 * `openssl rand -base64 32`, or as a 32-byte secret piqueld generates. Changing it
 * signs every user out, but ends no grant at auth: if the key leaked, rotate the
 * client secret too, with no grace period, since the refresh tokens in captured
 * cookies stay valid without it. The key is kept in a private field, so it is never
 * printed or serialized.
 *
 * ```ts
 * const cookieKey = CookieKey.parse(process.env.NOTES_COOKIE_KEY ?? '');
 * ```
 */
export class CookieKey {
  readonly #secret: Uint8Array<ArrayBuffer>;
  #keys: Promise<SealingKeys> | undefined;

  private constructor(secret: Uint8Array<ArrayBuffer>) {
    this.#secret = secret;
  }

  /**
   * The key `text` holds: 32 bytes in standard base64, as `openssl rand -base64 32`
   * prints, in base64url or in hex, as piqueld generates them. Base64 may be padded or
   * not, and surrounding ASCII whitespace is ignored. Anything else throws a
   * `TypeError`.
   */
  static parse(text: string): CookieKey {
    const trimmed = text.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '');
    const decoded = ENCODINGS.map((decode) => decode(trimmed)).filter(
      (bytes) => bytes !== undefined
    );
    const secret = decoded.find((bytes) => bytes.length === SECRET_BYTES);
    if (secret !== undefined) return new CookieKey(secret);
    const [other] = decoded;
    throw new TypeError(
      other === undefined
        ? 'a cookie key must be 32 bytes in base64, base64url or hex'
        : `a cookie key must hold 32 bytes, not ${String(other.length)}`
    );
  }

  /**
   * A random key, for development and tests: it lives in this process only, so other
   * replicas cannot open its cookies, and a restart signs every user out.
   */
  static generate(): CookieKey {
    return new CookieKey(crypto.getRandomValues(new Uint8Array(SECRET_BYTES)));
  }

  /** @internal The keys derived from the secret, derived on first use. */
  keys(): Promise<SealingKeys> {
    this.#keys ??= (async () => ({
      session: await SealingKey.derive(this.#secret, PURPOSES.session),
      pending: await SealingKey.derive(this.#secret, PURPOSES.pending)
    }))();
    return this.#keys;
  }
}
