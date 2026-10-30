/** Compact JWS parsing and the signing key cache. */
import * as base64 from './base64.ts';
import { asciiLowercase } from './challenge.ts';
import { AuthError } from './error.ts';
import { type Fetch, Http, type Reply } from './http.ts';
import * as json from './json.ts';
import type { Algorithm, Jwk, TokenType } from './protocol.ts';
import type { Clock } from './time.ts';
import { ALGORITHMS, KEY_TYPES, KEY_USES } from './vocabulary.ts';

/** Most bytes accepted for a compact token, checked before decoding it. */
const MAX_TOKEN_BYTES = 16 * 1024;
/** Shortest time between two key fetches, whatever triggers them, in milliseconds. */
const MIN_FETCH_INTERVAL = 30_000;
/** How long fetched keys stay fresh when the response sets no `max-age`. */
const DEFAULT_LIFETIME = 60 * 60_000;
/** Longest time fetched keys stay fresh, whatever `max-age` says. */
const MAX_LIFETIME = 24 * 60 * 60_000;
/** `typ` media types may carry this prefix (RFC 7515 §4.1.9). */
const MEDIA_TYPE_PREFIX = 'application/';

/** The protected header of a compact JWS. */
export type JwsHeader = {
  /** Signing algorithm, as sent. */
  alg: string;
  /** Key that signed the token. */
  kid?: string;
  /** Token type. */
  typ?: string;
};

const jwsHeader: json.Decoder<JwsHeader> = json.object({
  alg: json.string,
  kid: json.optional(json.string),
  typ: json.optional(json.string)
});

/**
 * A compact JWS, decoded but not yet verified. Parse a token, check its header, then
 * verify it with a {@link KeyCache} before reading the payload:
 *
 * ```ts
 * const jws = Jws.parse(token);
 * jws.requireType('JWT');
 * await keys.verify(jws, jws.requireAlgorithm(['RS256']));
 * const claims: unknown = JSON.parse(new TextDecoder().decode(jws.payload));
 * ```
 */
export class Jws {
  /** The protected header. */
  readonly header: JwsHeader;
  /** The payload. Read it only once the signature has been verified. */
  readonly payload: Uint8Array<ArrayBuffer>;
  /** `header.payload`, the bytes the signature covers. */
  readonly #signingInput: Uint8Array<ArrayBuffer>;
  readonly #signature: Uint8Array<ArrayBuffer>;

  private constructor(
    header: JwsHeader,
    signingInput: string,
    payload: Uint8Array<ArrayBuffer>,
    signature: Uint8Array<ArrayBuffer>
  ) {
    this.header = header;
    this.#signingInput = new TextEncoder().encode(signingInput);
    this.payload = payload;
    this.#signature = signature;
  }

  /**
   * Splits and decodes a compact JWS. Throws `malformed` unless the token is three
   * base64url segments, at most 16 KiB, with a JSON header, and
   * `unsupported_critical_header` if that header has `crit`, even `null`: this SDK
   * understands no JWS extensions (RFC 7515 §4.1.11).
   */
  static parse(token: string): Jws {
    if (new TextEncoder().encode(token).length > MAX_TOKEN_BYTES) {
      throw AuthError.invalidToken('malformed', 'the token exceeds 16 KiB');
    }
    const segments = token.split('.');
    const [header, payload, signature] = segments;
    if (
      header === undefined ||
      payload === undefined ||
      signature === undefined ||
      segments.length !== 3
    ) {
      throw AuthError.invalidToken('malformed', 'the token is not three segments');
    }
    const decode = (segment: string) => {
      const bytes = base64.decode(segment);
      if (bytes === undefined)
        throw AuthError.invalidToken('malformed', 'a segment is not base64url');
      return bytes;
    };
    const headerBytes = decode(header);
    let raw: unknown;
    let parsed: JwsHeader;
    try {
      raw = json.parse(new TextDecoder('utf-8', { fatal: true }).decode(headerBytes));
      parsed = jwsHeader(raw, 'header');
    } catch (error) {
      throw new AuthError(
        { code: 'invalid_token', reason: 'malformed' },
        'the header is not a JWS header',
        { cause: error }
      );
    }
    if (json.isObject(raw) && Object.hasOwn(raw, 'crit')) {
      throw AuthError.invalidToken(
        'unsupported_critical_header',
        'the token requires header extensions this SDK does not understand'
      );
    }
    return new Jws(parsed, `${header}.${payload}`, decode(payload), decode(signature));
  }

  /**
   * Requires `typ` to be `expected`, compared case-insensitively with or without the
   * `application/` prefix (RFC 7515 §4.1.9); otherwise throws `wrong_type`.
   */
  requireType(expected: TokenType): void {
    const typ = asciiLowercase(this.header.typ ?? '');
    const bare = typ.startsWith(MEDIA_TYPE_PREFIX) ? typ.slice(MEDIA_TYPE_PREFIX.length) : typ;
    if (this.header.typ === undefined || bare !== asciiLowercase(expected)) {
      throw AuthError.invalidToken(
        'wrong_type',
        `the token type is ${JSON.stringify(this.header.typ ?? null)}, expected ${expected}`
      );
    }
  }

  /**
   * Requires `alg` to be one of `allowed`, and returns it; otherwise throws
   * `unsupported_algorithm`, as for `none` and HMAC.
   */
  requireAlgorithm(allowed: readonly Algorithm[]): Algorithm {
    const algorithm = allowed.find((name) => name === this.header.alg);
    if (algorithm === undefined) {
      throw AuthError.invalidToken(
        'unsupported_algorithm',
        `the token algorithm ${JSON.stringify(this.header.alg)} is not accepted`
      );
    }
    return algorithm;
  }

  /** @internal Whether the signature verifies under `key`. */
  async verifiedBy(key: CryptoKey): Promise<boolean> {
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, this.#signature, this.#signingInput);
  }
}

const jwk: json.Decoder<Jwk> = json.object({
  alg: json.optional(json.oneOf(ALGORITHMS)),
  e: json.string,
  kid: json.string,
  kty: json.oneOf(KEY_TYPES),
  n: json.string,
  use: json.optional(json.oneOf(KEY_USES))
});

const jwkSet = json.object({ keys: json.array((value) => value) });

/** One usable signing key. */
class SigningKey {
  /** Key ID matched against token headers. */
  readonly kid: string;
  /** The algorithms the key may verify: the one the set names, or any. */
  readonly algorithms: readonly Algorithm[];
  readonly #jwk: Jwk;
  /** The imported key, once a token needed it. */
  #imported: Promise<CryptoKey> | undefined;

  constructor(key: Jwk) {
    this.kid = key.kid;
    this.algorithms = key.alg === undefined ? ALGORITHMS : [key.alg];
    this.#jwk = key;
  }

  /**
   * The key, imported for RS256 verification on first use. A modulus outside 2048 to
   * 8192 bits is refused, as the Rust SDK's verifier refuses it, so no SDK accepts a
   * token signed with a weak key.
   */
  imported(): Promise<CryptoKey> {
    this.#imported ??= (async () => {
      const bits = (base64.decode(this.#jwk.n)?.length ?? 0) * 8;
      if (bits < 2048 || bits > 8192) throw new RangeError(`an RSA key of ${String(bits)} bits`);
      return crypto.subtle.importKey(
        'jwk',
        { kty: this.#jwk.kty, n: this.#jwk.n, e: this.#jwk.e },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      );
    })();
    return this.#imported;
  }
}

/** The usable keys of a JSON Web Key Set. */
export class KeySet {
  /** Keys in document order. */
  readonly #keys: SigningKey[];

  private constructor(keys: SigningKey[]) {
    this.#keys = keys;
  }

  /** The empty set a cache holds before its first fetch. */
  static readonly empty = new KeySet([]);

  /**
   * Parses a key set. Keys this SDK cannot use are skipped, as RFC 7517 §5 asks: an
   * unknown `kty` or `alg`, a `use` other than `sig`, no `kid`, or material that is
   * not base64url. Throws `keys` errors when the document is not a key set
   * (`invalid_document`), or two usable keys share a `kid` (`duplicate_key_id`).
   */
  static parse(document: unknown): KeySet {
    return KeySet.#decode(() => document);
  }

  /** Parses a key set from a response body. */
  static read(reply: Reply): KeySet {
    return KeySet.#decode(() => reply.json());
  }

  static #decode(read: () => unknown): KeySet {
    let values: unknown[];
    try {
      values = jwkSet(read(), 'jwks').keys;
    } catch (error) {
      throw new AuthError(
        { code: 'keys', reason: 'invalid_document' },
        'signing keys are not a JSON Web Key Set',
        { cause: error }
      );
    }
    const keys: SigningKey[] = [];
    for (const [index, value] of values.entries()) {
      let key: Jwk;
      try {
        key = jwk(value, `jwks.keys[${String(index)}]`);
      } catch {
        continue;
      }
      if (base64.decode(key.n) === undefined || base64.decode(key.e) === undefined) continue;
      if (keys.some((usable) => usable.kid === key.kid)) {
        throw new AuthError(
          { code: 'keys', reason: 'duplicate_key_id' },
          `two signing keys share the key ID ${JSON.stringify(key.kid)}`
        );
      }
      keys.push(new SigningKey(key));
    }
    return new KeySet(keys);
  }

  /** Key IDs of the usable keys, in document order. */
  get kids(): string[] {
    return this.#keys.map((key) => key.kid);
  }

  /** @internal The key named `kid`. */
  find(kid: string): SigningKey | undefined {
    return this.#keys.find((key) => key.kid === kid);
  }
}

/** Options for a {@link KeyCache}. */
export type KeyCacheOptions = {
  /** Sends the key requests; the global `fetch` by default. */
  fetch?: Fetch;
  /** Reads time for freshness and fetch spacing; `Date.now` by default. */
  clock?: Clock;
};

/**
 * A cache of an issuer's signing keys, usable with any JWKS URL. Share one per
 * issuer: every verification shares its keys and fetch spacing.
 *
 * - An unknown `kid` triggers one refetch, then fails with `unknown_key`.
 * - Keys are fetched at most once every 30 seconds, whatever the reason, so unknown
 *   key IDs cannot flood the issuer.
 * - Keys stay fresh for the response's `Cache-Control: max-age`, bounded to 30
 *   seconds through 24 hours, or one hour without one.
 * - A failed fetch keeps the last good keys, and still counts as a fetch.
 */
export class KeyCache {
  readonly #url: string;
  readonly #http: Http;
  readonly #clock: Clock;
  /** Keys from the last successful fetch. */
  #keys = KeySet.empty;
  /** When the keys stop being fresh; `undefined` before the first successful fetch. */
  #freshUntil: number | undefined;
  /** Start of the last fetch, successful or not. */
  #fetchedAt: number | undefined;
  /** Whether the last fetch failed. */
  #failed = false;
  /** The fetch in flight, which concurrent verifications wait for instead of fetching. */
  #fetching: Promise<void> | undefined;

  /** Keys fetched from `jwksUri` on first use. */
  constructor(jwksUri: string, options: KeyCacheOptions = {}) {
    this.#url = jwksUri;
    this.#http = new Http(options.fetch);
    this.#clock = options.clock ?? Date.now;
  }

  /**
   * Verifies `jws`'s signature under `algorithm`, which the caller checked with
   * {@link Jws.requireAlgorithm}, with the key its `kid` names. Throws `unknown_key`
   * when no usable key matches, `keys` or `network` errors when keys were needed but
   * could not be fetched, and `bad_signature` when the signature does not verify.
   */
  async verify(jws: Jws, algorithm: Algorithm): Promise<void> {
    const kid = jws.header.kid;
    if (kid === undefined) throw AuthError.invalidToken('unknown_key', 'the token names no key');
    const key = await this.#key(kid);
    if (!key.algorithms.includes(algorithm)) {
      throw AuthError.invalidToken(
        'unknown_key',
        `key ${JSON.stringify(kid)} is not for ${algorithm}`
      );
    }
    let verified: boolean;
    try {
      verified = await jws.verifiedBy(await key.imported());
    } catch {
      verified = false;
    }
    if (!verified) throw AuthError.invalidToken('bad_signature', 'the token signature is invalid');
  }

  /** The key named `kid`, if the cached keys hold it and are fresh. */
  #fresh(kid: string): SigningKey | undefined {
    const fresh = this.#freshUntil !== undefined && this.#clock() < this.#freshUntil;
    return fresh ? this.#keys.find(kid) : undefined;
  }

  /** The key named `kid`, fetching keys when they are stale or lack it and the last fetch is old enough. */
  async #key(kid: string): Promise<SigningKey> {
    const fresh = this.#fresh(kid);
    if (fresh !== undefined) return fresh;
    // Another verification may be fetching the key already.
    while (this.#fetching !== undefined) await this.#fetching;
    const fetched = this.#fresh(kid);
    if (fetched !== undefined) return fetched;
    const now = this.#clock();
    if (this.#fetchedAt === undefined || now - this.#fetchedAt >= MIN_FETCH_INTERVAL) {
      // Counted as failed until it succeeds.
      this.#fetchedAt = now;
      this.#failed = true;
      const fetching = this.#refresh(now, kid);
      this.#fetching = fetching.then(
        () => undefined,
        () => undefined
      );
      try {
        await fetching;
      } finally {
        this.#fetching = undefined;
      }
    }
    const key = this.#keys.find(kid);
    if (key !== undefined) return key;
    if (this.#failed) {
      throw new AuthError({ code: 'network' }, 'signing keys could not be fetched recently');
    }
    throw AuthError.invalidToken(
      'unknown_key',
      `no signing key matches key ID ${JSON.stringify(kid)}`
    );
  }

  /** Fetches the key set, keeping the old one if the fetch fails. */
  async #refresh(now: number, kid: string): Promise<void> {
    try {
      const reply = (await this.#http.get(this.#url)).ok();
      const keys = KeySet.read(reply);
      const lifetime = reply.maxAge === undefined ? DEFAULT_LIFETIME : reply.maxAge * 1000;
      this.#keys = keys;
      this.#freshUntil = now + Math.min(Math.max(lifetime, MIN_FETCH_INTERVAL), MAX_LIFETIME);
      this.#failed = false;
    } catch (error) {
      // Stale keys that hold `kid` are better than failing every request while the
      // key endpoint is down.
      if (this.#keys.find(kid) === undefined) throw error;
    }
  }
}
