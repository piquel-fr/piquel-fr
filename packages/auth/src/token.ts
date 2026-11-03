/** Validated tokens, and the checks they pass. */
import * as wire from './claims.ts';
import { AuthError } from './error.ts';
import { Jws, type KeyCache } from './keys.ts';
import * as json from './json.ts';
import type {
  AccessTokenClaims,
  Acr,
  Algorithm,
  Audience,
  AuthenticationClaims,
  IdTokenClaims,
  LogoutTokenClaims,
  StepUpRequirement,
  TokenType
} from './protocol.ts';
import { Scopes } from './scope.ts';
import { type Clock, LEEWAY } from './time.ts';

/** Longest a logout token may be valid, in seconds: auth signs each delivery attempt for two minutes. */
const MAX_LOGOUT_LIFETIME = 10 * 60;

/** The registered claims every token type checks the same way. */
type RegisteredClaims = { iss: string; aud: Audience; exp: number; iat: number; nbf?: number };

/** What one kind of token is checked against. */
type Kind<C extends RegisteredClaims> = {
  /** The `typ` header auth signs it with. */
  typ: TokenType;
  /** Its claims. */
  claims: json.Decoder<C>;
  /**
   * Whether `aud` must name the expected audience alone. ID tokens trust no other
   * audience (OIDC Core §3.1.3.7), and auth addresses each logout token to one
   * client; access tokens may name several resources.
   */
  exclusiveAudience: boolean;
};

const ACCESS: Kind<AccessTokenClaims> = {
  typ: 'at+jwt',
  claims: wire.accessTokenClaims,
  exclusiveAudience: false
};
const ID: Kind<IdTokenClaims> = { typ: 'JWT', claims: wire.idTokenClaims, exclusiveAudience: true };
const LOGOUT: Kind<LogoutTokenClaims> = {
  typ: 'logout+jwt',
  claims: wire.logoutTokenClaims,
  exclusiveAudience: true
};

/** Where a validated token checks requirements. */
type Context = {
  /** The issuer's clock. */
  clock: Clock;
  /** The resource's metadata URL, for its challenges. */
  resourceMetadata?: string | undefined;
};

/** A validated token reporting how the user authenticated: an access or ID token. */
abstract class AuthenticatedToken<C extends AuthenticationClaims> {
  /** The validated claims. */
  readonly claims: C;
  /** @internal */
  protected readonly context: Context;

  protected constructor(claims: C, context: Context) {
    this.claims = claims;
    this.context = context;
  }

  /** Whether a session at class `acr` meets `required`: `phr` meets every class. */
  static #satisfies(acr: Acr | undefined, required: Acr): boolean {
    return acr === 'phr' || acr === required;
  }

  /**
   * Whether the authentication meets `requirement` now, as auth judges it: `acr`
   * meets the required class, and `auth_time` is at most `max_age` old, allowing the
   * 30-second leeway. A missing claim meets no requirement on it.
   */
  meets(requirement: StepUpRequirement): boolean {
    const { acr, auth_time } = this.claims;
    const strong =
      requirement.acr_values === undefined ||
      AuthenticatedToken.#satisfies(acr, requirement.acr_values);
    const recent =
      requirement.max_age === undefined ||
      (auth_time !== undefined &&
        this.context.clock() - LEEWAY - auth_time * 1000 <= requirement.max_age * 1000);
    return strong && recent;
  }

  /**
   * Requires the authentication to meet `requirement`, or throws
   * `insufficient_user_authentication`, whose challenge asks the client to sign the
   * user in again with `acr_values` and `max_age` (RFC 9470).
   */
  requireAuthentication(requirement: StepUpRequirement): void {
    if (this.meets(requirement)) return;
    throw new AuthError(
      { code: 'insufficient_user_authentication', requirement },
      'the authentication is too weak or too old'
    ).forResource(this.context.resourceMetadata);
  }
}

/** Who an access token acts for: a user's account, or the client itself (RFC 9068 §2.2). */
export type Subject = { kind: 'user'; id: string } | { kind: 'client'; id: string };

/** Names the scopes an {@link AccessToken} is proven to hold; exists only in types. */
declare const proven: unique symbol;

/**
 * `S` when it names one scope, `never` when it is a union: a value typed
 * `'notes:read' | 'notes:write'` is checked as one of them, so it proves neither.
 */
export type Single<S, All = S> = S extends unknown ? ([All] extends [S] ? S : never) : never;

/** Reads an application's own claims from a token's claims object; throws when they are invalid. */
export type ClaimsReader<Extra> = (claims: Readonly<Record<string, unknown>>) => Extra;

/**
 * A validated access token. `Declared` are the scopes its resource declared, and
 * `Proven` those it is proven to hold, so a function can ask for
 * `AccessToken<Notes, 'notes:write'>` and only receive tokens checked for it.
 * `Extra` are the application claims its resource reads, in {@link extra}.
 */
export class AccessToken<
  Declared extends string = string,
  Proven extends Declared = never,
  Extra = unknown
> extends AuthenticatedToken<AccessTokenClaims> {
  /** Phantom member carrying `Proven`: a token proving more scopes is still accepted. */
  declare readonly [proven]: (scope: Proven) => void;
  /** Who the token acts for. */
  readonly subject: Subject;
  /** The granted scopes. */
  readonly scopes: Scopes;
  /** The application claims the resource's `claims` reader returned; `undefined` without one. */
  readonly extra: Extra;

  private constructor(claims: AccessTokenClaims, extra: Extra, context: Context, subject: Subject) {
    super(claims, context);
    this.extra = extra;
    this.subject = subject;
    this.scopes = Scopes.parse(claims.scope) ?? Scopes.of([]);
  }

  /**
   * @internal Wraps validated claims. A `sub` equal to `client_id` with no session is
   * the client itself; any other `sub` must be an account ID.
   */
  static from<D extends string, X>(
    claims: AccessTokenClaims,
    extra: X,
    context: Context
  ): AccessToken<D, never, X> {
    if (claims.sid === undefined && claims.sub === claims.client_id) {
      return new AccessToken(claims, extra, context, { kind: 'client', id: claims.sub });
    }
    try {
      wire.uuid(claims.sub, 'sub');
    } catch (error) {
      throw AuthError.invalidToken(
        'invalid_claims',
        'the token subject is not an account ID',
        error
      );
    }
    return new AccessToken(claims, extra, context, { kind: 'user', id: claims.sub });
  }

  /** Whether the token holds `scope`; narrows its type when it does. */
  has<S extends Declared>(scope: S & Single<S>): this is AccessToken<Declared, Proven | S, Extra> {
    return this.scopes.has(scope);
  }

  /**
   * Requires every scope in `scopes`, returning the token with their proof, or throws
   * `insufficient_scope`, whose challenge names every scope required.
   */
  require<const T extends readonly [Declared, ...Declared[]]>(
    ...scopes: T & { [K in keyof T]: Single<T[K]> }
  ): AccessToken<Declared, Proven | T[number], Extra> {
    // The proof exists only in types, and the scopes were just checked.
    if (scopes.every((scope) => this.scopes.has(scope))) {
      return this as unknown as AccessToken<Declared, Proven | T[number], Extra>;
    }
    throw new AuthError(
      { code: 'insufficient_scope', scope: Scopes.of(scopes).toString() },
      `the token lacks a scope of ${scopes.join(' ')}`
    ).forResource(this.context.resourceMetadata);
  }
}

/** A validated ID token, kept with its compact form for logout's `id_token_hint`. */
export class IdToken extends AuthenticatedToken<IdTokenClaims> {
  /** The token as issued. */
  readonly token: string;

  private constructor(claims: IdTokenClaims, token: string, context: Context) {
    super(claims, context);
    this.token = token;
  }

  /** @internal Wraps validated claims and the compact token they came from. */
  static from(claims: IdTokenClaims, token: string, context: Context): IdToken {
    return new IdToken(claims, token, context);
  }

  /** @internal Whether `other` names the same user at the same issuer, as a refresh's ID token must (OIDC Core §12.2). */
  sameUser(other: IdToken): boolean {
    return other.claims.sub === this.claims.sub && other.claims.iss === this.claims.iss;
  }
}

/** Which sessions a back-channel logout ends: one auth session, or every session of a user. */
export type LogoutTarget = { kind: 'session'; sid: string } | { kind: 'subject'; sub: string };

/** A validated back-channel logout token (OIDC Back-Channel Logout 1.0 §2.6). */
export class LogoutToken {
  /** The validated claims. */
  readonly claims: LogoutTokenClaims;
  /** What the token ends: its `sid` when it names one, else every session of its `sub`. */
  readonly target: LogoutTarget;

  private constructor(claims: LogoutTokenClaims, target: LogoutTarget) {
    this.claims = claims;
    this.target = target;
  }

  /**
   * @internal Applies the checks particular to logout tokens: a lifetime of at most
   * 10 minutes, and `sub` or `sid`. Decoding already required the logout event and no
   * `nonce`.
   */
  static from(claims: LogoutTokenClaims): LogoutToken {
    if (claims.exp - claims.iat > MAX_LOGOUT_LIFETIME) {
      throw AuthError.invalidToken(
        'lifetime_too_long',
        'the logout token is valid for over 10 minutes'
      );
    }
    if (claims.sid !== undefined) {
      return new LogoutToken(claims, { kind: 'session', sid: claims.sid });
    }
    if (claims.sub !== undefined) {
      return new LogoutToken(claims, { kind: 'subject', sub: claims.sub });
    }
    throw AuthError.invalidToken('invalid_claims', 'the logout token names neither sub nor sid');
  }
}

/** @internal Validates an issuer's tokens, running the checks of docs/architecture/sdk.md in order. */
export class TokenValidator {
  readonly #issuer: string;
  readonly #algorithms: readonly Algorithm[];
  readonly #keys: KeyCache;
  readonly #clock: Clock;

  /** Validates tokens `issuer` signs with `algorithms` and `keys`. */
  constructor(issuer: string, algorithms: readonly Algorithm[], keys: KeyCache, clock: Clock) {
    this.#issuer = issuer;
    this.#algorithms = algorithms;
    this.#keys = keys;
    this.#clock = clock;
  }

  /** An access token for the resource `audience`, with the application claims `read` returns. */
  async accessToken<D extends string, X>(
    token: string,
    audience: string,
    resourceMetadata: string | undefined,
    read: ClaimsReader<X>
  ): Promise<AccessToken<D, never, X>> {
    const [decoded, extra] = await this.#decode(token, ACCESS, audience, read);
    return AccessToken.from(decoded, extra, { clock: this.#clock, resourceMetadata });
  }

  /**
   * An ID token for `client`, against the pending login's `nonce` and `max_age` when
   * it sent them.
   */
  async idToken(
    token: string,
    client: string,
    nonce: string | undefined,
    maxAge: number | undefined
  ): Promise<IdToken> {
    const [decoded] = await this.#decode(token, ID, client);
    if (nonce !== undefined && decoded.nonce !== nonce) {
      throw AuthError.invalidToken(
        'nonce_mismatch',
        'the ID token nonce does not match this login'
      );
    }
    if (decoded.azp !== undefined && decoded.azp !== client) {
      throw AuthError.invalidToken(
        'wrong_authorized_party',
        `the ID token authorized party is ${decoded.azp}, expected ${client}`
      );
    }
    const id = IdToken.from(decoded, token, { clock: this.#clock });
    if (maxAge !== undefined && !id.meets({ max_age: maxAge })) {
      throw AuthError.invalidToken(
        'authentication_too_old',
        `the authentication is older than ${String(maxAge)} seconds`
      );
    }
    return id;
  }

  /** A back-channel logout token for `client`. */
  async logoutToken(token: string, client: string): Promise<LogoutToken> {
    const [decoded] = await this.#decode(token, LOGOUT, client);
    return LogoutToken.from(decoded);
  }

  /**
   * The checks every token type shares, in order: framing, `crit`, `typ`, algorithm,
   * key, signature, claims, issuer, audience, then times with the leeway. `read`
   * reads application claims as part of the claims check, as the Rust SDK
   * deserializes them with the rest.
   */
  async #decode<C extends RegisteredClaims, X = undefined>(
    token: string,
    kind: Kind<C>,
    audience: string,
    read?: ClaimsReader<X>
  ): Promise<[C, X]> {
    const jws = Jws.parse(token);
    jws.requireType(kind.typ);
    await this.#keys.verify(jws, jws.requireAlgorithm(this.#algorithms));
    let decoded: C;
    let extra: X;
    try {
      const raw = json.parse(new TextDecoder('utf-8', { fatal: true }).decode(jws.payload));
      decoded = kind.claims(raw, 'claims');
      // The claims decoded, so `raw` is an object.
      extra = read === undefined ? (undefined as X) : read(raw as Record<string, unknown>);
    } catch (error) {
      throw AuthError.invalidToken('invalid_claims', 'the token claims are invalid', error);
    }
    if (decoded.iss !== this.#issuer) {
      throw AuthError.invalidToken(
        'issuer_mismatch',
        `the token issuer is ${decoded.iss}, expected ${this.#issuer}`
      );
    }
    const audiences = typeof decoded.aud === 'string' ? [decoded.aud] : decoded.aud;
    const others = kind.exclusiveAudience && audiences.some((value) => value !== audience);
    if (others || !audiences.includes(audience)) {
      throw AuthError.invalidToken('wrong_audience', `the token audience is not ${audience}`);
    }
    const now = this.#clock();
    if (now >= decoded.exp * 1000 + LEEWAY)
      throw AuthError.invalidToken('expired', 'the token expired');
    if (decoded.nbf !== undefined && decoded.nbf * 1000 > now + LEEWAY) {
      throw AuthError.invalidToken('not_yet_valid', 'the token is not valid yet');
    }
    if (decoded.iat * 1000 > now + LEEWAY) {
      throw AuthError.invalidToken('issued_in_future', 'the token is issued in the future');
    }
    return [decoded, extra];
  }
}
