/**
 * What the browser's cookies hold: the signed-in user's session, and each login
 * waiting for its callback. Both are sealed with the app's `CookieKey`; nothing is
 * kept server-side.
 */
import { idTokenClaims, scope } from './claims.ts';
import { type PendingLogin, type Tokens, pendingLogin } from './client.ts';
import * as json from './json.ts';
import type { IdTokenClaims } from './protocol.ts';
import { Scopes } from './scope.ts';

/**
 * What the session cookie holds, the Rust SDK's `LoginData`: every SDK reads and
 * writes this shape, which `tests/sdk-vectors/sessions` pins. Times are Unix seconds.
 */
const loginData = json.object({
  /** The validated claims of the sign-in's ID token, or of the latest refresh that returned one. */
  claims: idTokenClaims,
  /** The latest access token. */
  access_token: json.string,
  /** When the access token expires. */
  expires_at: json.seconds,
  /** Scopes granted to the access token, sorted and space-separated. */
  scopes: scope,
  /** The refresh token. A confidential client's does not rotate, so every copy of the cookie stays usable. */
  refresh_token: json.optional(json.string),
  /** When the session ends, checked as well as the cookie's `Max-Age`, which a copied cookie escapes. */
  ends_at: json.seconds
});
type LoginData = ReturnType<typeof loginData>;

/**
 * @internal A signed-in user's session, as its sealed cookie holds it: the access
 * token and the refresh token, and the claims of the sign-in's ID token, but not the
 * token itself, so the cookie stays small.
 */
export class StoredLogin {
  /** Reads a session cookie's plaintext. */
  static readonly decoder: json.Decoder<StoredLogin> = (value, path) =>
    new StoredLogin(loginData(value, path));

  /** The cookie's shape, as it is sealed. */
  readonly data: LoginData;

  private constructor(data: LoginData) {
    this.data = data;
  }

  /**
   * The session `tokens` start, ending at `endsAt`, in milliseconds since the epoch, if
   * they hold the ID token every sign-in returns. Without a refresh token, the session
   * cannot learn that auth revoked it, so it ends with its access token.
   */
  static start(tokens: Tokens, endsAt: number): StoredLogin | undefined {
    const { idToken, refreshToken, expiresAt } = tokens;
    if (idToken === undefined) return undefined;
    const end = refreshToken === undefined ? Math.min(endsAt, expiresAt) : endsAt;
    return StoredLogin.#of(idToken.claims, tokens, refreshToken, StoredLogin.#seconds(end));
  }

  /**
   * This session after a refresh returned `tokens`. An absent ID token or refresh
   * token keeps the current one. `undefined` if a new ID token names another user or
   * issuer (OIDC Core §12.2).
   */
  refreshed(tokens: Tokens): StoredLogin | undefined {
    const { idToken, refreshToken } = tokens;
    if (idToken !== undefined && !idToken.sameUser(this.claims)) return undefined;
    return StoredLogin.#of(
      idToken?.claims ?? this.claims,
      tokens,
      refreshToken ?? this.refreshToken,
      this.data.ends_at
    );
  }

  /** The session of `claims` with the access token of `tokens`, ending at Unix second `endsAt`. */
  static #of(
    claims: IdTokenClaims,
    tokens: Tokens,
    refreshToken: string | undefined,
    endsAt: number
  ): StoredLogin {
    return new StoredLogin({
      claims,
      access_token: tokens.accessToken,
      expires_at: StoredLogin.#seconds(tokens.expiresAt),
      scopes: tokens.scopes.toString(),
      ...(refreshToken === undefined ? {} : { refresh_token: refreshToken }),
      ends_at: endsAt
    });
  }

  /** Milliseconds since the epoch, as whole Unix seconds. */
  static #seconds(milliseconds: number): number {
    return Math.floor(milliseconds / 1000);
  }

  /** The validated claims of the sign-in's ID token, or of the latest refresh that returned one. */
  get claims(): IdTokenClaims {
    return this.data.claims;
  }

  /** The latest access token. */
  get accessToken(): string {
    return this.data.access_token;
  }

  /** When the access token expires, in milliseconds since the epoch. */
  get expiresAt(): number {
    return this.data.expires_at * 1000;
  }

  /** Scopes granted to the access token. */
  get scopes(): Scopes {
    return Scopes.parse(this.data.scopes) ?? Scopes.of([]);
  }

  /** The refresh token, which only the SDK redeems. */
  get refreshToken(): string | undefined {
    return this.data.refresh_token;
  }

  /** When the session ends, whatever happens at auth, in milliseconds since the epoch. */
  get endsAt(): number {
    return this.data.ends_at * 1000;
  }
}

/**
 * @internal A login waiting for its callback, with where to send the user afterwards.
 * The browser keeps it, sealed, in a cookie named for its `state`. Only the SDK that
 * started a login completes it, so its shape is this SDK's own.
 */
export type PendingAuthorization = {
  /** The PKCE verifier, `state` and `nonce` of the login. */
  login: PendingLogin;
  /** Where the user goes once signed in, a checked same-origin path. */
  returnTo: string;
  /** Whether the login steps up, so the return to `returnTo` is its retry. */
  stepUp: boolean;
  /**
   * When the login expires, in milliseconds since the epoch, checked as well as the
   * cookie's `Max-Age`, which a copied cookie escapes.
   */
  expiresAt: number;
};

/** @internal Reads a pending login cookie's plaintext. */
export const pendingAuthorization: json.Decoder<PendingAuthorization> = json.object({
  login: pendingLogin,
  returnTo: json.string,
  stepUp: json.boolean,
  expiresAt: json.integer(0, Number.MAX_SAFE_INTEGER)
});
