/**
 * `@piquel/auth/browser`: sign-in for applications with no server, as public
 * clients. Tokens live in this page's memory only. A login that leaves the page
 * keeps its pending login (PKCE verifier, `state`, `nonce` and issuer) in
 * `sessionStorage` until its callback, which deletes it; no token is ever written
 * to `localStorage`, `sessionStorage` or a cookie.
 *
 * ```ts
 * import { Issuer } from '@piquel/auth';
 * import { browserClient } from '@piquel/auth/browser';
 *
 * const issuer = await Issuer.discover('https://auth.piquel.fr');
 * const auth = browserClient(issuer, { clientId: 'notes-web', redirectUri: `${location.origin}/callback` });
 * const session =
 *   (await auth.handleCallback()) ??
 *   (await auth.restore()) ??
 *   (await auth.signInWithPasskey({ scopes: ['profile'] })); // or auth.login()
 * await session.fetch('https://notes.example/notes');
 * ```
 */
import { parseChallenge, stepUpRequirement } from './challenge.ts';
import { type AuthorizeRequest, type Client, type ClientConfig, pendingLogin } from './client.ts';
import type { PendingLogin, Tokens } from './client.ts';
import { AuthError } from './error.ts';
import type { Issuer } from './issuer.ts';
import * as json from './json.ts';
import { type PasskeyAuthorization, PasskeyCeremony, PasskeyError } from './passkey.ts';
import { type Platform, platform } from './platform.ts';
import type { IdTokenClaims } from './protocol.ts';
import type { Scopes } from './scope.ts';
import { REFRESH_MARGIN, STEP_UP_RETRY } from './time.ts';
import type { IdToken } from './token.ts';

export {
  authorizeWithPasskey,
  PasskeyError,
  type PasskeyAuthorization,
  type PasskeyStep
} from './passkey.ts';

/** What a `prompt=none` login answers when auth has no session it can use silently. */
const NO_SILENT_SESSION = [
  'login_required',
  'interaction_required',
  'consent_required',
  'account_selection_required'
];

/** A public client's registration: its ID and callback, exactly as registered. */
export type BrowserClientConfig = Omit<ClientConfig, 'clientSecret'> & {
  /** @internal The page's APIs; tests replace them. */
  platform?: Platform;
};

/** What a sign-in asks for, and where it comes back to when it leaves the page. */
export type SignInRequest = AuthorizeRequest & {
  /** A page of this origin to come back to; the current page by default. */
  returnTo?: string;
};

/** Why a login left the page, which decides how its callback ends. */
type Purpose = 'sign-in' | 'restore' | 'step-up';

/** A login waiting for its callback in `sessionStorage`. */
type StoredLogin = { pending: PendingLogin; returnTo: string; purpose: Purpose };

const storedLogin: json.Decoder<StoredLogin> = json.object({
  pending: pendingLogin,
  returnTo: json.string,
  purpose: json.oneOf(['sign-in', 'restore', 'step-up'])
});

/**
 * Signs users in to a page with no server, from {@link browserClient}. Call
 * {@link handleCallback} first on every page load, then {@link restore}: each page
 * load restores at most once, so a page whose user is signed out at auth does not
 * loop.
 */
export class BrowserClient {
  /** The login client it signs in with. */
  readonly client: Client;
  /** @internal */
  readonly platform: Platform;
  /** Where its login waits for the callback. */
  readonly #key: string;
  /** Whether a restore came back without a session on this page load. */
  #restored = false;

  private constructor(issuer: Issuer, config: BrowserClientConfig) {
    const { platform: injected, ...registration } = config;
    this.client = issuer.client(registration);
    this.platform = injected ?? platform();
    this.#key = `@piquel/auth:login:${registration.clientId}`;
  }

  /** @internal Use {@link browserClient}. */
  static from(issuer: Issuer, config: BrowserClientConfig): BrowserClient {
    return new BrowserClient(issuer, config);
  }

  /**
   * Completes the login whose callback this page is, or returns `null` when it is
   * not one. The pending login is deleted first, and the address bar goes back to the
   * page the login left from, without the code. A `restore()` auth could not answer
   * silently returns `null`; any other failure throws, as `Client.complete` does.
   */
  async handleCallback(): Promise<Session | null> {
    const here = new URL(this.platform.location.href);
    const callback = new URL(this.client.config.redirectUri);
    const answered = ['code', 'state', 'error', 'iss'].some((name) => here.searchParams.has(name));
    if (here.origin !== callback.origin || here.pathname !== callback.pathname || !answered) {
      return null;
    }
    const stored = this.#take();
    // The router's own state, if any, stays: only the address changes.
    const { history } = this.platform;
    history.replaceState(history.state, '', stored?.returnTo ?? callback.pathname);
    if (stored === undefined) {
      throw new AuthError(
        { code: 'callback', reason: 'state_mismatch' },
        'no login of this page is waiting for this authorization response'
      );
    }
    try {
      return await this.#session(stored.pending, here.searchParams, stored.purpose === 'step-up');
    } catch (error) {
      // A restore that came back without a session is not tried again on this page load.
      if (stored.purpose === 'restore') this.#restored = true;
      const silent =
        error instanceof AuthError && NO_SILENT_SESSION.includes(error.response?.error ?? '');
      if (stored.purpose !== 'restore' || !silent) throw error;
      return null;
    }
  }

  /**
   * Restores the user's session after a reload: the browser goes to auth with
   * `prompt=none`, and comes back to {@link handleCallback} with a session, or without
   * one when the user is signed out at auth. Returns `null` without leaving when this
   * page load already tried.
   */
  async restore(request: Pick<SignInRequest, 'scopes' | 'returnTo'> = {}): Promise<null> {
    if (this.#restored) return null;
    return this.login({ ...request, prompt: 'none' });
  }

  /** Sends the browser to auth's sign-in pages, coming back to {@link handleCallback}. */
  async login(request: SignInRequest = {}): Promise<never> {
    const returnTo = this.#returnTo(request);
    const { url, pending } = await this.client.authorize(request);
    return this.#redirect(url, pending, request, returnTo);
  }

  /**
   * Signs the user in with a passkey on this page, through WebAuthn related origins,
   * returning the same session as {@link handleCallback}. The client must be trusted,
   * and this page's origin approved for it. When the sign-in needs auth's pages, the
   * browser goes there with a pushed request, as {@link login} sends it: the same
   * request when auth left it unclaimed (the browser lacks related origins, or start
   * answered `interaction_required`), and a fresh one after any other failure, since
   * auth may have claimed it. A refused push, and a failed check of auth's answer,
   * throw.
   */
  async signInWithPasskey(request: SignInRequest = {}): Promise<Session> {
    const returnTo = this.#returnTo(request);
    const { url, pending } = await this.client.authorize(request);
    // Without pushed requests, there is no `request_uri` to sign in with on the page.
    const requestUri = new URL(url).searchParams.get('request_uri');
    if (requestUri === null) return this.#redirect(url, pending, request, returnTo);
    let authorization: PasskeyAuthorization;
    try {
      authorization = await new PasskeyCeremony(this.client.issuer, this.platform).run(requestUri);
    } catch (error) {
      if (!(error instanceof PasskeyError)) throw error;
      if (error.unclaimed) return this.#redirect(url, pending, request, returnTo);
      return this.login(request);
    }
    return this.#session(pending, new URLSearchParams(authorization), false);
  }

  /** @internal Sends the browser to `url`, a navigation this page does not come back from. */
  away(url: string): Promise<never> {
    this.platform.location.assign(url);
    return new Promise<never>(() => undefined);
  }

  /**
   * Where `request`'s login comes back to: its `returnTo`, which must be on this
   * page's origin, or this page. Checked before anything is sent.
   */
  #returnTo(request: SignInRequest): string {
    const here = new URL(this.platform.location.href);
    const returnTo = new URL(request.returnTo ?? here.href, here);
    if (returnTo.origin !== here.origin) {
      throw new TypeError(`returnTo must be on this page's origin, not ${returnTo.origin}`);
    }
    return returnTo.href;
  }

  /** Keeps `request`'s pending login until its callback, and leaves for `url`. */
  #redirect(
    url: string,
    pending: PendingLogin,
    request: SignInRequest,
    returnTo: string
  ): Promise<never> {
    const purpose: Purpose =
      request.prompt === 'none' ? 'restore' : request.stepUp === undefined ? 'sign-in' : 'step-up';
    const stored: StoredLogin = { pending, returnTo, purpose };
    this.platform.storage.setItem(this.#key, JSON.stringify(stored));
    return this.away(url);
  }

  /** Takes the waiting login out of storage, if there is a readable one. */
  #take(): StoredLogin | undefined {
    const text = this.platform.storage.getItem(this.#key);
    this.platform.storage.removeItem(this.#key);
    if (text === null) return undefined;
    try {
      return storedLogin(json.parse(text), 'login');
    } catch {
      // Not written by this version: no login is waiting.
      return undefined;
    }
  }

  /** Completes `pending` with its authorization response. */
  async #session(
    pending: PendingLogin,
    response: URLSearchParams,
    steppedUp: boolean
  ): Promise<Session> {
    const tokens = await this.client.complete(pending, response);
    return Session.from(this, tokens as SessionTokens, steppedUp);
  }
}

/** Tokens of a completed login, which always carry an ID token. */
type SessionTokens = Tokens & { idToken: IdToken };

/**
 * A signed-in user, in this page's memory only. {@link fetch} calls resource servers
 * with its access token, refreshing it with a refresh token when the login was
 * granted `offline_access`, and stepping up when a resource asks.
 */
export class Session {
  readonly #owner: BrowserClient;
  #tokens: SessionTokens;
  /** The refresh under way, which concurrent requests share. */
  #refreshing: Promise<void> | undefined;
  /** When this session returned from a step-up, until a refused step-up uses it. */
  #steppedUpAt: number | undefined;

  private constructor(owner: BrowserClient, tokens: SessionTokens, steppedUp: boolean) {
    this.#owner = owner;
    this.#tokens = tokens;
    this.#steppedUpAt = steppedUp ? this.#clock() : undefined;
  }

  /** @internal `steppedUp` marks a session returning from a step-up login. */
  static from(owner: BrowserClient, tokens: SessionTokens, steppedUp: boolean): Session {
    return new Session(owner, tokens, steppedUp);
  }

  /** The validated ID token. */
  get idToken(): IdToken {
    return this.#tokens.idToken;
  }

  /** The user's claims, from the ID token. */
  get claims(): IdTokenClaims {
    return this.#tokens.idToken.claims;
  }

  /** The granted scopes. */
  get scopes(): Scopes {
    return this.#tokens.scopes;
  }

  /**
   * A current access token, refreshed when it is about to expire. Without a refresh
   * token, it is used until it expires, then throws `invalid_token` (`expired`):
   * {@link BrowserClient.restore} signs in again.
   */
  async accessToken(): Promise<string> {
    const refreshToken = this.#tokens.refreshToken;
    const margin = refreshToken === undefined ? 0 : REFRESH_MARGIN;
    if (this.#clock() < this.#tokens.expiresAt - margin) return this.#tokens.accessToken;
    if (refreshToken === undefined) {
      throw new AuthError({ code: 'invalid_token', reason: 'expired' }, 'the access token expired');
    }
    this.#refreshing ??= this.#refresh(refreshToken).finally(() => {
      this.#refreshing = undefined;
    });
    await this.#refreshing;
    return this.#tokens.accessToken;
  }

  /**
   * `fetch` with the access token as a bearer credential. When the resource answers
   * `insufficient_user_authentication` (RFC 9470), the browser goes to auth to sign
   * in again with the challenge's `acr_values` and `max_age`, and comes back to this
   * page, where the action runs again; the returned promise never settles. If the
   * resource still refuses that retry, it throws the challenge as an
   * `insufficient_user_authentication` error instead of leaving again. A
   * cross-origin resource must expose `WWW-Authenticate` to the page
   * (`Access-Control-Expose-Headers`).
   */
  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = new Request(input, init);
    request.headers.set('authorization', `Bearer ${await this.accessToken()}`);
    const response = await this.#owner.platform.fetch(request);
    const header = response.status === 401 ? response.headers.get('www-authenticate') : null;
    const challenge = header === null ? undefined : parseChallenge(header);
    if (challenge?.error !== 'insufficient_user_authentication') return response;
    const requirement = stepUpRequirement(challenge);
    // Every refusal within the window is the retry, concurrent ones included.
    const retry =
      this.#steppedUpAt !== undefined && this.#clock() - this.#steppedUpAt < STEP_UP_RETRY;
    if (retry) {
      throw new AuthError(
        { code: 'insufficient_user_authentication', requirement },
        'the resource still refuses the authentication after stepping up'
      );
    }
    const scopes = this.#tokens.scopes.all.filter((scope) => scope !== 'openid');
    return this.#owner.login({ scopes, stepUp: requirement });
  }

  /**
   * Signs out: revokes the refresh token, if any, and sends the browser to auth's
   * RP-initiated logout, which ends the session there, then to `postLogout`, a URI
   * registered for this client. The returned promise never settles.
   */
  async logout(postLogout?: string): Promise<never> {
    const { client } = this.#owner;
    if (this.#tokens.refreshToken !== undefined) await client.revoke(this.#tokens.refreshToken);
    return this.#owner.away(client.logoutUrl(this.#tokens.idToken, postLogout));
  }

  #clock(): number {
    return this.#owner.client.issuer.clock();
  }

  /** Redeems `refreshToken`, keeping the session's user (OIDC Core §12.2). */
  async #refresh(refreshToken: string): Promise<void> {
    const tokens = await this.#owner.client.refresh(refreshToken);
    const idToken = tokens.idToken ?? this.#tokens.idToken;
    if (!this.#tokens.idToken.sameUser(idToken)) {
      throw new AuthError(
        { code: 'invalid_token', reason: 'invalid_claims' },
        'the refreshed ID token names another user'
      );
    }
    this.#tokens = { ...tokens, idToken };
  }
}

/**
 * Signs users in to this page as the public client `config` registers. Discover the
 * issuer with `Issuer.discover` from `@piquel/auth` first.
 */
export function browserClient(issuer: Issuer, config: BrowserClientConfig): BrowserClient {
  return BrowserClient.from(issuer, config);
}
