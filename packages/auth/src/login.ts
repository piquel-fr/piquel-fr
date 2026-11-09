/**
 * Server-side login: the `/login`, `/callback`, `/logout` and `/backchannel-logout`
 * routes, sessions with their refresh, and step-up, over standard `Request` and
 * `Response`. Sessions live in the browser, in a cookie sealed with the app's
 * {@link CookieKey}, so the app stores nothing.
 *
 * The routes take only confidential clients, whose refresh tokens auth does not
 * rotate, so concurrent requests may each refresh: every one gets valid tokens, and
 * the browser keeps whichever cookie arrives last. A failed refresh spends nothing,
 * so only auth's refusal ends the session; but an access token that expired and could
 * not be refreshed is never handed out, so a session auth ended stops within an
 * access token's lifetime even while auth is unreachable.
 */
import * as base64 from './base64.ts';
import { readAcrValues, readMaxAge } from './challenge.ts';
import type { Client } from './client.ts';
import { AuthError } from './error.ts';
import { Http } from './http.ts';
import type { IdTokenClaims, StepUpRequirement } from './protocol.ts';
import { Scopes } from './scope.ts';
import type { CookieKey } from './seal.ts';
import { type PendingAuthorization, StoredLogin, pendingAuthorization } from './session.ts';
import { REFRESH_MARGIN, STEP_UP_RETRY } from './time.ts';
import { AuthenticatedToken, type LogoutToken } from './token.ts';

/** How long a login may take at auth. */
const PENDING_LIFETIME = 10 * 60_000;
/** Default session lifetime. */
const DEFAULT_SESSION_LIFETIME = 12 * 60 * 60_000;
/** Longest a refresh may take, auth's response and its ID token check included. */
const REFRESH_DEADLINE = 20_000;
/**
 * Longest a session's revocation may hold up the sign-in or logout ending it,
 * whatever the injected `fetch` does with its own timeout.
 */
const REVOCATION_DEADLINE = 5_000;
/** Longest back-channel logout request read: a logout token is at most 16 KiB. */
const MAX_LOGOUT_REQUEST = 64 * 1024;
/** Methods that must not change anything, so any origin may send them with the session cookie. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
/** Most bytes in a `return_to` path. */
const MAX_RETURN_TO_BYTES = 2048;
/** Most bytes in a cookie's name, `=` and value: browsers drop larger cookies. */
const MAX_COOKIE_BYTES = 4096;
/**
 * Cookie slots for logins in progress: each login waits in the slot its `state`
 * hashes to, replacing any login there. Responses to logins started at once cannot
 * see each other's cookies, so only fixed slots bound how many a browser keeps.
 */
const PENDING_SLOTS = 3;
/**
 * Most bytes in one pending login cookie's name and value, so all slots together take
 * at most 3000 bytes. Common proxies refuse a `Cookie` header over 8 KiB, which they
 * share with the session, up to 4 KiB, and the app's own cookies. A login whose
 * `return_to` would outgrow it returns to the home page instead.
 */
const MAX_PENDING_COOKIE_BYTES = 1000;

/** What {@link Promise.race} resolves to when a deadline passes first. */
const TIMED_OUT: unique symbol = Symbol('timed out');

/** How {@link Login} signs users in and keeps their sessions. */
export type LoginOptions = {
  /** Seals the session and the pending logins the browser keeps: the same key on every replica. */
  cookieKey: CookieKey;
  /** Scopes to request besides `openid` and `offline_access`, which every login requests. */
  scopes?: readonly string[];
  /** Where users go after login when they came from no page, and after logout without a session; `/` by default. */
  afterLogin?: string;
  /** Where auth sends users after logout. It must be a registered post-logout URI of the client; without one, auth shows its own page. */
  afterLogout?: string;
  /** The path the routes are under; `/auth` by default. */
  mount?: string;
  /** How long a session lasts at most, in milliseconds; 12 hours by default. Auth may end it sooner. */
  sessionLifetime?: number;
  /**
   * Receives auth's back-channel logouts (OIDC Back-Channel Logout 1.0) at
   * `POST <mount>/backchannel-logout`, for an app that must end sessions sooner than
   * their next refresh; without it, there is no such route. Register
   * `https://<app><mount>/backchannel-logout` as the client's back-channel logout URI.
   *
   * The route validates the logout token and hands it to the handler. The SDK keeps
   * no sessions, so the handler records what the token names, where every replica
   * sees it, and the app refuses those sessions itself: by {@link SignedIn.sid} for an
   * auth session, or for a token naming only the user, every session of
   * {@link SignedIn.sub} whose sign-in (`auth_time`) came before the token's `iat`. A
   * record can go once no session it names can still be live, a session lifetime
   * after the token.
   *
   * The handler must be idempotent and resolve only once its record is durable: auth
   * delivers again until it is answered 200, so a token can arrive twice, and a
   * rejection answers 500 for auth to retry. The route answers 200 once the handler
   * resolves; 400 with `{"error":"invalid_request"}` for an invalid token; and 503
   * when auth's keys cannot be fetched.
   */
  backchannelLogout?: (token: LogoutToken) => Promise<void>;
};

/** How {@link Login.session} reads a request's session. */
export type SessionOptions = {
  /**
   * Takes unsafe requests from other origins too, for an endpoint other origins call
   * with the session cookie, such as a sibling site's `fetch` with credentials under
   * CORS. The endpoint then guards against cross-site request forgery itself.
   */
  crossOrigin?: boolean;
};

/** A route: its method, and what answers it. */
type Route = { method: 'GET' | 'POST'; answer: (request: Request) => Promise<Response> };

/** What a request's session cookie holds: no cookie, one to clear, or a live session. */
type SessionCookie = 'absent' | 'ended' | StoredLogin;

/**
 * What refreshing a session came to: new tokens, the session as it was, or its end,
 * when auth refused the refresh token or named another user or sign-in.
 */
type Refresh = StoredLogin | 'kept' | 'ended';

/**
 * One request's session, read once so a request refreshes at most once, and the
 * `Set-Cookie` values its response must carry, by cookie name.
 */
type RequestSession = {
  read: Promise<SignedIn | 'unavailable' | null>;
  cookies: Map<string, string>;
};

/**
 * Server-side login for apps, following the browser-based apps BCP: the browser holds
 * the session in a `__Host-` cookie that is `Secure`, `HttpOnly` and `SameSite=Lax`,
 * sealed with the {@link CookieKey}, so scripts cannot read its tokens and the app
 * stores nothing. {@link Login.handle} answers its routes, under `/auth` by default:
 *
 * - `GET /login?return_to=…` keeps a pending login in a sealed cookie and redirects
 *   to auth. A browser keeps up to three logins at once, in slots chosen by their
 *   `state`; a login that lands in a taken slot replaces the one there.
 * - `GET /callback` completes the login its `state` names and starts a session,
 *   revoking the refresh token of any session the browser already had first, or
 *   answering 502 and keeping that session when auth cannot within five seconds. A
 *   step-up must sign in the same user as that session, or it fails and keeps the
 *   session.
 * - `POST /logout` revokes the session's refresh token at auth, clears the cookies,
 *   and redirects to RP-initiated logout; it answers 502, keeping the cookie, when
 *   auth cannot revoke it within five seconds. It accepts only requests from the
 *   app's own pages: `Sec-Fetch-Site: same-origin` when the browser sends it, and
 *   otherwise an `Origin` equal to the redirect URI's.
 * - `POST /backchannel-logout`, only with {@link LoginOptions.backchannelLogout}.
 *
 * Every login requests `offline_access`, which the client's registration must allow:
 * a session learns that auth ended it, at a logout, an app removal or an account
 * suspension, when its next refresh is refused, within an access token's 5 minutes.
 * A sign-in auth gives no refresh token lasts as long as its access token.
 *
 * Every route answers with `Cache-Control: no-store`, and 500 when it fails, reporting
 * the failure with `console.error`. {@link Login.session} applies logout's origin rule
 * to every unsafe request, so handlers need no CSRF token, and
 * {@link Login.respond} adds the cookies the session's read needs to the response.
 *
 * ```ts
 * const login = new Login(issuer.client({ clientId, clientSecret, redirectUri }), {
 *   cookieKey: CookieKey.fromBase64(process.env.NOTES_COOKIE_KEY ?? ''),
 *   scopes: ['profile']
 * });
 *
 * async function fetch(request: Request): Promise<Response> {
 *   const routed = await login.handle(request);
 *   if (routed) return routed;
 *   const user = await login.session(request);
 *   if (user instanceof Response) return user; // 403 from another site, or 503
 *   if (!user) return login.respond(request, login.signIn(request));
 *   return login.respond(request, new Response(`Hello ${user.name}`));
 * }
 * ```
 */
export class Login {
  /** The client users sign in with. */
  readonly client: Client;
  readonly #cookieKey: CookieKey;
  readonly #scopes: readonly string[];
  readonly #home: string;
  readonly #afterLogout: string | undefined;
  readonly #mount: string;
  readonly #lifetime: number;
  readonly #onLogout: ((token: LogoutToken) => Promise<void>) | undefined;
  readonly #routes: Record<string, Route>;
  /** Holds the sealed session. */
  readonly #sessionCookie: string;
  /**
   * Names the page a step-up login returns to, by the base64url of its SHA-256 so it
   * stays small, so that page's request is known to be the retry.
   */
  readonly #stepUpCookie: string;
  /** Starts the name of each pending login's cookie, which ends with its slot. */
  readonly #pendingCookie: string;
  /** Each request's session, once read, until the request is collected. */
  readonly #requests = new WeakMap<Request, RequestSession>();

  /**
   * Signs users in with `client`, as `options` say. A public client, which has no
   * secret, throws a `TypeError`: its refresh token rotates, so two requests
   * refreshing one session would revoke it. Invalid options throw one too.
   */
  constructor(client: Client, options: LoginOptions) {
    const { scopes = [], afterLogin = '/', afterLogout, mount = '/auth' } = options;
    const lifetime = options.sessionLifetime ?? DEFAULT_SESSION_LIFETIME;
    if (!client.confidential) {
      throw new TypeError(
        'Login needs a confidential client: every copy of the session cookie redeems ' +
          "the same refresh token, which only a confidential client's keeps"
      );
    }
    Scopes.checked(scopes);
    const home = Login.#returnTo(afterLogin);
    if (home === undefined) throw new TypeError('afterLogin must be a same-origin path');
    if (afterLogout !== undefined && !URL.canParse(afterLogout)) {
      throw new TypeError('afterLogout must be a URL');
    }
    if (!mount.startsWith('/')) throw new TypeError('mount must be a path');
    if (!(lifetime > 0 && Number.isSafeInteger(lifetime))) {
      throw new TypeError('sessionLifetime must be a positive number of milliseconds');
    }
    this.client = client;
    this.#cookieKey = options.cookieKey;
    this.#scopes = [...scopes, 'offline_access'];
    this.#home = home;
    this.#afterLogout = afterLogout;
    this.#mount = mount.replace(/\/+$/, '');
    this.#lifetime = lifetime;
    this.#onLogout = options.backchannelLogout;
    // Client IDs are letters, digits, `.`, `_` and `-`, all valid in a cookie name,
    // and each app sharing a host keeps its own cookies. `__Host-` makes browsers
    // require `Secure`, `Path=/` and no `Domain`, so no other host can set or read them.
    const prefix = `__Host-piquel-${client.config.clientId}`;
    this.#sessionCookie = `${prefix}-session`;
    this.#stepUpCookie = `${prefix}-step-up`;
    this.#pendingCookie = `${prefix}-login-`;
    this.#routes = {
      '/login': { method: 'GET', answer: (request) => this.#start(request) },
      '/callback': { method: 'GET', answer: (request) => this.#callback(request) },
      '/logout': { method: 'POST', answer: (request) => this.#logout(request) }
    };
    if (this.#onLogout !== undefined) {
      this.#routes['/backchannel-logout'] = {
        method: 'POST',
        answer: (request) => this.#backchannelLogout(request)
      };
    }
  }

  /**
   * Answers the login routes, or returns `null` for any other request, which the
   * app answers itself.
   */
  async handle(request: Request): Promise<Response | null> {
    const { pathname } = new URL(request.url);
    const name = pathname.startsWith(`${this.#mount}/`) ? pathname.slice(this.#mount.length) : '';
    const route = Object.hasOwn(this.#routes, name) ? this.#routes[name] : undefined;
    if (route === undefined) return null;
    let response: Response;
    if (request.method !== route.method) {
      response = new Response(null, { status: 405, headers: { allow: route.method } });
    } else {
      try {
        response = await route.answer(request);
      } catch (error) {
        console.error('@piquel/auth: a login route failed', error);
        response = new Response(null, { status: 500 });
      }
    }
    response.headers.set('cache-control', 'no-store');
    return response;
  }

  /**
   * The signed-in user the request's session cookie holds, or `null`. An access token
   * about to expire is refreshed first. Concurrent requests may each refresh, and a
   * request read twice refreshes once. Auth's refusal ends the session; any other
   * failure keeps it, but once its access token expired, the answer is a 503 response
   * to send, and the next request tries again. A cookie that does not open, perhaps
   * sealed under an older key, or whose session ended, is no session.
   *
   * The read records the cookies the response must set: the refreshed session, the
   * deletion of an ended one, and on a step-up login's return, the spent step-up
   * marker. Pass the response through {@link Login.respond} to add them. A response
   * without them loses those updates: the next request refreshes again, a dead cookie
   * is sent until it expires, and the spent marker lingers for its minute, so another
   * load of the page within it still counts as the step-up's retry.
   *
   * A request that is not `GET`, `HEAD`, `OPTIONS` or `TRACE` must come from the app's
   * own pages, or the answer is a 403 response to send, before the session is read,
   * with or without a cookie: `Sec-Fetch-Site: same-origin` when the browser sends
   * it, and otherwise an `Origin` equal to the redirect URI's. So no other site, not
   * even a sibling the `SameSite=Lax` cookie reaches, acts as the user, and handlers
   * need no CSRF token. `{ crossOrigin: true }` skips the check, for an endpoint
   * other origins must call with the session cookie.
   */
  async session(
    request: Request,
    options: SessionOptions = {}
  ): Promise<SignedIn | Response | null> {
    if (
      options.crossOrigin !== true &&
      !SAFE_METHODS.has(request.method) &&
      !this.#sameOrigin(request)
    ) {
      return Login.text(403, "This request must come from this site's own pages.");
    }
    let session = this.#requests.get(request);
    if (session === undefined) {
      const cookies = new Map<string, string>();
      session = { read: this.#read(request, cookies), cookies };
      this.#requests.set(request, session);
    }
    const user = await session.read;
    return user === 'unavailable'
      ? Login.text(503, 'Your session could not be renewed; try again in a moment.')
      : user;
  }

  /**
   * `response` with the cookies {@link Login.session} recorded for `request`, and
   * `Cache-Control: no-store` when it sets the session cookie, since the response then
   * carries this user's session. A response whose headers cannot change, such as
   * `Response.redirect`'s, is copied first. Call it once per request, after the
   * session was read.
   */
  respond(request: Request, response: Response): Response {
    const session = this.#requests.get(request);
    if (session === undefined || session.cookies.size === 0) return response;
    const apply = (headers: Headers) => {
      for (const cookie of session.cookies.values()) headers.append('set-cookie', cookie);
      if (session.cookies.has(this.#sessionCookie)) headers.set('cache-control', 'no-store');
    };
    try {
      apply(response.headers);
      return response;
    } catch (error) {
      // Immutable headers: the first change throws, before any applies.
      if (!(error instanceof TypeError)) throw error;
      const copy = new Response(response.body, response);
      apply(copy.headers);
      return copy;
    }
  }

  /**
   * A response sending the browser through login and back to the request's page: a
   * redirect for a browser navigating to a page with `GET` (`Sec-Fetch-Mode:
   * navigate`), and 401 for any other request, a `fetch` or a client sending no fetch
   * metadata included, since following a redirect to auth would fail its CORS check.
   * With `stepUp`, the new sign-in must meet it, and the page's return is marked as
   * the step-up's retry; prefer {@link SignedIn.stepUp}, which stops at one retry.
   */
  signIn(request: Request, stepUp?: StepUpRequirement): Response {
    if (!Login.#navigation(request)) return new Response(null, { status: 401 });
    const query = new URLSearchParams();
    const returnTo = Login.#returnTo(Login.#page(request));
    if (returnTo !== undefined) query.append('return_to', returnTo);
    if (stepUp !== undefined) {
      if (stepUp.acr_values !== undefined) query.append('acr_values', stepUp.acr_values);
      if (stepUp.max_age !== undefined) query.append('max_age', String(stepUp.max_age));
      query.append('step_up', 'true');
    }
    return Login.#redirect(`${this.#mount}/login?${query.toString()}`);
  }

  /** @internal The current time by the issuer's clock. */
  now(): number {
    return this.client.issuer.clock();
  }

  /**
   * `path` if it is a same-origin relative path, so login cannot be turned into an
   * open redirect: it starts with one `/` (not `//` or `/\`), is printable ASCII
   * without `\` or `#`, as a `Location` header holds it, and has at most 2048 bytes.
   */
  static #returnTo(path: string | null): string | undefined {
    if (path === null) return undefined;
    const local =
      path.length <= MAX_RETURN_TO_BYTES &&
      /^\/(?![/\\])[\x21-\x7e]*$/.test(path) &&
      !/[\\#]/.test(path);
    return local ? path : undefined;
  }

  /**
   * Whether the request is a browser navigating to a page with `GET`
   * (`Sec-Fetch-Mode: navigate`), the only request a redirect through login serves:
   * a `fetch` following it would fail auth's CORS check, and a client sending no
   * fetch metadata is no browser that could sign in.
   */
  static #navigation(request: Request): boolean {
    return request.method === 'GET' && request.headers.get('sec-fetch-mode') === 'navigate';
  }

  /** The request's path and query. */
  static #page(request: Request): string {
    const url = new URL(request.url);
    return `${url.pathname}${url.search}`;
  }

  /** The request's cookies, as name and value. */
  static #cookies(request: Request): [string, string][] {
    const cookies: [string, string][] = [];
    for (const pair of (request.headers.get('cookie') ?? '').split(';')) {
      const separator = pair.indexOf('=');
      if (separator !== -1) {
        cookies.push([pair.slice(0, separator).trim(), pair.slice(separator + 1).trim()]);
      }
    }
    return cookies;
  }

  /** The value of cookie `name` in the request, if any. */
  static #cookie(request: Request, name: string): string | undefined {
    return Login.#cookies(request).find(([key]) => key === name)?.[1];
  }

  /** A `Set-Cookie` value for a host-only cookie scripts cannot read; zero `maxAge` deletes it. */
  static #setCookie(name: string, value: string, maxAge: number): string {
    const seconds = Math.max(0, Math.floor(maxAge / 1000));
    return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${String(seconds)}`;
  }

  /** The `Set-Cookie` value deleting cookie `name`. */
  static #clearCookie(name: string): string {
    return Login.#setCookie(name, '', 0);
  }

  /** The SHA-256 of `text`. */
  static async #sha256(text: string): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  }

  /** The step-up marker naming the page at `path`: the base64url of its SHA-256. */
  static async #stepUpMarker(path: string): Promise<string> {
    return base64.encode(await Login.#sha256(path));
  }

  /** A `303 See Other` to `location`, setting `cookies`. */
  static #redirect(location: string, cookies: string[] = []): Response {
    const headers = new Headers({ location });
    for (const cookie of cookies) headers.append('set-cookie', cookie);
    return new Response(null, { status: 303, headers });
  }

  /** @internal A plain-text answer. */
  static text(status: number, message: string): Response {
    return new Response(message, { status, headers: { 'content-type': 'text/plain' } });
  }

  /**
   * The associated data of cookie `name`: the client ID and the name, so a cookie
   * opens only as the cookie it was sealed as, and only for this client, even when
   * another app on the host shares the cookie key.
   */
  #context(name: string): string {
    return `${this.client.config.clientId}\0${name}`;
  }

  /** @internal The session the request's cookie holds. */
  async openSession(request: Request): Promise<SessionCookie> {
    const name = this.#sessionCookie;
    const sealed = Login.#cookie(request, name);
    if (sealed === undefined) return 'absent';
    const { session } = await this.#cookieKey.keys();
    const login = await session.open(sealed, this.#context(name), StoredLogin.decoder);
    return login !== undefined && login.endsAt > this.now() ? login : 'ended';
  }

  /**
   * The `Set-Cookie` value holding `login`, sealed, until the session ends. Throws a
   * `RangeError` when it is larger than browsers keep.
   */
  async #sealSession(login: StoredLogin): Promise<string> {
    const name = this.#sessionCookie;
    const { session } = await this.#cookieKey.keys();
    const sealed = await session.seal(login.data, this.#context(name));
    const size = name.length + 1 + sealed.length;
    if (size > MAX_COOKIE_BYTES) {
      throw new RangeError(
        `the session cookie would be ${String(size)} bytes; browsers keep ${String(MAX_COOKIE_BYTES)} at most`
      );
    }
    return Login.#setCookie(name, sealed, login.endsAt - this.now());
  }

  /**
   * Reads the request's session, refreshing its access token when it is about to
   * expire, and records in `cookies` what the response must set.
   */
  async #read(
    request: Request,
    cookies: Map<string, string>
  ): Promise<SignedIn | 'unavailable' | null> {
    // The `GET` a step-up login returns to is its retry, and uses up the marker.
    // Another tab loading the same page within the minute would use it instead.
    const marker = Login.#cookie(request, this.#stepUpCookie);
    const retry =
      request.method === 'GET' &&
      marker !== undefined &&
      marker === (await Login.#stepUpMarker(Login.#page(request)));
    if (retry) cookies.set(this.#stepUpCookie, Login.#clearCookie(this.#stepUpCookie));
    const opened = await this.openSession(request);
    if (opened === 'absent') return null;
    if (opened === 'ended') {
      cookies.set(this.#sessionCookie, Login.#clearCookie(this.#sessionCookie));
      return null;
    }
    let login = opened;
    if (login.refreshToken !== undefined && login.expiresAt <= this.now() + REFRESH_MARGIN) {
      const refreshed = await this.#refresh(login);
      if (refreshed === 'ended') {
        cookies.set(this.#sessionCookie, Login.#clearCookie(this.#sessionCookie));
        return null;
      }
      if (refreshed === 'kept') {
        if (login.expiresAt <= this.now()) return 'unavailable';
      } else {
        try {
          cookies.set(this.#sessionCookie, await this.#sealSession(refreshed));
        } catch (error) {
          // As when new profile claims outgrow the cookie: this request still uses
          // the new tokens, and the next refreshes again.
          if (!(error instanceof RangeError)) throw error;
          console.warn('@piquel/auth: the refreshed session could not be saved', error);
        }
        login = refreshed;
      }
    }
    // The session may have reached its end while the refresh ran.
    if (login.endsAt <= this.now()) {
      cookies.set(this.#sessionCookie, Login.#clearCookie(this.#sessionCookie));
      return null;
    }
    return SignedIn.from(this, login, request, retry);
  }

  /**
   * Refreshes the session's access token within {@link REFRESH_DEADLINE}. Auth's
   * `invalid_grant` ends the session, as does an ID token naming another user or
   * sign-in (OIDC Core §12.2); any other failure, or the deadline, keeps it.
   */
  async #refresh(login: StoredLogin): Promise<Refresh> {
    const { refreshToken } = login;
    if (refreshToken === undefined) return 'kept';
    let tokens;
    try {
      tokens = await Login.#within(
        REFRESH_DEADLINE,
        this.client.refresh(refreshToken, login.claims)
      );
    } catch (error) {
      if (!(error instanceof AuthError)) throw error;
      // Auth refused the refresh token: the grant is over.
      if (error.code === 'oauth' && error.response?.error === 'invalid_grant') return 'ended';
      // The session cannot go on as another user or sign-in.
      if (error.reason === 'subject_mismatch' || error.reason === 'authentication_changed') {
        console.warn('@piquel/auth: a refresh changed the signed-in user or sign-in', error);
        return 'ended';
      }
      console.warn('@piquel/auth: session refresh failed', error);
      return 'kept';
    }
    if (tokens === TIMED_OUT) {
      console.warn('@piquel/auth: session refresh timed out');
      return 'kept';
    }
    return login.refreshed(tokens);
  }

  /**
   * `promise`'s result, or {@link TIMED_OUT} once `milliseconds` pass first. The
   * operation itself goes on, and its late result or failure is ignored.
   */
  static async #within<T>(
    milliseconds: number,
    promise: Promise<T>
  ): Promise<T | typeof TIMED_OUT> {
    promise.catch(() => undefined);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<typeof TIMED_OUT>((resolve) => {
      timer = setTimeout(() => {
        resolve(TIMED_OUT);
      }, milliseconds);
    });
    try {
      return await Promise.race([promise, deadline]);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Revokes the grant of `login`, a sign-in the callback refuses after redeeming its
   * code, so it does not live on at auth unused. A failure is logged by
   * {@link Login.#revoke} and changes nothing: the refusal stands either way.
   */
  async #abandon(login: StoredLogin): Promise<void> {
    if (login.refreshToken !== undefined) await this.#revoke(login.refreshToken);
  }

  /**
   * Revokes `refreshToken` at auth within {@link REVOCATION_DEADLINE}, so a hanging
   * auth cannot hold up the sign-in or logout around it. Returns whether auth
   * revoked it, logging why not.
   */
  async #revoke(refreshToken: string): Promise<boolean> {
    let revoked;
    try {
      revoked = await Login.#within(REVOCATION_DEADLINE, this.client.revoke(refreshToken));
    } catch (error) {
      if (!(error instanceof AuthError)) throw error;
      console.warn('@piquel/auth: a refresh token could not be revoked', error);
      return false;
    }
    if (revoked === TIMED_OUT) {
      console.warn('@piquel/auth: revoking a refresh token timed out');
      return false;
    }
    return true;
  }

  /**
   * The name of the cookie holding the login started with `state`: its slot, by the
   * first byte of the `state`'s SHA-256.
   */
  async #pendingName(state: string): Promise<string> {
    const [first = 0] = await Login.#sha256(state);
    return `${this.#pendingCookie}${String(first % PENDING_SLOTS)}`;
  }

  /** `pending`, sealed for the cookie `name`. */
  async #sealPending(pending: PendingAuthorization, name: string): Promise<string> {
    const keys = await this.#cookieKey.keys();
    return keys.pending.seal(pending, this.#context(name));
  }

  /**
   * The pending login `sealed` holds as the cookie `name`, expired or not, if it
   * opens: only then is the cookie this client's to read or drop.
   */
  async #openPending(sealed: string, name: string): Promise<PendingAuthorization | undefined> {
    const keys = await this.#cookieKey.keys();
    return keys.pending.open(sealed, this.#context(name), pendingAuthorization);
  }

  /**
   * `GET /login`: keeps a pending login in a sealed cookie and redirects to auth. A
   * step-up strengthens the session it starts from, so it is pinned to its user: the
   * session holds no raw ID token to send as `id_token_hint`, so auth may let another
   * account sign in, and the callback refuses it.
   */
  async #start(request: Request): Promise<Response> {
    const query = new URL(request.url).searchParams;
    const returnTo = Login.#returnTo(query.get('return_to')) ?? this.#home;
    const stepUp: StepUpRequirement = {};
    const acrValues = query.get('acr_values');
    const acr = acrValues === null ? undefined : readAcrValues(acrValues);
    if (acr !== undefined) stepUp.acr_values = acr;
    const maxAgeValue = query.get('max_age');
    if (maxAgeValue !== null) {
      const maxAge = readMaxAge(maxAgeValue);
      if (maxAge === undefined) return Login.text(400, 'max_age must be a number of seconds.');
      stepUp.max_age = maxAge;
    }
    let authorization;
    try {
      authorization = await this.client.authorize({ scopes: this.#scopes, stepUp });
    } catch (error) {
      if (!(error instanceof AuthError)) throw error;
      return Login.text(502, `Sign-in could not start: ${error.message}.`);
    }
    const name = await this.#pendingName(authorization.pending.state);
    const stepUpLogin = query.get('step_up') === 'true';
    const session = stepUpLogin ? await this.openSession(request) : 'absent';
    const pending: PendingAuthorization = {
      login: authorization.pending,
      returnTo,
      stepUp: stepUpLogin,
      ...(session instanceof StoredLogin ? { subject: session.claims.sub } : {}),
      expiresAt: this.now() + PENDING_LIFETIME
    };
    // A `return_to` too long for the cookie returns home instead, or to the root if
    // home is too long too.
    const fallbacks = [this.#home, '/'];
    let sealed = await this.#sealPending(pending, name);
    while (name.length + sealed.length > MAX_PENDING_COOKIE_BYTES) {
      const fallback = fallbacks.shift();
      if (fallback === undefined)
        throw new Error('even a login returning to / outgrows its cookie');
      pending.returnTo = fallback;
      sealed = await this.#sealPending(pending, name);
    }
    return Login.#redirect(authorization.url, [Login.#setCookie(name, sealed, PENDING_LIFETIME)]);
  }

  /**
   * `GET /callback`: completes the pending login its `state` names and starts a
   * session. Only the cookie holding that login is read and dropped, so a callback for
   * another login, or a link with a made-up `state`, leaves logins in progress alone.
   * Auth redeems a code once, so a copied cookie completes nothing twice.
   */
  async #callback(request: Request): Promise<Response> {
    const callback = new URL(request.url).searchParams;
    const state = callback.get('state') ?? '';
    const name = await this.#pendingName(state);
    const sealed = Login.#cookie(request, name);
    const opened = sealed === undefined ? undefined : await this.#openPending(sealed, name);
    // A cookie that does not open, or holds another tab's login, is left alone.
    const pending = opened?.login.state === state ? opened : undefined;
    if (pending === undefined) {
      return Login.text(400, 'This sign-in has no pending login; start again.');
    }
    const response =
      pending.expiresAt > this.now()
        ? await this.#complete(request, pending, callback)
        : Login.text(400, 'This sign-in expired; start again.');
    // Spent whatever the outcome: the code may have been redeemed.
    response.headers.append('set-cookie', Login.#clearCookie(name));
    return response;
  }

  /**
   * Completes `pending` from `callback` and starts its session. The session the
   * browser had is replaced, and its refresh token revoked before the new session is
   * set, so no copy of it, nor a response still in flight that sets it back, outlives
   * its access token. If auth cannot revoke it within {@link REVOCATION_DEADLINE}, the
   * sign-in fails with 502 and the browser keeps its session; the code is spent, so
   * the user starts again.
   *
   * A step-up must sign in the user it started from, and the one whose session it
   * replaces, as after switching accounts in another tab: otherwise it fails, and the
   * session it would replace is kept, its refresh token unrevoked.
   */
  async #complete(
    request: Request,
    pending: PendingAuthorization,
    callback: URLSearchParams
  ): Promise<Response> {
    let tokens;
    try {
      tokens = await this.client.complete(pending.login, callback);
    } catch (error) {
      if (!(error instanceof AuthError)) throw error;
      // The issuer's failures, unreachable or with unusable keys, are not the browser's.
      const upstream = error.code === 'network' || error.code === 'keys';
      return Login.text(upstream ? 502 : 400, `Sign-in failed: ${error.message}.`);
    }
    // `complete` fails without an ID token, so this only narrows the type.
    const login = StoredLogin.start(tokens, this.now() + this.#lifetime);
    if (login === undefined) return Login.text(502, 'Sign-in failed: no ID token.');
    const previous = await this.openSession(request);
    const replaced = previous instanceof StoredLogin ? previous : undefined;
    if (
      pending.stepUp &&
      [pending.subject, replaced?.claims.sub].some(
        (subject) => subject !== undefined && subject !== login.claims.sub
      )
    ) {
      await this.#abandon(login);
      return Login.text(
        400,
        "Sign-in failed: this step-up signed in another account than this session's."
      );
    }
    if (replaced?.refreshToken !== undefined && !(await this.#revoke(replaced.refreshToken))) {
      await this.#abandon(login);
      return Login.text(502, 'Signing in could not end your previous session; start again.');
    }
    let session;
    try {
      session = await this.#sealSession(login);
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      console.error('@piquel/auth: sign-in failed', error);
      return Login.text(500, `Sign-in failed: ${error.message}.`);
    }
    // A step-up marks its return; any other sign-in drops an unused marker, which
    // belonged to the session this one replaces.
    const marker = pending.stepUp
      ? Login.#setCookie(
          this.#stepUpCookie,
          await Login.#stepUpMarker(pending.returnTo),
          STEP_UP_RETRY
        )
      : Login.#clearCookie(this.#stepUpCookie);
    return Login.#redirect(pending.returnTo, [session, marker]);
  }

  /**
   * Whether a browser request comes from this app's own pages, whose origin is the
   * redirect URI's: `Sec-Fetch-Site: same-origin` when the browser sends it, and
   * otherwise an `Origin` equal to the app's, which `null` never is. Logout and
   * {@link Login.session} both ask it.
   */
  #sameOrigin(request: Request): boolean {
    const site = request.headers.get('sec-fetch-site');
    if (site !== null) return site === 'same-origin';
    return request.headers.get('origin') === new URL(this.client.config.redirectUri).origin;
  }

  /**
   * `POST /logout`: revokes the session's refresh token at auth, so no copy of the
   * cookie refreshes again, clears the cookies, and redirects to RP-initiated logout.
   * If auth cannot revoke it within {@link REVOCATION_DEADLINE}, the answer is 502 and
   * the cookie is kept, so the user can try again: clearing it would leave copies
   * refreshing. `POST` only, and only from the app's own pages, so another site
   * cannot sign the user out.
   */
  async #logout(request: Request): Promise<Response> {
    if (!this.#sameOrigin(request)) {
      return Login.text(403, "Sign out from this site's own pages.");
    }
    let destination = this.#home;
    const session = await this.openSession(request);
    if (session instanceof StoredLogin) {
      if (session.refreshToken !== undefined && !(await this.#revoke(session.refreshToken))) {
        return Login.text(502, 'Signing out could not reach the sign-in service; try again.');
      }
      destination = this.client.logoutUrl(undefined, this.#afterLogout);
    }
    return Login.#redirect(destination, [
      Login.#clearCookie(this.#sessionCookie),
      Login.#clearCookie(this.#stepUpCookie)
    ]);
  }

  /**
   * `POST /backchannel-logout`: validates auth's logout token and hands it to the
   * app's handler (OIDC Back-Channel Logout 1.0 §2.8), answering as
   * {@link LoginOptions.backchannelLogout} documents. Auth posts it server to server,
   * so there is no origin to check: the signed token is the authentication. A handler
   * that rejects answers 500, through {@link Login.handle}.
   */
  async #backchannelLogout(request: Request): Promise<Response> {
    const invalid = () => Response.json({ error: 'invalid_request' }, { status: 400 });
    const type = request.headers.get('content-type') ?? '';
    if (!/^application\/x-www-form-urlencoded\s*(;|$)/i.test(type)) return invalid();
    const body = await Http.readBody(request.body, MAX_LOGOUT_REQUEST);
    if (body === undefined) return invalid();
    const form = new URLSearchParams(new TextDecoder().decode(body));
    const [token, ...others] = form.getAll('logout_token');
    if (token === undefined || others.length > 0) return invalid();
    let logout;
    try {
      logout = await this.client.logoutToken(token);
    } catch (error) {
      if (!(error instanceof AuthError)) throw error;
      // The keys could not be fetched: the failure is this server's, so auth retries.
      if (error.code === 'keys' || error.code === 'network') {
        return new Response(null, { status: 503 });
      }
      return invalid();
    }
    // The route exists only with a handler.
    await this.#onLogout?.(logout);
    return new Response(null, { status: 200 });
  }
}

/**
 * The signed-in user, from {@link Login.session}: the claims of the sign-in's ID
 * token, and the access token to call APIs with, refreshed when it was about to
 * expire.
 *
 * ```ts
 * const user = await login.session(request);
 * if (user instanceof Response) return user;
 * if (!user) return login.respond(request, login.signIn(request));
 * // A passkey sign-in within the last five minutes, or a redirect through login.
 * const stepUp = user.require({ acr_values: 'phr', max_age: 300 });
 * if (stepUp) return login.respond(request, stepUp);
 * ```
 */
export class SignedIn {
  /** The validated claims of the sign-in's ID token, or of the latest refresh that returned one. */
  readonly claims: IdTokenClaims;
  /** When the access token expires, in milliseconds since the epoch. */
  readonly expiresAt: number;
  /** Scopes granted to the access token. */
  readonly scopes: Scopes;
  readonly #accessToken: string;
  readonly #login: Login;
  readonly #request: Request;
  readonly #retry: boolean;

  private constructor(login: Login, stored: StoredLogin, request: Request, retry: boolean) {
    this.claims = stored.claims;
    this.#accessToken = stored.accessToken;
    this.expiresAt = stored.expiresAt;
    this.scopes = stored.scopes;
    this.#login = login;
    this.#request = request;
    this.#retry = retry;
  }

  /** @internal `retry` marks a request returning from a step-up login. */
  static from(login: Login, stored: StoredLogin, request: Request, retry: boolean): SignedIn {
    return new SignedIn(login, stored, request, retry);
  }

  /**
   * The access token, to send as a bearer credential. {@link Login.session} already
   * refreshed it if it was about to expire; it is a method, as on the browser's
   * session, which refreshes when asked.
   */
  accessToken(): Promise<string> {
    return Promise.resolve(this.#accessToken);
  }

  /** The user's name: the display name, else the username, else the account ID. */
  get name(): string {
    return this.claims.name ?? this.claims.preferred_username ?? this.claims.sub;
  }

  /**
   * The URL of the user's profile picture, a square JPEG, when the `profile` scope
   * was granted and the account has one. The image at a URL never changes, so
   * `<img>` tags and caches may keep it; a new picture comes with a new URL, at the
   * next sign-in.
   */
  get picture(): string | undefined {
    return this.claims.picture;
  }

  /** The user's `sub`, their account ID. */
  get sub(): string {
    return this.claims.sub;
  }

  /** Auth's session ID, if the ID token carries one: what a back-channel logout names. */
  get sid(): string | undefined {
    return this.claims.sid;
  }

  /**
   * `null` if the sign-in meets `requirement` now, allowing the 30-second leeway on
   * `auth_time`, else the {@link SignedIn.stepUp} response asking for it.
   */
  require(requirement: StepUpRequirement): Response | null {
    return AuthenticatedToken.claimsMeet(this.claims, requirement, this.#login.now())
      ? null
      : this.stepUp(requirement);
  }

  /**
   * The response signing the user in again as `requirement` asks, such as an API's
   * `insufficient_user_authentication` challenge read with `parseChallenge`, and
   * coming back to the same page to try again: a redirect through login for a
   * browser's navigation, 401 for any other request, a `fetch` included, as
   * {@link Login.signIn} answers. The login fails unless the new sign-in meets the
   * requirement. On that return the retry is spent: if the page asks again, the
   * answer is 403 instead of another redirect. The return is the first `GET` of the
   * page within a minute of the login; a later one counts as a new action.
   */
  stepUp(requirement: StepUpRequirement): Response {
    if (this.#retry) return Login.text(403, 'Signing in again did not give access to this page.');
    return this.#login.signIn(this.#request, requirement);
  }
}
