/**
 * Server-side login: the `/login`, `/callback`, `/logout` and `/backchannel-logout`
 * routes, sessions with their refresh, and step-up, over standard `Request` and
 * `Response`.
 */
import { readAcrValues, readMaxAge } from './challenge.ts';
import type { Client } from './client.ts';
import { AuthError } from './error.ts';
import type { IdTokenClaims, StepUpRequirement } from './protocol.ts';
import { Scopes } from './scope.ts';
import {
  type Session,
  type SessionBackend,
  SessionKey,
  Sessions,
  type StoredLogin
} from './sessions.ts';
import type { IdToken } from './token.ts';

/**
 * Cookie holding the session key. `__Host-` makes browsers require `Secure`,
 * `Path=/` and no `Domain`, so no other host can set or read it.
 */
const SESSION_COOKIE = '__Host-piquel-session';
/** Cookie holding the pending login's key while the browser is at auth. */
const LOGIN_COOKIE = '__Host-piquel-login';
/** Cookie holding the marker of a step-up login's return, so that page's request is known to be the retry. */
const STEP_UP_COOKIE = '__Host-piquel-step-up';
/** How long the browser has to follow the redirect back after a step-up login. */
const STEP_UP_RETURN = 60_000;
/** How long a login may take at auth. */
const PENDING_LIFETIME = 10 * 60_000;
/** Default session lifetime. */
const DEFAULT_SESSION_LIFETIME = 12 * 60 * 60_000;
/** Access tokens this close to expiry are refreshed first. */
const REFRESH_MARGIN = 30_000;
/** Longest a refresh may take, auth's response and its ID token check included. */
const REFRESH_DEADLINE = 20_000;
/** Time kept back from a lease for saving its result, so the save lands before the lease expires. */
const SAVE_MARGIN = 10_000;
/** How long a refresh lease lasts if its holder never gives it back. */
const REFRESH_LEASE = 60_000;
/** How long a request waits for another's refresh before using what it has. */
const REFRESH_WAIT = 25_000;
/** How often a request waiting for another's refresh reloads the session. */
const REFRESH_POLL = 50;
/** Most bytes in a `return_to` path. */
const MAX_RETURN_TO_BYTES = 2048;
/**
 * Error codes of a connection that could not be opened, so a request that never
 * reached auth: Node's and Bun's. Other runtimes do not say, and their failures
 * count as possibly sent.
 */
const CONNECT_ERRORS = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
  'ConnectionRefused',
  'FailedToOpenSocket'
]);

/** What {@link Promise.race} resolves to when a deadline passes first. */
const TIMED_OUT: unique symbol = Symbol('timed out');

/** How {@link Login} signs users in and keeps their sessions. */
export type LoginOptions = {
  /**
   * Where sessions live. {@link MemoryBackend} is for development: implement
   * {@link SessionBackend} to persist sessions and share them between replicas.
   */
  backend: SessionBackend;
  /** Scopes to request besides `openid`. Add `offline_access` to refresh access tokens in the session. */
  scopes?: readonly string[];
  /** Where users go after login when they came from no page, and after logout without a session; `/` by default. */
  afterLogin?: string;
  /** Where auth sends users after logout. It must be a registered post-logout URI of the client; without one, auth shows its own page. */
  afterLogout?: string;
  /** The path the routes are under; `/auth` by default. */
  mount?: string;
  /** How long a session lasts, in milliseconds; 12 hours by default. */
  sessionLifetime?: number;
};

/** A route: its method, and what answers it. */
type Route = { method: 'GET' | 'POST'; answer: (request: Request) => Promise<Response> };

/**
 * Server-side login for apps, following the browser-based apps BCP: tokens stay on
 * the server, and the browser holds only a random session key, in a `__Host-`
 * cookie that is `Secure`, `HttpOnly` and `SameSite=Lax`. {@link Login.handle}
 * answers its routes, under `/auth` by default:
 *
 * - `GET /login?return_to=…` stores a pending login under a fresh random key and
 *   redirects to auth.
 * - `GET /callback` completes it, then starts a session under another fresh key,
 *   ending any session the browser already had.
 * - `POST /logout` deletes the session and redirects to RP-initiated logout. It
 *   accepts only requests from the app's own pages: `Sec-Fetch-Site: same-origin`
 *   when the browser sends it, and otherwise an `Origin` equal to the redirect URI's.
 * - `POST /backchannel-logout` receives auth's logout tokens (OIDC Back-Channel
 *   Logout 1.0) and deletes every session started under the token's `sid`, or
 *   without one, every session of its `sub`. Register
 *   `https://<app><mount>/backchannel-logout` as the client's back-channel logout
 *   URI. It answers 200 once the sessions are gone, also for a token it applied
 *   before; 400 with `{"error":"invalid_request"}` for an invalid token; 503 when
 *   auth's keys cannot be fetched and 500 when the backend fails, so auth retries.
 *
 * Every route answers with `Cache-Control: no-store`, and 500 when the backend fails,
 * reporting the failure with `console.error`.
 *
 * ```ts
 * const login = new Login(issuer.client({ clientId, clientSecret, redirectUri }), {
 *   backend: new MemoryBackend(),
 *   scopes: ['profile', 'offline_access']
 * });
 *
 * async function fetch(request: Request): Promise<Response> {
 *   const routed = await login.handle(request);
 *   if (routed) return routed;
 *   const user = await login.session(request);
 *   if (!user) return login.signIn(request);
 *   return new Response(`Hello ${user.name}`);
 * }
 * ```
 */
export class Login {
  /** The client users sign in with. */
  readonly client: Client;
  readonly #sessions: Sessions;
  readonly #scopes: readonly string[];
  readonly #home: string;
  readonly #afterLogout: string | undefined;
  readonly #mount: string;
  readonly #lifetime: number;
  readonly #routes: Record<string, Route>;

  /** Signs users in with `client`, as `options` say. Invalid options throw a `TypeError`. */
  constructor(client: Client, options: LoginOptions) {
    const { scopes = [], afterLogin = '/', afterLogout, mount = '/auth' } = options;
    const lifetime = options.sessionLifetime ?? DEFAULT_SESSION_LIFETIME;
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
    this.#sessions = new Sessions(options.backend, client.issuer.clock);
    this.#scopes = [...scopes];
    this.#home = home;
    this.#afterLogout = afterLogout;
    this.#mount = mount.replace(/\/+$/, '');
    this.#lifetime = lifetime;
    this.#routes = {
      '/login': { method: 'GET', answer: (request) => this.#start(request) },
      '/callback': { method: 'GET', answer: (request) => this.#callback(request) },
      '/logout': { method: 'POST', answer: (request) => this.#logout(request) },
      '/backchannel-logout': {
        method: 'POST',
        answer: (request) => this.#backchannelLogout(request)
      }
    };
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
   * The signed-in user the request's cookie names, or `null`. An access token about
   * to expire is refreshed first, once for every request and replica: the others
   * wait for its result. A session whose refresh fails for good ends. Call it once
   * per request: on a step-up login's return, it marks the user as the retry.
   * Backend failures propagate.
   */
  async session(request: Request): Promise<SignedIn | null> {
    const key = SessionKey.parse(Login.#cookie(request, SESSION_COOKIE));
    if (key === undefined) return null;
    let current = await this.#sessions.load(key);
    if (current === null) return null;
    const { refreshToken, expiresAt } = current.login;
    if (refreshToken !== undefined && expiresAt <= this.#now() + REFRESH_MARGIN) {
      current = await this.#refresh(key, current);
      if (current === null) return null;
    }
    // The `GET` a step-up login returns to is its retry, and uses up the marker.
    // Another tab loading the same page within the minute would use it instead.
    const marker = SessionKey.parse(Login.#cookie(request, STEP_UP_COOKIE));
    const retry =
      request.method === 'GET' &&
      marker !== undefined &&
      (await this.#sessions.takeStepUp(marker, Login.#page(request)));
    return new SignedIn(this, current.login, request, retry);
  }

  /**
   * A response sending the browser through login and back to the request's page: a
   * redirect for a `GET`, and 401 for other methods, which cannot be repeated after
   * a redirect. With `stepUp`, the new sign-in must meet it, and the page's return is
   * marked as the step-up's retry; prefer {@link SignedIn.stepUp}, which stops at
   * one retry.
   */
  signIn(request: Request, stepUp?: StepUpRequirement): Response {
    if (request.method !== 'GET') return new Response(null, { status: 401 });
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

  /** The current time by the issuer's clock. */
  #now(): number {
    return this.client.issuer.clock();
  }

  /**
   * `path` if it is a same-origin relative path, so login cannot be turned into an
   * open redirect: it starts with one `/` (not `//` or `/\`), has no `\`, `#` or
   * control characters, and has at most 2048 bytes.
   */
  static #returnTo(path: string | null): string | undefined {
    if (path === null) return undefined;
    const local =
      new TextEncoder().encode(path).length <= MAX_RETURN_TO_BYTES &&
      /^\/(?![/\\])/.test(path) &&
      !/[\\#\p{Cc}]/u.test(path);
    return local ? path : undefined;
  }

  /** The request's path and query. */
  static #page(request: Request): string {
    const url = new URL(request.url);
    return `${url.pathname}${url.search}`;
  }

  /** The value of cookie `name` in the request, if any. */
  static #cookie(request: Request, name: string): string | undefined {
    for (const pair of (request.headers.get('cookie') ?? '').split(';')) {
      const separator = pair.indexOf('=');
      if (separator !== -1 && pair.slice(0, separator).trim() === name) {
        return pair.slice(separator + 1).trim();
      }
    }
    return undefined;
  }

  /** A `Set-Cookie` value for a host-only cookie scripts cannot read; zero `maxAge` deletes it. */
  static #setCookie(name: string, value: string, maxAge: number): string {
    const seconds = Math.max(0, Math.floor(maxAge / 1000));
    return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${String(seconds)}`;
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

  /** `GET /login`: stores a pending login and redirects to auth. */
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
    const key = SessionKey.generate();
    const pending = {
      login: authorization.pending,
      returnTo,
      stepUp: query.get('step_up') === 'true'
    };
    await this.#sessions.insertPending(key, pending, this.#now() + PENDING_LIFETIME);
    return Login.#redirect(authorization.url, [
      Login.#setCookie(LOGIN_COOKIE, key.value, PENDING_LIFETIME)
    ]);
  }

  /** `GET /callback`: completes the pending login and starts a session. */
  async #callback(request: Request): Promise<Response> {
    const key = SessionKey.parse(Login.#cookie(request, LOGIN_COOKIE));
    if (key === undefined) {
      return Login.text(400, 'This sign-in has no pending login; start again.');
    }
    const pending = await this.#sessions.takePending(key);
    if (pending === null) {
      return Login.text(400, 'This sign-in expired or was already used; start again.');
    }
    let tokens;
    try {
      tokens = await this.client.complete(pending.login, new URL(request.url).searchParams);
    } catch (error) {
      if (!(error instanceof AuthError)) throw error;
      return Login.text(error.code === 'network' ? 502 : 400, `Sign-in failed: ${error.message}.`);
    }
    // `complete` fails without an ID token, so this only narrows the type.
    const { idToken } = tokens;
    if (idToken === undefined) return Login.text(502, 'Sign-in failed: no ID token.');
    const login: StoredLogin = { ...tokens, idToken, issuer: this.client.issuer.issuer };
    // A fresh key on every sign-in: a key planted before login is worthless after.
    const previous = SessionKey.parse(Login.#cookie(request, SESSION_COOKIE));
    if (previous !== undefined) await this.#sessions.delete(previous);
    const session = SessionKey.generate();
    if (!(await this.#sessions.insert(session, login, this.#now() + this.#lifetime))) {
      return Login.text(400, 'Sign-in failed: this session was signed out; start again.');
    }
    const returnTo = Login.#returnTo(pending.returnTo) ?? this.#home;
    const cookies = [
      Login.#setCookie(SESSION_COOKIE, session.value, this.#lifetime),
      Login.#setCookie(LOGIN_COOKIE, '', 0)
    ];
    // A step-up marks its return; any other sign-in drops an unused marker, which
    // belonged to the session this one replaces.
    if (pending.stepUp) {
      const marker = SessionKey.generate();
      await this.#sessions.markStepUp(marker, returnTo, this.#now() + STEP_UP_RETURN);
      cookies.push(Login.#setCookie(STEP_UP_COOKIE, marker.value, STEP_UP_RETURN));
    } else {
      cookies.push(Login.#setCookie(STEP_UP_COOKIE, '', 0));
    }
    return Login.#redirect(returnTo, cookies);
  }

  /**
   * Whether a browser request comes from this app's own pages, whose origin is the
   * redirect URI's: `Sec-Fetch-Site: same-origin` when the browser sends it, and
   * otherwise an `Origin` equal to the app's, which `null` never is.
   */
  #sameOrigin(request: Request): boolean {
    const site = request.headers.get('sec-fetch-site');
    if (site !== null) return site === 'same-origin';
    return request.headers.get('origin') === new URL(this.client.config.redirectUri).origin;
  }

  /**
   * `POST /logout`: deletes the session and redirects to RP-initiated logout. `POST`
   * only, and only from the app's own pages, so another site cannot sign the user out.
   */
  async #logout(request: Request): Promise<Response> {
    if (!this.#sameOrigin(request)) {
      return Login.text(403, "Sign out from this site's own pages.");
    }
    let destination = this.#home;
    const key = SessionKey.parse(Login.#cookie(request, SESSION_COOKIE));
    if (key !== undefined) {
      const session = await this.#sessions.load(key);
      if (session !== null) {
        destination = this.client.logoutUrl(session.login.idToken, this.#afterLogout);
      }
      await this.#sessions.delete(key);
    }
    return Login.#redirect(destination, [
      Login.#setCookie(SESSION_COOKIE, '', 0),
      Login.#setCookie(STEP_UP_COOKIE, '', 0)
    ]);
  }

  /**
   * `POST /backchannel-logout`: validates auth's logout token and deletes the
   * sessions it names (OIDC Back-Channel Logout 1.0 §2.8). Auth posts it server to
   * server, so there is no origin to check: the signed token is the authentication.
   */
  async #backchannelLogout(request: Request): Promise<Response> {
    const invalid = () => Response.json({ error: 'invalid_request' }, { status: 400 });
    const type = request.headers.get('content-type') ?? '';
    if (!/^application\/x-www-form-urlencoded\s*(;|$)/i.test(type)) return invalid();
    const [token, ...others] = new URLSearchParams(await request.text()).getAll('logout_token');
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
    // An ended `sid` is remembered for as long as a session started now would last,
    // far beyond any ID token a racing sign-in could still complete with.
    await this.#sessions.logOut(logout, this.#now() + this.#lifetime);
    return new Response(null, { status: 200 });
  }

  /**
   * Refreshes the session's access token, serialized through the lease the SDK keeps
   * in the session record: only the lease holder calls auth, and other requests wait
   * for its result. Returns `null` once the session is gone.
   *
   * Auth rotates the refresh token as it answers, so once a refresh may have reached
   * auth without its answer being saved, the stored token may be spent and is never
   * redeemed again: the session ends instead, and the user signs in anew.
   */
  async #refresh(key: SessionKey, current: Session): Promise<Session | null> {
    const id = Sessions.leaseId();
    const lease = await this.#sessions.lease(key, current.version, id, REFRESH_LEASE);
    switch (lease.kind) {
      case 'missing':
        return null;
      case 'abandoned':
        // A refresh never finished: auth may have rotated the token.
        return this.#end(key);
      case 'changed':
      case 'busy':
        // Another request refreshed since this one read the session, or is
        // refreshing now: use its result.
        return this.#wait(key, current);
      case 'acquired':
        return this.#refreshLeased(key, id, lease.until, current);
    }
  }

  /**
   * Waits for another request's refresh to finish, then returns its result. After
   * {@link REFRESH_WAIT}, the session as last read is the best known.
   */
  async #wait(key: SessionKey, current: Session): Promise<Session | null> {
    const deadline = performance.now() + REFRESH_WAIT;
    for (;;) {
      const reloaded = await this.#sessions.load(key);
      if (!reloaded?.leased) return reloaded;
      if (performance.now() >= deadline) return current;
      await new Promise((resolve) => setTimeout(resolve, REFRESH_POLL));
    }
  }

  /**
   * Refreshes while holding lease `id` until `until`, then saves the result or gives
   * the lease back. The refresh must finish while enough of the lease is left to
   * save: the time is measured after acquiring the lease, since the backend calls
   * that acquired it may have been slow.
   */
  async #refreshLeased(
    key: SessionKey,
    id: string,
    until: number,
    current: Session
  ): Promise<Session | null> {
    const budget = until - this.#now() - SAVE_MARGIN;
    const refreshToken = current.login.refreshToken;
    // Nothing to refresh, or no time left to do it safely: auth was not called, so
    // give the lease back with the session unchanged.
    if (refreshToken === undefined || budget <= 0) return this.#save(key, id, until, current.login);
    let refreshed;
    try {
      refreshed = await Login.#within(
        Math.min(budget, REFRESH_DEADLINE),
        this.client.refresh(refreshToken)
      );
    } catch (error) {
      if (error instanceof AuthError && error.code === 'oauth') {
        // Auth refused the refresh token: the grant is over. Any other error
        // answer rotated nothing: keep the session.
        if (error.response?.error === 'invalid_grant') return this.#end(key);
        return this.#save(key, id, until, current.login);
      }
      // The request never reached auth, so nothing was rotated either.
      if (this.#unsent(error)) return this.#save(key, id, until, current.login);
      // No usable answer: auth may have rotated the token.
      await this.#end(key);
      if (error instanceof AuthError) return null;
      throw error;
    }
    if (refreshed === TIMED_OUT) return this.#end(key);
    // A new ID token must name the same user (OIDC Core §12.2).
    const old = current.login.idToken.claims;
    const idToken = refreshed.idToken ?? current.login.idToken;
    if (idToken.claims.sub !== old.sub || idToken.claims.iss !== old.iss) return this.#end(key);
    const login: StoredLogin = { ...current.login, ...refreshed, idToken };
    return this.#save(key, id, until, login);
  }

  /**
   * Saves `login` under lease `id`, giving the lease back. If the session no longer
   * holds the lease, it was logged out meanwhile and must stay that way. The save
   * must land before the lease expires at `until`, since afterwards another request
   * may find it abandoned and delete the session; a save still running then may or
   * may not have landed, so the session ends.
   */
  async #save(
    key: SessionKey,
    id: string,
    until: number,
    login: StoredLogin
  ): Promise<Session | null> {
    const saved = await Login.#within(until - this.#now(), this.#sessions.save(key, id, login));
    return saved === TIMED_OUT ? this.#end(key) : saved;
  }

  /** Ends the session. */
  async #end(key: SessionKey): Promise<null> {
    await this.#sessions.delete(key);
    return null;
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
      timer = setTimeout(
        () => {
          resolve(TIMED_OUT);
        },
        Math.max(0, milliseconds)
      );
    });
    try {
      return await Promise.race([promise, deadline]);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Whether `error` says the refresh request itself never reached auth: its connection
   * to the token endpoint could not be opened. A failure after auth answered, such as
   * fetching the keys to check the new ID token, may follow a rotation, so it is not.
   */
  #unsent(error: unknown): boolean {
    const tokenEndpoint = this.client.issuer.metadata.token_endpoint;
    if (!(error instanceof AuthError) || error.url !== tokenEndpoint) return false;
    for (let cause: unknown = error.cause; typeof cause === 'object' && cause !== null;) {
      const { code, name } = cause as { code?: unknown; name?: unknown };
      if (CONNECT_ERRORS.has(String(code)) || CONNECT_ERRORS.has(String(name))) return true;
      cause = (cause as { cause?: unknown }).cause;
    }
    return false;
  }
}

/**
 * The signed-in user, from {@link Login.session}: the ID token of the sign-in, and
 * the access token to call APIs with, refreshed when it was about to expire.
 *
 * ```ts
 * const user = await login.session(request);
 * if (!user) return login.signIn(request);
 * // A passkey sign-in within the last five minutes, or a redirect through login.
 * const stepUp = user.require({ acr_values: 'phr', max_age: 300 });
 * if (stepUp) return stepUp;
 * ```
 */
export class SignedIn {
  /** The validated ID token of the sign-in, or of the latest refresh that sent one. */
  readonly idToken: IdToken;
  /** The access token, to send as a bearer credential. */
  readonly accessToken: string;
  /** When the access token expires, in milliseconds since the epoch. */
  readonly expiresAt: number;
  /** Scopes granted to the access token. */
  readonly scopes: Scopes;
  readonly #login: Login;
  readonly #request: Request;
  readonly #retry: boolean;

  /** @internal `retry` marks a request returning from a step-up login. */
  constructor(login: Login, stored: StoredLogin, request: Request, retry: boolean) {
    this.idToken = stored.idToken;
    this.accessToken = stored.accessToken;
    this.expiresAt = stored.expiresAt;
    this.scopes = stored.scopes;
    this.#login = login;
    this.#request = request;
    this.#retry = retry;
  }

  /** The user's claims, from the ID token. */
  get claims(): IdTokenClaims {
    return this.idToken.claims;
  }

  /** The user's name: the display name, else the username, else the account ID. */
  get name(): string {
    return this.claims.name ?? this.claims.preferred_username ?? this.claims.sub;
  }

  /**
   * `null` if the sign-in meets `requirement`, else the {@link SignedIn.stepUp}
   * response asking for it.
   */
  require(requirement: StepUpRequirement): Response | null {
    return this.idToken.meets(requirement) ? null : this.stepUp(requirement);
  }

  /**
   * The response signing the user in again as `requirement` asks, such as an API's
   * `insufficient_user_authentication` challenge read with `parseChallenge`, and
   * coming back to the same page to try again: a redirect through login for a `GET`,
   * 401 for other methods. The login fails unless the new sign-in meets the
   * requirement. On that return the retry is spent: if the page asks again, the
   * answer is 403 instead of another redirect. The return is the first `GET` of the
   * page within a minute of the login; a later one counts as a new action.
   */
  stepUp(requirement: StepUpRequirement): Response {
    if (this.#retry) return Login.text(403, 'Signing in again did not give access to this page.');
    return this.#login.signIn(this.#request, requirement);
  }
}
