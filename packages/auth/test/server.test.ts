/**
 * Server-side login: the sealed cookies, `return_to`, pending logins, the origin
 * checks, redirects, refresh without a lease, logout and its deadline, back-channel
 * logout and step-up.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { BACKCHANNEL_LOGOUT_EVENT } from '../src/claims.ts';
import {
  Issuer,
  type IdTokenClaims,
  type LogoutTarget,
  type LogoutTokenClaims
} from '../src/index.ts';
import {
  CookieKey,
  Login,
  SignedIn,
  type LoginOptions,
  type SessionOptions
} from '../src/server.ts';
import {
  DISCOVERY_URL,
  DOCUMENT,
  FakeFetch,
  ISSUER,
  JWKS_URI,
  ManualClock,
  TOKEN_URL,
  vector
} from './vectors.ts';

const APP = 'https://notes.example';
const CLIENT_ID = 'notes-web';
const PAR_URL = `${ISSUER}/oauth/par`;
const REVOKE_URL = `${ISSUER}/oauth/revoke`;
/** The attributes every cookie of the login routes has. */
const ATTRIBUTES = 'Path=/; Secure; HttpOnly; SameSite=Lax';
const USER = '01936f3e-8c00-7000-8000-000000000001';
const OTHER_USER = '01936f3e-8c00-7000-8000-000000000002';
const SESSION_COOKIE = '__Host-piquel-notes-web-session';
const PENDING_COOKIE = '__Host-piquel-notes-web-login-';
const STEP_UP_COOKIE = '__Host-piquel-notes-web-step-up';

/**
 * `Sec-Fetch-Site` and `Origin` headers, and whether they show the app's own pages:
 * `Sec-Fetch-Site` decides when sent, and `Origin` only without it. A form on a
 * `no-referrer` page sends `Origin: null` with `Sec-Fetch-Site: same-origin`.
 */
const ORIGINS: [Record<string, string>, boolean][] = [
  [{ 'sec-fetch-site': 'same-origin', origin: 'null' }, true],
  [{ 'sec-fetch-site': 'same-origin' }, true],
  [{ origin: APP }, true],
  [{ 'sec-fetch-site': 'same-site', origin: APP }, false],
  [{ 'sec-fetch-site': 'cross-site', origin: APP }, false],
  [{ origin: 'null' }, false],
  [{}, false],
  [{ origin: 'https://evil.notes.example' }, false]
];

/** A UUIDv7 ending in `n`, for session and token IDs. */
function uuid(n: number): string {
  return `01936f3e-8c00-7000-8000-${String(n).padStart(12, '0')}`;
}

/**
 * What a sign-in's ID token says, besides what the login fixes; whether the token
 * response carries a refresh token, and members replacing others of the response.
 */
type SignIn = Partial<IdTokenClaims> & { refresh?: boolean; response?: Record<string, unknown> };

/** A request whose connection could not be opened, as Node's fetch fails. */
const unreachable = () =>
  Promise.reject(
    new TypeError('fetch failed', {
      cause: Object.assign(new Error('connect'), { code: 'ECONNREFUSED' })
    })
  );

/**
 * A fake auth, signing its tokens with a fresh RSA key, and the app's login in front
 * of it. `token` answers the token endpoint, and `revoke` the revocation of a token.
 */
class Auth {
  readonly clock = new ManualClock(1_800_000_000);
  /** When the user signed in, which auth keeps across refreshes: every ID token's `auth_time` by default. */
  readonly authTime = this.clock.seconds;
  token: () => Response | Promise<Response> = () => new Response(null, { status: 500 });
  revoke: (token: string) => Response | Promise<Response> = () =>
    new Response(null, { status: 200 });
  readonly fetch: FakeFetch;
  readonly #keys: CryptoKeyPair;
  /** The key ID new tokens name. */
  kid = 'test';
  #issued = 0;
  login!: Login;

  private constructor(keys: CryptoKeyPair, jwk: JsonWebKey) {
    this.#keys = keys;
    this.fetch = new FakeFetch({
      [DISCOVERY_URL]: () => Response.json(DOCUMENT),
      [JWKS_URI]: () =>
        Response.json({ keys: [{ ...jwk, kid: 'test', alg: 'RS256', use: 'sig' }] }),
      [PAR_URL]: () =>
        Response.json({ request_uri: 'urn:pushed', expires_in: 60 }, { status: 201 }),
      [TOKEN_URL]: () => this.token(),
      [REVOKE_URL]: (init) =>
        this.revoke(
          new URLSearchParams(typeof init.body === 'string' ? init.body : '').get('token') ?? ''
        )
    });
  }

  /** A fake auth and a login with a fresh cookie key and `options`. */
  static async start(options: Partial<LoginOptions> = {}): Promise<Auth> {
    const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    const keys = await crypto.subtle.generateKey(
      { ...algorithm, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ['sign', 'verify']
    );
    const auth = new Auth(keys, await crypto.subtle.exportKey('jwk', keys.publicKey));
    const issuer = await Issuer.discover(ISSUER, {
      fetch: auth.fetch.fetch,
      clock: auth.clock.now
    });
    const client = issuer.client({
      clientId: CLIENT_ID,
      clientSecret: 'secret',
      redirectUri: `${APP}/auth/callback`
    });
    auth.login = new Login(client, { cookieKey: CookieKey.generate(), ...options });
    return auth;
  }

  /** A compact JWS of `claims`, with header `typ`. */
  async sign(typ: string, claims: object): Promise<string> {
    const part = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const input = `${part({ alg: 'RS256', typ, kid: this.kid })}.${part(claims)}`;
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      this.#keys.privateKey,
      new TextEncoder().encode(input)
    );
    return `${input}.${Buffer.from(signature).toString('base64url')}`;
  }

  /** A token response, with an ID token for `nonce` and `claims` when given. */
  async tokens(claims?: SignIn, nonce?: string): Promise<Record<string, unknown>> {
    const now = this.clock.seconds;
    this.#issued += 1;
    const { refresh, response: replaced, ...signed } = claims ?? {};
    const response: Record<string, unknown> = {
      access_token: `at-${String(this.#issued)}`,
      token_type: 'Bearer',
      expires_in: 300,
      scope: 'openid profile',
      refresh_token: `rt-${String(this.#issued)}`
    };
    if (refresh === false) delete response.refresh_token;
    if (claims !== undefined) {
      response.id_token = await this.sign('JWT', {
        iss: ISSUER,
        sub: USER,
        aud: CLIENT_ID,
        iat: now,
        exp: now + 300,
        nonce,
        sid: uuid(1),
        auth_time: this.authTime,
        acr: 'urn:piquel:acr:social',
        ...signed
      });
    }
    return { ...response, ...replaced };
  }

  /** Refreshes answer new access tokens, without a refresh token, as for a confidential client. */
  refreshing(): void {
    this.token = async () => Response.json(await this.tokens({ refresh: false }));
  }

  /** The forms posted to `url`, in order. */
  #forms(url: string): URLSearchParams[] {
    return this.fetch.requests
      .filter((request) => request.url === url)
      .map(({ init }) => new URLSearchParams(typeof init.body === 'string' ? init.body : ''));
  }

  /** How many refreshes the token endpoint was asked for. */
  refreshes(): number {
    return this.#forms(TOKEN_URL).filter((form) => form.get('grant_type') === 'refresh_token')
      .length;
  }

  /** The refresh tokens auth was asked to revoke, in order. */
  revoked(): string[] {
    return this.#forms(REVOKE_URL).map((form) => form.get('token') ?? '');
  }

  /** A logout token naming `target`, with ID `jti`. */
  logoutToken(target: Partial<LogoutTokenClaims>, jti = uuid(100)): Promise<string> {
    const now = this.clock.seconds;
    return this.sign('logout+jwt', {
      iss: ISSUER,
      aud: CLIENT_ID,
      iat: now,
      exp: now + 120,
      jti,
      events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
      ...target
    });
  }

  /** Posts `form` to the back-channel logout route, as auth does. */
  async backchannelLogout(form: Record<string, string>): Promise<Response> {
    const request = new Request(`${APP}/auth/backchannel-logout`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form)
    });
    const response = await this.login.handle(request);
    assert.ok(response);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    return response;
  }
}

/** A login started: the response, its cookie's name (its slot), its `state` and `nonce`. */
type Started = { response: Response; name: string; state: string; nonce: string };

/** A browser of the app, keeping its cookies. */
class Browser {
  readonly cookies = new Map<string, string>();
  readonly #auth: Auth;

  constructor(auth: Auth) {
    this.#auth = auth;
  }

  /** The request for `path` with the browser's cookies and `headers`. */
  request(path: string, init: { method?: string; headers?: Record<string, string> } = {}) {
    const cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    return new Request(`${APP}${path}`, {
      method: init.method ?? 'GET',
      headers: { ...init.headers, ...(cookie === '' ? {} : { cookie }) }
    });
  }

  /** Keeps the cookies `response` sets. */
  keep(response: Response): Response {
    for (const cookie of response.headers.getSetCookie()) {
      const [pair = ''] = cookie.split(';');
      const [name = '', value = ''] = pair.split('=');
      if (value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return response;
  }

  /** Sends a request to the login routes, keeping the cookies they set. */
  async send(path: string, init: { method?: string; headers?: Record<string, string> } = {}) {
    const response = await this.#auth.login.handle(this.request(path, init));
    assert.ok(response, `${path} is not a login route`);
    return this.keep(response);
  }

  /**
   * A browser's navigation to the app's page at `path`, as an app answers it: its
   * session, and the response {@link Login.respond} completed, whose cookies the
   * browser keeps.
   */
  async visit(path = '/') {
    const request = this.request(path, { headers: { 'sec-fetch-mode': 'navigate' } });
    const user = await this.#auth.login.session(request);
    const answer = user instanceof Response ? user : new Response('page');
    return { user, response: this.keep(this.#auth.login.respond(request, answer)) };
  }

  /** The session of a navigation to `path`, which the origin check lets through. */
  async session(path = '/') {
    const { user } = await this.visit(path);
    assert.ok(!(user instanceof Response));
    return user;
  }

  /** Starts a login at `start`. */
  async start(start = '/auth/login'): Promise<Started> {
    const response = await this.send(start);
    assert.equal(response.status, 303);
    const pushed = this.#auth.fetch.sent(PAR_URL);
    assert.ok(pushed);
    const [pending] = response.headers.getSetCookie();
    const name = pending?.split('=')[0] ?? '';
    assert.match(name, new RegExp(`^${PENDING_COOKIE}[0-2]$`));
    return { response, name, state: pushed.form.state ?? '', nonce: pushed.form.nonce ?? '' };
  }

  /** Completes `login` with an ID token of `claims`, returning the callback's answer. */
  async complete(login: Started, claims: SignIn = {}) {
    const tokens = await this.#auth.tokens(claims, login.nonce);
    this.#auth.token = () => Response.json(tokens);
    const query = new URLSearchParams({ code: 'code', state: login.state, iss: ISSUER });
    return this.send(`/auth/callback?${query.toString()}`);
  }

  /** Starts a login at `start`, then completes it with an ID token of `claims`. */
  async signIn(claims: SignIn = {}, start = '/auth/login') {
    return this.complete(await this.start(start), claims);
  }
}

/** The `name=value` pair `response` sets for cookie `name`, empty when it deletes it. */
function setCookie(response: Response, name: string): string | undefined {
  return response.headers
    .getSetCookie()
    .map((cookie) => cookie.split(';')[0] ?? '')
    .find((pair) => pair.startsWith(`${name}=`));
}

test('a cookie key is 32 bytes of canonical base64, and is never printed', () => {
  const text = vector('sessions', 'valid').input.cookie_key as string;
  const key = CookieKey.fromBase64(` ${text}\n`);
  assert.ok(!inspect(key).includes(text.slice(0, 8)));
  assert.equal(JSON.stringify(key), '{}');
  for (const [bad, message] of [
    ['not base64!', /standard base64/],
    [text.replace(/=$/, ''), /standard base64/],
    [btoa('sixteen bytes!!!'), /32 bytes, not 16/]
  ] as const) {
    assert.throws(() => CookieKey.fromBase64(bad), { name: 'TypeError', message }, bad);
  }
});

test('a public client is refused', async () => {
  const issuer = await Issuer.discover(ISSUER, { fetch: FakeFetch.issuer().fetch });
  const client = issuer.client({ clientId: CLIENT_ID, redirectUri: `${APP}/auth/callback` });
  assert.throws(() => new Login(client, { cookieKey: CookieKey.generate() }), {
    name: 'TypeError',
    message: /confidential client/
  });
});

test('a sign-in requests offline_access and sets sealed host-only cookies', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  const started = await browser.start();
  assert.equal(started.response.headers.get('cache-control'), 'no-store');
  assert.match(
    started.response.headers.getSetCookie().join(),
    new RegExp(`^${started.name}=[\\w-]+; ${ATTRIBUTES}; Max-Age=600$`)
  );
  assert.ok(auth.fetch.sent(PAR_URL)?.form.scope?.split(' ').includes('offline_access'));

  const done = await browser.complete(started);
  assert.equal(done.status, 303);
  assert.equal(done.headers.get('location'), '/');
  const cookies = done.headers.getSetCookie();
  assert.match(
    cookies[0] ?? '',
    new RegExp(`^${SESSION_COOKIE}=[\\w-]+; ${ATTRIBUTES}; Max-Age=43200$`)
  );
  assert.ok(cookies.includes(`${STEP_UP_COOKIE}=; ${ATTRIBUTES}; Max-Age=0`));
  assert.ok(cookies.includes(`${started.name}=; ${ATTRIBUTES}; Max-Age=0`));
  const user = await browser.session();
  assert.deepEqual([user?.sub, user?.sid, user?.name], [USER, uuid(1), USER]);
  assert.equal(await user?.accessToken(), 'at-1');
});

test('a session without a refresh token ends with its access token', async () => {
  const auth = await Auth.start();
  const done = await new Browser(auth).signIn({ refresh: false });
  assert.match(done.headers.getSetCookie()[0] ?? '', /; Max-Age=300$/);
});

test('a sign-in revokes the session it replaces, or fails and keeps it when it cannot', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  // Auth cannot revoke the first session's grant, `rt-1`, and revokes any other.
  auth.revoke = (token) => (token === 'rt-1' ? unreachable() : new Response(null, { status: 200 }));
  const refused = await browser.signIn();
  assert.equal(refused.status, 502);
  assert.equal(
    setCookie(refused, SESSION_COOKIE),
    undefined,
    'no new session, and the old one stays'
  );
  assert.deepEqual(auth.revoked(), ['rt-1', 'rt-2'], 'the new grant is revoked');
  // The old session still renews.
  auth.clock.seconds += 300;
  auth.refreshing();
  assert.equal(await (await browser.session())?.accessToken(), 'at-3');
  auth.revoke = () => new Response(null, { status: 200 });
  assert.equal((await browser.signIn()).status, 303);
  assert.deepEqual(auth.revoked(), ['rt-1', 'rt-2', 'rt-1']);
});

test('a step-up stays on the signed-in account; an ordinary sign-in may switch', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  const session = browser.cookies.get(SESSION_COOKIE) ?? '';
  const stepUp = '/auth/login?step_up=true';
  const other = { sub: OTHER_USER };
  const refused = (response: Response) => {
    assert.equal(response.status, 400);
    assert.equal(setCookie(response, SESSION_COOKIE), undefined, 'the session is kept');
  };
  // Started from the session, then completed as another account.
  refused(await browser.signIn(other, stepUp));
  // Started from the session, which another tab then signed out of: the pin alone
  // stops another account.
  const pinned = await browser.start(stepUp);
  browser.cookies.delete(SESSION_COOKIE);
  refused(await browser.complete(pinned, other));
  // Started without a session, then completed beside another account's.
  const unpinned = await browser.start(stepUp);
  browser.cookies.set(SESSION_COOKIE, session);
  refused(await browser.complete(unpinned, other));
  // The session's grant is `rt-1`; each refused sign-in's, revoked, the next.
  assert.deepEqual(auth.revoked(), ['rt-2', 'rt-3', 'rt-4']);

  assert.equal((await browser.signIn({}, stepUp)).status, 303);
  assert.equal(auth.revoked().at(-1), 'rt-1', "the replaced session's grant");
  assert.equal((await browser.signIn(other)).status, 303, 'an ordinary sign-in');
});

test('a sign-in redirects only navigations, with their full path', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  const signIn = (headers: Record<string, string>) =>
    auth.login.signIn(browser.request('/notes?page=2', { headers }));
  const navigation = signIn({ 'sec-fetch-mode': 'navigate' });
  assert.equal(navigation.status, 303);
  assert.equal(navigation.headers.get('location'), '/auth/login?return_to=%2Fnotes%3Fpage%3D2');
  // Following a redirect to auth would fail a `fetch`'s CORS check.
  for (const mode of ['cors', 'same-origin', 'no-cors', undefined]) {
    const headers: Record<string, string> = mode === undefined ? {} : { 'sec-fetch-mode': mode };
    assert.equal(signIn(headers).status, 401, String(mode));
  }
});

test('revocations give up after their deadline', { timeout: 10_000 }, async (t) => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  // Auth never answers, and the injected `fetch` ignores its own timeout. The fake
  // answers before the deadline is set, so it waits the five seconds out just after.
  auth.revoke = () => {
    setImmediate(() => {
      t.mock.timers.tick(5000);
    });
    return new Promise(() => undefined);
  };
  const logout = await browser.send('/auth/logout', {
    method: 'POST',
    headers: { 'sec-fetch-site': 'same-origin' }
  });
  assert.equal(logout.status, 502);
  assert.deepEqual(logout.headers.getSetCookie(), []);
  const signIn = await browser.signIn();
  assert.equal(signIn.status, 502);
  assert.equal(setCookie(signIn, SESSION_COOKIE), undefined, 'the old session stays');
});

test('return_to accepts only same-origin paths', async () => {
  const auth = await Auth.start();
  const returnsTo = async (path: string) => {
    const done = await new Browser(auth).signIn(
      {},
      `/auth/login?${new URLSearchParams({ return_to: path }).toString()}`
    );
    return done.headers.get('location');
  };
  assert.equal(await returnsTo('/notes?page=2'), '/notes?page=2');
  for (const path of [
    'https://evil.example',
    '//evil.example',
    '/\\evil.example',
    '/a\\b',
    '/a#b',
    '/a\nb',
    // A `Location` header holds ASCII only, so the callback could not send it back.
    '/✓',
    'notes',
    `/${'a'.repeat(2048)}`
  ]) {
    assert.equal(await returnsTo(path), '/', path);
  }
});

test('logins in tabs whose states land in different slots all complete, three slots at most', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  // Start logins until every slot is used: random states land in all three within
  // 200 but for a chance of about 1 in 10^35.
  const started: Started[] = [];
  const slots = new Set<string>();
  while (slots.size < 3 && started.length < 200) {
    const login = await browser.start();
    slots.add(login.name);
    started.push(login);
  }
  assert.equal(slots.size, 3, 'three slots');
  assert.ok(browser.cookies.size <= 3);
  // The newest login of each of two slots, as the browser holds them.
  const latest = new Map(started.map((login) => [login.name, login]));
  const [first, second] = [...latest.values()];
  assert.ok(first && second);

  const forged = await browser.complete({ ...second, state: 'made-up' });
  assert.equal(forged.status, 400);
  assert.deepEqual(forged.headers.getSetCookie(), [], 'no login is touched');
  for (const login of [second, first]) {
    const done = await browser.complete(login);
    assert.equal(done.status, 303);
    assert.equal(setCookie(done, login.name), `${login.name}=`);
    const others = done.headers
      .getSetCookie()
      .filter((cookie) => cookie.startsWith(PENDING_COOKIE) && !cookie.startsWith(login.name));
    assert.deepEqual(others, [], "the other tab's login is kept");
  }
});

test('pending login cookies fit their slots', async () => {
  // Quotes double in JSON, so 2048 of them would seal to some 6 KB.
  const quotes = `/${'"'.repeat(2047)}`;
  const start = `/auth/login?${new URLSearchParams({ return_to: quotes }).toString()}`;
  for (const [afterLogin, destination] of [
    [undefined, '/'],
    ['/notes', '/notes'],
    [quotes, '/']
  ] as const) {
    const auth = await Auth.start(afterLogin === undefined ? {} : { afterLogin });
    const browser = new Browser(auth);
    const login = await browser.start(start);
    const pair = setCookie(login.response, login.name) ?? '';
    assert.ok(pair.length <= 1001, String(pair.length));
    assert.equal((await browser.complete(login)).headers.get('location'), destination);
  }
});

test('logout accepts only requests from the app’s own pages', async () => {
  const auth = await Auth.start();
  for (const [headers, own] of ORIGINS) {
    const name = JSON.stringify(headers);
    const browser = new Browser(auth);
    await browser.signIn();
    const out = await browser.send('/auth/logout', { method: 'POST', headers });
    assert.equal(out.status, own ? 303 : 403, name);
    assert.equal(setCookie(out, SESSION_COOKIE) === `${SESSION_COOKIE}=`, own, name);
  }
  assert.equal((await new Browser(auth).send('/auth/logout')).status, 405);
});

test('logout revokes the refresh token, and keeps the session when it cannot', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  const logout = () =>
    browser.send('/auth/logout', { method: 'POST', headers: { 'sec-fetch-site': 'same-origin' } });

  auth.revoke = () => Response.json({ error: 'temporarily_unavailable' }, { status: 503 });
  const failed = await logout();
  assert.equal(failed.status, 502);
  assert.deepEqual(failed.headers.getSetCookie(), []);
  assert.ok(await browser.session());

  auth.revoke = () => new Response(null, { status: 200 });
  const out = await logout();
  assert.equal(out.status, 303);
  assert.deepEqual(auth.revoked(), ['rt-1', 'rt-1']);
  assert.equal(setCookie(out, SESSION_COOKIE), `${SESSION_COOKIE}=`);
  const location = new URL(out.headers.get('location') ?? '');
  assert.equal(`${location.origin}${location.pathname}`, `${ISSUER}/oidc/logout`);
  // There is no ID token to hint with.
  assert.deepEqual([...location.searchParams.keys()], ['client_id']);
  assert.equal(await browser.session(), null);
});

test('session() takes unsafe requests only from the app’s own pages, unless told otherwise', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  const anonymous = new Browser(auth);
  const answer = (user: SignedIn | Response | null) =>
    user instanceof Response ? user.status : user === null ? 'signed out' : 'signed in';
  for (const [headers, own] of ORIGINS) {
    const name = JSON.stringify(headers);
    const read = (from: Browser, method: string, options?: SessionOptions) =>
      auth.login.session(from.request('/notes', { method, headers }), options).then(answer);
    // Without a cookie too, a request from elsewhere is refused, not signed out.
    assert.equal(await read(browser, 'POST'), own ? 'signed in' : 403, name);
    assert.equal(await read(browser, 'DELETE'), own ? 'signed in' : 403, name);
    assert.equal(await read(anonymous, 'POST'), own ? 'signed out' : 403, name);
    // Safe methods and the opt-out skip the check.
    assert.equal(await read(browser, 'GET'), 'signed in', name);
    assert.equal(await read(browser, 'POST', { crossOrigin: true }), 'signed in', name);
    assert.equal(await read(anonymous, 'POST', { crossOrigin: true }), 'signed out', name);
  }
});

test('concurrent refreshes all succeed, and a request read twice refreshes once', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  auth.clock.seconds += 300;
  auth.refreshing();
  const visits = await Promise.all([browser.visit(), browser.visit()]);
  assert.equal(auth.refreshes(), 2);
  assert.equal(auth.fetch.sent(TOKEN_URL)?.form.refresh_token, 'rt-1');
  const tokens = await Promise.all(
    visits.map(async ({ user, response }) => {
      assert.ok(user instanceof SignedIn);
      assert.ok(setCookie(response, SESSION_COOKIE));
      assert.equal(response.headers.get('cache-control'), 'no-store');
      return user.accessToken();
    })
  );
  assert.deepEqual(tokens.sort(), ['at-2', 'at-3']);
  // The browser kept the last cookie, which serves until it is about to expire.
  const kept = await browser.visit();
  assert.equal(setCookie(kept.response, SESSION_COOKIE), undefined);
  assert.equal(auth.refreshes(), 2);

  auth.clock.seconds += 300;
  const request = browser.request('/');
  const [once, twice] = await Promise.all([
    auth.login.session(request),
    auth.login.session(request)
  ]);
  assert.equal(auth.refreshes(), 3, 'one refresh');
  assert.ok(once instanceof SignedIn && twice instanceof SignedIn);
  assert.equal(await twice.accessToken(), 'at-4');
  const response = auth.login.respond(request, Response.redirect(`${APP}/`));
  assert.equal(response.headers.getSetCookie().length, 1);
});

test('auth’s refusal ends the session; other failures keep it while its access token is valid', async () => {
  /** The home page `seconds` after signing in, with the token endpoint answering `answer`. */
  const after = async (answer: () => Response | Promise<Response>, seconds: number) => {
    const auth = await Auth.start();
    const browser = new Browser(auth);
    await browser.signIn();
    auth.clock.seconds += seconds;
    auth.token = answer;
    return browser.visit();
  };
  const refused =
    (error: string, status = 400) =>
    () =>
      Response.json({ error }, { status });

  const ended = await after(refused('invalid_grant'), 280);
  assert.equal(ended.user, null);
  assert.equal(setCookie(ended.response, SESSION_COOKIE), `${SESSION_COOKIE}=`);
  for (const answer of [
    refused('temporarily_unavailable'),
    refused('temporarily_unavailable', 503),
    unreachable
  ]) {
    const served = await after(answer, 280);
    assert.ok(served.user instanceof SignedIn);
    assert.equal(await served.user.accessToken(), 'at-1');
    assert.equal(setCookie(served.response, SESSION_COOKIE), undefined);
    const expired = await after(answer, 300);
    assert.ok(expired.user instanceof Response);
    assert.equal(expired.user.status, 503);
    assert.match(await expired.user.text(), /could not be renewed/);
    assert.equal(setCookie(expired.response, SESSION_COOKIE), undefined);
  }
});

test('a refresh that changes the sign-in ends the session; one carrying it over keeps it', async () => {
  const changes: [string, SignIn][] = [
    ['unchanged', {}],
    ['another user', { sub: OTHER_USER }],
    ['a later auth_time', { auth_time: 1_800_000_060 }],
    ['another acr', { acr: 'phr' }],
    ['a nonce', { nonce: 'replayed' }]
  ];
  for (const [change, claims] of changes) {
    const auth = await Auth.start();
    const browser = new Browser(auth);
    await browser.signIn();
    auth.clock.seconds += 300;
    auth.token = async () => Response.json(await auth.tokens({ refresh: false, ...claims }));
    const { user, response } = await browser.visit();
    if (change === 'unchanged') {
      assert.ok(user instanceof SignedIn);
      assert.equal(await user.accessToken(), 'at-2');
    } else {
      assert.equal(user, null, change);
      assert.equal(setCookie(response, SESSION_COOKIE), `${SESSION_COOKIE}=`, change);
    }
  }
});

test('a refresh’s nonce must be the sign-in’s, which a refresh without one keeps', async () => {
  for (const kept of [true, false]) {
    const auth = await Auth.start();
    const browser = new Browser(auth);
    const login = await browser.start();
    await browser.complete(login);
    let refreshes = 0;
    auth.token = async () => {
      refreshes += 1;
      const nonce = refreshes === 1 ? {} : { nonce: kept ? login.nonce : 'another' };
      return Response.json(await auth.tokens({ refresh: false, ...nonce }));
    };
    auth.clock.seconds += 300;
    assert.equal(await (await browser.session())?.accessToken(), 'at-2');
    auth.clock.seconds += 300;
    const { user, response } = await browser.visit();
    assert.equal(user instanceof SignedIn, kept);
    if (!kept) assert.equal(setCookie(response, SESSION_COOKIE), `${SESSION_COOKIE}=`);
  }
});

test('ended or unreadable session cookies are cleared', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  const sealed = browser.cookies.get(SESSION_COOKIE) ?? '';
  // The same client's session, sealed by an app with another key.
  const other = new Browser(await Auth.start());
  await other.signIn();
  auth.clock.seconds += 12 * 60 * 60;
  for (const cookie of [sealed, other.cookies.get(SESSION_COOKIE) ?? '']) {
    browser.cookies.set(SESSION_COOKIE, cookie);
    const { user, response } = await browser.visit();
    assert.equal(user, null);
    assert.equal(setCookie(response, SESSION_COOKIE), `${SESSION_COOKIE}=`);
  }
});

test('a session whose end comes while its refresh runs is over', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  auth.clock.seconds += 12 * 60 * 60 - 5;
  auth.token = async () => {
    // The refresh takes ten seconds.
    auth.clock.seconds += 10;
    return Response.json(await auth.tokens({ refresh: false }));
  };
  const { user, response } = await browser.visit();
  assert.equal(auth.refreshes(), 1);
  assert.equal(user, null);
  assert.equal(setCookie(response, SESSION_COOKIE), `${SESSION_COOKIE}=`);
});

test('a worst-case session fits in a cookie once access tokens carry no profile', async () => {
  // The vectors' user, with the times and nonce of this sign-in.
  const { ok } = vector('tokens', 'id-valid').expected as { ok: IdTokenClaims };
  const fixed = ['nonce', 'iat', 'exp', 'auth_time'];
  const claims = Object.fromEntries(
    Object.entries(ok).filter(([name]) => !fixed.includes(name))
  ) as Partial<IdTokenClaims>;
  const signIn = async (accessBytes: number) =>
    new Browser(await Auth.start()).signIn({
      ...claims,
      name: '😀'.repeat(80),
      email: `${'e'.repeat(242)}@example.com`,
      email_verified: true,
      preferred_username: 'u'.repeat(32),
      profile_version: 0xffff_ffff,
      response: {
        access_token: 'a'.repeat(accessBytes),
        scope: 'email offline_access openid profile',
        refresh_token: `prt_${USER}.${'s'.repeat(43)}`
      }
    });
  // The 1,227-byte access token of a 3072-bit key with 64-byte IDs (#279).
  const minimal = await signIn(1227);
  assert.equal(minimal.status, 303);
  const pair = setCookie(minimal, SESSION_COOKIE) ?? '';
  assert.ok(pair.length <= 4096, String(pair.length));
  // Today's access tokens copy the profile, and the cookie would not fit.
  const today = await signIn(2272);
  assert.equal(today.status, 500);
  assert.match(
    await today.text(),
    /^Sign-in failed: the session cookie would be \d+ bytes; browsers keep 4096 at most\.$/
  );
  assert.equal(setCookie(today, SESSION_COOKIE), undefined);
});

test('back-channel logout hands valid tokens to the handler, and is no route without one', async () => {
  const without = await Auth.start();
  const request = new Request(`${APP}/auth/backchannel-logout`, { method: 'POST' });
  assert.equal(await without.login.handle(request), null);

  const received: LogoutTarget[] = [];
  let failing = false;
  const auth = await Auth.start({
    backchannelLogout: (token) => {
      if (failing) return Promise.reject(new Error('the app’s database is down'));
      received.push(token.target);
      return Promise.resolve();
    }
  });
  const bySession = await auth.logoutToken({ sub: USER, sid: uuid(1) });
  // Auth delivers again when it lost the answer: the handler sees it twice.
  for (const token of [bySession, bySession, await auth.logoutToken({ sub: USER }, uuid(101))]) {
    assert.equal((await auth.backchannelLogout({ logout_token: token })).status, 200);
  }
  assert.deepEqual(received, [
    { kind: 'session', sid: uuid(1) },
    { kind: 'session', sid: uuid(1) },
    { kind: 'subject', sub: USER }
  ]);

  failing = true;
  assert.equal((await auth.backchannelLogout({ logout_token: bySession })).status, 500);
  failing = false;

  const idToken = String((await auth.tokens({})).id_token);
  for (const form of [
    { logout_token: 'not.a.token' },
    // An ID token is no logout token.
    { logout_token: idToken },
    { token: 'abc' },
    // A body far longer than any logout token, even around a valid one.
    { logout_token: bySession, padding: 'a'.repeat(64 * 1024) }
  ]) {
    const invalid = await auth.backchannelLogout(form);
    assert.equal(invalid.status, 400);
    assert.deepEqual(await invalid.json(), { error: 'invalid_request' });
  }
  // Keys that cannot be fetched are this server's failure, for auth to retry.
  auth.kid = 'rotated';
  auth.fetch.routes[JWKS_URI] = unreachable;
  // Past the key cache's refetch interval.
  auth.clock.seconds += 60;
  const rotated = await auth.logoutToken({ sub: USER }, uuid(102));
  assert.equal((await auth.backchannelLogout({ logout_token: rotated })).status, 503);
  assert.equal(received.length, 3, 'never handled');
});

test('a step-up returns to the page, retries once, then answers 403', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn({ auth_time: auth.clock.seconds - 3600 });
  const requirement = { acr_values: 'phr', max_age: 60 } as const;
  // A page whose API keeps refusing, as one that still asks for a step-up.
  const page = async () => {
    const user = await browser.session('/settings?tab=1');
    assert.ok(user);
    return user.stepUp(requirement);
  };

  const asked = await page();
  assert.equal(asked.status, 303);
  const start = asked.headers.get('location') ?? '';
  assert.equal(
    start,
    '/auth/login?return_to=%2Fsettings%3Ftab%3D1&acr_values=phr&max_age=60&step_up=true'
  );
  // A sign-in below the requirement fails rather than asking again.
  assert.equal((await browser.signIn({}, start)).status, 400);
  assert.deepEqual(
    {
      acr_values: auth.fetch.sent(PAR_URL)?.form.acr_values,
      max_age: auth.fetch.sent(PAR_URL)?.form.max_age
    },
    { acr_values: 'phr', max_age: '60' }
  );

  const done = await browser.signIn({ acr: 'phr' }, start);
  assert.equal(done.headers.get('location'), '/settings?tab=1');
  // The marker names the page by its SHA-256, so it stays small.
  assert.match(
    done.headers.getSetCookie()[1] ?? '',
    new RegExp(`^${STEP_UP_COOKIE}=[\\w-]{43}; ${ATTRIBUTES}; Max-Age=60$`)
  );
  const { user, response } = await browser.visit('/settings?tab=1');
  assert.ok(user instanceof SignedIn);
  assert.equal(user.require(requirement), null);
  // The return was the retry: asking again is refused, not redirected.
  assert.equal(user.stepUp(requirement).status, 403);
  // The marker is spent, so a later visit is a new action.
  assert.equal(setCookie(response, STEP_UP_COOKIE), `${STEP_UP_COOKIE}=`);
  assert.equal((await page()).status, 303);
  // Only a navigation is redirected: a `fetch` gets the 401, as do other methods.
  for (const init of [
    { headers: { 'sec-fetch-mode': 'cors' } },
    { method: 'POST', headers: { 'sec-fetch-site': 'same-origin' } }
  ]) {
    const user = await auth.login.session(browser.request('/settings', init));
    assert.ok(user instanceof SignedIn);
    assert.equal(user.stepUp(requirement).status, 401);
  }
});
