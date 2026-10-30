/** Server-side login: cookies, `return_to`, logout, the refresh lease, back-channel logout and step-up. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Issuer, type IdTokenClaims, type LogoutTokenClaims } from '../src/index.ts';
import { Login, MemoryBackend, checkBackend, type SessionBackend } from '../src/server.ts';
import {
  DISCOVERY_URL,
  DOCUMENT,
  FakeFetch,
  ISSUER,
  JWKS_URI,
  ManualClock,
  TOKEN_URL
} from './vectors.ts';

const APP = 'https://notes.example';
const CLIENT_ID = 'notes-web';
const PAR_URL = `${ISSUER}/oauth/par`;
const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
/** The attributes every cookie of the login routes has. */
const ATTRIBUTES = 'Path=/; Secure; HttpOnly; SameSite=Lax';
const USER = '01936f3e-8c00-7000-8000-000000000001';
const OTHER_USER = '01936f3e-8c00-7000-8000-000000000002';

/** A UUIDv7 ending in `n`, for session and token IDs. */
function uuid(n: number): string {
  return `01936f3e-8c00-7000-8000-${String(n).padStart(12, '0')}`;
}

/** What a sign-in's ID token says, besides what the login fixes. */
type SignIn = Partial<IdTokenClaims> & { refresh?: boolean };

/**
 * A fake auth, signing its tokens with a fresh RSA key, and the app's login in front
 * of it. `token` answers the token endpoint.
 */
class Auth {
  readonly clock = new ManualClock(1_800_000_000);
  readonly backend = new MemoryBackend({ clock: this.clock.now });
  token: () => Response | Promise<Response> = () => new Response(null, { status: 500 });
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
      [TOKEN_URL]: () => this.token()
    });
  }

  /** A fake auth and a login with `options` and the memory backend. */
  static async start(options: { scopes?: string[] } = {}): Promise<Auth> {
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
    auth.login = new Login(client, { backend: auth.backend, ...options });
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
  async tokens(claims?: SignIn, nonce?: string): Promise<object> {
    const now = this.clock.seconds;
    this.#issued += 1;
    const response: Record<string, unknown> = {
      access_token: `at-${String(this.#issued)}`,
      token_type: 'Bearer',
      expires_in: 300,
      scope: 'openid profile',
      refresh_token: `rt-${String(this.#issued)}`
    };
    if (claims !== undefined) {
      const { refresh, ...signed } = claims;
      if (refresh === false) delete response.refresh_token;
      response.id_token = await this.sign('JWT', {
        iss: ISSUER,
        sub: USER,
        aud: CLIENT_ID,
        iat: now,
        exp: now + 300,
        nonce,
        sid: uuid(1),
        auth_time: now,
        acr: 'urn:piquel:acr:social',
        ...signed
      });
    }
    return response;
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

  /** Posts `token` to the back-channel logout route, as auth does. */
  async backchannelLogout(token: string): Promise<Response> {
    const request = new Request(`${APP}/auth/backchannel-logout`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ logout_token: token })
    });
    const response = await this.login.handle(request);
    assert.ok(response);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    return response;
  }
}

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

  /** Sends a request to the login routes, keeping the cookies they set. */
  async send(path: string, init: { method?: string; headers?: Record<string, string> } = {}) {
    const response = await this.#auth.login.handle(this.request(path, init));
    assert.ok(response, `${path} is not a login route`);
    for (const cookie of response.headers.getSetCookie()) {
      const [pair = ''] = cookie.split(';');
      const [name = '', value = ''] = pair.split('=');
      if (value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return response;
  }

  /** The session of a request for `path`. */
  session(path = '/') {
    return this.#auth.login.session(this.request(path));
  }

  /**
   * Starts a login at `start`, then completes it with an ID token of `claims`,
   * returning the callback's answer.
   */
  async signIn(claims: SignIn = {}, start = '/auth/login') {
    const started = await this.send(start);
    assert.equal(started.status, 303);
    const pushed = this.#auth.fetch.sent(PAR_URL);
    assert.ok(pushed);
    const tokens = await this.#auth.tokens(claims, pushed.form.nonce);
    this.#auth.token = () => Response.json(tokens);
    const state = pushed.form.state ?? '';
    return this.send(
      `/auth/callback?${new URLSearchParams({ code: 'code', state, iss: ISSUER }).toString()}`
    );
  }
}

test('a sign-in sets host-only cookies, under a fresh session key each time', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  const started = await browser.send('/auth/login');
  const [login] = started.headers.getSetCookie();
  assert.match(
    login ?? '',
    new RegExp(`^__Host-piquel-login=[\\w-]{43}; ${ATTRIBUTES}; Max-Age=600$`)
  );
  assert.equal(started.headers.get('cache-control'), 'no-store');

  const done = await browser.signIn();
  assert.equal(done.status, 303);
  assert.equal(done.headers.get('location'), '/');
  const cookies = done.headers.getSetCookie();
  assert.match(
    cookies[0] ?? '',
    new RegExp(`^__Host-piquel-session=[\\w-]{43}; ${ATTRIBUTES}; Max-Age=43200$`)
  );
  assert.ok(cookies.includes(`__Host-piquel-login=; ${ATTRIBUTES}; Max-Age=0`));
  const first = browser.cookies.get('__Host-piquel-session');
  assert.equal((await browser.session())?.claims.sub, USER);

  // Signing in again replaces the session: the first key is worthless after.
  const old = browser.request('/');
  await browser.signIn();
  assert.notEqual(browser.cookies.get('__Host-piquel-session'), first);
  assert.equal(await auth.login.session(old), null);
  assert.equal((await browser.session())?.claims.sub, USER);
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

test('logout accepts only requests from the app’s own pages', async () => {
  const auth = await Auth.start();
  const refused = [
    { 'sec-fetch-site': 'cross-site', origin: APP },
    { 'sec-fetch-site': 'same-site' },
    { origin: 'https://evil.example' },
    { origin: 'null' },
    {}
  ];
  const browser = new Browser(auth);
  await browser.signIn();
  for (const headers of refused) {
    const response = await browser.send('/auth/logout', { method: 'POST', headers });
    assert.equal(response.status, 403, JSON.stringify(headers));
  }
  assert.ok(await browser.session());
  assert.equal((await browser.send('/auth/logout')).status, 405);

  // A form on a page sending no referrer posts `Origin: null` from the same origin.
  const idToken = (await browser.session())?.idToken.token ?? '';
  const out = await browser.send('/auth/logout', {
    method: 'POST',
    headers: { 'sec-fetch-site': 'same-origin', origin: 'null' }
  });
  assert.equal(out.status, 303);
  const location = new URL(out.headers.get('location') ?? '');
  assert.equal(`${location.origin}${location.pathname}`, `${ISSUER}/oidc/logout`);
  assert.equal(location.searchParams.get('id_token_hint'), idToken);
  assert.ok(
    out.headers.getSetCookie().includes(`__Host-piquel-session=; ${ATTRIBUTES}; Max-Age=0`)
  );
  assert.equal(browser.cookies.has('__Host-piquel-session'), false);

  // Without Sec-Fetch-Site, the Origin must be the app's.
  await browser.signIn();
  const key = browser.cookies.get('__Host-piquel-session');
  const viaOrigin = await browser.send('/auth/logout', {
    method: 'POST',
    headers: { origin: APP }
  });
  assert.equal(viaOrigin.status, 303);
  browser.cookies.set('__Host-piquel-session', key ?? '');
  assert.equal(await browser.session(), null);
});

test('concurrent requests with an expired access token refresh it once', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  auth.clock.seconds += 600;
  const refreshed = await auth.tokens();
  auth.token = async () => {
    await new Promise((resolve) => setTimeout(resolve, 100));
    return Response.json(refreshed);
  };
  const users = await Promise.all(Array.from({ length: 5 }, () => browser.session()));
  assert.equal(auth.fetch.count(TOKEN_URL), 2); // The code exchange, then one refresh.
  assert.deepEqual(
    await Promise.all(users.map(async (user) => user?.accessToken())),
    Array.from({ length: 5 }, () => 'at-2')
  );
  assert.equal(auth.fetch.sent(TOKEN_URL)?.form.refresh_token, 'rt-1');
});

test('a logout during a refresh leaves the session deleted', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  auth.clock.seconds += 600;
  const refreshed = await auth.tokens();
  let answer: (response: Response) => void = () => undefined;
  let requested: () => void = () => undefined;
  const reached = new Promise<void>((resolve) => (requested = resolve));
  auth.token = () => {
    requested();
    return new Promise((resolve) => (answer = resolve));
  };
  const session = browser.session();
  await reached;
  const logout = browser.request('/auth/logout', {
    method: 'POST',
    headers: { 'sec-fetch-site': 'same-origin' }
  });
  assert.equal((await auth.login.handle(logout))?.status, 303);
  answer(Response.json(refreshed));
  assert.equal(await session, null);
  assert.equal(await browser.session(), null);
});

/** A request whose connection could not be opened, as Node's fetch fails. */
const unreachable = () =>
  Promise.reject(
    new TypeError('fetch failed', {
      cause: Object.assign(new Error('connect'), { code: 'ECONNREFUSED' })
    })
  );

test('a refresh ends the session only when its token may be spent', async () => {
  const outcome = async (answer: () => Response | Promise<Response>) => {
    const auth = await Auth.start();
    const browser = new Browser(auth);
    await browser.signIn();
    auth.clock.seconds += 600;
    auth.token = answer;
    await browser.session();
    auth.token = async () => Response.json(await auth.tokens());
    return (await (await browser.session())?.accessToken()) ?? 'ended';
  };
  const refused = (error: string) => () => Response.json({ error }, { status: 400 });
  assert.equal(await outcome(refused('invalid_grant')), 'ended');
  assert.equal(await outcome(() => new Response('<h1>Bad gateway</h1>', { status: 502 })), 'ended');
  assert.equal(await outcome(refused('temporarily_unavailable')), 'at-2');
  assert.equal(await outcome(unreachable), 'at-2');
});

test('a refresh auth answered ends the session when its ID token cannot be checked', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn();
  auth.clock.seconds += 600;
  // Auth rotates the refresh token, but the keys its new ID token names cannot be fetched.
  auth.kid = 'rotated';
  auth.fetch.routes[JWKS_URI] = unreachable;
  auth.token = async () => Response.json(await auth.tokens({}));
  assert.equal(await browser.session(), null);
});

test('back-channel logout ends the sessions of a sid or of a user, once', async () => {
  const auth = await Auth.start();
  const [first, second, other] = [new Browser(auth), new Browser(auth), new Browser(auth)];
  await first.signIn({ sid: uuid(1) });
  await second.signIn({ sid: uuid(2) });
  await other.signIn({ sid: uuid(3), sub: OTHER_USER });

  assert.equal(
    (await auth.backchannelLogout(await auth.logoutToken({ sid: uuid(1) }))).status,
    200
  );
  assert.equal(await first.session(), null);
  assert.ok(await second.session());
  // The ended auth session takes no new sign-in.
  assert.equal((await first.signIn({ sid: uuid(1) })).status, 400);
  assert.equal(await first.session(), null);

  const byUser = await auth.logoutToken({ sub: USER }, uuid(101));
  assert.equal((await auth.backchannelLogout(byUser)).status, 200);
  assert.equal(await second.session(), null);
  assert.ok(await other.session());
  // A replay changes nothing, not even sessions started since.
  await second.signIn({ sid: uuid(4) });
  assert.equal((await auth.backchannelLogout(byUser)).status, 200);
  assert.ok(await second.session());

  const invalid = await auth.backchannelLogout('not.a.token');
  assert.equal(invalid.status, 400);
  assert.deepEqual(await invalid.json(), { error: 'invalid_request' });
  // An ID token is no logout token.
  const idToken = (await other.session())?.idToken.token ?? '';
  assert.equal((await auth.backchannelLogout(idToken)).status, 400);
  // A body far longer than any logout token is refused, even around a valid one.
  const padded = new Request(`${APP}/auth/backchannel-logout`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      logout_token: await auth.logoutToken({ sub: USER }, uuid(102)),
      padding: 'a'.repeat(64 * 1024)
    })
  });
  assert.equal((await auth.login.handle(padded))?.status, 400);
});

test('a step-up returns to the page, retries once, then answers 403', async () => {
  const auth = await Auth.start();
  const browser = new Browser(auth);
  await browser.signIn({ auth_time: auth.clock.seconds - 3600 });
  const requirement = { acr_values: 'phr', max_age: 60 } as const;
  // A page whose API keeps refusing, as one that still asks for a step-up.
  const page = async () => {
    const user = await auth.login.session(browser.request('/settings?tab=1'));
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
  assert.match(
    done.headers.getSetCookie()[2] ?? '',
    new RegExp(`^__Host-piquel-step-up=[\\w-]{43}; ${ATTRIBUTES}; Max-Age=60$`)
  );
  const user = await browser.session('/settings?tab=1');
  assert.equal(user?.require(requirement), null);
  // The return was the retry: asking again is refused, not redirected.
  assert.equal(user.stepUp(requirement).status, 403);
  // The marker is spent, so a later visit is a new action.
  assert.equal((await page()).status, 303);
  // Other methods cannot follow a redirect.
  const posted = await auth.login.session(browser.request('/settings', { method: 'POST' }));
  assert.equal(posted?.stepUp(requirement).status, 401);
});

test('the memory backend keeps the backend contract, which a read-then-write one breaks', async () => {
  await checkBackend(new MemoryBackend());
  const memory = new MemoryBackend();
  const racy: SessionBackend = {
    load: (key) => memory.load(key),
    async insert(key, record) {
      if ((await memory.load(key)) !== null) return false;
      await new Promise((resolve) => setTimeout(resolve, 1));
      await memory.remove(key);
      return memory.insert(key, record);
    },
    replace: (key, expected, record) => memory.replace(key, expected, record),
    remove: (key) => memory.remove(key)
  };
  await assert.rejects(checkBackend(racy), /exactly one must store/);
});
