/** The browser client: callbacks and their cleanup, restoring, passkey sign-in and its fallbacks, and step-up. */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { Issuer } from '../src/index.ts';
import { type BrowserClient, browserClient } from '../src/browser.ts';
import type { Platform } from '../src/platform.ts';
import {
  DISCOVERY_URL,
  DOCUMENT,
  FakeFetch,
  ISSUER,
  JWKS_URI,
  ManualClock,
  REDIRECT_URI,
  TOKEN_URL
} from './vectors.ts';

const APP = new URL(REDIRECT_URI).origin;
const PAGE = `${APP}/notes/42?tab=history`;
const PAR_URL = `${ISSUER}/oauth/par`;
const AUTHORIZE_URL = `${ISSUER}/oauth/authorize`;
const START_URL = `${ISSUER}/webauthn/related/start`;
const FINISH_URL = `${ISSUER}/webauthn/related/finish`;
const RESOURCE = 'https://notes.example/notes';
const USER = '01936f3e-8c00-7000-8000-000000000001';
const NOW = 1_767_225_540;

/** Unpadded base64url of `text` or bytes. */
const base64url = (value: string | Uint8Array) => Buffer.from(value).toString('base64url');

/** How a fake route answers: JSON with a status. */
const answer =
  (body: unknown, status = 200) =>
  () =>
    Response.json(body, { status });
const refusal = (code?: string) =>
  answer({ error: 'Sign in on Piquel', ...(code === undefined ? {} : { code }) }, 400);

/** The text body of a request, as the SDK sends every one. */
const text = (init: RequestInit) => (typeof init.body === 'string' ? init.body : '');
const jsonBody = (init: RequestInit): unknown => JSON.parse(text(init));
const form = (init: RequestInit) => Object.fromEntries(new URLSearchParams(text(init)));

/**
 * Auth, faked: it pushes requests, answers them with codes, and redeems codes for
 * ID tokens it signs with a key of its own, echoing each request's `nonce`.
 */
class FakeAuth {
  readonly clock = new ManualClock(NOW);
  /** Every pushed request's form, by `request_uri`. */
  readonly pushed = new Map<string, Record<string, string>>();
  readonly fetch: FakeFetch;
  readonly #codes = new Map<string, Record<string, string>>();
  readonly #key: CryptoKeyPair;
  readonly #jwk: JsonWebKey;

  private constructor(key: CryptoKeyPair, jwk: JsonWebKey) {
    this.#key = key;
    this.#jwk = jwk;
    this.fetch = new FakeFetch({
      [DISCOVERY_URL]: answer(DOCUMENT),
      [JWKS_URI]: answer({ keys: [{ ...this.#jwk, kid: 'k1', use: 'sig', alg: 'RS256' }] }),
      [PAR_URL]: (init) => {
        const requestUri = `urn:ietf:params:oauth:request_uri:${String(this.pushed.size + 1)}`;
        this.pushed.set(requestUri, form(init));
        return Response.json({ request_uri: requestUri, expires_in: 60 }, { status: 201 });
      },
      [TOKEN_URL]: () => new Response(null, { status: 500 }),
      [START_URL]: answer({
        ceremony_id: 'ceremony',
        public_key: {
          publicKey: {
            challenge: base64url('challenge'),
            rpId: 'auth.example.com',
            allowCredentials: [{ type: 'public-key', id: base64url('passkey') }]
          }
        }
      }),
      [FINISH_URL]: () => Response.json(this.authorization(this.lastRequestUri))
    });
  }

  static async start(): Promise<FakeAuth> {
    const key = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['sign', 'verify']
    );
    const auth = new FakeAuth(key, await crypto.subtle.exportKey('jwk', key.publicKey));
    auth.fetch.routes[TOKEN_URL] = (init) => auth.#token(form(init));
    return auth;
  }

  /** The `request_uri` of the latest push. */
  get lastRequestUri(): string {
    return [...this.pushed.keys()].at(-1) ?? '';
  }

  /** An issuer discovered through this fake. */
  issuer(): Promise<Issuer> {
    return Issuer.discover(ISSUER, { fetch: this.fetch.fetch, clock: this.clock.now });
  }

  /** The authorization response to the pushed request `requestUri`, with a fresh code. */
  authorization(requestUri: string): Record<string, string> {
    const request = this.pushed.get(requestUri);
    assert.ok(request, `no pushed request ${requestUri}`);
    const code = `pac_v1_${String(this.#codes.size + 1)}`;
    this.#codes.set(code, request);
    return { code, state: request.state ?? '', iss: ISSUER };
  }

  /** Redeems a code, or a refresh token, signing an ID token for its request. */
  async #token(parameters: Record<string, string>): Promise<Response> {
    const request = this.#codes.get(parameters.code ?? '') ?? {};
    const now = this.clock.seconds;
    const claims = {
      iss: ISSUER,
      sub: USER,
      aud: 'notes-web',
      iat: now,
      exp: now + 300,
      auth_time: now,
      acr: 'phr',
      sid: '01936f3e-8c00-7000-8000-000000000002',
      preferred_username: 'ada',
      ...(request.nonce === undefined ? {} : { nonce: request.nonce })
    };
    const encode = (value: object) => base64url(JSON.stringify(value));
    const input = `${encode({ alg: 'RS256', typ: 'JWT', kid: 'k1' })}.${encode(claims)}`;
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      this.#key.privateKey,
      new TextEncoder().encode(input)
    );
    return Response.json({
      access_token: `at_${String(now)}`,
      token_type: 'Bearer',
      expires_in: 300,
      scope: request.scope ?? 'openid offline_access',
      id_token: `${input}.${base64url(new Uint8Array(signature))}`,
      refresh_token: `prt_${String(now)}`
    });
  }
}

/** A page: its address, history, `sessionStorage`, passkeys and resource server, faked. */
class FakePage {
  /** Where the page navigated, in order. */
  readonly navigations: string[] = [];
  /** Every value ever written to storage. */
  readonly written: string[] = [];
  readonly storage = new Map<string, string>();
  capabilities: PublicKeyCredentialClientCapabilities = { relatedOrigins: true };
  /** What the passkey prompt resolves to, or throws. */
  prompt: () => Promise<unknown> = () => Promise.resolve(FakePage.credential());
  /** The options the passkey prompt got. */
  readonly prompts: CredentialRequestOptions[] = [];
  /** How the resource server answers. */
  resource: (request: Request) => Response = () => new Response('notes');
  readonly requests: Request[] = [];

  /** Waiting for the next navigation. */
  #waiting: (() => void)[] = [];

  readonly location = {
    href: PAGE,
    assign: (url: string | URL) => {
      this.navigations.push(String(url));
      for (const resolve of this.#waiting.splice(0)) resolve();
    }
  };

  /** Resolves once the page has navigated more than `count` times. */
  left(count: number): Promise<void> {
    if (this.navigations.length > count) return Promise.resolve();
    return new Promise((resolve) => this.#waiting.push(resolve));
  }

  readonly platform: Platform = {
    location: this.location,
    history: {
      replaceState: (_data, _unused, url) => {
        this.location.href = new URL(String(url), this.location.href).href;
      }
    },
    storage: {
      getItem: (key) => this.storage.get(key) ?? null,
      setItem: (key, value) => {
        this.written.push(value);
        this.storage.set(key, value);
      },
      removeItem: (key) => {
        this.storage.delete(key);
      }
    },
    credentials: {
      get: (options) => {
        if (options !== undefined) this.prompts.push(options);
        return this.prompt() as Promise<Credential | null>;
      }
    },
    capabilities: () => Promise.resolve(this.capabilities),
    fetch: (request) => {
      this.requests.push(request);
      return Promise.resolve(this.resource(request));
    }
  };

  /** An assertion, as the browser returns one. */
  static credential() {
    const bytes = (text: string) => new TextEncoder().encode(text).buffer;
    return {
      type: 'public-key',
      id: base64url('passkey'),
      rawId: bytes('passkey'),
      response: {
        authenticatorData: bytes('authenticator'),
        clientDataJSON: bytes('{}'),
        signature: bytes('signature'),
        userHandle: null
      },
      getClientExtensionResults: () => ({})
    };
  }

  /** The `request_uri` of the latest navigation to auth's authorize endpoint. */
  get redirectedWith(): string | null {
    const url = new URL(this.navigations.at(-1) ?? AUTHORIZE_URL);
    assert.equal(`${url.origin}${url.pathname}`, AUTHORIZE_URL);
    return url.searchParams.get('request_uri');
  }

  /** Lands on the callback with `parameters`. */
  callback(parameters: Record<string, string>) {
    this.location.href = `${REDIRECT_URI}?${new URLSearchParams(parameters).toString()}`;
  }
}

/** A fresh auth, page and browser client. */
async function setUp(): Promise<{ auth: FakeAuth; page: FakePage; client: BrowserClient }> {
  const auth = await FakeAuth.start();
  const page = new FakePage();
  const client = browserClient(await auth.issuer(), {
    clientId: 'notes-web',
    redirectUri: REDIRECT_URI,
    platform: page.platform
  });
  return { auth, page, client };
}

/**
 * Waits for `navigation` to leave the page. It never settles once it has, so it may
 * only fail before.
 */
async function leaving(navigation: Promise<unknown>, page: FakePage): Promise<void> {
  const before = page.navigations.length;
  await Promise.race([
    page.left(before),
    navigation.then(() => assert.fail('the page did not leave')),
    new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error('the page did not leave within 5 seconds'));
      }, 5000).unref();
    })
  ]);
  assert.equal(page.navigations.length, before + 1, 'the page left more than once');
}

describe('a redirect sign-in', () => {
  test('crosses the redirect with only its pending login, and the callback deletes it', async () => {
    const { auth, page, client } = await setUp();
    await leaving(client.login({ scopes: ['profile'] }), page);
    const requestUri = page.redirectedWith;
    assert.ok(requestUri !== null);
    const [stored] = [...page.storage.values()];
    assert.ok(stored !== undefined);
    assert.deepEqual(Object.keys(JSON.parse(stored) as object).sort(), [
      'pending',
      'purpose',
      'returnTo'
    ]);

    page.callback(auth.authorization(requestUri));
    const session = await client.handleCallback();
    assert.ok(session);
    assert.equal(session.claims.sub, USER);
    assert.equal(page.storage.size, 0);
    // Back where the login left from, without the code in the address bar.
    assert.equal(page.location.href, PAGE);
    // No token was ever written to storage.
    const tokens = [await session.accessToken(), session.idToken.token, `prt_${String(NOW)}`];
    assert.ok(page.written.every((value) => tokens.every((token) => !value.includes(token))));
    // The page is no longer a callback.
    assert.equal(await client.handleCallback(), null);
  });

  test('a callback no login of this page waits for fails, and cleans the address bar', async () => {
    const { page, client } = await setUp();
    assert.equal(await client.handleCallback(), null);
    page.callback({ code: 'pac_v1_stolen', state: 'state', iss: ISSUER });
    await assert.rejects(client.handleCallback(), { code: 'callback', reason: 'state_mismatch' });
    assert.equal(page.location.href, REDIRECT_URI);
  });

  test('a refused sign-in throws its OAuth error', async () => {
    const { auth, page, client } = await setUp();
    await leaving(client.login(), page);
    const { state } = auth.authorization(page.redirectedWith ?? '');
    page.callback({ error: 'access_denied', state: state ?? '', iss: ISSUER });
    await assert.rejects(client.handleCallback(), {
      code: 'oauth',
      response: { error: 'access_denied' }
    });
    assert.equal(page.storage.size, 0);
  });
});

describe('restore', () => {
  test('asks with prompt=none, and gives up once auth has no session for it', async () => {
    const { auth, page, client } = await setUp();
    await leaving(client.restore(), page);
    assert.equal(auth.pushed.get(page.redirectedWith ?? '')?.prompt, 'none');
    const { state } = auth.authorization(page.redirectedWith ?? '');
    page.callback({ error: 'login_required', state: state ?? '', iss: ISSUER });
    assert.equal(await client.handleCallback(), null);
    assert.equal(page.location.href, PAGE);
    // The same page load does not try again.
    const navigations = page.navigations.length;
    assert.equal(await client.restore(), null);
    assert.equal(page.navigations.length, navigations);
  });

  test('comes back with a session when auth has one', async () => {
    const { auth, page, client } = await setUp();
    await leaving(client.restore(), page);
    page.callback(auth.authorization(page.redirectedWith ?? ''));
    assert.equal((await client.handleCallback())?.claims.preferred_username, 'ada');
  });
});

describe('passkey sign-in on the page', () => {
  test('signs in without leaving the page or writing to storage', async () => {
    const { auth, page, client } = await setUp();
    const session = await client.signInWithPasskey({ scopes: ['profile'] });
    assert.equal(session.claims.sub, USER);
    assert.deepEqual(page.navigations, []);
    assert.deepEqual(page.written, []);
    const start = auth.fetch.requests.find((request) => request.url === START_URL);
    assert.ok(start);
    assert.equal(start.init.credentials, 'omit');
    assert.deepEqual(Object.fromEntries(new Headers(start.init.headers)), {
      'content-type': 'application/json',
      'x-piquel-csrf': '1'
    });
    assert.deepEqual(jsonBody(start.init), { request_uri: auth.lastRequestUri });
    // The prompt gets bytes, and finish gets them back in base64url.
    const options = page.prompts[0]?.publicKey;
    assert.ok(options);
    assert.deepEqual(options.challenge, new TextEncoder().encode('challenge'));
    assert.equal(options.rpId, 'auth.example.com');
    const finish = auth.fetch.requests.find((request) => request.url === FINISH_URL);
    assert.deepEqual(jsonBody(finish?.init ?? {}), {
      ceremony_id: 'ceremony',
      credential: {
        id: base64url('passkey'),
        rawId: base64url('passkey'),
        type: 'public-key',
        response: {
          authenticatorData: base64url('authenticator'),
          clientDataJSON: base64url('{}'),
          signature: base64url('signature'),
          userHandle: null
        },
        clientExtensionResults: {}
      }
    });
  });

  /** Each way the sign-in falls back to auth's pages, and whether it pushes a fresh request first. */
  const fallbacks: {
    name: string;
    arrange: (auth: FakeAuth, page: FakePage) => void;
    fresh: boolean;
  }[] = [
    {
      name: 'a browser without related origins',
      arrange: (_auth, page) => {
        page.capabilities = {};
      },
      fresh: false
    },
    {
      name: 'start answering interaction_required',
      arrange: (auth) => {
        auth.fetch.routes[START_URL] = refusal('interaction_required');
      },
      fresh: false
    },
    {
      name: 'start failing otherwise',
      arrange: (auth) => {
        auth.fetch.routes[START_URL] = answer({ error: 'Something went wrong' }, 500);
      },
      fresh: true
    },
    {
      name: 'a cancelled passkey prompt',
      arrange: (_auth, page) => {
        page.prompt = () => Promise.reject(new DOMException('cancelled', 'NotAllowedError'));
      },
      fresh: true
    },
    {
      name: 'finish answering interaction_required',
      arrange: (auth) => {
        auth.fetch.routes[FINISH_URL] = refusal('interaction_required');
      },
      fresh: true
    }
  ];
  for (const { name, arrange, fresh } of fallbacks) {
    test(`falls back to the redirect after ${name}`, async () => {
      const { auth, page, client } = await setUp();
      arrange(auth, page);
      await leaving(client.signInWithPasskey(), page);
      const first = [...auth.pushed.keys()][0];
      assert.equal(auth.pushed.size, fresh ? 2 : 1);
      // A claimed request is never used again.
      assert.equal(page.redirectedWith, fresh ? auth.lastRequestUri : first);
      assert.equal(auth.fetch.count(START_URL), name.includes('related origins') ? 0 : 1);
      // The redirect's callback completes as any other.
      page.callback(auth.authorization(page.redirectedWith));
      assert.equal((await client.handleCallback())?.claims.sub, USER);
    });
  }

  test('a finish answering for another login fails its check', async () => {
    const { auth, client } = await setUp();
    auth.fetch.routes[FINISH_URL] = answer({ code: 'pac_v1_x', state: 'forged', iss: ISSUER });
    await assert.rejects(client.signInWithPasskey(), {
      code: 'callback',
      reason: 'state_mismatch'
    });
  });
});

describe('a session', () => {
  /** A signed-in session, through a passkey. */
  async function signedIn() {
    const setup = await setUp();
    return { ...setup, session: await setup.client.signInWithPasskey({ scopes: ['profile'] }) };
  }

  const challenge = new Response(null, {
    status: 401,
    headers: {
      'www-authenticate':
        'Bearer error="insufficient_user_authentication", acr_values="phr", max_age="0"'
    }
  });

  test('sends its access token', async () => {
    const { page, session } = await signedIn();
    assert.equal(await (await session.fetch(RESOURCE)).text(), 'notes');
    assert.equal(page.requests[0]?.headers.get('authorization'), `Bearer at_${String(NOW)}`);
  });

  test('steps up when a resource asks, and the retry after the return fails at most once', async () => {
    const { auth, page, client, session } = await signedIn();
    page.resource = () => challenge.clone();
    await leaving(session.fetch(RESOURCE), page);
    const request = auth.pushed.get(page.redirectedWith ?? '');
    assert.equal(request?.acr_values, 'phr');
    assert.equal(request.max_age, '0');
    assert.equal(request.scope, 'openid profile');

    page.callback(auth.authorization(page.redirectedWith ?? ''));
    const stepped = await client.handleCallback();
    assert.ok(stepped);
    assert.equal(page.location.href, PAGE);
    const navigations = page.navigations.length;
    await assert.rejects(stepped.fetch(RESOURCE), {
      code: 'insufficient_user_authentication'
    });
    assert.equal(page.navigations.length, navigations);
  });

  test('refreshes an expiring access token once for concurrent requests', async () => {
    const { auth, page, session } = await signedIn();
    auth.clock.seconds += 290;
    await Promise.all([session.fetch(RESOURCE), session.fetch(RESOURCE)]);
    assert.equal(auth.fetch.count(TOKEN_URL), 2);
    assert.deepEqual(
      page.requests.map((request) => request.headers.get('authorization')),
      [`Bearer at_${String(NOW + 290)}`, `Bearer at_${String(NOW + 290)}`]
    );
  });

  test('logs out through auth, revoking its refresh token', async () => {
    const { auth, page, session } = await signedIn();
    auth.fetch.routes[`${ISSUER}/oauth/revoke`] = () => new Response(null, { status: 200 });
    await leaving(session.logout(`${APP}/`), page);
    const logout = new URL(page.navigations.at(-1) ?? '');
    assert.equal(`${logout.origin}${logout.pathname}`, `${ISSUER}/oidc/logout`);
    assert.equal(logout.searchParams.get('post_logout_redirect_uri'), `${APP}/`);
    assert.equal(auth.fetch.count(`${ISSUER}/oauth/revoke`), 1);
  });
});
