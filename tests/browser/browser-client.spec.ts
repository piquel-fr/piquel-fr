import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect, test, type BrowserContext, type CDPSession, type Page } from '@playwright/test';
import type * as Browser from '../../packages/auth/src/browser.ts';
import type * as Core from '../../packages/auth/src/index.ts';
import { addPasskeys, authUrl, serveClient, signUp } from './helpers';

/**
 * The `browser-e2e-inline` trusted public client, approved for passkey sign-in on its
 * own pages, as in `related-origins.spec.ts`: on auth's own host with auth on
 * `localhost`, as in CI, and on another site elsewhere.
 */
const client =
  new URL(authUrl).hostname === 'localhost' ? 'https://localhost:4443' : 'https://related-e2e.test';
const clientId = 'browser-e2e-inline';

/** The built SDK, which the client's page imports from `/sdk/`: `pnpm --filter @piquel/auth build`. */
const dist = new URL('../../packages/auth/dist/', import.meta.url);
const sdk = Object.fromEntries(
  readdirSync(dist)
    .filter((name) => name.endsWith('.js'))
    .map((name) => [`/sdk/${name}`, fileURLToPath(new URL(name, dist))])
);

const atCallback = (url: URL) => url.origin === client && url.pathname === '/callback';

/** What the page reports of its session: the user, and the tokens it holds in memory. */
type Reported = { username: string | undefined; tokens: string[] } | null;

/**
 * Runs `step` in the client's page with the built SDK. `login`, `restore` without a
 * callback, and `passkey-fallback` leave the page, so they report nothing.
 */
function inPage(
  page: Page,
  step: 'login' | 'callback' | 'restore' | 'passkey' | 'passkey-fallback',
  request: Browser.SignInRequest = {}
): Promise<Reported> {
  return page.evaluate(
    async ({ authUrl, clientId, step, request }) => {
      // Named through a variable, so TypeScript does not resolve the page's paths.
      const load = (path: string): Promise<unknown> => import(path);
      const { Issuer } = (await load('/sdk/index.js')) as typeof Core;
      const { browserClient } = (await load('/sdk/browser.js')) as typeof Browser;
      const auth = browserClient(await Issuer.discover(authUrl), {
        clientId,
        redirectUri: `${location.origin}/callback`
      });
      const report = async (session: Browser.Session | null) =>
        session && {
          username: session.claims.preferred_username,
          tokens: [await session.accessToken(), session.idToken.token]
        };
      switch (step) {
        case 'login':
          void auth.login(request);
          return null;
        case 'callback':
          return report(await auth.handleCallback());
        case 'restore': {
          const session = await auth.handleCallback();
          if (session === null) void auth.restore(request);
          return report(session);
        }
        case 'passkey':
          return report(await auth.signInWithPasskey(request));
        case 'passkey-fallback':
          void auth.signInWithPasskey(request);
          return null;
      }
    },
    { authUrl, clientId, step, request }
  );
}

/**
 * The pushes the page sent, with their prompts, and the `request_uri`s it posted to
 * start and sent the browser to auth with.
 */
class Requests {
  readonly prompts: (string | null)[] = [];
  readonly started: string[] = [];
  readonly authorized: string[] = [];

  constructor(page: Page) {
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.origin !== authUrl) return;
      if (url.pathname === '/oauth/par') {
        this.prompts.push(new URLSearchParams(request.postData() ?? '').get('prompt'));
      } else if (url.pathname === '/webauthn/related/start') {
        this.started.push((request.postDataJSON() as { request_uri: string }).request_uri);
      } else if (url.pathname === '/oauth/authorize' && request.isNavigationRequest()) {
        this.authorized.push(url.searchParams.get('request_uri') ?? '');
      }
    });
  }
}

/** A page of the client, served with the built SDK, and an account signed up at auth. */
async function setUp(
  page: Page,
  context: BrowserContext,
  name: string
): Promise<{ cdp: CDPSession; authenticatorId: string; handle: string }> {
  const passkeys = await addPasskeys(context, page);
  await serveClient(context, passkeys.cdp, client, sdk);
  const handle = `${name}-${Date.now().toString(36)}`;
  await signUp(page, handle, 'Browser client');
  return { ...passkeys, handle };
}

/**
 * Nothing the page stores holds `tokens`, and it set no cookie. The SDK runs in the
 * page, so it could only write cookies `document.cookie` shows; the browser's own
 * cookie jar would also show auth's, which share the client's host in CI.
 */
async function expectNoStoredTokens(page: Page, tokens: string[]) {
  const stored = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
    cookie: document.cookie
  }));
  expect(stored).toEqual({ local: [], session: [], cookie: '' });
  const everything = JSON.stringify(stored);
  for (const token of tokens) expect(everything).not.toContain(token);
}

test('the browser client signs in with a redirect, and restores with prompt=none after a reload', async ({
  page,
  context
}) => {
  const { handle } = await setUp(page, context, 'browser');
  const requests = new Requests(page);
  await page.goto(`${client}/notes`);
  await inPage(page, 'login', { scopes: ['profile'] });
  await page.waitForURL(atCallback);
  const signedIn = await inPage(page, 'callback');
  expect(signedIn?.username).toBe(handle);
  // Back where the login left from, without the code.
  expect(page.url()).toBe(`${client}/notes`);
  await expectNoStoredTokens(page, signedIn?.tokens ?? []);

  // Tokens live in memory only: after a reload, auth's session signs in again silently.
  await page.reload();
  await inPage(page, 'restore', { scopes: ['profile'] });
  await page.waitForURL(atCallback);
  const restored = await inPage(page, 'restore');
  expect(restored?.username).toBe(handle);
  expect(page.url()).toBe(`${client}/notes`);
  expect(requests.prompts).toEqual([null, 'none']);
  await expectNoStoredTokens(page, restored?.tokens ?? []);
});

test('the browser client signs in with a passkey without leaving the page', async ({
  page,
  context
}) => {
  const { handle } = await setUp(page, context, 'browser-passkey');
  // From here on, auth sets no cookie: the page signs in by itself.
  await context.clearCookies();
  await page.goto(`${client}/notes`);
  const navigations: string[] = [];
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.push(frame.url());
  });
  const signedIn = await inPage(page, 'passkey', { scopes: ['profile'] });
  expect(signedIn?.username).toBe(handle);
  expect(navigations).toEqual([]);
  await expectNoStoredTokens(page, signedIn?.tokens ?? []);
  expect(
    (await context.cookies(authUrl)).filter((cookie) => cookie.name === '__Host-piquel_session')
  ).toEqual([]);
});

test('the passkey sign-in falls back to auth, never reusing a claimed request', async ({
  page,
  context
}) => {
  const { handle, cdp, authenticatorId } = await setUp(page, context, 'browser-fallback');

  // prompt=consent needs auth's pages: start refuses it unclaimed, so the browser
  // goes to auth with the same request.
  let requests = new Requests(page);
  await page.goto(`${client}/notes`);
  await inPage(page, 'passkey-fallback', { scopes: ['profile'], prompt: 'consent' });
  await expect(page.getByRole('heading', { name: /^Continue to / })).toBeVisible();
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await page.waitForURL(atCallback);
  expect((await inPage(page, 'callback'))?.username).toBe(handle);
  expect(requests.prompts).toEqual(['consent']);
  expect(requests.authorized).toEqual(requests.started);

  // A failed passkey prompt: start claimed the request, so a fresh one goes to auth.
  await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
  requests = new Requests(page);
  await page.goto(`${client}/notes`);
  await inPage(page, 'passkey-fallback', { scopes: ['profile'] });
  await page.waitForURL(atCallback);
  expect((await inPage(page, 'callback'))?.username).toBe(handle);
  expect(requests.prompts).toHaveLength(2);
  expect(requests.started).toHaveLength(1);
  expect(requests.authorized).toHaveLength(1);
  expect(requests.authorized).not.toEqual(requests.started);
  await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: true });

  // A browser without related origins goes to auth with its only push, never starting.
  await page.addInitScript(() => {
    PublicKeyCredential.getClientCapabilities = () => Promise.resolve({});
  });
  requests = new Requests(page);
  await page.goto(`${client}/notes`);
  await inPage(page, 'passkey-fallback', { scopes: ['profile'] });
  await page.waitForURL(atCallback);
  expect((await inPage(page, 'callback'))?.username).toBe(handle);
  expect(requests.prompts).toHaveLength(1);
  expect(requests.started).toEqual([]);
  expect(requests.authorized).toHaveLength(1);
});
