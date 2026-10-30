import { expect, test, type APIRequestContext } from '@playwright/test';
import { Issuer, type Fetch } from '../../packages/auth/src/index.ts';
import { addPasskeys, authUrl, serveClient, signUp } from './helpers';

/**
 * The `browser-e2e-sdk` client's origin: a trusted public client registered with
 * `--require-par`, so it can only sign in through pushed requests. No server runs
 * it: the test serves its callback page, and plays its server from Node.
 */
const client = 'https://sdk-e2e.test';

/** Statuses whose responses have no body, which `Response` refuses one for. */
const NULL_BODY = [101, 204, 205, 304];

/**
 * `fetch` through Playwright's request context, which accepts the suite's test
 * certificates as the browser does. Redirects are not followed, as the SDK asks.
 */
function fetchThrough(request: APIRequestContext): Fetch {
  return async (url, init) => {
    const response = await request.fetch(url, {
      method: init.method ?? 'GET',
      headers: Object.fromEntries(new Headers(init.headers)),
      data: typeof init.body === 'string' ? init.body : undefined,
      maxRedirects: 0
    });
    const body = NULL_BODY.includes(response.status())
      ? null
      : new Uint8Array(await response.body());
    return new Response(body, { status: response.status(), headers: response.headers() });
  };
}

/** Runs against the real Rust binary and an isolated PostgreSQL database. */
test('the TypeScript SDK signs in through a pushed request, then steps up', async ({
  page,
  context,
  request
}) => {
  const username = `sdk-${Date.now().toString(36)}`;
  const { cdp } = await addPasskeys(context, page);
  await serveClient(context, cdp, client);
  await signUp(page, username);
  const atCallback = (url: URL) => url.origin === client && url.pathname === '/callback';

  const issuer = await Issuer.discover(authUrl, { fetch: fetchThrough(request) });
  const login = issuer.client({ clientId: 'browser-e2e-sdk', redirectUri: `${client}/callback` });
  const { url, pending } = await login.authorize({ scopes: ['profile'] });
  // Only the pushed request's handle crosses the browser.
  expect([...new URL(url).searchParams.keys()]).toEqual(['client_id', 'request_uri']);
  await page.goto(url);
  await page.waitForURL(atCallback);
  const tokens = await login.complete(pending, new URL(page.url()).searchParams);
  const claims = tokens.idToken?.claims;
  expect(claims?.preferred_username).toBe(username);
  expect(await login.userinfo(tokens.accessToken)).toMatchObject({
    sub: claims?.sub,
    preferred_username: username
  });

  // A step-up asks for a fresh passkey: the ID token must meet it, or `complete`
  // fails. Auth counts whole seconds, so let one pass first.
  await page.waitForTimeout(1_100);
  const stepUp = await login.authorize({ stepUp: { acr_values: 'phr', max_age: 0 } });
  await page.goto(stepUp.url);
  await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await page.waitForURL(atCallback);
  const stepped = await login.complete(stepUp.pending, new URL(page.url()).searchParams);
  expect(stepped.idToken?.claims).toMatchObject({ sub: claims?.sub, sid: claims?.sid, acr: 'phr' });
  expect(stepped.idToken?.claims.auth_time).toBeGreaterThan(Number(claims?.auth_time));
});
