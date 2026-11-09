/**
 * Signing in through `browser-e2e`, a public, untrusted client whose pages the
 * test serves, so its fetches to auth are cross-origin: consent, posted once on a
 * double click, the `iss` of each authorization response, a PKCE exchange and
 * userinfo, with no email claims for a passkey-only account, and `prompt=none`
 * with remembered consent.
 */
import { expect, test } from '@playwright/test';
import { addPasskeys, authorization, authUrl, serveClient, signUp } from './helpers';

/**
 * The `browser-e2e` public client's origin. No server runs it: the test serves its
 * pages itself, so its fetches to auth are genuinely cross-origin.
 */
const client = 'https://browser-e2e.test';

/** Runs against the real Rust binary and an isolated PostgreSQL database. */
test('browser OIDC consent and SSO for a public client', async ({ page, context }) => {
  const username = `browser-${Date.now().toString(36)}`;
  const { cdp } = await addPasskeys(context, page, true);
  await serveClient(context, cdp, client);
  await signUp(page, username, 'Synced passkey');

  const redirectUri = `${client}/callback`;
  const atCallback = (url: URL) => url.origin === client && url.pathname === '/callback';
  const request = authorization('browser-e2e', redirectUri, 'openid profile email');
  const authorize = new URL(request.url);
  const state = authorize.searchParams.get('state') ?? '';
  await page.goto(authorize.href);
  await expect(page.getByRole('heading', { name: /^Continue to / })).toBeVisible();
  // A second click while the decision is on its way still reaches the application:
  // the page's script keeps the form from posting it again, which would find the
  // request used. The decision waits for the second click, as on a slow network.
  const consent = new URL('/authorize', authUrl).href;
  let decisions = 0;
  const clickedTwice = Promise.withResolvers<undefined>();
  await page.route(consent, async (route) => {
    decisions += 1;
    await clickedTwice.promise;
    await route.continue();
  });
  // Clicked with the mouse: a locator's click would wait for the held decision.
  const decide = await page.getByRole('button', { name: 'Continue', exact: true }).boundingBox();
  if (!decide) throw new Error('the Continue button has no box');
  const [x, y] = [decide.x + decide.width / 2, decide.y + decide.height / 2];
  const sent = page.waitForRequest(consent);
  await page.mouse.click(x, y);
  await sent;
  await page.mouse.click(x, y);
  clickedTwice.resolve(undefined);
  await page.waitForURL(atCallback);
  expect(decisions).toBe(1);
  // No route may stay: Playwright would answer the client's CORS preflights itself.
  await page.unroute(consent);
  const callback = new URL(page.url());
  expect(callback.searchParams.get('state')).toBe(state);
  expect(callback.searchParams.get('iss')).toBe(authUrl);
  const code = callback.searchParams.get('code') ?? '';
  expect(code).toBeTruthy();

  // The client redeems the code and reads userinfo from its own origin, under
  // auth's real CORS policy.
  const exchange = await page.evaluate(
    async ({ origin, redirectUri, code, verifier }) => {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'browser-e2e',
        redirect_uri: redirectUri,
        code,
        code_verifier: verifier
      });
      const response = await fetch(`${origin}/oauth/token`, { method: 'POST', body });
      if (!response.ok) return { status: response.status };
      const tokens = (await response.json()) as { id_token: string; access_token: string };
      const payload = tokens.id_token.split('.')[1];
      const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as Record<
        string,
        unknown
      >;
      const userinfoResponse = await fetch(`${origin}/oidc/userinfo`, {
        headers: { authorization: `Bearer ${tokens.access_token}` }
      });
      const userinfo = (await userinfoResponse.json()) as Record<string, unknown>;
      return {
        status: response.status,
        hasRefreshToken: 'refresh_token' in tokens,
        userinfoStatus: userinfoResponse.status,
        sameUser: userinfo.sub === claims.sub,
        username: userinfo.preferred_username,
        // Passkey-only accounts have no email to release.
        hasEmail:
          'email' in userinfo ||
          'email_verified' in userinfo ||
          'email' in claims ||
          'email_verified' in claims
      };
    },
    { origin: authUrl, redirectUri, code, verifier: request.verifier }
  );
  expect(exchange).toEqual({
    status: 200,
    hasRefreshToken: false,
    userinfoStatus: 200,
    sameUser: true,
    username,
    hasEmail: false
  });

  // The remembered consent answers a `prompt=none` request with a new code.
  authorize.searchParams.set('prompt', 'none');
  authorize.searchParams.set('state', `${state}-sso`);
  await page.goto(authorize.href);
  await page.waitForURL(atCallback);
  const sso = new URL(page.url());
  expect(sso.searchParams.get('state')).toBe(`${state}-sso`);
  expect(sso.searchParams.get('iss')).toBe(authUrl);
  expect(sso.searchParams.get('code')).toBeTruthy();
  expect(sso.searchParams.get('code')).not.toBe(code);
});
