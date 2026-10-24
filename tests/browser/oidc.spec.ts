import { createHash, randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';

// Response shapes this test reads; anything else stays unknown.
type Tokens = { id_token: string; access_token: string };
type Jwks = { keys: (JsonWebKey & { kid: string })[] };
type Json = Record<string, unknown>;
type Session = { user: { id: string } };

/**
 * The `browser-e2e` public client's origin. No server runs it: the test serves its
 * pages itself, so its fetches to auth are genuinely cross-origin.
 */
const client = 'https://browser-e2e.test';

/** Runs against the real Rust binary and an isolated PostgreSQL database. */
test('browser OIDC consent, SSO and step-up for a public client', async ({ page, context }) => {
  const authUrl = process.env.E2E_AUTH_URL ?? 'http://localhost:3000';
  const username = `browser-${Date.now().toString(36)}`;
  // A page the test serves has no address, so Chromium counts it as public, and asks
  // before it fetches auth on a local address, as in CI and on previews.
  await context.grantPermissions(['local-network-access'], { origin: client });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      defaultBackupEligibility: true,
      defaultBackupState: true
    }
  });
  // Serves the client's pages through DevTools, which also sees the redirects that
  // reach them; Playwright's routes would not, and would answer CORS preflights to
  // auth themselves.
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: `${client}/*` }] });
  cdp.on('Fetch.requestPaused', ({ requestId }) => {
    void cdp.send('Fetch.fulfillRequest', {
      requestId,
      responseCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'text/html' }],
      body: Buffer.from('<!doctype html><title>Browser E2E</title>').toString('base64')
    });
  });

  const invitation = process.env.E2E_INVITATION;
  await page.goto(`/register${invitation ? `?invitation=${encodeURIComponent(invitation)}` : ''}`);
  await page.getByLabel('Handle', { exact: true }).fill(username);
  await page.getByLabel('Passkey name', { exact: true }).fill('Synced passkey');
  await page.getByRole('button', { name: 'Create account with a passkey' }).click();
  await expect(page).toHaveURL('/settings');
  const session = (await (
    await page.request.get(new URL('/session', authUrl).href)
  ).json()) as Session;

  const redirectUri = `${client}/callback`;
  const atCallback = (url: URL) => url.origin === client && url.pathname === '/callback';
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(16).toString('base64url');
  const nonce = randomBytes(16).toString('base64url');
  const authorization = new URL('/oauth/authorize', authUrl);
  authorization.search = new URLSearchParams({
    client_id: 'browser-e2e',
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state,
    nonce
  }).toString();
  await page.goto(authorization.href);
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
  expect(callback.searchParams.has('error')).toBe(false);
  const code = callback.searchParams.get('code') ?? '';
  expect(code).toBeTruthy();

  // The client handles its tokens on its own origin, under auth's real CORS policy.
  const exchange = await page.evaluate(
    async ({ origin, redirectUri, code, verifier, nonce, user }) => {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'browser-e2e',
        redirect_uri: redirectUri,
        code,
        code_verifier: verifier
      });
      const response = await fetch(`${origin}/oauth/token`, { method: 'POST', body });
      if (!response.ok) return { status: response.status };
      const tokens = (await response.json()) as Tokens;
      const decode = (value: string) =>
        Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (character) =>
          character.charCodeAt(0)
        );
      const [header, payload, signature] = tokens.id_token.split('.');
      const metadata = JSON.parse(new TextDecoder().decode(decode(header))) as Json;
      const claims = JSON.parse(new TextDecoder().decode(decode(payload))) as Json;
      const jwks = (await fetch(`${origin}/.well-known/jwks.json`).then((result) =>
        result.json()
      )) as Jwks;
      const jwk = jwks.keys.find((key) => key.kid === metadata.kid);
      if (!jwk) throw new Error('The ID token signing key is not published.');
      const key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      );
      const signatureValid =
        metadata.alg === 'RS256' &&
        (await crypto.subtle.verify(
          'RSASSA-PKCS1-v1_5',
          key,
          decode(signature),
          new TextEncoder().encode(`${header}.${payload}`)
        ));
      const userinfoResponse = await fetch(`${origin}/oidc/userinfo`, {
        headers: { authorization: `Bearer ${tokens.access_token}` }
      });
      const userinfo = (await userinfoResponse.json()) as Json;
      const replay = await fetch(`${origin}/oauth/token`, { method: 'POST', body });
      return {
        status: response.status,
        signatureValid,
        correctClaims:
          claims.iss === origin &&
          claims.aud === 'browser-e2e' &&
          claims.nonce === nonce &&
          claims.sub === user,
        sid: claims.sid,
        authTime: claims.auth_time,
        hasRefreshToken: 'refresh_token' in tokens,
        userinfoStatus: userinfoResponse.status,
        sameUser: userinfo.sub === user,
        username: userinfo.preferred_username,
        hasEmail:
          'email' in userinfo ||
          'email_verified' in userinfo ||
          'email' in claims ||
          'email_verified' in claims,
        replayStatus: replay.status
      };
    },
    { origin: authUrl, redirectUri, code, verifier, nonce, user: session.user.id }
  );
  expect(exchange).toEqual({
    status: 200,
    signatureValid: true,
    correctClaims: true,
    sid: expect.any(String),
    authTime: expect.any(Number),
    hasRefreshToken: false,
    userinfoStatus: 200,
    sameUser: true,
    username,
    hasEmail: false,
    replayStatus: 400
  });

  authorization.searchParams.set('prompt', 'none');
  authorization.searchParams.set('state', `${state}-sso`);
  await page.goto(authorization.href);
  await page.waitForURL(atCallback);
  const sso = new URL(page.url());
  expect(sso.searchParams.get('state')).toBe(`${state}-sso`);
  expect(sso.searchParams.get('iss')).toBe(authUrl);
  expect(sso.searchParams.has('error')).toBe(false);
  expect(sso.searchParams.get('code')).toBeTruthy();
  expect(sso.searchParams.get('code')).not.toBe(code);

  // An application stepping up (RFC 9470) asks for a fresh passkey with `acr_values`
  // and `max_age`. Auth re-authenticates the same session: `sid` stays and
  // `auth_time` moves. It counts whole seconds, so let one pass first.
  await page.waitForTimeout(1_100);
  authorization.searchParams.delete('prompt');
  authorization.searchParams.set('state', `${state}-step-up`);
  authorization.searchParams.set('acr_values', 'phr');
  authorization.searchParams.set('max_age', '0');
  await page.goto(authorization.href);
  await expect(page.getByText('This app asks you to sign in with a passkey.')).toBeVisible();
  await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await page.waitForURL(atCallback);
  const stepUp = new URL(page.url());
  expect(stepUp.searchParams.get('state')).toBe(`${state}-step-up`);
  expect(stepUp.searchParams.get('iss')).toBe(authUrl);
  expect(stepUp.searchParams.has('error')).toBe(false);
  // A public client redeems without an origin, so the test runner can.
  const stepUpTokens = await page.request.post(new URL('/oauth/token', authUrl).href, {
    form: {
      grant_type: 'authorization_code',
      client_id: 'browser-e2e',
      redirect_uri: redirectUri,
      code: stepUp.searchParams.get('code') ?? '',
      code_verifier: verifier
    }
  });
  expect(stepUpTokens.status()).toBe(200);
  const { id_token } = (await stepUpTokens.json()) as Tokens;
  const stepped = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64url').toString()) as Json;
  expect(stepped.sid).toBe(exchange.sid);
  expect(stepped.acr).toBe('phr');
  expect(stepped.auth_time).toBeGreaterThan(Number(exchange.authTime));
});
