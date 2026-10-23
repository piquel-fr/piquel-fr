import { expect, test } from '@playwright/test';
import { addAuthenticator, deployment, pkce, signUp } from './helpers';

// Response shapes this test reads; anything else stays unknown.
type Tokens = { id_token: string; access_token: string };
type Jwks = { keys: (JsonWebKey & { kid: string })[] };
type Json = Record<string, unknown>;
type Session = { user: { id: string } };
type Passkeys = { id: string; friendly_name: string }[];

/** Runs against the real Rust binary and an isolated PostgreSQL database. */
test('passkey lifecycle, passkey confirmation and browser OIDC consent with SSO', async ({
  page,
  context
}) => {
  const { authUrl, settingsUrl } = deployment();
  const { cdp, authenticatorId } = await addAuthenticator(context, page);
  try {
    const username = await signUp(page);

    const redirectUri = new URL('/callback', settingsUrl).href;
    const atCallback = (url: URL) =>
      url.origin === new URL(redirectUri).origin && url.pathname === '/callback';
    const oidc = pkce();
    const authorization = new URL('/oauth/authorize', authUrl);
    authorization.search = new URLSearchParams({
      client_id: 'browser-e2e',
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid profile email',
      code_challenge: oidc.challenge,
      code_challenge_method: 'S256',
      state: oidc.state,
      nonce: oidc.nonce
    }).toString();
    await page.goto(authorization.href);
    await expect(page.getByRole('heading', { name: /^Continue to / })).toBeVisible();
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await page.waitForURL(atCallback);
    const callback = new URL(page.url());
    expect(callback.searchParams.get('state')).toBe(oidc.state);
    expect(callback.searchParams.get('iss')).toBe(authUrl);
    expect(callback.searchParams.has('error')).toBe(false);
    const code = callback.searchParams.get('code') ?? '';
    expect(code).toBeTruthy();
    // Execute token handling on the genuine client origin, under its real CSP and CORS policy.
    await page.goto(settingsUrl);
    const exchange = await page.evaluate(
      async ({ origin, redirectUri, code, verifier, nonce }) => {
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
        const session = (await fetch(`${origin}/session`, { credentials: 'include' }).then(
          (result) => result.json()
        )) as Session;
        const replay = await fetch(`${origin}/oauth/token`, { method: 'POST', body });
        return {
          status: response.status,
          signatureValid,
          correctClaims:
            claims.iss === origin &&
            claims.aud === 'browser-e2e' &&
            claims.nonce === nonce &&
            claims.sub === session.user.id,
          sid: claims.sid,
          authTime: claims.auth_time,
          hasRefreshToken: 'refresh_token' in tokens,
          userinfoStatus: userinfoResponse.status,
          sameUser: userinfo.sub === session.user.id,
          username: userinfo.preferred_username,
          hasEmail:
            'email' in userinfo ||
            'email_verified' in userinfo ||
            'email' in claims ||
            'email_verified' in claims,
          replayStatus: replay.status
        };
      },
      { origin: authUrl, redirectUri, code, verifier: oidc.verifier, nonce: oidc.nonce }
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
    authorization.searchParams.set('state', `${oidc.state}-sso`);
    await page.goto(authorization.href);
    await page.waitForURL(atCallback);
    const sso = new URL(page.url());
    expect(sso.searchParams.get('state')).toBe(`${oidc.state}-sso`);
    expect(sso.searchParams.get('iss')).toBe(authUrl);
    expect(sso.searchParams.has('error')).toBe(false);
    expect(sso.searchParams.get('code')).toBeTruthy();
    expect(sso.searchParams.get('code')).not.toBe(code);

    // An application stepping up (RFC 9470) asks for a fresh passkey with `acr_values`
    // and `max_age`. Auth re-authenticates the same session: `sid` stays and
    // `auth_time` moves. It counts whole seconds, so let one pass first.
    await page.waitForTimeout(1_100);
    authorization.searchParams.delete('prompt');
    authorization.searchParams.set('state', `${oidc.state}-step-up`);
    authorization.searchParams.set('acr_values', 'phr');
    authorization.searchParams.set('max_age', '0');
    await page.goto(authorization.href);
    await expect(page.getByText('This app asks you to sign in with a passkey.')).toBeVisible();
    await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
    await page.waitForURL(atCallback);
    const stepUp = new URL(page.url());
    expect(stepUp.searchParams.get('state')).toBe(`${oidc.state}-step-up`);
    // A public client redeems without an origin, so the test runner can.
    const stepUpTokens = await page.request.post(new URL('/oauth/token', authUrl).href, {
      form: {
        grant_type: 'authorization_code',
        client_id: 'browser-e2e',
        redirect_uri: redirectUri,
        code: stepUp.searchParams.get('code') ?? '',
        code_verifier: oidc.verifier
      }
    });
    expect(stepUpTokens.status()).toBe(200);
    const { id_token } = (await stepUpTokens.json()) as Tokens;
    const stepped = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64url').toString()) as Json;
    expect(stepped.sid).toBe(exchange.sid);
    expect(stepped.acr).toBe('phr');
    expect(stepped.auth_time).toBeGreaterThan(Number(exchange.authTime));
    // Settings have no unlock step, and renaming needs no passkey confirmation.
    await page.goto(settingsUrl);
    await page.getByRole('button', { name: 'Rename Synced passkey' }).click();
    await page.getByLabel('Passkey name', { exact: true }).fill('My synced passkey');
    await page.getByRole('button', { name: 'Save name' }).click();
    await expect(page.getByText('My synced passkey', { exact: true })).toBeVisible();

    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
    const second = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'usb',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true
      }
    });
    // The step-up above confirmed this session, so enrollment asks for no other passkey:
    // the first authenticator no longer answers, and the second has no credential to
    // confirm with.
    await page.getByRole('link', { name: 'Add a passkey', exact: true }).click();
    await page.getByLabel('Passkey name', { exact: true }).fill('Second passkey');
    await page.getByRole('button', { name: 'Add passkey', exact: true }).click();
    await expect(page).toHaveURL(settingsUrl);
    await expect(page.getByText('Second passkey', { exact: true })).toBeVisible();

    // The confirmation is still fresh, so removal would complete in place. Leave the way
    // the SDK does when it is stale, through auth's /confirm page, and check that the
    // removal resumes on return.
    const secondId = await page.evaluate(async (origin) => {
      const options = { credentials: 'include' as const };
      const list = (await fetch(`${origin}/account/passkeys`, options).then((response) =>
        response.json()
      )) as Passkeys;
      const session = (await fetch(`${origin}/session`, options).then((response) =>
        response.json()
      )) as Session;
      const id = list.find((key) => key.friendly_name === 'Second passkey')?.id ?? '';
      sessionStorage.setItem(
        'piquel.step_up',
        JSON.stringify({
          key: 'remove',
          argument: id,
          account: session.user.id,
          started_at: Date.now()
        })
      );
      return id;
    }, authUrl);
    expect(secondId).toBeTruthy();
    await page.goto(`${authUrl}/confirm?${new URLSearchParams({ return_to: settingsUrl })}`);
    await page.getByRole('button', { name: 'Verify with a passkey' }).click();
    await expect(page).toHaveURL(settingsUrl);
    await expect(page.getByText('My synced passkey', { exact: true })).toBeVisible();
    await expect(page.getByText('Second passkey', { exact: true })).not.toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Remove My synced passkey', exact: true })
    ).toBeDisabled();
    await cdp.send('WebAuthn.removeVirtualAuthenticator', {
      authenticatorId: second.authenticatorId
    });
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
    const lastPasskey = await page.evaluate(async (origin) => {
      const list = (await fetch(`${origin}/account/passkeys`, { credentials: 'include' }).then(
        (response) => response.json()
      )) as Passkeys;
      return fetch(`${origin}/account/passkeys/${list[0].id}`, {
        credentials: 'include',
        method: 'DELETE',
        headers: { 'x-piquel-csrf': '1' }
      }).then((response) => response.status);
    }, authUrl);
    expect(lastPasskey).toBeGreaterThanOrEqual(400);

    // The devices page lists this browser's session, which it cannot sign out there.
    await page.getByRole('link', { name: 'Devices', exact: true }).click();
    await expect(page).toHaveURL(new URL('/settings/sessions', settingsUrl).href);
    await expect(page.getByText('This device', { exact: true })).toBeVisible();
    await expect(page.getByText('You’re only signed in on this device.')).toBeVisible();
    await page.getByRole('link', { name: 'Sign-in methods', exact: true }).click();
    await expect(page).toHaveURL(settingsUrl);

    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    // The prompt appears once auth ends the session; reloading sooner cancels the request.
    await expect(page.getByRole('heading', { name: 'Sign in to see your settings' })).toBeVisible();
    // A signed-out visit offers sign-in without reporting an error.
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Sign in to see your settings' })).toBeVisible();
    await expect(page.getByRole('alert')).toHaveCount(0);
    await page.getByRole('link', { name: 'Sign in', exact: true }).click();
    await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
    await expect(page).toHaveURL(settingsUrl);
    await expect(page.getByText(`@${username}`, { exact: true })).toBeVisible();
  } finally {
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  }
});
