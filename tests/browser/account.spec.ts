import { expect, test } from '@playwright/test';

// Response shapes this test reads; anything else stays unknown.
type Tokens = { id_token: string; access_token: string };
type Jwks = { keys: (JsonWebKey & { kid: string })[] };
type Json = Record<string, unknown>;
type Session = { user: { id: string } };
type Passkeys = { id: string }[];

/** Runs against the real Rust binary and an isolated PostgreSQL database. */
test('passkey lifecycle, protected settings and browser OIDC consent with SSO', async ({
  page,
  context
}) => {
  const settingsUrl = process.env.E2E_SETTINGS_URL;
  if (!settingsUrl)
    throw new Error(
      'Set E2E_SETTINGS_URL to the separately served piquel-web frontend, with AUTH_ORIGIN matching E2E_AUTH_URL.'
    );
  const authUrl = process.env.E2E_AUTH_URL ?? 'http://localhost:3000';
  const username = `browser-${Date.now().toString(36)}`;
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
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
  try {
    const invitation = process.env.E2E_INVITATION;
    await page.goto(
      `/register${invitation ? `?invitation=${encodeURIComponent(invitation)}` : ''}`
    );
    await page.getByLabel('Username', { exact: true }).fill(username);
    await page.getByLabel('Passkey name', { exact: true }).fill('Synced passkey');
    await page.getByRole('button', { name: 'Create account with a passkey' }).click();
    await expect(page).toHaveURL(settingsUrl);
    await expect(page.getByText(`@${username}`, { exact: true })).toBeVisible();

    const redirectUri = new URL('/callback', settingsUrl).href;
    const oidc = await page.evaluate(async () => {
      const encode = (bytes: Uint8Array) =>
        btoa(String.fromCharCode(...bytes))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
      const verifier = encode(crypto.getRandomValues(new Uint8Array(32)));
      return {
        verifier,
        challenge: encode(
          new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
        ),
        state: crypto.randomUUID(),
        nonce: crypto.randomUUID()
      };
    });
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
    await page.waitForURL(
      (url) => url.origin === new URL(redirectUri).origin && url.pathname === '/callback'
    );
    const callback = new URL(page.url());
    expect(callback.searchParams.get('state')).toBe(oidc.state);
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
    await page.waitForURL(
      (url) => url.origin === new URL(redirectUri).origin && url.pathname === '/callback'
    );
    const sso = new URL(page.url());
    expect(sso.searchParams.get('state')).toBe(`${oidc.state}-sso`);
    expect(sso.searchParams.has('error')).toBe(false);
    expect(sso.searchParams.get('code')).toBeTruthy();
    expect(sso.searchParams.get('code')).not.toBe(code);
    await page.goto(settingsUrl);
    await expect(page.getByRole('button', { name: 'Rename Synced passkey' })).toBeDisabled();

    const rejected = await page.evaluate(async (origin) => {
      const options = { credentials: 'include' as const };
      const list = (await fetch(`${origin}/account/passkeys`, options).then((response) =>
        response.json()
      )) as Passkeys;
      return fetch(`${origin}/account/passkeys/${list[0].id}`, {
        ...options,
        method: 'PATCH',
        headers: { 'content-type': 'application/json', 'x-piquel-csrf': '1' },
        body: JSON.stringify({ friendly_name: 'Unauthorized rename' })
      }).then((response) => response.status);
    }, authUrl);
    expect(rejected).toBeGreaterThanOrEqual(400);

    await page.getByRole('link', { name: 'Unlock with a passkey' }).click();
    await page.getByRole('button', { name: 'Verify with a passkey' }).click();
    await expect(page).toHaveURL(settingsUrl);
    await expect(page.getByText('Security settings unlocked', { exact: true })).toBeVisible();
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
    await page.getByRole('link', { name: 'Add a passkey', exact: true }).click();
    await page.getByLabel('Passkey name', { exact: true }).fill('Second passkey');
    await page.getByRole('button', { name: 'Verify and add passkey' }).click();
    await expect(page).toHaveURL(settingsUrl);
    await expect(page.getByText('Second passkey', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Remove Second passkey', exact: true }).click();
    await page.getByRole('button', { name: 'Confirm removal' }).click();
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

    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('link', { name: 'Sign in', exact: true }).click();
    await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
    await expect(page).toHaveURL(settingsUrl);
    await expect(page.getByText(`@${username}`, { exact: true })).toBeVisible();
  } finally {
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  }
});
