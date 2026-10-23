import { expect, test } from '@playwright/test';

/**
 * A trusted application's page on another origin signs its user in with their auth
 * passkey, without leaving the page, and redeems the code with its PKCE verifier.
 */
test('passkey sign-in on an approved related origin', async ({ page, context }) => {
  const settingsUrl = process.env.E2E_SETTINGS_URL;
  if (!settingsUrl)
    throw new Error(
      'Set E2E_SETTINGS_URL to the separately served piquel-web frontend, with AUTH_ORIGIN matching E2E_AUTH_URL.'
    );
  const authUrl = process.env.E2E_AUTH_URL ?? 'http://localhost:3000';
  const pageOrigin = new URL(settingsUrl).origin;
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true
    }
  });
  try {
    const invitation = process.env.E2E_INVITATION;
    await page.goto(
      `/register${invitation ? `?invitation=${encodeURIComponent(invitation)}` : ''}`
    );
    await page.getByLabel('Username', { exact: true }).fill(`related-${Date.now().toString(36)}`);
    await page.getByLabel('Passkey name', { exact: true }).fill('Related passkey');
    await page.getByRole('button', { name: 'Create account with a passkey' }).click();
    await expect(page).toHaveURL(settingsUrl);
    // From here on, auth sets no cookie: the page signs in by itself.
    await context.clearCookies();

    const listed = (await (
      await page.request.get(new URL('/.well-known/webauthn', authUrl).href)
    ).json()) as { origins: string[] };
    expect(listed.origins).toContain(pageOrigin);

    await page.goto(settingsUrl);
    const result = await page.evaluate(
      async ({ authUrl, redirectUri }) => {
        const encode = (bytes: ArrayBuffer | Uint8Array) =>
          btoa(String.fromCharCode(...new Uint8Array(bytes)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
        const decode = (value: string) =>
          Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (character) =>
            character.charCodeAt(0)
          );
        const verifier = encode(crypto.getRandomValues(new Uint8Array(32)));
        const challenge = encode(
          await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
        );
        const state = crypto.randomUUID();
        const pushed = await fetch(`${authUrl}/oauth/par`, {
          method: 'POST',
          body: new URLSearchParams({
            client_id: 'browser-e2e-inline',
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: 'openid',
            code_challenge: challenge,
            code_challenge_method: 'S256',
            state
          })
        });
        const { request_uri } = (await pushed.json()) as { request_uri: string };
        const post = (path: string, body: unknown) =>
          fetch(`${authUrl}${path}`, {
            method: 'POST',
            credentials: 'omit',
            headers: { 'content-type': 'application/json', 'x-piquel-csrf': '1' },
            body: JSON.stringify(body)
          });
        const start = (await (await post('/webauthn/related/start', { request_uri })).json()) as {
          ceremony_id: string;
          public_key: { publicKey: { challenge: string; rpId: string } };
        };
        const options = start.public_key.publicKey;
        const credential = (await navigator.credentials.get({
          publicKey: { ...options, challenge: decode(options.challenge) }
        })) as PublicKeyCredential;
        const response = credential.response as AuthenticatorAssertionResponse;
        const finish = {
          ceremony_id: start.ceremony_id,
          credential: {
            id: credential.id,
            rawId: encode(credential.rawId),
            type: credential.type,
            response: {
              authenticatorData: encode(response.authenticatorData),
              clientDataJSON: encode(response.clientDataJSON),
              signature: encode(response.signature),
              userHandle: response.userHandle ? encode(response.userHandle) : null
            },
            clientExtensionResults: credential.getClientExtensionResults()
          }
        };
        const finished = await post('/webauthn/related/finish', finish);
        const answer = (await finished.json()) as { code: string; state: string; iss: string };
        const replay = await post('/webauthn/related/finish', finish);
        const exchange = (code_verifier: string) =>
          fetch(`${authUrl}/oauth/token`, {
            method: 'POST',
            body: new URLSearchParams({
              grant_type: 'authorization_code',
              client_id: 'browser-e2e-inline',
              redirect_uri: redirectUri,
              code: answer.code,
              code_verifier
            })
          });
        const tokens = await exchange(verifier);
        return {
          rpId: options.rpId,
          finishStatus: finished.status,
          sameState: answer.state === state,
          iss: answer.iss,
          replayStatus: replay.status,
          tokenStatus: tokens.status,
          hasIdToken: 'id_token' in ((await tokens.json()) as object)
        };
      },
      { authUrl, redirectUri: `${pageOrigin}/callback` }
    );
    expect(result).toEqual({
      rpId: new URL(authUrl).hostname,
      finishStatus: 200,
      sameState: true,
      iss: authUrl,
      replayStatus: 400,
      tokenStatus: 200,
      hasIdToken: true
    });
    expect(
      (await context.cookies(authUrl)).filter((cookie) => cookie.name === '__Host-piquel_session')
    ).toEqual([]);
  } finally {
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  }
});
