import { createHash, randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { addPasskeys, authUrl, serveClient, signUp } from './helpers';

/**
 * The `browser-e2e-inline` trusted client's origin, approved for passkey sign-in on
 * its own pages. No server runs it: the test serves its page itself, so its fetches
 * to auth are genuinely cross-origin. On `localhost`, as in CI, it is on auth's own
 * host, where browsers need no list. Elsewhere, as on a preview, it is another
 * site, so the browser reads auth's `/.well-known/webauthn` before signing.
 */
const client =
  new URL(authUrl).hostname === 'localhost' ? 'https://localhost:4443' : 'https://related-e2e.test';

/**
 * A trusted application's page signs its user in with their auth passkey, without
 * leaving the page or getting an auth cookie, and redeems the code with its PKCE
 * verifier.
 */
test('passkey sign-in on an approved related origin', async ({ page, context }) => {
  const { cdp } = await addPasskeys(context, page);
  await serveClient(context, cdp, client);
  await signUp(page, `related-${Date.now().toString(36)}`, 'Related passkey');
  // From here on, auth sets no cookie: the page signs in by itself.
  await context.clearCookies();

  const listed = (await (
    await page.request.get(new URL('/.well-known/webauthn', authUrl).href)
  ).json()) as { origins: string[] };
  expect(listed.origins).toContain(client);

  const verifier = randomBytes(32).toString('base64url');
  await page.goto(client);
  const result = await page.evaluate(
    async ({ authUrl, redirectUri, challenge }) => {
      const encode = (bytes: ArrayBuffer) =>
        btoa(String.fromCharCode(...new Uint8Array(bytes)))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
      const decode = (value: string) =>
        Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (character) =>
          character.charCodeAt(0)
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
      return {
        rpId: options.rpId,
        finishStatus: finished.status,
        sameState: answer.state === state,
        iss: answer.iss,
        replayStatus: replay.status,
        code: answer.code
      };
    },
    {
      authUrl,
      redirectUri: `${client}/callback`,
      challenge: createHash('sha256').update(verifier).digest('base64url')
    }
  );
  expect(result).toMatchObject({
    rpId: new URL(authUrl).hostname,
    finishStatus: 200,
    sameState: true,
    iss: authUrl,
    replayStatus: 400
  });
  // Only the pushed request's PKCE verifier redeems the code.
  const tokens = await page.request.post(new URL('/oauth/token', authUrl).href, {
    form: {
      grant_type: 'authorization_code',
      client_id: 'browser-e2e-inline',
      redirect_uri: `${client}/callback`,
      code: result.code,
      code_verifier: verifier
    }
  });
  expect(tokens.status()).toBe(200);
  expect(await tokens.json()).toHaveProperty('id_token');
  expect(
    (await context.cookies(authUrl)).filter((cookie) => cookie.name === '__Host-piquel_session')
  ).toEqual([]);
});
