import { expect, test, type Page } from '@playwright/test';
import { addAuthenticator, deployment, pkce, signUp } from './helpers';

/** Whether `secret` appears in the page's storage, URL or history state. */
function exposed(page: Page, secret: string): Promise<boolean> {
  return page.evaluate((secret) => {
    const values = [window.location.href, JSON.stringify(history.state)];
    for (const storage of [localStorage, sessionStorage])
      for (let index = 0; index < storage.length; index++) {
        const key = storage.key(index) ?? '';
        values.push(key, storage.getItem(key) ?? '');
      }
    return values.some((value) => value.includes(secret));
  }, secret);
}

/** Runs against the real Rust binary, piquel-web and an isolated PostgreSQL database. */
test('a client registered in the developer console signs a user in', async ({ page, context }) => {
  const { authUrl, settingsUrl } = deployment();
  const { cdp, authenticatorId } = await addAuthenticator(context, page);
  try {
    await signUp(page);
    const redirectUri = new URL('/callback', settingsUrl).href;
    await page.getByRole('link', { name: 'Developers', exact: true }).click();
    await page.getByRole('link', { name: 'New app', exact: true }).click();
    await page.getByLabel('App name').fill('Console E2E');
    await page.getByLabel('Redirect URIs').fill('http://app.example/callback');
    await page.getByRole('button', { name: 'Register app' }).click();
    // The form refuses plain HTTP before auth sees it.
    await expect(page.getByText(/must use https:\/\//)).toBeVisible();
    await page.getByLabel('Redirect URIs').fill(redirectUri);
    // A new account's passkey sign-in is a recent confirmation, so no step-up is needed.
    await page.getByRole('button', { name: 'Register app' }).click();

    await expect(page.getByText('This is the only time this secret is shown.')).toBeVisible();
    const secret = (await page.locator('code', { hasText: /^pqcs_/ }).textContent()) ?? '';
    expect(secret).toMatch(/^pqcs_/);
    expect(await exposed(page, secret)).toBe(false);
    await page.getByRole('button', { name: 'I saved it' }).click();
    await expect(page).toHaveURL(/\/developers\/clients\/c_[A-Za-z0-9]+$/);
    const clientId = page.url().split('/').pop() ?? '';
    await expect(page.getByText(clientId, { exact: true }).first()).toBeVisible();
    // Client pages are rendered by the server, so reloading one works.
    await page.reload();
    await expect(page.getByRole('heading', { name: 'OpenID Connect settings' })).toBeVisible();
    await expect(page.getByText(secret)).toHaveCount(0);
    expect(await exposed(page, secret)).toBe(false);

    const oidc = pkce();
    const authorization = new URL('/oauth/authorize', authUrl);
    authorization.search = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid profile',
      code_challenge: oidc.challenge,
      code_challenge_method: 'S256',
      state: oidc.state,
      nonce: oidc.nonce
    }).toString();
    await page.goto(authorization.href);
    await expect(page.getByRole('heading', { name: 'Continue to Console E2E' })).toBeVisible();
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await page.waitForURL((url) => url.href.startsWith(`${redirectUri}?`));
    const callback = new URL(page.url());
    expect(callback.searchParams.get('state')).toBe(oidc.state);
    // A confidential client redeems from its server, authenticating with its secret.
    const tokens = await page.request.post(new URL('/oauth/token', authUrl).href, {
      headers: {
        authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}`
      },
      form: {
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
        code: callback.searchParams.get('code') ?? '',
        code_verifier: oidc.verifier
      }
    });
    expect(tokens.status()).toBe(200);
    const { id_token } = (await tokens.json()) as { id_token: string };
    const claims = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64url').toString()) as {
      aud: string;
      nonce: string;
    };
    expect(claims).toMatchObject({ aud: clientId, nonce: oidc.nonce });
  } finally {
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  }
});
