import { createHash, randomBytes } from 'node:crypto';
import { expect, type Request, test } from '@playwright/test';
import { addPasskeys, authUrl, serveClient, signUp } from './helpers';

/** The app the test registers. No server runs it: the test serves its pages itself. */
const client = 'https://console-e2e.test';

/** Runs against auth's developer console, with Chromium's virtual passkey authenticator. */
test('the developer console registers an app, shows its secret once, and the app signs in', async ({
  page,
  context
}) => {
  const { cdp } = await addPasskeys(context, page);
  await serveClient(context, cdp, client);
  await signUp(page, `console-${Date.now().toString(36)}`);
  /**
   * Reloads the page showing the secret `shown`: it loads again by `GET`, so the
   * change that made it never posts twice, and the secret is gone.
   */
  const reloadsSafely = async (shown: string) => {
    const posts: string[] = [];
    const post = (request: Request) => {
      if (request.method() === 'POST') posts.push(request.url());
    };
    page.on('request', post);
    const reloaded = page.waitForRequest((request) => request.isNavigationRequest());
    await page.reload();
    expect((await reloaded).method()).toBe('GET');
    page.off('request', post);
    expect(posts).toEqual([]);
    expect(await page.content()).not.toContain(shown);
  };
  await page.getByRole('link', { name: 'Developers', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your apps' })).toBeVisible();
  await page.getByRole('link', { name: 'New app', exact: true }).click();

  // A setting auth refuses says why beside its input, and keeps what was typed.
  await page.getByLabel('App name', { exact: true }).fill('Console E2E');
  const redirects = page.getByRole('textbox', { name: 'Redirect URIs', exact: true });
  await redirects.fill('http://console-e2e.test/callback');
  await page.getByRole('button', { name: 'Register app', exact: true }).click();
  await expect(page.locator('#redirect_uris-error')).toContainText('must use https');
  await expect(redirects).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByLabel('App name', { exact: true })).toHaveValue('Console E2E');

  // A confidential app's secret shows only in the answer to its registration, which
  // no cache keeps, and never reaches a URL, the history or the browser's storage.
  await redirects.fill(`${client}/callback`);
  const registered = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' && response.url().endsWith('/developers/new')
  );
  await page.getByRole('button', { name: 'Register app', exact: true }).click();
  const answer = await registered;
  expect(answer.status()).toBe(200);
  expect(answer.headers()['cache-control']).toBe('no-store, no-transform');
  await expect(page.getByRole('heading', { name: 'Your client secret' })).toBeVisible();
  const secret = (await page.locator('#client-secret').textContent()) ?? '';
  expect(secret).toMatch(/^pqcs_/);
  const kept = await page.evaluate(() => ({
    url: location.href,
    state: JSON.stringify(history.state),
    local: JSON.stringify(Object.entries(localStorage)),
    session: JSON.stringify(Object.entries(sessionStorage))
  }));
  for (const value of Object.values(kept)) expect(value).not.toContain(secret);
  const overview =
    (await page.getByRole('link', { name: 'I saved it', exact: true }).getAttribute('href')) ?? '';
  expect(overview).toMatch(/^\/developers\/clients\/c_[\w-]+$/);
  await reloadsSafely(secret);

  await page.goto(overview);
  const id = overview.split('/').at(-1) ?? '';
  await expect(page.locator('#client-id')).toHaveText(id);
  await expect(page.locator('#client-auth')).toHaveText('client_secret_basic');
  expect(await page.content()).not.toContain(secret);

  // A rotation shows the new secret the same way, once.
  await page
    .getByRole('navigation', { name: 'App' })
    .getByRole('link', { name: 'Secrets', exact: true })
    .click();
  await page.getByRole('button', { name: 'Rotate secret', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your client secret' })).toBeVisible();
  const rotated = (await page.locator('#client-secret').textContent()) ?? '';
  expect(rotated).toMatch(/^pqcs_/);
  expect(rotated).not.toBe(secret);
  await reloadsSafely(rotated);

  // The app signs a user in, and redeems the code with its new secret.
  const verifier = randomBytes(32).toString('base64url');
  const nonce = randomBytes(16).toString('base64url');
  const authorization = new URL('/oauth/authorize', authUrl);
  authorization.search = new URLSearchParams({
    client_id: id,
    redirect_uri: `${client}/callback`,
    response_type: 'code',
    scope: 'openid profile',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: 'console',
    nonce
  }).toString();
  await page.goto(authorization.href);
  await expect(page.getByRole('heading', { name: 'Continue to Console E2E.' })).toBeVisible();
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await page.waitForURL((url) => url.origin === client);
  const code = new URL(page.url()).searchParams.get('code') ?? '';
  const tokens = await page.request.post(new URL('/oauth/token', authUrl).href, {
    headers: { authorization: `Basic ${Buffer.from(`${id}:${rotated}`).toString('base64')}` },
    form: {
      grant_type: 'authorization_code',
      redirect_uri: `${client}/callback`,
      code,
      code_verifier: verifier
    }
  });
  expect(tokens.status()).toBe(200);
  const { id_token } = (await tokens.json()) as { id_token: string };
  const claims = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64url').toString()) as Record<
    string,
    unknown
  >;
  expect(claims.aud).toBe(id);
  expect(claims.nonce).toBe(nonce);
});
