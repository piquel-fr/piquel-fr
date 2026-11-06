import { expect, type Page, type Request, test } from '@playwright/test';
import { addPasskeys, authorization, authUrl, consent, serveClient, signUp } from './helpers';

/** The app the tests register. No server runs it: the tests serve its pages themselves. */
const client = 'https://console-e2e.test';
const redirectUri = `${client}/callback`;

/**
 * Redeems `code`, of the request `verifier` made, at auth's token endpoint as the
 * app `id`, authenticating with `secret`.
 */
async function redeem(page: Page, id: string, secret: string, code: string, verifier: string) {
  return page.request.post(new URL('/oauth/token', authUrl).href, {
    headers: { authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}` },
    form: {
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code,
      code_verifier: verifier
    }
  });
}

/** Runs against auth's developer console, with Chromium's virtual passkey authenticator. */
test('the developer console registers an app, shows its secret once, and the app signs in', async ({
  page,
  context
}) => {
  const { cdp } = await addPasskeys(context, page);
  await serveClient(context, cdp, client);
  const handle = `console-${Date.now().toString(36)}`;
  await signUp(page, handle);
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
  await page.getByRole('link', { name: 'Your apps', exact: true }).click();
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

  // Accounts cannot name an app after Piquel or another well-known brand.
  await page.getByLabel('App name', { exact: true }).fill('P1quel Settings');
  await redirects.fill(`${client}/callback`);
  await page.getByRole('button', { name: 'Register app', exact: true }).click();
  await expect(page.locator('#display_name-error')).toContainText('reserved');
  await page.getByLabel('App name', { exact: true }).fill('Console E2E');

  // A confidential app's secret shows only in the answer to its registration, which
  // no cache keeps, and never reaches a URL, the history or the browser's storage.
  await redirects.fill(`${client}/callback`);
  const logout = `${client}/auth/backchannel-logout`;
  await page.getByLabel('Back-channel logout URI', { exact: true }).fill(logout);
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
  await expect(page.locator('#backchannel-logout')).toHaveText(logout);
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

  // The app signs a user in, and redeems the code with its new secret. Its consent
  // page says where the app sends the browser, and who registered it, unverified.
  const { url, verifier, nonce } = authorization(id, redirectUri);
  await page.goto(url);
  await expect(page.locator('.lead strong')).toHaveText(new URL(client).host);
  await expect(page.getByText(`Unverified app, registered by @${handle}`)).toBeVisible();
  await expect(page.getByText(`Signed in as @${handle}.`)).toBeVisible();
  const code = await consent(page, 'Console E2E', client);
  const tokens = await redeem(page, id, rotated, code, verifier);
  expect(tokens.status()).toBe(200);
  const { id_token } = (await tokens.json()) as { id_token: string };
  const claims = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64url').toString()) as Record<
    string,
    unknown
  >;
  expect(claims.aud).toBe(id);
  expect(claims.nonce).toBe(nonce);
});

/** An app's life after its registration, in the console. */
test('a rotation retires the old secret, and a disabled or deleted app signs nobody in', async ({
  page,
  context
}) => {
  const { cdp } = await addPasskeys(context, page);
  await serveClient(context, cdp, client);
  await signUp(page, `lifecycle-${Date.now().toString(36)}`);
  await page.goto('/developers/new');
  await page.getByLabel('App name', { exact: true }).fill('Lifecycle E2E');
  await page.getByRole('textbox', { name: 'Redirect URIs', exact: true }).fill(redirectUri);
  await page.getByRole('button', { name: 'Register app', exact: true }).click();
  const first = (await page.locator('#client-secret').textContent()) ?? '';
  await page.getByRole('link', { name: 'I saved it', exact: true }).click();
  const id = (await page.locator('#client-id').textContent()) ?? '';
  const tabs = page.getByRole('navigation', { name: 'App' });

  /**
   * Signs the user in to the app, whose consent the user gave already, and
   * redeems the code with `secret`, answering the token endpoint's status.
   */
  const signsIn = async (secret: string) => {
    const { url, verifier } = authorization(id, redirectUri);
    await page.goto(url);
    await page.waitForURL((url) => url.origin === client);
    const code = new URL(page.url()).searchParams.get('code') ?? '';
    return (await redeem(page, id, secret, code, verifier)).status();
  };
  /**
   * Auth refuses to start signing in to the app: it never sends the browser back to
   * a redirect URI it cannot trust is the app's.
   */
  const refused = async () => {
    const answer = await page.goto(authorization(id, redirectUri).url);
    expect(answer?.status()).toBe(400);
    expect(await answer?.json()).toEqual({
      error: 'invalid_request',
      error_description: 'client_id is not a registered, enabled client'
    });
  };
  const { url, verifier } = authorization(id, redirectUri);
  await page.goto(url);
  const code = await consent(page, 'Lifecycle E2E', client);
  expect((await redeem(page, id, first, code, verifier)).status()).toBe(200);

  // A rotation that stops the earlier secrets now leaves only the new one working.
  await page.goto(`/developers/clients/${id}`);
  await tabs.getByRole('link', { name: 'Secrets', exact: true }).click();
  await page.getByRole('combobox', { name: 'Earlier secrets keep working' }).selectOption({
    label: 'Stop them now'
  });
  await page.getByRole('button', { name: 'Rotate secret', exact: true }).click();
  const second = (await page.locator('#client-secret').textContent()) ?? '';
  expect(second).not.toBe(first);
  expect(await signsIn(first)).toBe(401);
  expect(await signsIn(second)).toBe(200);

  // The settings change the back-channel logout URI, refusing one beside its input,
  // and an empty one stops logout tokens.
  await page.goto(`/developers/clients/${id}`);
  await tabs.getByRole('link', { name: 'Settings', exact: true }).click();
  const logout = page.getByLabel('Back-channel logout URI', { exact: true });
  const save = page.getByRole('button', { name: 'Save changes', exact: true });
  await logout.fill('http://console-e2e.test/auth/backchannel-logout');
  await save.click();
  await expect(page.locator('#backchannel_logout_uri-error')).toContainText('must use https');
  await expect(logout).toHaveValue('http://console-e2e.test/auth/backchannel-logout');
  await logout.fill(`${client}/auth/backchannel-logout`);
  await save.click();
  await expect(page.getByText('Your changes were saved.')).toBeVisible();
  await page.goto(`/developers/clients/${id}`);
  await expect(page.locator('#backchannel-logout')).toHaveText(`${client}/auth/backchannel-logout`);
  await tabs.getByRole('link', { name: 'Settings', exact: true }).click();
  await logout.fill('');
  await save.click();
  await expect(page.getByText('Your changes were saved.')).toBeVisible();
  await page.goto(`/developers/clients/${id}`);
  await expect(page.locator('#backchannel-logout')).toHaveCount(0);

  // Disabled, the app signs nobody in until it is enabled again.
  await tabs.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(page.getByText('The app was disabled.')).toBeVisible();
  await refused();
  await page.goto(`/developers/clients/${id}`);
  await expect(page.getByText(/This app is disabled: it cannot sign users in/)).toBeVisible();
  await tabs.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Enable', exact: true }).click();
  await expect(page.getByText('The app was enabled.')).toBeVisible();
  expect(await signsIn(second)).toBe(200);

  // Deleted, it leaves the list, and never signs anyone in again.
  await page.goto(`/developers/clients/${id}`);
  await tabs.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByText('Delete “Lifecycle E2E”?')).toBeVisible();
  await page.getByRole('button', { name: 'Delete for good', exact: true }).click();
  await expect(page.getByText('The app was deleted.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Your apps' })).toBeVisible();
  await expect(page.getByText('Lifecycle E2E', { exact: true })).toHaveCount(0);
  await refused();
});
