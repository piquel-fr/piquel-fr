/**
 * What a browser is shown when a request fails: a page of its own for a
 * navigation, with a way back, while a `fetch` still reads JSON; the sign-in page
 * saying why for a provider's callback that cannot go on; and a page saying so
 * for a form larger than a page reads. Downloading the account's data works
 * again after a download.
 */
import { expect, test } from '@playwright/test';
import { authUrl, signedUp } from './helpers';

test('an address with no page is a page saying so, and a fetch of it JSON', async ({ page }) => {
  const response = await page.goto('/no-such-page');
  expect(response?.status()).toBe(404);
  expect(response?.headers()['content-type']).toContain('text/html');
  await expect(page.getByRole('heading', { name: 'Page not found', level: 1 })).toBeVisible();
  await expect(page.getByText('There is no page at this address.')).toBeVisible();
  await page.getByRole('link', { name: 'Go to Origin Auth', exact: true }).click();
  await expect(page).toHaveURL(/\/settings$/);
  // A fetch from a page of auth's reads the same failure as JSON. The error
  // page itself fetches nothing: its policy allows none.
  const fetched = await page.evaluate(async () => {
    const answer = await fetch('/no-such-page');
    return { status: answer.status, body: (await answer.json()) as unknown };
  });
  expect(fetched).toEqual({ status: 404, body: { error: 'There is no page at this address.' } });
});

test("a provider's callback that cannot go on says why on the sign-in page", async ({ page }) => {
  // No sign-in started in this browser, as when a callback is opened again
  // elsewhere, or after it expired.
  await page.goto('/login/github/callback?state=unknown&code=unknown');
  await expect(page).toHaveURL(/\/login\?error=social_expired/);
  await expect(page.getByRole('alert')).toHaveText(
    'This sign-in did not start in this browser, has expired or was already used. Please start again.'
  );
});

test('a form posted from another site is a page saying so', async ({ page }) => {
  await page.setContent(
    `<form method="post" action="${authUrl}/settings"><button>Post</button></form>`
  );
  const [response] = await Promise.all([
    page.waitForResponse((answer) => answer.url().endsWith('/settings')),
    page.getByRole('button', { name: 'Post' }).click()
  ]);
  expect(response.status()).toBe(403);
  await expect(page.getByRole('heading', { name: 'Not allowed', level: 1 })).toBeVisible();
  await expect(page.getByText('Submit this form from its page on this site.')).toBeVisible();
});

test('a form larger than a page reads says so', async ({ page }) => {
  await page.goto('/login');
  // No field of the page takes this much: an edited page, or a page past its
  // limits.
  await page.evaluate(() => {
    const form = document.createElement('form');
    form.method = 'post';
    form.action = '/login';
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'action';
    input.value = 'x'.repeat(70 * 1024);
    form.append(input);
    document.body.append(form);
    form.submit();
  });
  await expect(page.getByRole('alert')).toHaveText(
    'What you entered is too long to send. Shorten it and try again.'
  );
});

test('downloading the data works again once the file is on its way', async ({ browser }) => {
  const page = await signedUp(browser, `download-${Date.now().toString(36)}`);
  await page.goto('/settings/data');
  const button = page.getByRole('button', { name: 'Download your data', exact: true });
  await Promise.all([page.waitForEvent('download'), button.click()]);
  // The page never changes for a download, so the button must not stay locked.
  await expect(async () => {
    await Promise.all([page.waitForEvent('download', { timeout: 2000 }), button.click()]);
  }).toPass({ timeout: 15_000 });
});
