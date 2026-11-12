/**
 * Auth's pages in a browser with JavaScript disabled, as the `no-javascript`
 * project runs them: failures are pages that need no script, passkey forms say
 * what they need instead of failing, an address is confirmed by pasting its link,
 * and the account's data downloads again and again. Signing up needs a passkey,
 * so it runs in a browser of its own with JavaScript, whose session the
 * script-less browser then holds.
 */
import { expect, test, type Browser, type Page } from '@playwright/test';
import { mailed, mailUrl, signUp, withPasskeys } from './helpers';

/**
 * A page with JavaScript disabled, signed in to an account `handle` that a browser
 * with JavaScript signed up.
 */
async function signedInWithoutScripts(browser: Browser, handle: string): Promise<Page> {
  const scripted = await withPasskeys(browser, { javaScriptEnabled: true });
  await signUp(scripted, handle);
  const context = await browser.newContext({
    javaScriptEnabled: false,
    storageState: await scripted.context().storageState()
  });
  await scripted.context().close();
  return context.newPage();
}

test('a failure is a page that needs no script', async ({ page }) => {
  const response = await page.goto('/no-such-page');
  expect(response?.status()).toBe(404);
  await expect(page.getByRole('heading', { name: 'Page not found', level: 1 })).toBeVisible();
  await expect(page.locator('script')).toHaveCount(0);
  await page.getByRole('link', { name: 'Go to Origin Auth', exact: true }).click();
  await expect(page).toHaveURL(/\/settings$/);
});

test("a provider's callback that cannot go on says why, and signing in what it needs", async ({
  page
}) => {
  await page.goto('/login/github/callback?state=unknown&code=unknown');
  await expect(page.getByRole('alert')).toHaveText(
    'This sign-in did not start in this browser, has expired or was already used. Please start again.'
  );
  await expect(
    page.getByRole('button', { name: 'Sign in with a passkey', exact: true })
  ).toBeDisabled();
  await expect(
    page.getByText(/Passkeys need a supported browser .* with scripts allowed/)
  ).toBeVisible();
});

test('the account data downloads again and again', async ({ browser }) => {
  const page = await signedInWithoutScripts(browser, `noscript-${Date.now().toString(36)}`);
  await page.goto('/settings/data');
  const button = page.getByRole('button', { name: 'Download your data', exact: true });
  for (let time = 0; time < 2; time++)
    await Promise.all([page.waitForEvent('download'), button.click()]);
});

test('an address is confirmed by pasting its link', async ({ browser }) => {
  test.skip(!mailUrl, 'needs E2E_MAIL_URL, to read the confirmation link');
  const page = await signedInWithoutScripts(browser, `noscript-${Date.now().toString(36)}`);
  const address = `noscript-${Date.now().toString(36)}@example.com`;
  await page.goto('/settings/emails');
  await page.getByText('Add an address', { exact: true }).click();
  await page.getByLabel('Email address', { exact: true }).fill(address);
  await page.getByRole('button', { name: 'Send a confirmation link', exact: true }).click();
  const link = await mailed(address, /https?:\/\/\S+\/settings\/emails\/verify#token=\S+/);
  await page.goto(link);
  // The page cannot read the link's fragment, so it asks for the link itself.
  await page.getByLabel('Link from the email', { exact: true }).fill(link);
  await page.getByRole('button', { name: 'Confirm this address', exact: true }).last().click();
  await expect(page.getByRole('heading', { name: 'Address confirmed' })).toBeVisible();
});
