import { expect, test } from '@playwright/test';
import { addPasskeys, signUp } from './helpers';

/** Runs against auth's sign-in page, with Chromium's virtual passkey authenticator. */
test('signing in with a handle, after one without an account is refused', async ({
  page,
  context
}) => {
  await addPasskeys(context, page);
  const handle = `sign-in-${Date.now().toString(36)}`;
  await signUp(page, handle);
  // Signed out, the authenticator still holds the account's passkey.
  await context.clearCookies();

  await page.goto('/login');
  await page.getByRole('button', { name: 'Use a handle instead', exact: true }).click();
  const field = page.getByLabel('Handle', { exact: true });
  const signIn = page.getByRole('button', { name: 'Sign in with a passkey', exact: true });
  // Handles are public, so a handle without an account is refused before any ceremony.
  await field.fill(`nobody-${Date.now().toString(36)}`);
  await signIn.click();
  await expect(page.locator('form[data-passkey-sign-in]').getByRole('alert')).toHaveText(
    'No active account has this handle.'
  );
  await expect(page).toHaveURL(/\/login/);

  await field.fill(handle);
  await signIn.click();
  await expect(page).toHaveURL('/settings');
  await expect(
    page.getByRole('region', { name: 'Handle' }).getByText(`@${handle}`, { exact: true })
  ).toBeVisible();
});
