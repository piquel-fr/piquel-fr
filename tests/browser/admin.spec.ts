import { type Browser, expect, type Page, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { addPasskeys, signUp } from './helpers';

const adminUrl = process.env.E2E_ADMIN_URL ?? '';
// A command that makes the account named by its last argument an administrator,
// e.g. `just auth admin grant` or `piquelctl app exec … -- auth-service admin grant`.
const grantAdmin = process.env.E2E_GRANT_ADMIN;

/** A browser of its own, with a passkey authenticator, signed up as `username`. */
async function signedUp(browser: Browser, username: string): Promise<Page> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await addPasskeys(context, page);
  await signUp(page, username);
  return page;
}

/** Runs against a deployment with the dashboard, such as a preview. */
test('an administrator disables a user from the dashboard, and the user is signed out', async ({
  browser
}) => {
  test.skip(
    !adminUrl || !grantAdmin,
    'Set E2E_ADMIN_URL and E2E_GRANT_ADMIN to run the dashboard test.'
  );
  const suffix = Date.now().toString(36);
  const admin = await signedUp(browser, `admin-${suffix}`);
  const [command, ...args] = (grantAdmin ?? '').split(' ');
  execFileSync(command, [...args, `admin-${suffix}`], { stdio: 'inherit' });
  const user = await signedUp(browser, `user-${suffix}`);

  // A non-administrator signs in to the dashboard, and sees none of its data. The
  // first sign-in to a dashboard that just started can take longer than usual.
  await user.goto(`${adminUrl}/users`);
  await expect(user.getByRole('heading', { name: 'This account has no access' })).toBeVisible({
    timeout: 20_000
  });
  await expect(user.getByRole('table')).toHaveCount(0);

  // The administrator signed up with a passkey moments ago, which is recent enough
  // to disable without signing in again.
  await admin.goto(`${adminUrl}/users?q=user-${suffix}`);
  await admin.getByRole('link', { name: `user-${suffix}`, exact: true }).click();
  await admin.getByRole('link', { name: 'Disable', exact: true }).click();
  await admin.getByLabel('Reason').fill('Browser test');
  await admin.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(admin.getByText('disabled', { exact: true })).toBeVisible();
  await expect(admin.getByText('No active session.')).toBeVisible();

  await user.goto('/settings');
  await expect(user.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(user.getByText(`@user-${suffix}`, { exact: true })).toHaveCount(0);

  // The dashboard sends no referrer, so its sign-out form posts with `Origin: null`.
  // The dashboard ends its session and hands over to auth, which asks to confirm,
  // then returns to the dashboard, which asks to sign in again.
  await admin.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Ready to sign out?' })).toBeVisible();
  await admin.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(
    admin.getByRole('button', { name: 'Sign in with a passkey', exact: true })
  ).toBeVisible();
});
