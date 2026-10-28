import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { signedUp } from './helpers';

const adminUrl = process.env.E2E_ADMIN_URL ?? '';
// A command that makes the account named by its last argument an administrator,
// e.g. `just auth admin grant` or `piquelctl app exec … -- auth-service admin grant`.
const grantAdmin = process.env.E2E_GRANT_ADMIN;

/** Runs against a deployment with the dashboard, as CI's and previews have. */
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

  // Auth's handoff page tells a non-administrator so, and hands nothing off.
  await user.goto(`${adminUrl}/users`);
  await expect(user.getByRole('heading', { name: 'This account has no access' })).toBeVisible();
  await expect(user.getByRole('table')).toHaveCount(0);

  // The administrator's passkey session hands off to the dashboard silently. A
  // change needs the dashboard's own confirmation: auth asks for a passkey, for
  // the dashboard only, then the dashboard shows the change's form.
  await admin.goto(`${adminUrl}/users?q=user-${suffix}`);
  await admin.getByRole('link', { name: `user-${suffix}`, exact: true }).click();
  await admin.getByRole('link', { name: 'Disable', exact: true }).click();
  await expect(admin.getByRole('heading', { name: "Confirm it's you" })).toBeVisible();
  await admin.getByRole('button', { name: 'Confirm with a passkey', exact: true }).click();
  await admin.getByLabel('Reason').fill('Browser test');
  await admin.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(admin.getByText('disabled', { exact: true })).toBeVisible();
  await expect(admin.getByText('No active session.')).toBeVisible();

  await user.goto('/settings');
  await expect(user.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(user.getByText(`@user-${suffix}`, { exact: true })).toHaveCount(0);

  // The dashboard sends no referrer, so its sign-out form posts with `Origin: null`.
  // Signing out of the dashboard keeps the Piquel session, so signing in again is
  // silent.
  await admin.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Signed out of the dashboard' })).toBeVisible();
  await admin.getByRole('link', { name: 'Sign in again', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();

  // Signed out of Piquel too, the administrator signs in with a passkey on auth,
  // whose sign-in form then goes on through the handoff to the dashboard.
  await admin.getByRole('button', { name: 'Sign out', exact: true }).click();
  await admin.getByRole('link', { name: 'Sign out of Piquel', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Ready to sign out?' })).toBeVisible();
  await admin.getByRole('button', { name: 'Sign out', exact: true }).click();
  await admin.goto(`${adminUrl}/users`);
  await admin.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
});
