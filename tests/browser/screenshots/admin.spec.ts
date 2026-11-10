import { test } from '@playwright/test';
import { cli, reason, signedUp } from '../helpers';
import { adminUrl, handle, shoot } from './docs';

// A command that makes the account named by its last argument an administrator,
// as for the dashboard's tests.
const grantAdmin = process.env.E2E_GRANT_ADMIN ?? '';

test.skip(!adminUrl || !grantAdmin, 'Set E2E_ADMIN_URL and E2E_GRANT_ADMIN for the dashboard.');

/** The admin dashboard, as an administrator sees it. */
test('admin dashboard', async ({ browser }) => {
  const account = handle('sam');
  const admin = await signedUp(browser, account);
  cli(grantAdmin, ...reason, account);
  // Signing in to the dashboard asks for the passkey on auth's handoff page.
  await admin.goto(adminUrl);
  await admin.getByRole('button', { name: 'Confirm with a passkey', exact: true }).click();
  await admin.waitForURL((url) => url.origin === new URL(adminUrl).origin);
  await shoot(admin, 'admin/overview');
});
