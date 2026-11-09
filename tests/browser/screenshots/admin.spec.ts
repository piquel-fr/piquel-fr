import { test } from '@playwright/test';
import { cli, signedUp } from '../helpers';
import { adminUrl, handle, shoot } from './docs';

// A command that makes the account named by its last argument an administrator,
// as for the dashboard's tests.
const grantAdmin = process.env.E2E_GRANT_ADMIN ?? '';

test.skip(!adminUrl || !grantAdmin, 'Set E2E_ADMIN_URL and E2E_GRANT_ADMIN for the dashboard.');

/** The admin dashboard, as an administrator sees it. */
test('admin dashboard', async ({ browser }) => {
  const account = handle('sam');
  const admin = await signedUp(browser, account);
  cli(grantAdmin, account);
  await admin.goto(adminUrl);
  await shoot(admin, 'admin/overview');
});
