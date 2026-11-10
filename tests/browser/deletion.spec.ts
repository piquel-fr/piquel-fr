/**
 * Downloading an account's data from `/settings/data`, deleting the account by
 * typing its handle, and restoring it: signing in with its passkey offers to
 * restore it instead of a session, and restoring signs in.
 */
import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { addPasskeys, signUp } from './helpers';

/** Runs against auth's data page and sign-in page, with Chromium's virtual passkey authenticator. */
test('downloading the data, deleting the account and restoring it with its passkey', async ({
  page,
  context
}) => {
  await addPasskeys(context, page);
  const handle = `deletion-${Date.now().toString(36)}`;
  await signUp(page, handle);
  await page.getByRole('link', { name: 'Your data', exact: true }).click();

  // The session confirmed with a passkey moments ago, so the download needs no new
  // confirmation. The browser saves the account's records as a file named for it.
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download your data', exact: true }).click()
  ]);
  // The file streams as it is read; it parses only if it arrived whole, its
  // events last.
  const data = JSON.parse(await readFile(await download.path(), 'utf8')) as {
    version: number;
    exported_at: string;
    profile: { handle: string };
    events: { kind: string }[];
  };
  expect(download.suggestedFilename()).toBe(
    `sourceorigin-account-${handle}-${data.exported_at.slice(0, 10)}.json`
  );
  expect(data.version).toBe(5);
  expect(data.profile.handle).toBe(handle);
  expect(data.events.map((event) => event.kind)).toContain('account_created');

  await page.getByRole('button', { name: 'Delete account', exact: true }).click();
  await page.getByLabel(`Type your handle, ${handle}, to confirm`).fill(handle);
  await page.getByRole('button', { name: 'Delete my account', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Your account is scheduled for deletion' })
  ).toBeVisible();
  expect((await context.cookies()).map((cookie) => cookie.name)).not.toContain(
    '__Host-sourceorigin_session'
  );

  // Signing in with the account's passkey offers to restore it instead.
  await page.getByRole('link', { name: 'Restore my account', exact: true }).click();
  await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Restore your account?' })).toBeVisible();
  expect((await context.cookies()).map((cookie) => cookie.name)).not.toContain(
    '__Host-sourceorigin_session'
  );
  await page.getByRole('button', { name: 'Restore my account', exact: true }).click();
  await expect(page).toHaveURL('/settings');
  await page.goto('/settings/profile');
  await expect(page.getByRole('definition').getByText(`@${handle}`, { exact: true })).toBeVisible();
});
