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
  // confirmation. The file names the account and holds its records.
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download your data', exact: true }).click()
  ]);
  const data = JSON.parse(await readFile(await download.path(), 'utf8')) as {
    format: string;
    exported_at: string;
    profile: { handle: string };
    passkeys: unknown[];
  };
  expect(download.suggestedFilename()).toBe(
    `piquel-account-${handle}-${data.exported_at.slice(0, 10)}.json`
  );
  expect(data.format).toBe('piquel.account-export');
  expect(data.profile.handle).toBe(handle);
  expect(data.passkeys).toHaveLength(1);

  await page.getByRole('button', { name: 'Delete account', exact: true }).click();
  await page.getByLabel(`Type your handle, ${handle}, to confirm`).fill(handle);
  await page.getByRole('button', { name: 'Delete my account', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Your account is scheduled for deletion' })
  ).toBeVisible();
  expect((await context.cookies()).map((cookie) => cookie.name)).not.toContain(
    '__Host-piquel_session'
  );

  // Signing in with the account's passkey offers to restore it instead.
  await page.getByRole('link', { name: 'Restore my account', exact: true }).click();
  await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Restore your account?' })).toBeVisible();
  expect((await context.cookies()).map((cookie) => cookie.name)).not.toContain(
    '__Host-piquel_session'
  );
  await page.getByRole('button', { name: 'Restore my account', exact: true }).click();
  await expect(page).toHaveURL('/settings');
  await expect(
    page.getByRole('region', { name: 'Handle' }).getByText(`@${handle}`, { exact: true })
  ).toBeVisible();

  await page.getByRole('link', { name: 'Security history', exact: true }).click();
  await expect(page.getByText('Account restored')).toBeVisible();
  await expect(page.getByText(/Account deletion scheduled for/)).toBeVisible();
  await expect(page.getByText('Account data downloaded')).toBeVisible();
});
