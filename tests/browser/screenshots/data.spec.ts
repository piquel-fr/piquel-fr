import { expect, test } from '@playwright/test';
import { addPasskeys, signUp } from '../helpers';
import { handle, shoot } from './docs';

/** The Your data tab, then its form for deleting the account, which it never posts. */
test('your data', async ({ page, context }) => {
  await addPasskeys(context, page);
  const name = handle();
  await signUp(page, name);

  await page.goto('/settings/data');
  await expect(page.getByRole('heading', { name: 'Your data', exact: true })).toBeVisible();
  await shoot(page, 'account/data');

  await page.getByRole('button', { name: 'Delete account', exact: true }).click();
  await page.getByLabel(`Type your handle, ${name}, to confirm`).fill(name);
  await shoot(
    page,
    'account/delete',
    page
      .locator('section')
      .filter({ has: page.getByRole('heading', { name: 'Delete your account' }) })
  );
});
