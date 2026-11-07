import { expect, test } from '@playwright/test';
import { addPasskeys, signUp } from '../helpers';
import { handle, shoot } from './docs';

/** The app the screenshots register. Nothing serves it: no one signs in to it. */
const app = 'https://notes.example';

/**
 * A confidential app's Settings and Secrets tabs, after a rotation with a grace
 * period. Neither image shows a secret: each is taken once the page showing it
 * is left with "I saved it".
 */
test('app settings and secrets', async ({ page, context }) => {
  await addPasskeys(context, page);
  await signUp(page, handle());

  await page.goto('/developers/new');
  await page.getByLabel('App name', { exact: true }).fill('Notes');
  await page.getByLabel('Yes, a web app with a backend').check();
  await page
    .getByRole('textbox', { name: 'Redirect URIs', exact: true })
    .fill(`${app}/auth/callback`);
  await page.getByRole('checkbox', { name: 'offline_access' }).check();
  await page.getByLabel('Allow refresh tokens', { exact: true }).check();
  await page.getByRole('button', { name: 'Register app', exact: true }).click();
  await page.getByRole('link', { name: 'I saved it', exact: true }).click();
  await expect(page.locator('#client-id')).toBeVisible();

  const tabs = page.getByRole('navigation', { name: 'App' });
  await tabs.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Danger zone' })).toBeVisible();
  await shoot(page, 'apps/app-settings', page.locator('main'));

  await tabs.getByRole('link', { name: 'Secrets', exact: true }).click();
  await page.getByRole('button', { name: 'Rotate secret', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your client secret' })).toBeVisible();
  await page.getByRole('link', { name: 'I saved it', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your client secret' })).toHaveCount(0);
  await expect(page.getByText('Expiring', { exact: true })).toBeVisible();
  await shoot(page, 'apps/app-secrets');
});
