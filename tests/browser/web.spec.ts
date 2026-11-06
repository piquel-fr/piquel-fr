import { expect, test } from '@playwright/test';
import { authUrl } from './helpers';

/** piquel.fr's origin, whose policies auth's pages link. */
const webUrl = process.env.E2E_WEB_URL ?? '';

/** Runs against piquel.fr's web server, which CI runs beside auth. */
test("piquel.fr's pages lead to auth, and auth's footer back to its policies", async ({ page }) => {
  test.skip(!webUrl, "Set E2E_WEB_URL to piquel.fr's origin to run the site test.");
  // The pages allow only their stylesheet, so a violation would show on the console.
  const violations: string[] = [];
  page.on('console', (message) => {
    if (message.text().includes('Content Security Policy')) violations.push(message.text());
  });

  // Auth's footer links the policies on piquel.fr.
  await page.goto('/login');
  await page.getByRole('link', { name: 'Privacy', exact: true }).click();
  await expect(page).toHaveURL(`${webUrl}/privacy`);
  await expect(page.getByRole('heading', { name: 'Privacy policy', level: 1 })).toBeVisible();
  await page.getByRole('link', { name: 'Terms', exact: true }).click();
  await expect(page).toHaveURL(`${webUrl}/terms`);
  await expect(page.getByRole('heading', { name: 'Terms of service', level: 1 })).toBeVisible();
  // The stylesheet applied: it lays the policy out as a grid.
  expect(
    await page.locator('article.policy').evaluate((article) => getComputedStyle(article).display)
  ).toBe('grid');

  // The homepage sends people to auth to sign up.
  await page.getByRole('link', { name: 'Piquel home' }).click();
  await page
    .getByRole('main')
    .getByRole('link', { name: 'Create an account', exact: true })
    .click();
  await expect(page).toHaveURL(`${authUrl}/register`);

  // A settings link sent before the settings moved to auth still opens its page,
  // with its fragment.
  await page.goto(`${webUrl}/settings/emails/verify#token=sent`);
  await expect(page).toHaveURL(`${authUrl}/settings/emails/verify#token=sent`);
  await expect(
    page.getByRole('button', { name: 'Confirm this address', exact: true })
  ).toBeVisible();
  expect(violations).toEqual([]);
});
