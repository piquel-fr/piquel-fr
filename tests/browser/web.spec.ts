/**
 * sourceorigin.dev's own web server: auth's footer links its policies, which allow
 * nothing but their stylesheet; its homepage links auth's pages; and a link to a
 * settings path on sourceorigin.dev goes on to auth with its fragment. Skipped
 * without `E2E_WEB_URL`.
 */
import { expect, test } from '@playwright/test';
import { authUrl } from './helpers';

/** sourceorigin.dev's origin, whose policies auth's pages link. */
const webUrl = process.env.E2E_WEB_URL ?? '';

/** Runs against sourceorigin.dev's web server, which CI runs beside auth. */
test("sourceorigin.dev's pages lead to auth, and auth's footer back to its policies", async ({
  page
}) => {
  test.skip(!webUrl, "Set E2E_WEB_URL to sourceorigin.dev's origin to run the site test.");
  // The pages allow only their stylesheet, so a violation would show on the console.
  const violations: string[] = [];
  page.on('console', (message) => {
    if (message.text().includes('Content Security Policy')) violations.push(message.text());
  });

  // Auth's footer links the policies on sourceorigin.dev.
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
  await page.getByRole('banner').getByRole('link', { name: 'SourceOrigin', exact: true }).click();
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
