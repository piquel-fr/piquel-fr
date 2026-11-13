/**
 * An axe pass over auth's pages, signed out and in, the developer console, an
 * error page, and the admin dashboard's pages, an account's settings included:
 * each meets WCAG 2.2 AA as far as axe checks, in the light and the dark theme.
 * The dashboard's pages are skipped without `E2E_ADMIN_URL` and
 * `E2E_GRANT_ADMIN`.
 */
import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { adminUrl, administrator, grantAdmin, openDashboard, signedUp } from './helpers';

// Each test checks many pages, twice.
test.describe.configure({ timeout: 180_000 });

/** The WCAG levels axe checks against. */
const levels = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

/** Expects the page `page` shows, named `name`, to break no rule axe checks, in either theme. */
async function expectAccessible(page: Page, name: string): Promise<void> {
  for (const colorScheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme, reducedMotion: 'reduce' });
    const { violations } = await new AxeBuilder({ page }).withTags(levels).analyze();
    const found = violations.map(
      ({ id, nodes }) => `${id}: ${nodes.map(({ target }) => target.join(' ')).join(', ')}`
    );
    expect.soft(found, `${name}, ${colorScheme}`).toEqual([]);
  }
}

test("auth's pages, signed out", async ({ page }) => {
  for (const path of ['/login', '/register', '/recover', '/no-such-page']) {
    await page.goto(path);
    await expectAccessible(page, path);
  }
});

test("auth's pages, signed in", async ({ browser }) => {
  const page = await signedUp(browser, `axe-${Date.now().toString(36)}`);
  for (const path of [
    '/settings',
    '/settings/sign-in',
    '/settings/profile',
    '/settings/emails',
    '/settings/sessions',
    '/settings/apps',
    '/settings/history',
    '/settings/notifications',
    '/settings/data',
    '/developers',
    '/developers/new'
  ]) {
    await page.goto(path);
    await expectAccessible(page, path);
  }
  // The sidebar collapsed, which hides its words.
  await page.goto('/settings');
  await page.getByRole('button', { name: 'Collapse the sidebar', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Expand the sidebar', exact: true })).toBeVisible();
  await expectAccessible(page, '/settings, the sidebar collapsed');
});

test("the dashboard's pages", async ({ browser }) => {
  test.skip(!adminUrl || !grantAdmin, 'Set E2E_ADMIN_URL and E2E_GRANT_ADMIN.');
  const handle = `axe-admin-${Date.now().toString(36)}`;
  const admin = await administrator(browser, handle);
  for (const path of [
    '/',
    '/users',
    '/administrators',
    '/invitations',
    '/handles',
    '/clients',
    '/events',
    '/deliveries',
    '/keys',
    '/audit',
    '/announcements',
    '/alerts',
    '/alerts/previous',
    // The forms of changes no account or client page offers.
    '/administrators/grant',
    '/invitations/new',
    '/announcements/new',
    '/clients/new',
    '/handles/reserve',
    '/keys/rotate',
    '/no-such-page'
  ]) {
    await openDashboard(admin, path);
    await expectAccessible(admin, path);
  }
  // An account, and its settings as an administrator changes them, each headed
  // by the account: one that administers nothing, whose settings they may open.
  const user = `axe-user-${Date.now().toString(36)}`;
  await (await signedUp(browser, user)).context().close();
  await openDashboard(admin, `/users?q=${user}`);
  await admin.getByRole('link', { name: `@${user}`, exact: true }).click();
  await expectAccessible(admin, 'an account');
  for (const tab of [
    'Sign-in methods',
    'Profile',
    'Email addresses',
    'Connected apps',
    'Security history',
    'Notifications'
  ]) {
    // The account's page links its first tab; each tab, the others.
    const tabs =
      tab === 'Sign-in methods'
        ? admin
        : admin.getByRole('navigation', { name: 'Account settings' });
    await tabs.getByRole('link', { name: tab, exact: true }).click();
    await expect(admin.getByRole('heading', { name: `${user} · ${tab}`, level: 1 })).toBeVisible();
    await expectAccessible(admin, `an account's ${tab}`);
  }
});
