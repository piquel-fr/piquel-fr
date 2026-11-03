import { expect, test, type Page } from '@playwright/test';
import { signUp, withPasskeys } from './helpers';

/** The window sizes the pages must work at, phones to a wide desktop. */
const viewports = [
  { name: 'small phone', width: 320, height: 568 },
  { name: 'phone', width: 390, height: 844 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'laptop', width: 1280, height: 800 },
  { name: 'desktop', width: 1920, height: 1080 }
];

/** Whether the page body scrolls sideways, which no page may. */
async function scrollsSideways(page: Page): Promise<boolean> {
  return page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth
  );
}

/**
 * The shell at every size: the sidebar beside the page on wide windows, a drawer
 * behind the menu button on narrow ones, and nothing ever wider than the window.
 */
test('the settings and sign-in pages fit every window size', async ({ browser }) => {
  const page = await withPasskeys(browser);
  const handle = `layout-${Date.now().toString(36)}`;
  await signUp(page, handle);
  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    for (const path of ['/settings', '/settings/sign-in', '/settings/history', '/developers']) {
      await page.goto(path);
      expect(await scrollsSideways(page), `${viewport.name} ${path}`).toBe(false);
      const menu = page.getByRole('checkbox', { name: 'Menu' });
      const nav = page.getByRole('link', { name: 'Devices', exact: true });
      if (viewport.width <= 860) {
        // A drawer: hidden until the menu opens it, and the links then work.
        await expect(menu, `${viewport.name} ${path}`).toBeVisible();
        await expect(nav).toBeHidden();
        await menu.check();
        await expect(nav).toBeVisible();
      } else {
        await expect(menu, `${viewport.name} ${path}`).toBeHidden();
        await expect(nav).toBeVisible();
      }
    }
    await page.goto('/login');
    expect(await scrollsSideways(page), `${viewport.name} /login`).toBe(false);
    await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();
  }
});

/** The theme and the sidebar's width are chosen once and kept across pages. */
test('the theme and sidebar preferences are kept across pages', async ({ browser }) => {
  const page = await withPasskeys(browser);
  await signUp(page, `prefs-${Date.now().toString(36)}`);
  await page.setViewportSize({ width: 1280, height: 800 });
  const root = page.locator('html');
  await expect(root).not.toHaveAttribute('data-theme');
  await page.getByRole('button', { name: 'Dark theme', exact: true }).click();
  await expect(page).toHaveURL('/settings');
  await expect(root).toHaveAttribute('data-theme', 'dark');
  await page.getByRole('link', { name: 'Devices', exact: true }).click();
  await expect(root).toHaveAttribute('data-theme', 'dark');
  await page.getByRole('button', { name: 'Light theme', exact: true }).click();
  await expect(page).toHaveURL('/settings/sessions');
  await expect(root).toHaveAttribute('data-theme', 'light');

  await page.getByRole('button', { name: 'Collapse the sidebar', exact: true }).click();
  await expect(root).toHaveAttribute('data-sidebar', 'collapsed');
  // Collapsed, the links keep their names for assistive technology and tooltips.
  await page.getByRole('link', { name: 'Security history', exact: true }).click();
  await expect(page).toHaveURL('/settings/history');
  await expect(root).toHaveAttribute('data-sidebar', 'collapsed');
  await page.getByRole('button', { name: 'Expand the sidebar', exact: true }).click();
  await expect(root).toHaveAttribute('data-sidebar', 'expanded');
});
