/**
 * The settings and sign-in pages at every window size from a small phone to a
 * wide desktop, where nothing scrolls sideways; and the theme and sidebar
 * preferences, which pages keep across navigations.
 */
import { expect, test } from '@playwright/test';
import { scrollsSideways, signUp, viewports, withPasskeys } from './helpers';

/**
 * The shell at every size: the sidebar beside the page on wide windows, a drawer
 * behind the menu button on narrow ones, and nothing ever wider than the window.
 * Each page loads once and is resized in place, as the stylesheet reacts to the
 * window alone: auth's pages share one request budget a minute, which the whole
 * suite spends.
 */
test('the settings and sign-in pages fit every window size', async ({ browser }) => {
  const page = await withPasskeys(browser);
  const handle = `layout-${Date.now().toString(36)}`;
  await signUp(page, handle);
  // One page of each section: every page shares the shell.
  for (const path of ['/settings', '/developers']) {
    await page.goto(path);
    for (const viewport of viewports) {
      await page.setViewportSize(viewport);
      expect(await scrollsSideways(page), `${viewport.name} ${path}`).toBe(false);
      const menu = page.locator('.menu-button');
      const state = page.locator('#menu');
      const nav = page.getByRole('link', { name: 'Devices', exact: true });
      if (viewport.width <= 860) {
        // A drawer: hidden until the menu opens it, and the links then work.
        // The keyboard reaches the drawer's state ahead of the drawer itself.
        await expect(menu, `${viewport.name} ${path}`).toBeVisible();
        await expect(nav).toBeHidden();
        await state.focus();
        await page.keyboard.press('Space');
        await expect(nav).toBeVisible();
        await page.keyboard.press('Space');
        await expect(nav).toBeHidden();
      } else {
        await expect(menu, `${viewport.name} ${path}`).toBeHidden();
        await expect(state).toBeHidden();
        await expect(nav).toBeVisible();
      }
    }
  }
  await page.goto('/login');
  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
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
