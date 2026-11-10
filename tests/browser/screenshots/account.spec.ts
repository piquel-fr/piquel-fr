import { expect, test } from '@playwright/test';
import { addPasskeys, addSecondPasskey, signUp } from '../helpers';
import { handle, shoot } from './docs';

/** The browsers the devices page names: this one on a Mac, the other on Windows. */
const mac =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const windows = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0';

test.use({ userAgent: mac });

/**
 * The account's settings tabs, as the user guide's account pages show them: two
 * passkeys, a second device signed in with one of them and the alert it raised, a
 * display name of its own,
 * an address being added, the history all of that left, and the inbox's email
 * preferences.
 */
test('account settings', async ({ page, context, browser }) => {
  const { cdp, authenticatorId } = await addPasskeys(context, page);
  await signUp(page, handle(), 'MacBook');
  const yubikey = await addSecondPasskey(page, cdp, authenticatorId, 'YubiKey');
  await shoot(
    page,
    'account/sign-in-methods',
    page.locator('section').filter({ has: page.getByRole('heading', { name: /^Passkeys/ }) })
  );

  // The other device signs in with a copy of the YubiKey's passkey.
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId: yubikey });
  const laptop = await (await browser.newContext({ userAgent: windows })).newPage();
  const other = await addPasskeys(laptop.context(), laptop);
  await other.cdp.send('WebAuthn.addCredential', {
    authenticatorId: other.authenticatorId,
    credential: credentials[0]
  });
  await laptop.goto('/login');
  await laptop.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(laptop).toHaveURL('/settings');
  // The new device's sign-in alerts: the top bar's bell counts it.
  await page.goto('/settings/sessions');
  const bell = page.getByRole('link', { name: /^Notifications, \d+ unread$/ });
  await expect(bell).toBeVisible();
  await shoot(page, 'account/notification-bell', page.locator('header.topbar'));
  await page.goto('/settings/notifications');
  await page.getByRole('button', { name: 'Mark all as read', exact: true }).click();
  await page.goto('/settings/sessions');
  await expect(page.getByText('Firefox on Windows', { exact: true }).first()).toBeVisible();
  await shoot(page, 'account/devices');

  await page.goto('/settings/profile');
  await page.getByRole('button', { name: 'Change display name', exact: true }).click();
  await page.getByLabel('Display name', { exact: true }).fill('Alice Martin');
  await page.getByRole('button', { name: 'Save name', exact: true }).click();
  await expect(page.getByText('Your display name changed.')).toBeVisible();
  await page.goto('/settings/profile');
  await shoot(page, 'account/profile');

  await page.goto('/settings/emails');
  await page.getByText('Add an address', { exact: true }).click();
  await page.getByLabel('Email address', { exact: true }).fill('alice@example.com');
  await shoot(page, 'account/email-addresses');

  await page.goto('/settings/history');
  await shoot(page, 'account/security-history');

  await page.goto('/settings/notifications');
  await page.getByRole('button', { name: 'Email preferences', exact: true }).click();
  await shoot(
    page,
    'account/notification-email',
    page.getByRole('dialog', { name: 'Email preferences' })
  );
});
