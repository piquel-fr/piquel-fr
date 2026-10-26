import { expect, test } from '@playwright/test';
import { addPasskeys, signUp } from './helpers';

/** Runs against auth's own settings pages, with Chromium's virtual passkey authenticator. */
test('settings on auth: passkeys, devices, an email link and signing out', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const { cdp, authenticatorId } = await addPasskeys(context, page);
  let assertions = 0;
  cdp.on('WebAuthn.credentialAsserted', () => (assertions += 1));
  const username = `settings-${Date.now().toString(36)}`;
  await signUp(page, username, 'First passkey');
  await expect(page.getByText(`@${username}`, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Rename First passkey', exact: true }).click();
  await page.getByLabel('Passkey name', { exact: true }).fill('My first passkey');
  await page.getByRole('button', { name: 'Save name', exact: true }).click();
  await expect(page.getByText('The passkey was renamed.')).toBeVisible();
  // The last passkey cannot be removed.
  await expect(
    page.getByRole('button', { name: 'Remove My first passkey', exact: true })
  ).toBeDisabled();

  // An authenticator already holding the account's credential refuses a second one:
  // the form says why, and can be tried again.
  const enroll = page.locator('form[data-passkey-enroll]');
  await page.getByLabel('New passkey name', { exact: true }).fill('Second passkey');
  await page.getByRole('button', { name: 'Add a passkey', exact: true }).click();
  await expect(enroll.getByRole('alert')).toBeVisible();

  // The passkey script enables adding a passkey, then comes back with the notice.
  // Add it to another authenticator.
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
  const second = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true
    }
  });
  await page.getByRole('button', { name: 'Add a passkey', exact: true }).click();
  await expect(page.getByText('The passkey was added.')).toBeVisible();
  await expect(page.getByText('Second passkey', { exact: true })).toBeVisible();

  // The session confirmed with a passkey moments ago, so the page asks for no new
  // confirmation. Mark the form as a page with a lapsed one would, to run it.
  await page.getByRole('button', { name: 'Remove Second passkey', exact: true }).click();
  // The passkey script runs once the page has loaded.
  await page.waitForURL(/[?&]remove=/);
  const removal = page.locator('form', {
    has: page.getByRole('button', { name: 'Confirm removal' })
  });
  await removal.evaluate((form) => {
    form.setAttribute('data-passkey-confirm', '');
  });
  const asserted = assertions;
  await page.getByRole('button', { name: 'Confirm removal', exact: true }).click();
  await expect(page.getByText('The passkey was removed.')).toBeVisible();
  await expect(page.getByText('Second passkey', { exact: true })).toHaveCount(0);
  // The passkey script confirmed with a passkey before posting.
  expect(assertions).toBeGreaterThan(asserted);

  await page.getByRole('link', { name: 'Devices', exact: true }).click();
  await expect(page.getByText('This device', { exact: true })).toBeVisible();
  await expect(page.getByText('You’re only signed in on this device.')).toBeVisible();

  // A verification link's form posts its token, which never stays in the address, and
  // a spent one is refused. A link differing only in its fragment loads no new page,
  // and still fills the form.
  await page.goto('/settings/emails/verify');
  await expect(page.getByRole('heading', { name: 'This link is incomplete' })).toBeVisible();
  await page.goto('/settings/emails/verify#token=spent');
  const confirmation = page.waitForRequest((request) => request.method() === 'POST');
  await page.getByRole('button', { name: 'Confirm this address', exact: true }).click();
  expect((await confirmation).postData()).toContain('token=spent');
  await expect(page.getByRole('alert')).toBeVisible();
  await page.goBack();
  expect(new URL(page.url()).hash).toBe('');

  await page.goto('/settings/sessions');
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();
  // Signed out, a page offers sign-in and comes back to itself.
  await page.goto('/settings/sessions');
  await expect(page.getByRole('heading', { name: 'Sign in to see your settings' })).toBeVisible();
  await page.getByRole('link', { name: 'Sign in', exact: true }).click();
  // Only the first authenticator holds a passkey the account still has.
  await cdp.send('WebAuthn.removeVirtualAuthenticator', second);
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
  await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/sessions$/);
  await expect(page.getByText('This device', { exact: true })).toBeVisible();
});
