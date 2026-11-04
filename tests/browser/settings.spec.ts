import { expect, test } from '@playwright/test';
import {
  addPasskeys,
  addSecondPasskey,
  authorization,
  consent,
  serveClient,
  signUp
} from './helpers';

/** Runs against auth's own settings pages, with Chromium's virtual passkey authenticator. */
test('settings on auth: passkeys, devices, an email link and signing out', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const { cdp, authenticatorId } = await addPasskeys(context, page);
  let assertions = 0;
  cdp.on('WebAuthn.credentialAsserted', () => (assertions += 1));
  const username = `settings-${Date.now().toString(36)}`;
  await signUp(page, username, 'First passkey');
  // The settings open on the overview; the sidebar leads to the sign-in methods.
  await page.getByRole('link', { name: 'Sign-in methods', exact: true }).click();
  await expect(page).toHaveURL('/settings/sign-in');
  await expect(page.getByRole('heading', { name: 'Sign-in methods', level: 1 })).toBeVisible();
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
  // The form is folded behind a button until it is wanted.
  const enroll = page.locator('form[data-passkey-enroll]');
  await expect(enroll).toBeHidden();
  await page.getByText('Add a passkey', { exact: true }).click();
  await page.getByLabel('New passkey name', { exact: true }).fill('Second passkey');
  await page.getByRole('button', { name: 'Create the passkey', exact: true }).click();
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
  await page.getByRole('button', { name: 'Create the passkey', exact: true }).click();
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
  // a spent one is refused, still leading to the addresses. A link differing only in
  // its fragment loads no new page, and still fills the form.
  await page.goto('/settings/emails/verify');
  await expect(page.getByRole('heading', { name: 'This link is incomplete' })).toBeVisible();
  await page.goto('/settings/emails/verify#token=spent');
  const confirmation = page.waitForRequest((request) => request.method() === 'POST');
  await page.getByRole('button', { name: 'Confirm this address', exact: true }).click();
  expect((await confirmation).postData()).toContain('token=spent');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Manage your addresses', exact: true })
  ).toBeVisible();
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

test('removing a connected app ends its access, so it asks for consent again', async ({
  page,
  context
}) => {
  // The `browser-e2e` public client's origin, which the test serves.
  const client = 'https://browser-e2e.test';
  const { cdp } = await addPasskeys(context, page);
  await serveClient(context, cdp, client);
  await signUp(page, `apps-${Date.now().toString(36)}`);
  await page.goto(authorization('browser-e2e', `${client}/callback`).url);
  await consent(page, 'Browser E2E', client);

  await page.goto('/settings');
  await page.getByRole('link', { name: 'Connected apps', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Connected apps 1', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Remove access for Browser E2E', exact: true }).click();
  await expect(
    page.getByText('Browser E2E will need your approval again to use your account.', {
      exact: false
    })
  ).toBeVisible();
  await page.getByRole('button', { name: 'Remove access', exact: true }).click();
  await expect(page.getByText('The app no longer has access to your account.')).toBeVisible();
  await expect(page.getByText('No apps have access to your account.')).toBeVisible();

  // Its remembered consent went with it.
  await page.goto(authorization('browser-e2e', `${client}/callback`).url);
  await consent(page, 'Browser E2E', client);
});

test('reporting a change in the history signs every other device out, and undoes it', async ({
  browser
}) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const { cdp, authenticatorId } = await addPasskeys(context, page);
  await signUp(page, `history-${Date.now().toString(36)}`, 'First passkey');

  // Another device signs in with the same passkey, synced to its authenticator.
  const elsewhere = await browser.newContext();
  const other = await elsewhere.newPage();
  const synced = await addPasskeys(elsewhere, other);
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  await synced.cdp.send('WebAuthn.addCredential', {
    authenticatorId: synced.authenticatorId,
    credential: credentials[0]
  });
  await other.goto('/login');
  await other.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(other).toHaveURL('/settings');

  await addSecondPasskey(page, cdp, authenticatorId, 'Unknown passkey');
  await page.getByRole('link', { name: 'Security history', exact: true }).click();
  await page
    .getByRole('button', { name: 'This wasn’t me: Passkey “Unknown passkey” added', exact: true })
    .click();
  await expect(page.getByText('Secure your account?')).toBeVisible();
  await page.getByRole('button', { name: 'Sign out everywhere else', exact: true }).click();
  await expect(page.getByText('Your account is secured.')).toBeVisible();
  await expect(page.getByText('You reported activity that wasn’t you')).toBeVisible();
  await other.reload();
  await expect(other.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible();

  // The report offers to undo the change it was about.
  await page.getByRole('button', { name: 'Remove passkey “Unknown passkey”', exact: true }).click();
  await expect(page.getByText('The passkey was removed.')).toBeVisible();
  await expect(page.getByText('Unknown passkey', { exact: true })).toHaveCount(0);
});
