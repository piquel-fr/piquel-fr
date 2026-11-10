/**
 * Auth's own settings pages: passkeys, which each page tells the password
 * manager about, devices, an email link and signing out; reporting a passkey in
 * the security history as not the owner's, which signs every other device out;
 * and the top bar's search, which finds the settings as the owner types.
 */
import { expect, test } from '@playwright/test';
import {
  addPasskeys,
  addSecondPasskey,
  expectAccepted,
  recordAcceptedCredentials,
  secondAuthenticator,
  signedUp,
  signUp
} from './helpers';

/** Runs against auth's own settings pages, with Chromium's virtual passkey authenticator. */
test('settings on auth: passkeys, devices, an email link and signing out', async ({ browser }) => {
  const context = await browser.newContext();
  await recordAcceptedCredentials(context);
  const page = await context.newPage();
  const { cdp, authenticatorId } = await addPasskeys(context, page);
  let assertions = 0;
  cdp.on('WebAuthn.credentialAsserted', () => (assertions += 1));
  const username = `settings-${Date.now().toString(36)}`;
  await signUp(page, username, 'First passkey');
  // Each page tells the password manager every passkey that still signs in, so it
  // forgets the others: it lists the passkeys the authenticators hold, as they do.
  await expectAccepted(page, cdp, authenticatorId);
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
  const second = await secondAuthenticator(cdp, authenticatorId);
  await page.getByRole('button', { name: 'Create the passkey', exact: true }).click();
  await expect(page.getByText('The passkey was added.')).toBeVisible();
  await expect(page.getByText('Second passkey', { exact: true })).toBeVisible();
  await expectAccepted(page, cdp, authenticatorId, second);

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
  // Only the first authenticator's passkey still signs in.
  await expectAccepted(page, cdp, authenticatorId);
  // The passkey script confirmed with a passkey before posting.
  expect(assertions).toBeGreaterThan(asserted);

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
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: second });
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
  await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/sessions$/);
  await expect(page.getByText('This device', { exact: true })).toBeVisible();
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

/**
 * The top bar's search ranks the settings and the pages as the owner types,
 * forgives a typo, and goes where the chosen result leads: to a section of a
 * page, or to a dialog open on it.
 */
test('the top bar finds settings as the owner types', async ({ browser }) => {
  const page = await signedUp(browser, `search-${Date.now().toString(36)}`);
  const search = page.getByRole('combobox', { name: 'Search settings and apps' });
  const results = page.getByRole('listbox', { name: 'Results' });
  const chosen = results.locator('[aria-selected="true"]');
  // `/` focuses it from anywhere, and an empty query lists the pages.
  await page.locator('main').click();
  await page.keyboard.press('/');
  await expect(search).toBeFocused();
  await expect(results.getByRole('option', { name: /Security history/ })).toBeVisible();

  await search.pressSequentially('passk');
  await expect(chosen).toContainText('Passkeys');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL('/settings/sign-in#passkeys-heading');

  // One letter swapped still finds the page.
  await search.fill('devcies');
  await expect(chosen).toContainText('Devices');

  await search.fill('display name');
  await expect(chosen).toContainText('Change display name');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL('/settings/profile?open=name');
  await expect(page.getByRole('dialog', { name: 'Change your display name' })).toBeVisible();

  await search.fill('nothing like this');
  await expect(page.getByText('Nothing matches.', { exact: true })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(results).toBeHidden();
});
