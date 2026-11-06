import { expect, test, type Browser, type Locator, type Page } from '@playwright/test';
import {
  addPasskeys,
  addSecondPasskey,
  cli,
  mailed,
  mailUrl,
  scrollsSideways,
  signedUp,
  signUp,
  viewports
} from './helpers';

const adminUrl = process.env.E2E_ADMIN_URL ?? '';
// A command that makes the account named by its last argument an administrator,
// e.g. `just auth admin grant` or `piquelctl app exec … -- auth-service admin grant`.
const grantAdmin = process.env.E2E_GRANT_ADMIN ?? '';

/** Runs against a deployment with the dashboard, as CI's and previews have. */
test.skip(
  !adminUrl || !grantAdmin,
  'Set E2E_ADMIN_URL and E2E_GRANT_ADMIN to run the dashboard tests.'
);

/** A browser of its own, signed up as `handle`, an administrator. */
async function administrator(browser: Browser, handle: string): Promise<Page> {
  const page = await signedUp(browser, handle);
  cli(grantAdmin, handle);
  return page;
}

/**
 * Confirms the dashboard with a passkey on auth's handoff page, where a change's
 * page opened without the dashboard's script sends the browser: auth asks for one,
 * for the dashboard only, then the dashboard shows the change's form.
 */
async function confirmThroughAuth(admin: Page): Promise<void> {
  await expect(admin.getByRole('heading', { name: "Confirm it's you" })).toBeVisible();
  await admin.getByRole('button', { name: 'Confirm with a passkey', exact: true }).click();
  await admin.waitForURL((url) => url.origin === adminUrl);
}

/**
 * Follows the dashboard's `link` to a change, which its first change asks to
 * confirm: the dashboard's script asks for a passkey, for the dashboard only, in a
 * dialog on the page. The page then goes on to the change's form, never leaving
 * the dashboard.
 */
async function confirmInDialog(admin: Page, link: Locator): Promise<void> {
  const target = await link.evaluate((anchor: HTMLAnchorElement) => anchor.href);
  await link.click();
  const dialog = admin.getByRole('dialog', { name: "Confirm it's you" });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Confirm with a passkey', exact: true }).click();
  await expect(admin).toHaveURL(target);
}

/** Opens the dashboard's page of the account `handle`. */
async function openAccount(admin: Page, handle: string): Promise<void> {
  await admin.goto(`${adminUrl}/users?q=${handle}`);
  await admin.getByRole('link', { name: `@${handle}`, exact: true }).click();
}

/** Adds `address` to the account signed in on `page`, confirmed with its emailed link. */
async function addAddress(page: Page, address: string): Promise<void> {
  await page.goto('/settings/emails');
  await page.getByText('Add an address', { exact: true }).click();
  await page.getByLabel('Email address', { exact: true }).fill(address);
  await page.getByRole('button', { name: 'Send a confirmation link', exact: true }).click();
  await expect(
    page.getByText('We sent a confirmation link. Open it to confirm the address.')
  ).toBeVisible();
  await page.goto(await mailed(address, /https?:\/\/\S+\/settings\/emails\/verify#token=\S+/));
  await page.getByRole('button', { name: 'Confirm this address', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Address confirmed' })).toBeVisible();
}

/** The entry of the security history on `page` saying `change`, made by an administrator for `reason`. */
function entry(page: Page, change: string, reason: string) {
  return page
    .getByRole('listitem')
    .filter({ hasText: change })
    .filter({ hasText: `By a Piquel administrator: “${reason}”` })
    .first();
}

/**
 * The top bar at every size: the crumb, the search box and the avatar each keep
 * their own room. The search box has run under the avatar on tablets before, as
 * its input refused to shrink with the form.
 */
test("the dashboard's top bar fits every window size", async ({ browser }) => {
  const admin = await administrator(browser, `bar-${Date.now().toString(36)}`);
  await admin.goto(`${adminUrl}/users`);
  const bar = admin.locator('.topbar');
  const parts = {
    crumb: bar.locator('.crumb'),
    search: bar.locator('.search-box'),
    avatar: bar.getByRole('link', { name: 'Your account', exact: true })
  };
  for (const viewport of viewports) {
    await admin.setViewportSize(viewport);
    expect(await scrollsSideways(admin), viewport.name).toBe(false);
    const boxes = await Promise.all(
      Object.entries(parts).map(async ([name, part]) => {
        const box = await part.boundingBox();
        if (!box) throw new Error(`${viewport.name}: the ${name} is not shown`);
        return { name, ...box };
      })
    );
    for (const [i, a] of boxes.entries()) {
      for (const b of boxes.slice(i + 1)) {
        const crosses =
          a.x < b.x + b.width &&
          b.x < a.x + a.width &&
          a.y < b.y + b.height &&
          b.y < a.y + a.height;
        expect(crosses, `${viewport.name}: ${a.name} crosses ${b.name}`).toBe(false);
      }
    }
  }
});

test('an administrator disables a user from the dashboard, and the user is signed out', async ({
  browser
}) => {
  const suffix = Date.now().toString(36);
  const admin = await administrator(browser, `admin-${suffix}`);
  const user = await signedUp(browser, `user-${suffix}`);

  // Auth's handoff page tells a non-administrator so, and hands nothing off.
  await user.goto(`${adminUrl}/users`);
  await expect(user.getByRole('heading', { name: 'This account has no access' })).toBeVisible();
  await expect(user.getByRole('table')).toHaveCount(0);

  // The administrator's passkey session hands off to the dashboard silently. A
  // change needs the dashboard's own confirmation.
  await openAccount(admin, `user-${suffix}`);
  await confirmInDialog(admin, admin.getByRole('link', { name: 'Disable', exact: true }));
  await admin.getByLabel('Reason').fill('Browser test');
  await admin.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(admin.getByText('Disabled', { exact: true })).toBeVisible();
  await expect(admin.getByText('No active session.')).toBeVisible();

  // Confirmed now, the dashboard offers the next change in a dialog on the page
  // itself, which the browser opens and closes with no script. Cancelling leaves
  // the account as it is; confirming enables it.
  await admin.getByRole('button', { name: 'Enable', exact: true }).click();
  const dialog = admin.getByRole('dialog', { name: 'Enable this account' });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect(admin.getByText('Disabled', { exact: true })).toBeVisible();
  await admin.getByRole('button', { name: 'Enable', exact: true }).click();
  await dialog.getByRole('button', { name: 'Enable', exact: true }).click();
  await expect(admin.getByText('Active', { exact: true })).toBeVisible();

  await user.goto('/settings');
  await expect(user.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(user.getByText(`@user-${suffix}`, { exact: true })).toHaveCount(0);

  // The dashboard sends no referrer, so its sign-out form posts with `Origin: null`.
  // Signing out of the dashboard keeps the Piquel session, so signing in again is
  // silent.
  await admin.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Signed out of the dashboard' })).toBeVisible();
  await admin.getByRole('link', { name: 'Sign in again', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();

  // Signed out of Piquel too, the administrator signs in with a passkey on auth,
  // whose sign-in form then goes on through the handoff to the dashboard.
  await admin.getByRole('button', { name: 'Sign out', exact: true }).click();
  await admin.getByRole('link', { name: 'Sign out of Piquel', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Ready to sign out?' })).toBeVisible();
  await admin.getByRole('button', { name: 'Sign out', exact: true }).click();
  await admin.goto(`${adminUrl}/users`);
  await admin.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
});

test("an administrator's views of an account are listed only when shown", async ({ browser }) => {
  const suffix = Date.now().toString(36);
  const admin = await administrator(browser, `admin-${suffix}`);
  await signedUp(browser, `user-${suffix}`);
  await openAccount(admin, `user-${suffix}`);
  await admin.getByRole('link', { name: 'All events', exact: true }).click();
  const viewed = admin.getByText('Account details viewed');
  const created = admin.getByText('Account created with a passkey');

  // The toggle is a link, so it applies at once, keeping the account filter, which
  // the form then keeps it through.
  await expect(created).toBeVisible();
  await expect(viewed).toHaveCount(0);
  await admin.getByRole('link', { name: 'Show views', exact: true }).click();
  await expect(viewed).toBeVisible();
  await expect(created).toBeVisible();
  await admin.getByRole('button', { name: 'Filter', exact: true }).click();
  await expect(viewed).toBeVisible();
  await admin.getByRole('link', { name: 'Hide views', exact: true }).click();
  await expect(viewed).toHaveCount(0);
  await expect(created).toBeVisible();
});

test('rights granted from the dashboard open it, until revoked', async ({ browser }) => {
  const suffix = Date.now().toString(36);
  const admin = await administrator(browser, `granter-${suffix}`);
  const user = await signedUp(browser, `grantee-${suffix}`);

  // Opened by its address, the change's page sends the browser to auth's handoff
  // page to confirm, then shows the search's results, each result confirming the
  // grant in its own dialog.
  await admin.goto(`${adminUrl}/administrators/grant?q=grantee-${suffix}`);
  await confirmThroughAuth(admin);
  await admin
    .getByRole('button', { name: `Grant administrator rights: @grantee-${suffix}`, exact: true })
    .click();
  const grant = admin.getByRole('dialog', { name: 'Grant administrator rights' });
  await expect(grant.getByText(`@grantee-${suffix}`)).toBeVisible();
  await grant.getByRole('button', { name: 'Grant', exact: true }).click();
  await expect(admin).toHaveURL(`${adminUrl}/administrators`);
  const row = (handle: string) =>
    admin
      .getByRole('listitem')
      .filter({ has: admin.getByRole('link', { name: `@${handle}`, exact: true }) });
  await expect(row(`grantee-${suffix}`)).toBeVisible();
  // Nobody changes their own rights.
  await expect(row(`granter-${suffix}`).getByRole('button', { name: 'Revoke' })).toBeDisabled();
  await expect(row(`granter-${suffix}`)).toContainText('You cannot change your own rights.');
  await user.goto(`${adminUrl}/users`);
  await expect(user.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();

  await admin.goto(`${adminUrl}/administrators`);
  await row(`grantee-${suffix}`).getByRole('button', { name: 'Revoke', exact: true }).click();
  const revoke = admin.getByRole('dialog', { name: 'Revoke administrator rights' });
  await revoke.getByRole('button', { name: 'Revoke', exact: true }).click();
  await expect(admin).toHaveURL(`${adminUrl}/administrators`);
  await expect(row(`grantee-${suffix}`)).toHaveCount(0);
  // The account keeps its session, but no longer reaches the dashboard.
  await user.goto(`${adminUrl}/users`);
  await expect(user.getByRole('heading', { name: 'This account has no access' })).toBeVisible();
});

test("an administrator changes an account's passkeys and addresses, and its owner sees why", async ({
  browser
}) => {
  test.skip(!mailUrl, 'Set E2E_MAIL_URL to the API of the Mailpit receiving the email.');
  const suffix = Date.now().toString(36);
  const handle = `behalf-${suffix}`;
  const [first, second] = [`first-${suffix}@e2e.test`, `second-${suffix}@e2e.test`];
  const admin = await administrator(browser, `support-${suffix}`);

  // The owner adds two addresses, each confirmed from its emailed link, and a
  // second passkey.
  const context = await browser.newContext();
  const owner = await context.newPage();
  const { cdp, authenticatorId } = await addPasskeys(context, owner);
  await signUp(owner, handle, 'First passkey');
  await addAddress(owner, first);
  await addAddress(owner, second);
  const lost = await addSecondPasskey(owner, cdp, authenticatorId, 'Second passkey');

  // Every change asks why, beside its own form.
  await openAccount(admin, handle);
  await confirmInDialog(admin, admin.getByRole('link', { name: 'Sign-in methods', exact: true }));
  await admin.getByRole('button', { name: 'Rename Second passkey', exact: true }).click();
  await admin.getByLabel('Passkey name', { exact: true }).fill('Lost passkey');
  await admin.getByLabel('Reason, shown to the owner in their history').fill('Named for the owner');
  await admin.getByRole('button', { name: 'Save name', exact: true }).click();
  await admin.getByRole('button', { name: 'Remove Lost passkey', exact: true }).click();
  await admin.getByLabel('Reason, shown to the owner in their history').fill('Reported lost');
  await admin.getByRole('button', { name: 'Confirm removal', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Passkeys 1', exact: true })).toBeVisible();

  const tabs = admin.getByRole('navigation').filter({ hasText: 'Connected apps' });
  await tabs.getByRole('link', { name: 'Email addresses', exact: true }).click();
  // Making an address primary takes its reason on its own row.
  const row = admin.getByRole('listitem').filter({ hasText: second });
  await row.getByLabel('Reason, shown to the owner in their history').fill('Asked by the owner');
  await row.getByRole('button', { name: `Make primary ${second}`, exact: true }).click();
  await admin.getByRole('button', { name: `Remove ${first}`, exact: true }).click();
  await admin.getByLabel('Reason, shown to the owner in their history').fill('Mailbox closed');
  await admin.getByRole('button', { name: 'Confirm removal', exact: true }).click();
  await expect(admin.getByText(first)).toHaveCount(0);

  // Removing a passkey signed the owner out. They sign in with the one left.
  await owner.goto('/settings/sign-in');
  await expect(owner.getByRole('heading', { name: 'Sign in to see your settings' })).toBeVisible();
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: lost });
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
  await owner.getByRole('link', { name: 'Sign in', exact: true }).click();
  await owner.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();

  // The owner's settings show the changes, and their history who made them, and why.
  await expect(owner).toHaveURL('/settings/sign-in');
  await expect(owner.getByRole('heading', { name: 'Passkeys 1', exact: true })).toBeVisible();
  await owner.goto('/settings/emails');
  await expect(owner.getByText(first)).toHaveCount(0);
  await expect(owner.getByRole('listitem').filter({ hasText: second })).toContainText('Primary');
  await owner.goto('/settings/history');
  for (const [change, reason] of [
    ['Passkey renamed', 'Named for the owner'],
    ['Passkey removed', 'Reported lost'],
    [`Primary email address changed to ${second}`, 'Asked by the owner'],
    ['Email address removed', 'Mailbox closed']
  ]) {
    await expect(entry(owner, change, reason)).toBeVisible();
  }
});
