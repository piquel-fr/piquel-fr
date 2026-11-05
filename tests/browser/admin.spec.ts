import { expect, test, type Browser, type Locator, type Page } from '@playwright/test';
import {
  addPasskeys,
  addSecondPasskey,
  authorization,
  authUrl,
  cli,
  consent,
  mailed,
  mailUrl,
  scrollsSideways,
  serveClient,
  signedUp,
  signUp,
  viewports,
  withPasskeys
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
 * page opened directly sends the browser: auth asks for one,
 * for the dashboard only, then the dashboard shows the change's form.
 */
async function confirmThroughAuth(admin: Page): Promise<void> {
  await expect(admin.getByRole('heading', { name: "Confirm it's you" })).toBeVisible();
  await admin.getByRole('button', { name: 'Confirm with a passkey', exact: true }).click();
  await admin.waitForURL((url) => url.origin === adminUrl);
}

/**
 * Follows the dashboard's `link` to a change, which its first change asks to
 * confirm: the dashboard asks for a passkey, for the dashboard only, in a
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

test('rights granted from the dashboard open it, until revoked, and the audit chain keeps both', async ({
  browser
}) => {
  const suffix = Date.now().toString(36);
  const admin = await administrator(browser, `granter-${suffix}`);
  const user = await signedUp(browser, `grantee-${suffix}`);

  // The chain's newest position, once every event so far is sealed, within seconds.
  const newest = async () => {
    await expect
      .poll(
        async () => {
          await admin.goto(`${adminUrl}/audit`);
          return admin.locator('dt:text-is("Unsealed") + dd').textContent();
        },
        { timeout: 15_000 }
      )
      .toBe('0');
    await expect(admin.getByText('Intact', { exact: true })).toBeVisible();
    await expect(admin.getByText('Broken', { exact: true })).toHaveCount(0);
    // A point of the chain reads as its position, then its hash.
    const point = await admin.locator('dt:text-is("Newest") + dd').textContent();
    return Number(point?.split(' ')[0]);
  };
  const before = await newest();

  // Rights are granted from a search, each result confirming in its own dialog.
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
  // The grant joined the audit chain, which still verifies.
  const granted = await newest();
  expect(granted).toBeGreaterThan(before);

  await admin.goto(`${adminUrl}/administrators`);
  await row(`grantee-${suffix}`).getByRole('button', { name: 'Revoke', exact: true }).click();
  const revoke = admin.getByRole('dialog', { name: 'Revoke administrator rights' });
  await revoke.getByRole('button', { name: 'Revoke', exact: true }).click();
  await expect(admin).toHaveURL(`${adminUrl}/administrators`);
  await expect(row(`grantee-${suffix}`)).toHaveCount(0);
  // So did the revocation.
  expect(await newest()).toBeGreaterThan(granted);
  // The account keeps its session, but no longer reaches the dashboard.
  await user.goto(`${adminUrl}/users`);
  await expect(user.getByRole('heading', { name: 'This account has no access' })).toBeVisible();
});

test('an invitation from the dashboard signs one person up, and a revoked one nobody', async ({
  browser
}) => {
  test.skip(!process.env.E2E_INVITE, 'Signup needs no invitation: set E2E_INVITE where it does.');
  const suffix = Date.now().toString(36);
  const admin = await administrator(browser, `inviter-${suffix}`);
  /** Creates an invitation, valid for a day, and answers its link. */
  const invite = async () => {
    await admin.goto(`${adminUrl}/invitations`);
    await admin.getByRole('link', { name: 'Invite someone', exact: true }).click();
    await admin.getByLabel('Valid for').fill('1d');
    await admin.getByRole('button', { name: 'Create link', exact: true }).click();
    await expect(admin.getByRole('heading', { name: 'Invitation created' })).toBeVisible();
    return admin.getByLabel('Signup link').inputValue();
  };
  /** Whether signing up as `handle` with `link`'s invitation is refused. */
  const refused = async (link: string, handle: string) => {
    const page = await withPasskeys(browser);
    await page.goto(link);
    await page.getByLabel('Handle', { exact: true }).fill(handle);
    await page.getByLabel('Passkey name', { exact: true }).fill('Passkey');
    await page.getByRole('button', { name: 'Create account with a passkey' }).click();
    await expect(page.getByRole('alert')).toBeVisible();
    await expect(page).toHaveURL(/\/register/);
  };
  await admin.goto(`${adminUrl}/invitations/new`);
  await confirmThroughAuth(admin);
  const first = await invite();
  expect(new URL(first).origin).toBe(authUrl);
  // The link shows once, on a page reached by `GET`: reloading it shows the form
  // again, and creates nothing.
  await admin.reload();
  await expect(admin.getByRole('heading', { name: 'Invitation created' })).toHaveCount(0);
  await expect(admin.getByLabel('Valid for')).toBeVisible();

  // The link signs one account up, once.
  await signUp(await withPasskeys(browser), `invited-${suffix}`, 'Passkey', first);
  await refused(first, `again-${suffix}`);

  // A revoked link signs nobody up. The open invitation is the only one with a
  // button: the redeemed one has none.
  const second = await invite();
  await admin.getByRole('link', { name: 'Done', exact: true }).click();
  // Invitations list newest first.
  await admin.getByRole('row').nth(1).getByRole('button', { name: 'Revoke', exact: true }).click();
  await admin
    .getByRole('dialog', { name: 'Revoke this invitation' })
    .getByRole('button', { name: 'Revoke', exact: true })
    .click();
  await expect(admin).toHaveURL(`${adminUrl}/invitations`);
  await expect(admin.getByRole('row').nth(1)).toContainText('Revoked');
  await refused(second, `revoked-${suffix}`);
});

test('an origin approved from the dashboard is listed for passkeys until removed', async ({
  browser
}) => {
  // `browser-e2e-sdk`, a trusted client, redirects to this origin.
  const origin = 'https://sdk-e2e.test';
  const admin = await administrator(browser, `origins-${Date.now().toString(36)}`);
  /** The origins auth lists for browsers to accept passkeys on. */
  const related = async () => {
    const response = await admin.request.get(new URL('/.well-known/webauthn', authUrl).href);
    return ((await response.json()) as { origins: string[] }).origins;
  };
  const page = `${adminUrl}/clients/browser-e2e-sdk/overview`;
  const card = admin
    .locator('section')
    .filter({ has: admin.getByRole('heading', { name: 'Passkey sign-in' }) });
  expect(await related()).not.toContain(origin);

  // The clients list opens each client's page, which lists its approved origins.
  await admin.goto(`${adminUrl}/clients`);
  await admin.getByRole('link', { name: 'Browser E2E SDK', exact: true }).click();
  await expect(admin).toHaveURL(page);
  await confirmInDialog(
    admin,
    card.getByRole('link', { name: 'Add approved origin', exact: true })
  );
  // An origin of none of the client's redirect URIs is refused, keeping what was typed.
  const field = admin.getByLabel('Origin', { exact: true });
  await field.fill('https://elsewhere-e2e.test');
  await admin.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(admin.getByRole('alert')).toBeVisible();
  await expect(field).toHaveValue('https://elsewhere-e2e.test');
  await field.fill(origin);
  await admin.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(admin).toHaveURL(page);
  await expect(card.getByText(origin, { exact: true })).toBeVisible();
  expect(await related()).toContain(origin);

  await card.getByRole('link', { name: `Remove ${origin}`, exact: true }).click();
  await expect(admin.getByText(`Client browser-e2e-sdk, origin ${origin}.`)).toBeVisible();
  await admin.getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(admin).toHaveURL(page);
  await expect(card.getByText(origin, { exact: true })).toHaveCount(0);
  expect(await related()).not.toContain(origin);
});

test('an administrator registers a client, suspends it and rotates its secret, each shown once', async ({
  browser
}) => {
  const suffix = Date.now().toString(36);
  const admin = await administrator(browser, `clients-${suffix}`);
  const id = `e2e-${suffix}`;

  // Registering is a change, so the dashboard confirms with a passkey first.
  await admin.goto(`${adminUrl}/clients`);
  await confirmInDialog(admin, admin.getByRole('link', { name: 'Register a client', exact: true }));
  await admin.getByRole('textbox', { name: 'Client ID', exact: true }).fill(id);
  await admin.getByRole('textbox', { name: 'App name', exact: true }).fill(`E2E ${suffix}`);
  const redirects = admin.getByRole('textbox', { name: 'Redirect URIs', exact: true });
  await redirects.fill('not a URI');
  await admin.getByRole('button', { name: 'Register', exact: true }).click();
  // A refused setting keeps what was typed.
  await expect(admin.getByRole('alert')).toContainText('redirect_uris');
  await expect(admin.getByRole('textbox', { name: 'Client ID', exact: true })).toHaveValue(id);
  await redirects.fill(`https://${id}.test/callback`);

  // Registering goes on to the client's page, which shows a confidential client's
  // first secret once, in an answer no cache keeps, the secret in no URL.
  // Reloading it, with no script to rewrite the history, posts nothing again.
  const shown = admin.waitForResponse(
    (response) =>
      response.request().method() === 'GET' &&
      response.url() === `${adminUrl}/clients/${id}/overview`
  );
  await admin.getByRole('button', { name: 'Register', exact: true }).click();
  expect((await shown).headers()['cache-control']).toBe('no-store, no-transform');
  await expect(admin).toHaveURL(`${adminUrl}/clients/${id}/overview`);
  await expect(admin.getByRole('heading', { name: 'Your client secret' })).toBeVisible();
  const secret = (await admin.locator('#client-secret').textContent()) ?? '';
  expect(secret).toMatch(/^pqcs_/);
  await admin.reload();
  await expect(admin.getByRole('heading', { name: `E2E ${suffix}` })).toBeVisible();
  expect(await admin.content()).not.toContain(secret);

  // Confirmed now, the client's page suspends it from a dialog: it stops working,
  // and only an administrator can let its owner enable it again.
  await admin.getByRole('button', { name: 'Suspend', exact: true }).click();
  const suspend = admin.getByRole('dialog', { name: 'Suspend this client' });
  await suspend.getByRole('button', { name: 'Suspend', exact: true }).click();
  await expect(admin.getByText('Suspended', { exact: true })).toBeVisible();
  await expect(admin.getByRole('button', { name: 'Lift suspension', exact: true })).toBeVisible();

  // A rotation shows the new secret the same way, once: reloading neither shows
  // it again nor rotates again.
  await admin.getByRole('link', { name: 'Rotate the secret', exact: true }).click();
  await admin.getByRole('button', { name: 'Rotate secret', exact: true }).click();
  await expect(admin).toHaveURL(`${adminUrl}/clients/${id}/secret`);
  await expect(admin.getByRole('heading', { name: 'Your client secret' })).toBeVisible();
  const rotated = (await admin.locator('#client-secret').textContent()) ?? '';
  expect(rotated).toMatch(/^pqcs_/);
  expect(rotated).not.toBe(secret);
  await expect(admin.getByText('Expiring', { exact: true })).toBeVisible();
  await admin.reload();
  await expect(admin.getByRole('heading', { name: 'Your client secret' })).toHaveCount(0);
  expect(await admin.content()).not.toContain(rotated);
  await expect(admin.getByText('Expiring', { exact: true })).toHaveCount(1);

  // The crumb leads back to the client. Deleting it goes back to the list,
  // which still opens its page.
  await admin
    .locator('.crumb')
    .getByRole('link', { name: `E2E ${suffix}`, exact: true })
    .click();
  await admin.getByRole('button', { name: 'Delete', exact: true }).click();
  const remove = admin.getByRole('dialog', { name: 'Delete this client' });
  await remove.getByRole('button', { name: 'Delete for good', exact: true }).click();
  await expect(admin).toHaveURL(`${adminUrl}/clients`);
  await admin
    .getByRole('row', { name: new RegExp(id) })
    .getByRole('link')
    .click();
  await expect(admin.getByText(/Deleted on/)).toBeVisible();

  // Its change pages, opened by URL, say why instead of showing a form that
  // could only be refused.
  await admin.goto(`${adminUrl}/clients/${id}/settings`);
  await expect(admin.getByText(`client ${id} was deleted`)).toBeVisible();
  await expect(admin.getByRole('button', { name: 'Save changes', exact: true })).toHaveCount(0);
});

test("an administrator changes an account's passkeys, addresses and apps, and its owner sees why", async ({
  browser
}) => {
  test.skip(!mailUrl, 'Set E2E_MAIL_URL to the API of the Mailpit receiving the email.');
  // The `browser-e2e` public client's origin, which the test serves.
  const client = 'https://browser-e2e.test';
  const suffix = Date.now().toString(36);
  const handle = `behalf-${suffix}`;
  const [first, second] = [`first-${suffix}@e2e.test`, `second-${suffix}@e2e.test`];
  const admin = await administrator(browser, `support-${suffix}`);

  // The owner adds two addresses, a second passkey and an app.
  const context = await browser.newContext();
  const owner = await context.newPage();
  const { cdp, authenticatorId } = await addPasskeys(context, owner);
  await serveClient(context, cdp, client);
  await signUp(owner, handle, 'First passkey');
  await addAddress(owner, first);
  await addAddress(owner, second);
  const lost = await addSecondPasskey(owner, cdp, authenticatorId, 'Second passkey');
  await owner.goto(authorization('browser-e2e', `${client}/callback`).url);
  await consent(owner, 'Browser E2E', client);

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

  await tabs.getByRole('link', { name: 'Connected apps', exact: true }).click();
  await admin.getByRole('button', { name: 'Remove access for Browser E2E', exact: true }).click();
  await admin.getByLabel('Reason, shown to the owner in their history').fill('Unwanted app');
  await admin.getByRole('button', { name: 'Remove access', exact: true }).click();
  await expect(admin.getByText('No app has access to this account.')).toBeVisible();

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
  await owner.goto('/settings/apps');
  await expect(owner.getByText('No apps have access to your account.')).toBeVisible();
  await owner.goto('/settings/history');
  for (const [change, reason] of [
    ['Passkey renamed', 'Named for the owner'],
    ['Passkey removed', 'Reported lost'],
    [`Primary email address changed to ${second}`, 'Asked by the owner'],
    ['Email address removed', 'Mailbox closed'],
    ['App access withdrawn', 'Unwanted app']
  ]) {
    await expect(entry(owner, change, reason)).toBeVisible();
  }
});

test('a recovery started from the dashboard mails its link, and the dashboard undoes it', async ({
  browser
}) => {
  test.skip(!mailUrl, 'Set E2E_MAIL_URL to the API of the Mailpit receiving the email.');
  const suffix = Date.now().toString(36);
  const handle = `lost-${suffix}`;
  const address = `${handle}@e2e.test`;
  const admin = await administrator(browser, `rescuer-${suffix}`);
  const owner = await signedUp(browser, handle);
  // The link goes only to a verified primary address.
  await addAddress(owner, address);

  await openAccount(admin, handle);
  await confirmInDialog(admin, admin.getByRole('link', { name: 'Recover', exact: true }));
  const reason = 'Reason, shown to the owner in their history: what was asked, never the evidence';
  await admin.getByLabel(reason).fill('Lost every passkey');
  await admin.getByRole('button', { name: 'Send the recovery link', exact: true }).click();
  await expect(admin.getByRole('heading', { name: handle, level: 1 })).toBeVisible();

  // Whoever holds the mailbox adds a passkey with the link.
  const recovering = await withPasskeys(browser);
  await recovering.goto(await mailed(address, /https?:\/\/\S+\/recover#token=\S+/));
  await recovering.getByRole('button', { name: 'Continue', exact: true }).click();
  await recovering.getByLabel('Passkey name', { exact: true }).fill('Recovered passkey');
  await recovering.getByRole('button', { name: 'Create a passkey', exact: true }).click();
  await expect(
    recovering.getByText('Your account is recovered. Your new passkey signs you in.')
  ).toBeVisible();

  // Support undoes it for an owner it confirmed: the recovery's passkey goes, and
  // every session with it.
  await admin.getByRole('link', { name: 'Undo recovery', exact: true }).click();
  await admin.getByLabel(reason).fill('Not the owner');
  await admin.getByRole('button', { name: 'Undo the recovery', exact: true }).click();
  await recovering.reload();
  await expect(recovering.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible();

  // The owner signs in with the passkey from before, and reads both in the history.
  await owner.goto('/login');
  await owner.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(owner).toHaveURL('/settings');
  await owner.goto('/settings/sign-in');
  await expect(owner.getByRole('heading', { name: 'Passkeys 1', exact: true })).toBeVisible();
  await owner.goto('/settings/history');
  await expect(
    entry(owner, 'Account recovery started by Piquel support', 'Lost every passkey')
  ).toBeVisible();
  await expect(entry(owner, 'Account recovery undone', 'Not the owner')).toBeVisible();
});

test('a handle support renames signs in at once, while the owner waits a month', async ({
  browser
}) => {
  const suffix = Date.now().toString(36);
  const admin = await administrator(browser, `renamer-${suffix}`);
  const owner = await signedUp(browser, `old-${suffix}`);
  // An owner changes their handle once every 30 days, counting from signup.
  await owner.goto('/settings/profile');
  await expect(owner.getByRole('button', { name: 'Change handle', exact: true })).toBeDisabled();
  await expect(owner.getByText(/You can change it again on/)).toBeVisible();

  // Support renames it without waiting, such as a handle that impersonates another.
  await openAccount(admin, `old-${suffix}`);
  await confirmInDialog(admin, admin.getByRole('link', { name: 'Change handle', exact: true }));
  await admin.getByLabel('New handle').fill(`new-${suffix}`);
  await admin.getByLabel('Reason, shown to the owner in their history').fill('Impersonation');
  await admin.getByRole('button', { name: 'Change handle', exact: true }).click();
  // It lands on the account's Profile tab, whose Handle row shows the new one.
  await expect(
    admin.getByRole('definition').getByText(`@new-${suffix}`, { exact: true })
  ).toBeVisible();

  await owner.reload();
  await expect(
    owner.getByRole('definition').getByText(`@new-${suffix}`, { exact: true })
  ).toBeVisible();
  await owner.goto('/settings/history');
  await expect(entry(owner, 'Handle changed', 'Impersonation')).toBeVisible();

  // The old handle signs nobody in; the new one does.
  await owner.context().clearCookies();
  await owner.goto('/login');
  await owner.getByRole('button', { name: 'Use a handle instead', exact: true }).click();
  const field = owner.getByLabel('Handle', { exact: true });
  const signIn = owner.getByRole('button', { name: 'Sign in with a passkey', exact: true });
  await field.fill(`old-${suffix}`);
  await signIn.click();
  await expect(owner.locator('form', { has: signIn }).getByRole('alert')).toHaveText(
    'No active account has this handle.'
  );
  await field.fill(`new-${suffix}`);
  await signIn.click();
  await expect(owner).toHaveURL('/settings');
});

/**
 * The pages that once only the terminal had, against the same deployment: an
 * account's security history, signing keys, the delivery queue and handles. Each
 * change leaves the deployment as it found it.
 */
test('an administrator reads a history, rotates a key and checks the queue and handles', async ({
  browser
}) => {
  const suffix = Date.now().toString(36);
  const admin = await administrator(browser, `keeper-${suffix}`);
  await signedUp(browser, `owner-${suffix}`);

  // Reading the history needs no confirmation, and reports nothing: only the
  // owner can.
  await openAccount(admin, `owner-${suffix}`);
  await admin.getByRole('link', { name: 'Security history', exact: true }).click();
  await expect(admin.getByRole('heading', { name: 'Security history', exact: true })).toBeVisible();
  await expect(admin.getByText('Account created with a passkey')).toBeVisible();
  await expect(admin.getByRole('button', { name: /This wasn’t me/ })).toHaveCount(0);

  // Rotating publishes a key that waits a day; revoking it from its row's dialog
  // leaves the key set as it was.
  await admin.getByRole('link', { name: 'Signing keys', exact: true }).click();
  await confirmInDialog(admin, admin.getByRole('link', { name: 'Rotate', exact: true }));
  await admin.getByRole('button', { name: 'Rotate', exact: true }).click();
  await expect(admin).toHaveURL(`${adminUrl}/keys`);
  // The badge, not the revoke dialog's text, which every row holds.
  const waiting = admin
    .getByRole('row')
    .filter({ has: admin.getByText('Waiting', { exact: true }) });
  await expect(waiting).toHaveCount(1);
  const id = (await waiting.locator('code').first().textContent()) ?? '';
  await waiting
    .getByRole('button', { name: `Revoke this signing key: ${id}`, exact: true })
    .click();
  const revoke = admin.getByRole('dialog', { name: 'Revoke this signing key' });
  await revoke.getByRole('button', { name: 'Revoke', exact: true }).click();
  await expect(admin.getByRole('row').filter({ hasText: id })).toHaveCount(0);

  // The queue filters by status without a script.
  await admin.getByRole('link', { name: 'Deliveries', exact: true }).click();
  await admin.getByLabel('Status').selectOption('failed');
  await admin.getByRole('button', { name: 'Filter', exact: true }).click();
  await expect(admin).toHaveURL(/status=failed/);
  await expect(admin.getByRole('heading', { name: 'Deliveries', exact: true })).toBeVisible();

  // A handle is reserved for someone, listed with why, and removed again from
  // its row's dialog.
  await admin.getByRole('link', { name: 'Handles', exact: true }).click();
  await admin.getByRole('link', { name: 'Reserve a handle', exact: true }).click();
  await admin.getByLabel('Handle', { exact: true }).fill(`kept-${suffix}`);
  await admin.getByLabel('Who or what it is kept for').fill('Browser test');
  await admin.getByRole('button', { name: 'Reserve', exact: true }).click();
  await expect(admin).toHaveURL(`${adminUrl}/handles`);
  await expect(admin.getByText('Browser test')).toBeVisible();
  await admin
    .getByRole('button', { name: `Remove this reservation: @kept-${suffix}`, exact: true })
    .click();
  const unreserve = admin.getByRole('dialog', { name: 'Remove this reservation' });
  await unreserve.getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(admin.getByText(`@kept-${suffix}`, { exact: true })).toHaveCount(0);
});
