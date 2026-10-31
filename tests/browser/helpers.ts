import { readFileSync } from 'node:fs';
import {
  expect,
  type Browser,
  type BrowserContext,
  type CDPSession,
  type Page
} from '@playwright/test';

/** Auth's origin, which the suite's `baseURL` also names. */
export const authUrl = process.env.E2E_AUTH_URL ?? 'http://localhost:3000';

/**
 * A virtual platform authenticator on `page`, which verifies its user without
 * asking. A `synced` one backs its credentials up, like a synced passkey.
 */
export async function addPasskeys(
  context: BrowserContext,
  page: Page,
  synced = false
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      defaultBackupEligibility: synced,
      defaultBackupState: synced
    }
  });
  return { cdp, authenticatorId };
}

/**
 * Signs `handle` up with a passkey named `passkey`, with `E2E_INVITATION` when
 * signup needs one, and waits for the settings it lands on.
 */
export async function signUp(page: Page, handle: string, passkey = 'Passkey'): Promise<void> {
  const invitation = process.env.E2E_INVITATION;
  await page.goto(`/register${invitation ? `?invitation=${encodeURIComponent(invitation)}` : ''}`);
  await page.getByLabel('Handle', { exact: true }).fill(handle);
  await page.getByLabel('Passkey name', { exact: true }).fill(passkey);
  await page.getByRole('button', { name: 'Create account with a passkey' }).click();
  await expect(page).toHaveURL('/settings');
}

/** A page in a browser of its own, with a passkey authenticator. */
export async function withPasskeys(browser: Browser): Promise<Page> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await addPasskeys(context, page);
  return page;
}

/** A browser of its own, with a passkey authenticator, signed up as `username`. */
export async function signedUp(browser: Browser, username: string): Promise<Page> {
  const page = await withPasskeys(browser);
  await signUp(page, username);
  return page;
}

/**
 * Serves `origin`, a client application with no server, as a blank page through
 * DevTools, which also sees the redirects that reach it: Playwright's routes would
 * not, and would answer CORS preflights to auth themselves. Its fetches to auth are
 * then genuinely cross-origin. Chromium counts a page with no address as public, and
 * asks before it fetches auth on a local address, as in CI and on previews, so
 * `origin` is granted local network access. `modules` maps paths to JavaScript
 * files served from disk, such as the built SDK.
 */
export async function serveClient(
  context: BrowserContext,
  cdp: CDPSession,
  origin: string,
  modules: Partial<Record<string, string>> = {}
): Promise<void> {
  await context.grantPermissions(['local-network-access'], { origin });
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: `${origin}/*` }] });
  cdp.on('Fetch.requestPaused', ({ requestId, request }) => {
    const module = modules[new URL(request.url).pathname];
    void cdp.send('Fetch.fulfillRequest', {
      requestId,
      responseCode: 200,
      responseHeaders: [
        { name: 'Content-Type', value: module === undefined ? 'text/html' : 'text/javascript' }
      ],
      body: (module === undefined
        ? Buffer.from('<!doctype html><title>Client</title>')
        : readFileSync(module)
      ).toString('base64')
    });
  });
}
