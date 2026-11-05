import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
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
 * The window sizes the pages must work at, the smallest phone to a wide desktop,
 * either side of the drawer's breakpoint. Few, and few pages each: auth's pages
 * share one request budget a minute, which the whole suite spends.
 */
export const viewports = [
  { name: 'small phone', width: 320, height: 568 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'laptop', width: 1280, height: 800 },
  { name: 'desktop', width: 1920, height: 1080 }
];

/** Whether the page body scrolls sideways, which no page may. */
export async function scrollsSideways(page: Page): Promise<boolean> {
  return page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth
  );
}

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
 * Runs `command`, a deployment's CLI named by an environment variable such as
 * `E2E_GRANT_ADMIN`, with `args` appended, and returns what it printed.
 */
export function cli(command: string, ...args: string[]): string {
  const [program, ...given] = command.split(' ');
  return execFileSync(program, [...given, ...args], { encoding: 'utf8' });
}

// A command printing a new signup link, e.g. `just auth invite create`, for a
// deployment whose signup needs an invitation.
const invite = process.env.E2E_INVITE;

/**
 * Signs `handle` up with a passkey named `passkey`, and waits for the settings it
 * lands on. Signup takes the invitation of `link`, or of a link `E2E_INVITE`
 * prints, when set.
 */
export async function signUp(
  page: Page,
  handle: string,
  passkey = 'Passkey',
  link = invite ? cli(invite).trim() : undefined
): Promise<void> {
  await page.goto(link ?? '/register');
  await page.getByLabel('Handle', { exact: true }).fill(handle);
  await page.getByLabel('Passkey name', { exact: true }).fill(passkey);
  await page.getByRole('button', { name: 'Create account with a passkey' }).click();
  await expect(page).toHaveURL('/settings');
}

/**
 * Adds a passkey named `name` from `page`'s sign-in methods, made by a second
 * authenticator: the first, `authenticatorId`, holds the account's passkey
 * already, so it stops answering. Answers the second authenticator's ID.
 */
export async function addSecondPasskey(
  page: Page,
  cdp: CDPSession,
  authenticatorId: string,
  name: string
): Promise<string> {
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
  await page.goto('/settings/sign-in');
  await page.getByText('Add a passkey', { exact: true }).click();
  await page.getByLabel('New passkey name', { exact: true }).fill(name);
  await page.getByRole('button', { name: 'Create the passkey', exact: true }).click();
  await expect(page.getByText('The passkey was added.')).toBeVisible();
  return second.authenticatorId;
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

/** The origin of Mailpit's API, which receives the deployment's email. */
export const mailUrl = process.env.E2E_MAIL_URL ?? '';

/**
 * The first match of `pattern` in the plain text of the newest email Mailpit
 * received for `address` that has one, waiting up to 15 seconds for it: auth
 * sends email from a queue.
 */
export async function mailed(address: string, pattern: RegExp): Promise<string> {
  type Search = { messages: { ID: string }[] };
  const query = new URLSearchParams({ query: `to:"${address}"` });
  for (const deadline = Date.now() + 15_000; Date.now() < deadline;) {
    const search = (await (await fetch(`${mailUrl}/api/v1/search?${query}`)).json()) as Search;
    for (const { ID } of search.messages) {
      const { Text } = (await (await fetch(`${mailUrl}/api/v1/message/${ID}`)).json()) as {
        Text: string;
      };
      const found = pattern.exec(Text)?.[0];
      if (found) return found;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`No email to ${address} matches ${pattern.source}.`);
}

/**
 * An authorization code request of `client` back to `redirectUri`, for `scope`,
 * with a PKCE challenge whose `verifier` redeems its code, and a `nonce`.
 */
export function authorization(client: string, redirectUri: string, scope = 'openid profile') {
  const verifier = randomBytes(32).toString('base64url');
  const nonce = randomBytes(16).toString('base64url');
  const url = new URL('/oauth/authorize', authUrl);
  url.search = new URLSearchParams({
    client_id: client,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: randomBytes(16).toString('base64url'),
    nonce
  }).toString();
  return { url: url.href, verifier, nonce };
}

/**
 * Approves `app`'s consent page on `page`, and returns the code its callback, on
 * `origin`, receives.
 */
export async function consent(page: Page, app: string, origin: string): Promise<string> {
  await expect(page.getByRole('heading', { name: `Continue to ${app}?` })).toBeVisible();
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await page.waitForURL((url) => url.origin === origin);
  return new URL(page.url()).searchParams.get('code') ?? '';
}
