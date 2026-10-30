import { type BrowserContext, expect, test } from '@playwright/test';
import { type ChildProcess, spawn } from 'node:child_process';
import { once } from 'node:events';
import { addPasskeys, authUrl, signUp } from './helpers';

/**
 * The example app of `@piquel/auth/server`, signing users in as `browser-e2e-server`:
 * a trusted confidential client whose secret is in `E2E_SERVER_CLIENT_SECRET`. Auth
 * accepts plain HTTP redirect URIs on loopback IPs only, and browsers count them as
 * secure, so its `__Host-` cookies work there.
 */
const app = 'http://127.0.0.1:4100';
const secret = process.env.E2E_SERVER_CLIENT_SECRET;

let server: ChildProcess | undefined;

/**
 * The app's cookies. `context.cookies(app)` would leave `Secure` ones out, as for any
 * `http:` URL, although the browser sends them to a loopback address.
 */
async function appCookies(context: BrowserContext) {
  const { hostname } = new URL(app);
  return (await context.cookies()).filter((cookie) => cookie.domain === hostname);
}

test.beforeAll(async () => {
  if (secret === undefined) return;
  const example = new URL('../../packages/auth/examples/server.ts', import.meta.url);
  server = spawn(process.execPath, [example.pathname], {
    env: {
      ...process.env,
      AUTH_URL: authUrl,
      CLIENT_ID: 'browser-e2e-server',
      CLIENT_SECRET: secret,
      APP_URL: app,
      // The app calls auth from Node, which must then accept the suite's test certificates too.
      ...(process.env.E2E_ALLOW_SELF_SIGNED_TLS ? { NODE_TLS_REJECT_UNAUTHORIZED: '0' } : {})
    },
    stdio: ['ignore', 'pipe', 'inherit']
  });
  const [listening] = (await Promise.race([
    once(server.stdout ?? server, 'data'),
    once(server, 'exit').then(([code]) => {
      throw new Error(`the example app exited with ${String(code)}`);
    })
  ])) as [Buffer];
  expect(listening.toString()).toContain('listening');
});

test.afterAll(() => {
  server?.kill();
});

/** Runs against the real Rust binary and an isolated PostgreSQL database. */
test('the server SDK signs in, keeps the session across a reload, and signs out', async ({
  page,
  context
}) => {
  test.skip(secret === undefined, 'E2E_SERVER_CLIENT_SECRET names no registered client secret');
  const username = `server-${Date.now().toString(36)}`;
  await addPasskeys(context, page);
  await signUp(page, username);

  // Signed in at auth, and the client is trusted: login goes straight back.
  await page.goto(app);
  await page.getByRole('link', { name: 'Sign in', exact: true }).click();
  await expect(page.getByText(`Signed in as ${username}.`)).toBeVisible();
  expect(new URL(page.url()).origin).toBe(app);
  const cookies = await appCookies(context);
  expect(cookies.map((cookie) => cookie.name)).toEqual(['__Host-piquel-session']);
  expect(cookies[0]).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Lax', path: '/' });

  await page.reload();
  await expect(page.getByText(`Signed in as ${username}.`)).toBeVisible();
  // A passkey sign-in a moment ago meets the settings page's step-up requirement.
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page.getByText(`Recently confirmed as ${username}.`)).toBeVisible();

  // Signing out ends the app's session, then auth's, which sends the browser back.
  await page.goto(app);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Ready to sign out?' })).toBeVisible();
  expect(await appCookies(context)).toEqual([]);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  // No Content-Security-Policy can name a loopback address, so auth links back.
  await expect(page.getByRole('heading', { name: 'Return to the application' })).toBeVisible();
  await page.getByRole('link', { name: 'Continue', exact: true }).click();
  await expect(page.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible();
  expect(new URL(page.url()).origin).toBe(app);
  await page.goto(`${authUrl}/settings`);
  await expect(page.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible();
});
