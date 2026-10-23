import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { expect, type BrowserContext, type CDPSession, type Page } from '@playwright/test';

/** The deployment under test, from the variables `README.md` describes. */
export function deployment(): { authUrl: string; settingsUrl: string } {
  const settingsUrl = process.env.E2E_SETTINGS_URL;
  if (!settingsUrl)
    throw new Error(
      'Set E2E_SETTINGS_URL to the separately served piquel-web frontend, with AUTH_ORIGIN matching E2E_AUTH_URL.'
    );
  return { authUrl: process.env.E2E_AUTH_URL ?? 'http://localhost:3000', settingsUrl };
}

/**
 * Adds a virtual platform authenticator that verifies the user without prompting, and
 * whose credentials are backup eligible and backed up, like a synced passkey.
 */
export async function addAuthenticator(
  context: BrowserContext,
  page: Page
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
      defaultBackupEligibility: true,
      defaultBackupState: true
    }
  });
  return { cdp, authenticatorId };
}

/**
 * Registers a new account with a passkey named “Synced passkey”, using `E2E_INVITATION`
 * when signup needs one, and returns its handle once settings show it.
 */
export async function signUp(page: Page): Promise<string> {
  const username = `browser-${Date.now().toString(36)}`;
  const invitation = process.env.E2E_INVITATION;
  await page.goto(`/register${invitation ? `?invitation=${encodeURIComponent(invitation)}` : ''}`);
  await page.getByLabel('Handle', { exact: true }).fill(username);
  await page.getByLabel('Passkey name', { exact: true }).fill('Synced passkey');
  await page.getByRole('button', { name: 'Create account with a passkey' }).click();
  await expect(page).toHaveURL(deployment().settingsUrl);
  await expect(page.getByText(`@${username}`, { exact: true })).toBeVisible();
  return username;
}

/** A PKCE (S256) verifier and challenge, with a fresh `state` and `nonce`. */
export function pkce(): { verifier: string; challenge: string; state: string; nonce: string } {
  const verifier = randomBytes(32).toString('base64url');
  return {
    verifier,
    challenge: createHash('sha256').update(verifier).digest('base64url'),
    state: randomUUID(),
    nonce: randomUUID()
  };
}
