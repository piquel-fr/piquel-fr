import { expect, test, type Page } from '@playwright/test';

const credentialScript = () => {
  const bytes = (values: number[]) => new Uint8Array(values).buffer;
  Object.defineProperty(window, 'PublicKeyCredential', {
    configurable: true,
    value: class PublicKeyCredential {}
  });
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: {
      get: async () => ({
        id: 'credential-id',
        rawId: bytes([1, 2, 3]),
        type: 'public-key',
        response: {
          authenticatorData: bytes([4, 5]),
          clientDataJSON: bytes([6, 7]),
          signature: bytes([8, 9]),
          userHandle: bytes([10])
        },
        getClientExtensionResults: () => ({})
      }),
      create: async () => ({
        id: 'new-credential-id',
        rawId: bytes([11, 12]),
        type: 'public-key',
        response: {
          attestationObject: bytes([13, 14]),
          clientDataJSON: bytes([15, 16])
        },
        getClientExtensionResults: () => ({})
      })
    }
  });
};

async function mockSecurity(page: Page) {
  await page.route('**/account/passkeys', (route) => route.fulfill({
    json: [{ id: 'passkey-1', friendly_name: 'Laptop' }]
  }));
  await page.route('**/account/social-identities', (route) => route.fulfill({
    json: [{ provider: 'github', linked_email: 'person@example.test' }]
  }));
}

test('passkey login resumes an authorization transaction', async ({ page }) => {
  await page.addInitScript(credentialScript);
  await mockSecurity(page);
  let startBody = '';
  let finishBody = '';
  await page.route('**/webauthn/authenticate/start', async (route) => {
    startBody = route.request().postData() ?? '';
    await route.fulfill({ json: {
      ceremony_id: 'ceremony-1',
      public_key: {
        challenge: 'AQID',
        allowCredentials: [{ type: 'public-key', id: 'BAUG' }]
      }
    } });
  });
  await page.route('**/webauthn/authenticate/finish', async (route) => {
    finishBody = route.request().postData() ?? '';
    await route.fulfill({ status: 204 });
  });

  await page.goto('/login?transaction=authorization-1');
  await page.getByLabel('Username').fill('piquel_user');
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();

  await expect(page).toHaveURL('/authorize?transaction=authorization-1');
  expect(JSON.parse(startBody)).toEqual({ username: 'piquel_user' });
  expect(JSON.parse(finishBody).ceremony_id).toBe('ceremony-1');
});

test('social login preserves the same server-side continuation', async ({ page }) => {
  await page.goto('/login?transaction=authorization-2');
  await expect(page.getByRole('link', { name: 'Sign in with GitHub' })).toHaveAttribute(
    'href',
    '/login/github?return_to=%2Fauthorize%3Ftransaction%3Dauthorization-2'
  );
  await expect(page.getByRole('link', { name: 'Sign in with Google' })).toHaveAttribute(
    'href',
    '/login/google?return_to=%2Fauthorize%3Ftransaction%3Dauthorization-2'
  );
});

test('authorization renders server-owned grants and posts cancellation', async ({ page }) => {
  await page.route('**/oauth/authorize/transaction/authorization-3', (route) => route.fulfill({
    json: { client_name: 'Piquel Photos', scopes: ['openid', 'profile'], audience: 'photos-api' }
  }));
  let decision = '';
  await page.route('**/oauth/authorize/decision', async (route) => {
    decision = route.request().postData() ?? '';
    await route.fulfill({ status: 303, headers: { location: '/login' } });
  });

  await page.goto('/authorize?transaction=authorization-3');
  await expect(page.getByRole('heading', { name: 'Continue to Piquel Photos' })).toBeVisible();
  await expect(page.getByText('photos-api')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel' }).click();

  await expect(page).toHaveURL('/login');
  expect(new URLSearchParams(decision).get('transaction')).toBe('authorization-3');
  expect(new URLSearchParams(decision).get('decision')).toBe('deny');
});

test('security page enrolls a passkey and performs CSRF-protected logout', async ({ page }) => {
  await page.addInitScript(credentialScript);
  await mockSecurity(page);
  await page.route('**/account/passkeys/enroll/start', (route) => route.fulfill({ json: {
    ceremony_id: 'enrollment-1',
    public_key: {
      challenge: 'AQID',
      user: { id: 'BAUG', name: 'piquel_user', displayName: 'Piquel User' }
    }
  } }));
  let enrollment = '';
  await page.route('**/account/passkeys/enroll/finish', async (route) => {
    enrollment = route.request().postData() ?? '';
    await route.fulfill({ status: 204 });
  });
  let logoutCsrf = '';
  await page.route('**/session/logout', async (route) => {
    logoutCsrf = route.request().headers()['x-piquel-csrf'] ?? '';
    await route.fulfill({ status: 204 });
  });
  page.on('dialog', (dialog) => dialog.accept('Security key'));

  await page.goto('/security');
  await expect(page.getByText('Sign in with GitHub')).toBeVisible();
  await page.getByRole('button', { name: 'Add a passkey' }).click();
  await expect.poll(() => enrollment).not.toBe('');
  expect(JSON.parse(enrollment).friendly_name).toBe('Security key');

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL('/login');
  expect(logoutCsrf).toBe('1');
});
