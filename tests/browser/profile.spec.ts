import { expect, test } from '@playwright/test';
import { signedUp } from './helpers';

/** A 1×1 PNG, which auth stores as a 512-pixel square JPEG. */
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==',
  'base64'
);

/**
 * The profile's dialogs, which open with no script: a picture the page, the sidebar
 * and the top bar load under their Content-Security-Policy, a notice that closes, a
 * new display name, and removing the picture, which brings the initials back.
 */
test('profile: picture, display name and a notice that closes', async ({ browser }) => {
  const username = `picture-${Date.now().toString(36)}`;
  const page = await signedUp(browser, username);
  const blocked: string[] = [];
  page.on('console', (message) => {
    if (message.text().includes('Content Security Policy')) blocked.push(message.text());
  });

  await page.getByRole('link', { name: 'Profile', exact: true }).click();
  await page.getByRole('button', { name: 'Add a picture', exact: true }).click();
  const choose = page.getByRole('dialog', { name: 'Choose a picture' });
  await choose.getByLabel('Picture', { exact: true }).setInputFiles({
    name: 'me.png',
    mimeType: 'image/png',
    buffer: PNG
  });
  await choose.getByRole('button', { name: 'Upload picture', exact: true }).click();
  const notice = page.getByText('Your profile picture changed.');
  await expect(notice).toBeVisible();
  await page.getByLabel('Dismiss').check();
  await expect(notice).toBeHidden();

  // The sidebar's, the top bar's and the page's own.
  const pictures = page.locator('img.avatar');
  await expect(pictures).toHaveCount(3);
  for (const picture of await pictures.all()) {
    // Loaded and decoded, not blocked.
    await expect
      .poll(() => picture.evaluate((image: HTMLImageElement) => image.naturalWidth))
      .toBe(512);
  }
  expect(blocked).toEqual([]);

  await page.getByRole('button', { name: 'Change display name', exact: true }).click();
  const rename = page.getByRole('dialog', { name: 'Change your display name' });
  await rename.getByLabel('Display name').fill('Ada Lovelace');
  await rename.getByRole('button', { name: 'Save name', exact: true }).click();
  await expect(page.getByText('Your display name changed.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Ada Lovelace' })).toBeVisible();

  await page.getByRole('button', { name: 'Remove', exact: true }).click();
  const remove = page.getByRole('dialog', { name: 'Remove the picture?' });
  await remove.getByRole('button', { name: 'Remove picture', exact: true }).click();
  await expect(page.getByText('Your profile picture was removed.')).toBeVisible();
  await expect(pictures).toHaveCount(0);
  await expect(page.locator('span.avatar.large')).toHaveText('AL');
});
