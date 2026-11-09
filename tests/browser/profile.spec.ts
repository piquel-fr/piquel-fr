/**
 * The Profile tab's dialogs, which open without a script: uploading a picture,
 * which the pages load under their Content-Security-Policy, and removing it; then
 * the picture script's crop, where zooming and dragging change the square the
 * form sends.
 */
import { expect, test } from '@playwright/test';
import { signedUp } from './helpers';

/** A 1×1 PNG, which auth stores as a 512-pixel square JPEG. */
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==',
  'base64'
);

/**
 * The profile's dialogs, which open with no script: a picture the page, the sidebar
 * and the top bar load under their Content-Security-Policy, a notice that closes,
 * and removing the picture, which brings the initials back.
 */
test('profile: a picture, and a notice that closes', async ({ browser }) => {
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

  await page.getByRole('button', { name: 'Remove', exact: true }).click();
  const remove = page.getByRole('dialog', { name: 'Remove the picture?' });
  await remove.getByRole('button', { name: 'Remove picture', exact: true }).click();
  await expect(page.getByText('Your profile picture was removed.')).toBeVisible();
  await expect(pictures).toHaveCount(0);
  // The display name's initial: signup names the account after its handle.
  await expect(page.locator('span.avatar.large')).toHaveText('P');
});

/**
 * The picture form's crop: a chosen image shows under a circle, at its centred
 * square, and zooming in and dragging it choose the square the form sends, which
 * auth keeps.
 */
test('profile: zooming and dragging choose the square a picture keeps', async ({ browser }) => {
  const page = await signedUp(browser, `crop-${Date.now().toString(36)}`);
  await page.goto('/settings/profile');
  // A 600 by 400 image, drawn here: blue, but red along its top 100 pixels, which
  // the centred square keeps and the square chosen below leaves out.
  const wide = await page.evaluate(() => {
    const canvas = document.createElement('canvas');
    canvas.width = 600;
    canvas.height = 400;
    const context = canvas.getContext('2d');
    if (!context) throw new Error('no canvas');
    context.fillStyle = '#4353e0';
    context.fillRect(0, 0, 600, 400);
    context.fillStyle = '#e04343';
    context.fillRect(0, 0, 600, 100);
    return canvas.toDataURL('image/png').split(',')[1];
  });
  await page.getByRole('button', { name: 'Add a picture', exact: true }).click();
  const choose = page.getByRole('dialog', { name: 'Choose a picture' });
  await choose.getByLabel('Picture', { exact: true }).setInputFiles({
    name: 'wide.png',
    mimeType: 'image/png',
    buffer: Buffer.from(wide, 'base64')
  });
  const stage = choose.getByRole('application', { name: /The part of the picture apps show/ });
  await expect(stage).toBeVisible();
  const square = () =>
    page.evaluate(() =>
      ['crop_x', 'crop_y', 'crop_size'].map((name) =>
        Number(document.querySelector<HTMLInputElement>(`input[name="${name}"]`)?.value)
      )
    );
  expect(await square()).toEqual([100, 0, 400]);

  await choose.getByLabel('Zoom').evaluate((zoom: HTMLInputElement) => {
    zoom.value = '2';
    zoom.dispatchEvent(new Event('input'));
  });
  expect(await square()).toEqual([200, 100, 200]);
  // Dragging the image left moves the square right.
  const box = await stage.boundingBox();
  if (!box) throw new Error('no stage');
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width / 2 - 40, box.y + box.height / 2);
  await page.mouse.up();
  const [x, y, size] = await square();
  expect(x).toBeGreaterThan(200);
  expect([y, size]).toEqual([100, 200]);

  await choose.getByRole('button', { name: 'Upload picture', exact: true }).click();
  await expect(page.getByText('Your profile picture changed.')).toBeVisible();
  // The stored picture's top-left corner is blue, not the centred square's red.
  const stored = page.locator('img.avatar.large');
  await expect
    .poll(() => stored.evaluate((image: HTMLImageElement) => image.naturalWidth))
    .toBe(512);
  const corner = await stored.evaluate((image: HTMLImageElement) => {
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 512;
    const context = canvas.getContext('2d');
    if (!context) throw new Error('no canvas');
    context.drawImage(image, 0, 0);
    return Array.from(context.getImageData(8, 8, 1, 1).data.slice(0, 3));
  });
  const [red, , blue] = corner;
  expect(blue).toBeGreaterThan(red);
});
