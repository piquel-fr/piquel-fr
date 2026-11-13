/**
 * What auth's pages may ask of the browser, as Chromium enforces their
 * Permissions-Policy: passkeys and writing to the clipboard, and no other
 * feature that reaches a device, the user's data or another site.
 */
import { expect, test } from '@playwright/test';

/** Powerful features no page of auth's uses. */
const unused = [
  'bluetooth',
  'camera',
  'captured-surface-control',
  'clipboard-read',
  'digital-credentials-get',
  'direct-sockets',
  'display-capture',
  'fullscreen',
  'gamepad',
  'geolocation',
  'hid',
  'identity-credentials-get',
  'idle-detection',
  'local-fonts',
  'microphone',
  'midi',
  'otp-credentials',
  'payment',
  'screen-wake-lock',
  'serial',
  'smart-card',
  'speaker-selection',
  'usb',
  'web-share',
  'window-management',
  'xr-spatial-tracking'
];

test("auth's pages may use passkeys and the clipboard, and no other powerful feature", async ({
  page
}) => {
  await page.goto('/login');
  // Chromium's Feature Policy API lists what the page's policy allows it.
  const allowed = await page.evaluate(
    () =>
      (
        document as Document & { featurePolicy?: { allowedFeatures(): string[] } }
      ).featurePolicy?.allowedFeatures() ?? []
  );
  expect(allowed).toEqual(
    expect.arrayContaining([
      'publickey-credentials-get',
      'publickey-credentials-create',
      'clipboard-write'
    ])
  );
  expect(allowed.filter((feature) => unused.includes(feature))).toEqual([]);
});
