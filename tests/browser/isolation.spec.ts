/**
 * What auth's pages may ask of the browser, as Chromium enforces their
 * Permissions-Policy: passkeys and writing to the clipboard, and none of the
 * features it turns off.
 */
import { expect, test } from '@playwright/test';

/** Every feature the policy turns off, which no page of auth's uses. */
const off = [
  'accelerometer',
  'ambient-light-sensor',
  'attribution-reporting',
  'autoplay',
  'bluetooth',
  'browsing-topics',
  'camera',
  'captured-surface-control',
  'clipboard-read',
  'compute-pressure',
  'digital-credentials-get',
  'direct-sockets',
  'display-capture',
  'encrypted-media',
  'fullscreen',
  'gamepad',
  'geolocation',
  'gyroscope',
  'hid',
  'identity-credentials-get',
  'idle-detection',
  'join-ad-interest-group',
  'keyboard-map',
  'local-fonts',
  'magnetometer',
  'microphone',
  'midi',
  'otp-credentials',
  'payment',
  'picture-in-picture',
  'private-state-token-issuance',
  'private-state-token-redemption',
  'run-ad-auction',
  'screen-wake-lock',
  'serial',
  'smart-card',
  'speaker-selection',
  'storage-access',
  'usb',
  'web-share',
  'window-management',
  'xr-spatial-tracking'
];

test("auth's pages may use passkeys and the clipboard, and no feature their policy turns off", async ({
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
  expect(allowed.filter((feature) => off.includes(feature))).toEqual([]);
});
