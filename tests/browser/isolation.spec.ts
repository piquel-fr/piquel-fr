/**
 * What auth's pages may ask of the browser, as Chromium enforces their
 * Permissions-Policy: passkeys and writing to the clipboard, beside the defaults
 * that reach nothing, so a feature a browser adds, or one the policy misses,
 * fails here rather than slipping through. It sees only what the build the suite
 * runs turns on by default: a feature behind an origin trial, a flag or a field
 * trial, such as `tools`, is in the policy without this test seeing it.
 */
import { expect, test } from '@playwright/test';

/**
 * Allowed features that reach no device, data or other site: the defaults the
 * policy leaves unlisted (`crates/common/src/protocol/isolation.rs`).
 */
const harmless = (feature: string) =>
  feature.startsWith('ch-') ||
  [
    'aria-notify',
    'cross-origin-isolated',
    'execution-while-not-rendered',
    'execution-while-out-of-viewport',
    'focus-without-user-activation',
    'sync-xhr',
    'unload',
    'vertical-scroll'
  ].includes(feature);

test("auth's pages may use passkeys and the clipboard, and nothing else that reaches beyond the page", async ({
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
  expect(allowed.filter((feature) => !harmless(feature)).sort()).toEqual([
    'clipboard-write',
    'publickey-credentials-create',
    'publickey-credentials-get'
  ]);
});
