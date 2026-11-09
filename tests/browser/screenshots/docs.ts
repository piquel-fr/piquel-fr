import { expect, type Locator, type Page } from '@playwright/test';
import { authUrl } from '../helpers';

/**
 * Helpers for the documentation's screenshots, which `just docs screenshots` takes
 * into `docs/images/`. Each run signs up new accounts on a real deployment, so
 * `shoot` first rewrites what changes from run to run into what the guides show:
 * the handle, hosts, IDs and dates.
 */

/** The admin dashboard's origin, when the deployment serves one. */
export const adminUrl = process.env.E2E_ADMIN_URL ?? '';

/**
 * A new handle, which every screenshot shows as `name`: `just docs screenshots`
 * runs on a fresh database, but a spec may run twice against one deployment.
 */
export function handle(name = 'alice'): string {
  return `${name}-docs${Date.now().toString(36)}`;
}

/** The hosts the guides name, for the deployment's own. */
const shownHosts: [string, string][] = [
  [new URL(authUrl).host, 'auth.piquel.fr'],
  ...(adminUrl ? [[new URL(adminUrl).host, 'admin.piquel.fr'] as [string, string]] : [])
];

/**
 * Saves `page` as `docs/images/<name>.png`: the element `area`, or the window,
 * 1280 by 800 pixels, in the dark theme the `docs` project asks for. It first replaces, in the page's text, every handle from
 * `handle` with its name, the deployment's hosts with production's, IDs with fixed
 * ones, and every date with the same one, so the image changes only when the page
 * does. Run with `--update-snapshots=changed`, an image is rewritten only then.
 */
export async function shoot(page: Page, name: string, area?: Locator): Promise<void> {
  await page.setViewportSize({ width: 1280, height: 800 });
  // No focus ring on whatever the spec typed into last.
  await page.evaluate(() => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  await page.evaluate(
    ({ shownHosts }) => {
      let ids = 0;
      const seen = new Map<string, string>();
      // The same ID gets the same stand-in everywhere on the page.
      const id = (value: string) => {
        if (!seen.has(value)) {
          ids += 1;
          seen.set(value, `0195f3a2-7c4d-7e6a-9b1f-${String(ids).padStart(12, '0')}`);
        }
        return seen.get(value) ?? value;
      };
      const replacements: [RegExp, string | ((match: string) => string)][] = [
        // Hosts first: a preview's host may contain what looks like a handle.
        ...shownHosts.map(
          ([from, to]) => [new RegExp(from.replaceAll('.', '\\.'), 'g'), to] as [RegExp, string]
        ),
        [/\b([a-z]+)-docs[a-z0-9]+\b/g, '$1'],
        [/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, id],
        // Client IDs, which auth generates for the apps accounts register.
        [/\bc_[a-z2-7]{20}\b/g, 'c_nq4dx3vlr2kmt7wzbyp5'],
        [
          /\b(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday) \d{1,2} [A-Z][a-z]+ \d{4}\b/g,
          'Tuesday 12 May 2026'
        ],
        [/\b\d{1,2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}\b/g, '12 May 2026 09:41'],
        [/\b\d{1,2} [A-Z][a-z]{2} \d{4}\b/g, '12 May 2026'],
        // A time alone, under a heading naming its day, as the history shows it.
        [/\b\d{2}:\d{2} UTC\b/g, '09:41 UTC'],
        [/\bActive \d+ \w+ ago\b/g, 'Active 2 minutes ago'],
        // Trace IDs, and the host of the container a command ran in.
        [/\b[0-9a-f]{32}\b/g, '4bf92f3577b34da6a3ce929d0e0e4736'],
        [/@[0-9a-f]{12}\b/g, '@auth'],
        [/\b(\d{1,3}\.){3}\d{1,3}\b/g, '203.0.113.7'],
        [/\b[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}\b/g, '2001:db8::7']
      ];
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        let text = node.textContent ?? '';
        for (const [pattern, replacement] of replacements) {
          text = text.replace(pattern, replacement as (match: string) => string);
        }
        node.textContent = text;
      }
      for (const input of document.querySelectorAll('input')) {
        let value = input.value;
        for (const [pattern, replacement] of replacements) {
          value = value.replace(pattern, replacement as (match: string) => string);
        }
        input.value = value;
      }
    },
    { shownHosts }
  );
  const path = `${name}.png`.split('/');
  const options = { animations: 'disabled' } as const;
  await (area
    ? expect(area).toHaveScreenshot(path, options)
    : expect(page).toHaveScreenshot(path, options));
}
