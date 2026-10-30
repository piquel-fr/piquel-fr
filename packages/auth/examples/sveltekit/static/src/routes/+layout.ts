import { Issuer } from '@piquel/auth';
import { type BrowserClient, browserClient } from '@piquel/auth/browser';
import type { Load } from '@sveltejs/kit';

// adapter-static: the app runs in the browser only, as a public client.
export const ssr = false;

let auth: BrowserClient | undefined;

/** Finishes a callback, or restores the session with prompt=none, on every page load. */
export const load: Load = async ({ url }) => {
  auth ??= browserClient(await Issuer.discover('https://auth.piquel.fr'), {
    clientId: 'notes-web',
    redirectUri: `${url.origin}/callback`
  });
  const session = (await auth.handleCallback()) ?? (await auth.restore({ scopes: ['profile'] }));
  return { auth, session };
};
