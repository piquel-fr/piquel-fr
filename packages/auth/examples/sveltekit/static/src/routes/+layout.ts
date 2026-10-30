import { Issuer } from '@piquel/auth';
import { type BrowserClient, type Session, browserClient } from '@piquel/auth/browser';
import { type Load, redirect } from '@sveltejs/kit';

// adapter-static with a fallback page: the app runs in the browser only, as a public client.
export const ssr = false;

let auth: BrowserClient | undefined;
let session: Session | null = null;

/**
 * Signs the user in once per page load: finishes the callback auth sends to `/`,
 * then shows the page the login left from, or restores the session with prompt=none.
 */
export const load: Load = async ({ url }) => {
  auth ??= browserClient(await Issuer.discover('https://auth.piquel.fr'), {
    clientId: 'notes-web',
    redirectUri: `${url.origin}/`
  });
  if (!session) {
    const before = location.href;
    const signedIn = await auth.handleCallback().catch((error: unknown) => {
      // The sign-in failed, such as the user cancelling at auth: stay signed out.
      console.error(error);
      return null;
    });
    // A callback, with or without a session, put the page the login left from back
    // in the address bar: render that page rather than the callback.
    if (location.href !== before) {
      session = signedIn;
      redirect(303, location.href);
    }
    session = await auth.restore({ scopes: ['profile'] });
  }
  return { auth, session };
};
