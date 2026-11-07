/**
 * A page with no server signing users in with `@piquel/auth/browser`, as a public
 * client. Tokens live in the page's memory only. Bundle it into a page served at the
 * redirect URI's origin, with a `#sign-in` button, a `#sign-out` button and a
 * `#notes` list. An app outside this repository imports `@piquel/auth` and
 * `@piquel/auth/browser` instead of the sources. The `ANCHOR` comments mark the parts
 * `docs/user/apps/browser-apps.md` shows.
 */
import { browserClient, type Session } from '../src/browser.ts';
import { Issuer } from '../src/index.ts';

// ANCHOR: client
const issuer = await Issuer.discover('https://auth.piquel.fr');
const auth = browserClient(issuer, {
  clientId: 'notes-web',
  redirectUri: `${location.origin}/callback`
});
// ANCHOR_END: client

// ANCHOR: session
/** Shows the signed-in user's notes, from an API that accepts their access token. */
async function show(session: Session): Promise<void> {
  // Sends the access token, refreshing it first when it is about to expire.
  const response = await session.fetch('https://notes.example/api/notes');
  const notes = (await response.json()) as string[];
  document
    .querySelector('#notes')
    ?.replaceChildren(
      ...notes.map((note) => Object.assign(document.createElement('li'), { textContent: note }))
    );
  document.querySelector('#sign-out')?.addEventListener('click', () => {
    void session.logout(`${location.origin}/`);
  });
}
// ANCHOR_END: session

// ANCHOR: load
// On every page load: finish a callback, or restore the session with prompt=none,
// which leaves the page and comes back, or returns null once the user is signed out.
const session = (await auth.handleCallback()) ?? (await auth.restore({ scopes: ['profile'] }));
if (session) {
  await show(session);
} else {
  // On the user's click: a passkey on this page, or auth's pages when it cannot.
  document.querySelector('#sign-in')?.addEventListener('click', () => {
    void auth.signInWithPasskey({ scopes: ['profile'] }).then(show);
  });
}
// ANCHOR_END: load
