import { Issuer } from '@piquel/auth';
import { Login, MemoryBackend } from '@piquel/auth/server';
import { AUTH_CLIENT_ID, AUTH_CLIENT_SECRET, ORIGIN } from '$app/env/private';
import type { RequestEvent } from '@sveltejs/kit';
import type { Handle } from '@sveltejs/kit/hooks';

const issuer = await Issuer.discover('https://auth.piquel.fr');
const login = new Login(
  issuer.client({
    clientId: AUTH_CLIENT_ID,
    clientSecret: AUTH_CLIENT_SECRET,
    redirectUri: `${ORIGIN}/auth/callback`
  }),
  // MemoryBackend is for development: implement SessionBackend to keep sessions.
  { backend: new MemoryBackend(), scopes: ['profile'] }
);

/** A form post from another site, which SvelteKit refuses unless vite.config.js trusts it. */
function crossSiteForm({ request, url }: RequestEvent): boolean {
  const type = request.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() ?? '';
  const form = ['', 'application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain'];
  return (
    ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) &&
    form.includes(type) &&
    request.headers.get('origin') !== url.origin
  );
}

export const handle: Handle = async ({ event, resolve }) => {
  // Back-channel logout is signed; every other cross-site form post is refused.
  if (event.url.pathname !== '/auth/backchannel-logout' && crossSiteForm(event)) {
    return new Response('Cross-site form submissions are forbidden.', { status: 403 });
  }
  const routed = await login.handle(event.request); // /auth/login, /callback, /logout, …
  if (routed) return routed;
  // `event.url` names the page even when the request is for its `__data.json`.
  const page = new Request(event.url, { headers: event.request.headers });
  event.locals.user = await login.session(page);
  return resolve(event);
};
