import { Issuer } from '@piquel/auth';
import { Login, MemoryBackend } from '@piquel/auth/server';
import { AUTH_CLIENT_ID, AUTH_CLIENT_SECRET, ORIGIN } from '$app/env/private';
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

export const handle: Handle = async ({ event, resolve }) => {
  const routed = await login.handle(event.request); // /auth/login, /callback, /logout, …
  if (routed) return routed;
  // `event.url` names the page even when the request is for its `__data.json`.
  const { method, headers } = event.request;
  const page = new Request(event.url, { method, headers });
  const user = await login.session(page);
  // 403 for a post, put, patch or delete from another site's pages, before any
  // form action or endpoint runs.
  if (user instanceof Response) return user;
  event.locals.user = user;
  return resolve(event);
};
