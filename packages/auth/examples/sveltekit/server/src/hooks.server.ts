import { Issuer } from '@piquel/auth';
import { Login, MemoryBackend } from '@piquel/auth/server';
import type { Handle } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';

/** A required environment variable, read at startup. */
function setting(name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

const issuer = await Issuer.discover('https://auth.piquel.fr');
const login = new Login(
  issuer.client({
    clientId: setting('AUTH_CLIENT_ID'),
    clientSecret: setting('AUTH_CLIENT_SECRET'),
    redirectUri: `${setting('ORIGIN')}/auth/callback`
  }),
  // MemoryBackend is for development: implement SessionBackend to keep sessions.
  { backend: new MemoryBackend(), scopes: ['profile'] }
);

export const handle: Handle = async ({ event, resolve }) => {
  const routed = await login.handle(event.request); // /auth/login, /callback, /logout, …
  if (routed) return routed;
  event.locals.user = await login.session(event.request);
  return resolve(event);
};
