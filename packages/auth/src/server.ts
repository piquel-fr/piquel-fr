/**
 * Server-side login for `@piquel/auth`, over standard `Request` and `Response`, so
 * it runs as is in Node, Deno, Bun, Workers, Hono, SvelteKit and the like. Tokens
 * stay on the server, in the application's {@link SessionBackend}; the browser holds
 * only a random session key.
 *
 * ```ts
 * import { Issuer } from '@piquel/auth';
 * import { Login, MemoryBackend } from '@piquel/auth/server';
 *
 * const issuer = await Issuer.discover('https://auth.piquel.fr');
 * const login = new Login(issuer.client({ clientId, clientSecret, redirectUri }), {
 *   backend: new MemoryBackend(), // development only: implement SessionBackend
 *   scopes: ['profile']
 * });
 *
 * async function fetch(request: Request): Promise<Response> {
 *   const routed = await login.handle(request); // /auth/login, /callback, /logout, /backchannel-logout
 *   if (routed) return routed;
 *   const user = await login.session(request);
 *   if (!user) return login.signIn(request);
 *   return new Response(`Hello ${user.name}`);
 * }
 * ```
 */
export { Login, SignedIn, type LoginOptions } from './login.ts';
export {
  MemoryBackend,
  checkBackend,
  type SessionBackend,
  type SessionRecord
} from './sessions.ts';
