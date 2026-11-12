/**
 * Server-side login for `@sourceorigin/auth`, over standard `Request` and `Response`, so
 * it runs as is in Node, Bun, Workers, Hono, SvelteKit and the like. Sessions live in
 * the browser, in a cookie sealed with the app's {@link CookieKey}: the app stores
 * nothing.
 *
 * ```ts
 * import { Issuer } from '@sourceorigin/auth';
 * import { CookieKey, Login } from '@sourceorigin/auth/server';
 *
 * const issuer = await Issuer.discover('https://auth.sourceorigin.dev');
 * const login = new Login(issuer.client({ clientId, clientSecret, redirectUri }), {
 *   cookieKey: CookieKey.parse(process.env.NOTES_COOKIE_KEY ?? ''), // openssl rand -base64 32
 *   scopes: ['profile']
 * });
 *
 * async function fetch(request: Request): Promise<Response> {
 *   const routed = await login.handle(request); // /auth/login, /callback, /logout
 *   if (routed) return routed;
 *   const user = await login.session(request);
 *   if (user instanceof Response) return user; // 403 from another site, or 503
 *   if (!user) return login.respond(request, login.signIn(request));
 *   // `respond` sets the cookies the session's read needs, such as a refreshed one.
 *   return login.respond(request, new Response(`Hello ${user.name}`));
 * }
 * ```
 */
export { Login, SignedIn, type LoginOptions, type SessionOptions } from './login.ts';
export { CookieKey } from './seal.ts';
