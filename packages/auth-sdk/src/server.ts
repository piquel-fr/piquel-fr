/**
 * Server-side helpers for piquel.fr's SvelteKit servers. Each server reads its auth
 * origin at runtime, so one image serves every environment:
 *
 * ```ts
 * // src/hooks.server.ts
 * export const handle = AuthOrigin.parse(env.AUTH_ORIGIN, dev).handle;
 * ```
 *
 * Pages read the origin from `locals.authOrigin`, usually through root layout data.
 */
import type { Handle } from '@sveltejs/kit';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- SvelteKit declares app types in this namespace.
  namespace App {
    // eslint-disable-next-line @typescript-eslint/consistent-type-definitions -- only an interface merges with SvelteKit's Locals.
    interface Locals {
      /** The validated auth origin, without a trailing slash. */
      authOrigin: string;
    }
  }
}

/** A bare HTTPS origin, or in development an exact loopback origin. */
export class AuthOrigin {
  private constructor(readonly value: string) {}

  /** Throws unless `value` is a bare origin, so an invalid server never starts listening. */
  static parse(value: string | undefined, dev: boolean): AuthOrigin {
    if (value !== undefined && /^https:\/\/[a-z0-9.:-]+$/.test(value)) return new AuthOrigin(value);
    if (dev && value !== undefined && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(value))
      return new AuthOrigin(value);
    throw new Error(
      `AUTH_ORIGIN must be an https:// origin${dev ? ' or a loopback http:// origin' : ''}, got '${value ?? ''}'`
    );
  }

  /**
   * Exposes the origin as `locals.authOrigin` and adds security headers to every page
   * and endpoint response. The page's own CSP allows any HTTPS `connect-src`, since
   * the build serves every environment; browsers enforce both policies. Framing is
   * forbidden because other piquel.fr sites, previews included, are the same site,
   * so `SameSite=Lax` cookies reach their frames. It is set here rather than in
   * `kit.csp` so endpoints and every server using this hook get it too.
   * SvelteKit's trailing-slash redirects and built assets bypass hooks.
   */
  readonly handle: Handle = async ({ event, resolve }) => {
    event.locals.authOrigin = this.value;
    // Copied, since endpoints may return responses with immutable headers, such as
    // `Response.redirect()` or a proxied `fetch()`.
    const resolved = await resolve(event);
    const response = new Response(resolved.body, resolved);
    response.headers.append(
      'content-security-policy',
      `frame-ancestors 'none'; connect-src 'self' ${this.value}`
    );
    response.headers.set('x-frame-options', 'DENY');
    response.headers.set('x-content-type-options', 'nosniff');
    response.headers.set('referrer-policy', 'strict-origin-when-cross-origin');
    // Ingress sets no HSTS, so the server does, as the auth service does.
    response.headers.set('strict-transport-security', 'max-age=31536000');
    if (response.headers.get('content-type')?.startsWith('text/html'))
      response.headers.set('cache-control', 'no-store');
    return response;
  };
}
