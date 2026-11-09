/**
 * A resource server validating access tokens with `@piquel/auth`: `handle` answers a
 * standard `Request`, so Node, Bun, Workers, Hono or SvelteKit can serve it. It
 * accepts tokens whose `aud` is `notes-api`, and declares the scopes it
 * understands. An app outside this repository imports `@piquel/auth` instead of the
 * sources. The `ANCHOR` comments mark the parts `docs/user/apps/protect-an-api.md`
 * shows.
 */
import { AuthError, Issuer, defineScopes } from '../src/index.ts';

// ANCHOR: resource
const issuer = await Issuer.discover('https://auth.piquel.fr');
const notes = defineScopes('notes:read', 'notes:write');
const api = issuer.resource({ identifier: 'notes-api', scopes: notes });
// ANCHOR_END: resource

// ANCHOR: handle
/** `POST /notes`: needs `notes:write`, and a passkey sign-in within five minutes. */
export async function handle(request: Request): Promise<Response> {
  try {
    // A request without a token is told it needs notes:write; 'notes:delete' would
    // not compile.
    const token = await api.authenticate(request, 'notes:write');
    token.requireAuthentication({ acr_values: 'phr', max_age: 300 });
    return Response.json({ user: token.subject.id }, { status: 201 });
  } catch (error) {
    // The status and `WWW-Authenticate` challenge, or 503 when keys are unavailable.
    if (error instanceof AuthError) return error.toResponse();
    throw error;
  }
}
// ANCHOR_END: handle
