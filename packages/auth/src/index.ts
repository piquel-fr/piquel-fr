/**
 * TypeScript SDK for auth.piquel.fr. It follows `docs/architecture/sdk.md` in the
 * piquel-fr repository, as the Rust SDK `piquel-auth` does, and passes the same
 * shared vectors.
 *
 * - **Resource servers** validate access tokens with {@link Issuer.resource}, and
 *   declare their scopes with {@link defineScopes}, so an undeclared scope does not
 *   compile.
 * - **Applications** sign users in with {@link Issuer.client}: the authorization
 *   code flow with PKCE, pushed authorization requests, and the RFC 9207 issuer check.
 *   `@piquel/auth/server` builds the routes and sessions of a server-side app on it.
 * - {@link KeyCache} verifies JWS signatures against any JWKS URL, refetching on key
 *   rotation without letting unknown key IDs flood the issuer.
 * - Every failure is an {@link AuthError}, whose `toResponse()` answers with the
 *   canonical `WWW-Authenticate` challenge.
 *
 * The wire types are generated from the Rust types auth issues them with, so the
 * two cannot disagree on their shape.
 */
export type * from './protocol.ts';
export { formatChallenge, parseChallenge, type FormattedChallenge } from './challenge.ts';
export {
  Client,
  type AuthorizeRequest,
  type ClientConfig,
  type PendingLogin,
  type Tokens
} from './client.ts';
export { AuthError, type AuthErrorCode, type AuthErrorDetail, type TokenReason } from './error.ts';
export type { Fetch } from './http.ts';
export { Issuer, type IssuerOptions } from './issuer.ts';
export { Jws, KeyCache, type JwsHeader, type KeyCacheOptions } from './keys.ts';
export { Resource, type ResourceConfig } from './resource.ts';
export { Scopes, defineScopes } from './scope.ts';
export type { Clock } from './time.ts';
export {
  AccessToken,
  type ClaimsReader,
  IdToken,
  LogoutToken,
  type LogoutTarget,
  type Subject
} from './token.ts';
