/**
 * Decoders for the signed claims and `UserInfo`, reading them exactly as the shared
 * Rust types do: required claims present and well typed, account and session IDs as
 * canonical UUIDv7, unknown `amr` values dropped and an unknown `acr` read as none.
 */
import * as json from './json.ts';
import type {
  AccessTokenClaims,
  Actor,
  Audience,
  IdTokenClaims,
  LogoutEvents,
  LogoutTokenClaims,
  UserInfo
} from './protocol.ts';
import { Scopes } from './scope.ts';
import { ACR, AMR } from './vocabulary.ts';

/** The `events` member every logout token carries (OIDC Back-Channel Logout 1.0 §2.4). */
export const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/** A canonical lower-case UUIDv7, as account, session and token IDs are. */
export const uuid = json.matching(
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  'a UUIDv7'
);

/** A registered client's ID: 1 to 64 ASCII letters, digits, `.`, `_` or `-`. */
export const clientId = json.matching(/^[A-Za-z0-9._-]{1,64}$/, 'a client ID');

/** `aud`: one string or an array (RFC 7519 §4.1.3). */
const audience: json.Decoder<Audience> = (value, path) =>
  typeof value === 'string' ? value : json.array(json.string)(value, path);

/** Granted scopes, in their sorted wire form. */
const scope = json.refine('a scope list', (value) => Scopes.parse(value)?.toString());

/** `act` (RFC 8693 §4.1), nested for delegation chains. */
const actor: json.Decoder<Actor> = (value, path) =>
  json.object({ sub: json.string, act: json.optional(actor) })(value, path);

/** How the session behind a token authenticated. An empty `amr` is left out, as Rust writes it. */
const authentication = {
  sid: json.optional(uuid),
  auth_time: json.optional(json.seconds),
  amr: (value: unknown, path: string) => {
    const methods = json.withDefault(json.known(AMR), [])(value, path);
    return methods.length === 0 ? undefined : methods;
  },
  acr: json.knownOne(ACR)
};

/** Profile and email claims. */
const profile = {
  preferred_username: json.optional(json.string),
  name: json.optional(json.string),
  profile_version: json.optional(json.integer(0, Number.MAX_SAFE_INTEGER)),
  email: json.optional(json.string),
  email_verified: json.optional(json.boolean)
};

export const accessTokenClaims: json.Decoder<AccessTokenClaims> = json.object({
  iss: json.string,
  sub: json.string,
  aud: audience,
  client_id: clientId,
  jti: uuid,
  scope,
  iat: json.seconds,
  exp: json.seconds,
  nbf: json.optional(json.seconds),
  act: json.optional(actor),
  cnf: json.optional(json.object({ jkt: json.optional(json.string) })),
  ...authentication,
  ...profile
});

export const idTokenClaims: json.Decoder<IdTokenClaims> = json.object({
  iss: json.string,
  sub: json.string,
  aud: audience,
  azp: json.optional(clientId),
  iat: json.seconds,
  exp: json.seconds,
  nbf: json.optional(json.seconds),
  nonce: json.optional(json.string),
  ...authentication,
  ...profile
});

/** `events`, whose members must all be objects (RFC 8417 §2.2), one the back-channel logout event. */
const events: json.Decoder<LogoutEvents> = (value, path) => {
  const members = json.isObject(value) ? Object.values(value) : [];
  if (!json.isObject(value) || !members.every(json.isObject)) {
    throw new json.DecodeError(`${path} must be an object of event objects`);
  }
  if (!Object.hasOwn(value, BACKCHANNEL_LOGOUT_EVENT)) {
    throw new json.DecodeError(`${path} must hold ${BACKCHANNEL_LOGOUT_EVENT}`);
  }
  return { [BACKCHANNEL_LOGOUT_EVENT]: {} };
};

export const logoutTokenClaims: json.Decoder<LogoutTokenClaims> = json.object({
  iss: json.string,
  aud: audience,
  iat: json.seconds,
  exp: json.seconds,
  jti: uuid,
  sub: json.optional(json.string),
  sid: json.optional(uuid),
  events,
  // Never present, not even `null`, so an ID token cannot pass as a logout token.
  nonce: json.absent
});

export const userInfo: json.Decoder<UserInfo> = json.object({ sub: json.string, ...profile });
