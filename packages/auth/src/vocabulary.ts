/**
 * The spellings of each closed wire vocabulary, for decoders. Each list is built
 * from a record keyed by the generated union, so the compiler rejects a list that
 * misses a value or adds one.
 */
import type {
  Acr,
  Algorithm,
  Amr,
  ClientAuthMethod,
  Claim,
  CodeChallengeMethod,
  GrantType,
  KeyType,
  KeyUse,
  ResponseMode,
  ResponseType,
  Scope,
  SubjectType
} from './protocol.ts';

/** Every key of `record`, which must name each value of `T` once. */
function spellings<T extends string>(record: Record<T, true>): readonly T[] {
  // The keys of a `Record<T, true>` literal are exactly the values of `T`.
  return Object.keys(record) as T[];
}

export const AMR = spellings<Amr>({ pop: true, mfa: true, user: true, fed: true });
export const ACR = spellings<Acr>({ phr: true, 'urn:piquel:acr:social': true });
export const ALGORITHMS = spellings<Algorithm>({ RS256: true });
export const KEY_TYPES = spellings<KeyType>({ RSA: true });
export const KEY_USES = spellings<KeyUse>({ sig: true });
export const SCOPES = spellings<Scope>({
  openid: true,
  profile: true,
  email: true,
  offline_access: true
});
export const RESPONSE_TYPES = spellings<ResponseType>({ code: true });
export const RESPONSE_MODES = spellings<ResponseMode>({ query: true });
export const GRANT_TYPES = spellings<GrantType>({ authorization_code: true, refresh_token: true });
export const CLIENT_AUTH_METHODS = spellings<ClientAuthMethod>({
  none: true,
  client_secret_basic: true
});
export const CODE_CHALLENGE_METHODS = spellings<CodeChallengeMethod>({ S256: true });
export const SUBJECT_TYPES = spellings<SubjectType>({ public: true });
export const CLAIMS = spellings<Claim>({
  iss: true,
  sub: true,
  aud: true,
  iat: true,
  exp: true,
  nbf: true,
  sid: true,
  auth_time: true,
  amr: true,
  acr: true,
  act: true,
  cnf: true,
  azp: true,
  name: true,
  preferred_username: true,
  email: true,
  email_verified: true,
  profile_version: true,
  client_id: true,
  jti: true,
  scope: true,
  nonce: true
});
