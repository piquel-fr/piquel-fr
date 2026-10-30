/** Resource servers: reading bearer tokens from requests and validating them. */
import { asciiLowercase } from './challenge.ts';
import { AuthError } from './error.ts';
import { Scopes } from './scope.ts';
import type { AccessToken, ClaimsReader, Single, TokenValidator } from './token.ts';

/** What a resource server is. */
export type ResourceConfig<S extends string, X = undefined> = {
  /**
   * The resource identifier, the `aud` its access tokens carry, such as `notes-api`.
   * It is compared exactly.
   */
  identifier: string;
  /** The scopes the resource understands, from {@link defineScopes}. */
  scopes?: Scopes<S>;
  /**
   * Where the resource serves its protected resource metadata (RFC 9728), named in
   * every challenge as `resource_metadata`.
   */
  metadata?: string;
  /**
   * Reads the application's own claims, which auth does not define, from each
   * token's claims object into {@link AccessToken.extra}. It runs with the claims
   * check: throwing fails the token with `invalid_claims`.
   */
  claims?: ClaimsReader<X>;
};

/**
 * Validates access tokens for one resource. `S` are its declared scopes, the only
 * ones {@link AccessToken.require} accepts, and `X` its application claims.
 *
 * ```ts
 * const api = issuer.resource({ identifier: 'notes-api', scopes: defineScopes('notes:read') });
 * try {
 *   const token = (await api.authenticate(request)).require('notes:read');
 * } catch (error) {
 *   if (error instanceof AuthError) return error.toResponse();
 *   throw error;
 * }
 * ```
 */
export class Resource<S extends string = never, X = undefined> {
  /** The identifier its tokens' `aud` must contain. */
  readonly identifier: string;
  /** The declared scopes. */
  readonly scopes: Scopes<S>;
  /** Where its protected resource metadata is served, if configured. */
  readonly metadata: string | undefined;
  readonly #tokens: TokenValidator;
  readonly #claims: ClaimsReader<X>;

  private constructor(tokens: TokenValidator, config: ResourceConfig<S, X>) {
    if (!/^[\x21-\x7e]+$/.test(config.identifier)) {
      throw new TypeError('a resource identifier must be printable ASCII without spaces');
    }
    if (config.metadata !== undefined && !URL.canParse(config.metadata)) {
      throw new TypeError('a resource metadata URL must be a URL');
    }
    this.identifier = config.identifier;
    this.scopes = config.scopes ?? Scopes.of([]);
    this.metadata = config.metadata === undefined ? undefined : new URL(config.metadata).href;
    this.#tokens = tokens;
    this.#claims = config.claims ?? (() => undefined as X);
  }

  /** @internal Use {@link Issuer.resource}. */
  static from<S extends string, X>(
    tokens: TokenValidator,
    config: ResourceConfig<S, X>
  ): Resource<S, X> {
    return new Resource(tokens, config);
  }

  /**
   * Validates the request's bearer token, read from `Authorization: Bearer` only, and
   * requires `scopes`, narrowing the token's type to them. Throws `missing_token`
   * when there is none (another scheme counts as none), whose challenge names
   * `scopes`, and `invalid_request` when the header is malformed: `Bearer` without a
   * token, or several `Authorization` headers one of which is Bearer, as the Rust
   * SDK reads them (`Headers` joins them with `, `). Otherwise see {@link validate} and {@link AccessToken.require}.
   */
  async authenticate<const T extends readonly S[] = readonly []>(
    request: { headers: Headers },
    ...scopes: T & { [K in keyof T]: Single<T[K]> }
  ): Promise<AccessToken<S, T[number], X>> {
    const header = request.headers.get('authorization') ?? '';
    // One header of another scheme may hold commas itself, such as Digest's.
    const values = header.split(', ');
    const joined = values.length > 1 && values.some((value) => /^bearer(?: |$)/i.test(value));
    const space = header.indexOf(' ');
    const scheme = space === -1 ? header : header.slice(0, space);
    if (joined || (asciiLowercase(scheme) === 'bearer' && space === -1)) {
      throw new AuthError(
        { code: 'invalid_request' },
        'the Authorization header is malformed'
      ).forResource(this.metadata);
    }
    if (asciiLowercase(scheme) !== 'bearer') {
      const scope = scopes.length === 0 ? undefined : Scopes.of(scopes).toString();
      throw new AuthError(
        scope === undefined ? { code: 'missing_token' } : { code: 'missing_token', scope },
        'the request has no bearer token'
      ).forResource(this.metadata);
    }
    const token = header.slice(space + 1).trim();
    if (token === '') {
      throw new AuthError(
        { code: 'invalid_request' },
        'the Authorization header is malformed'
      ).forResource(this.metadata);
    }
    const validated = await this.validate(token);
    // `require` throws unless the token holds every scope; the proof exists only in types.
    const require = validated.require.bind(validated) as (...required: readonly S[]) => unknown;
    if (scopes.length > 0) require(...scopes);
    return validated as unknown as AccessToken<S, T[number], X>;
  }

  /**
   * Validates an access token, running every check of the SDK design in order:
   * framing, `crit`, `typ`, algorithm, key, signature, claims, issuer, audience and
   * times with a 30-second leeway. Throws `invalid_token` with the failed check as
   * `reason`, or `keys` and `network` errors when signing keys cannot be fetched.
   */
  async validate(token: string): Promise<AccessToken<S, never, X>> {
    try {
      return await this.#tokens.accessToken<S, X>(
        token,
        this.identifier,
        this.metadata,
        this.#claims
      );
    } catch (error) {
      throw error instanceof AuthError ? error.forResource(this.metadata) : error;
    }
  }
}
