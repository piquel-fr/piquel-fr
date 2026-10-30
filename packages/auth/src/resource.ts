/** Resource servers: reading bearer tokens from requests and validating them. */
import { asciiLowercase } from './challenge.ts';
import { AuthError } from './error.ts';
import { Scopes } from './scope.ts';
import type { AccessToken, TokenValidator } from './token.ts';

/** What a resource server is. */
export type ResourceConfig<S extends string> = {
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
};

/**
 * Validates access tokens for one resource. `S` are its declared scopes, the only
 * ones {@link AccessToken.require} accepts.
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
export class Resource<S extends string = never> {
  /** The identifier its tokens' `aud` must contain. */
  readonly identifier: string;
  /** The declared scopes. */
  readonly scopes: Scopes<S>;
  /** Where its protected resource metadata is served, if configured. */
  readonly metadata: string | undefined;
  readonly #tokens: TokenValidator;

  /** @internal Use {@link Issuer.resource}. */
  constructor(tokens: TokenValidator, config: ResourceConfig<S>) {
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
  }

  /**
   * Validates the request's bearer token, read from `Authorization: Bearer` only.
   * Throws `missing_token` when there is none (another scheme counts as none), and
   * `invalid_request` when the header is malformed: `Bearer` without a token, or a
   * token holding whitespace or commas, as several `Authorization` headers joined by
   * `Headers` do. Otherwise see {@link validate}.
   */
  async authenticate(request: { headers: Headers }): Promise<AccessToken<S>> {
    const header = request.headers.get('authorization') ?? '';
    const space = header.indexOf(' ');
    if (asciiLowercase(space === -1 ? header : header.slice(0, space)) !== 'bearer') {
      throw new AuthError({ code: 'missing_token' }, 'the request has no bearer token').forResource(
        this.metadata
      );
    }
    const token = space === -1 ? '' : header.slice(space + 1).trim();
    if (token === '' || /[\s,]/.test(token)) {
      throw new AuthError(
        { code: 'invalid_request' },
        'the Authorization header is malformed'
      ).forResource(this.metadata);
    }
    return this.validate(token);
  }

  /**
   * Validates an access token, running every check of the SDK design in order:
   * framing, `crit`, `typ`, algorithm, key, signature, claims, issuer, audience and
   * times with a 30-second leeway. Throws `invalid_token` with the failed check as
   * `reason`, or `keys` and `network` errors when signing keys cannot be fetched.
   */
  async validate(token: string): Promise<AccessToken<S>> {
    try {
      return await this.#tokens.accessToken<S>(token, this.identifier, this.metadata);
    } catch (error) {
      throw error instanceof AuthError ? error.forResource(this.metadata) : error;
    }
  }
}
