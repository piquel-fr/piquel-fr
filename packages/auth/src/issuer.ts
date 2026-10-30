/** Discovery, and the issuer handle every resource and client shares. */
import { AuthError } from './error.ts';
import { type Fetch, Http, type Reply } from './http.ts';
import * as json from './json.ts';
import { KeyCache } from './keys.ts';
import type { ServerMetadata } from './protocol.ts';
import { Resource, type ResourceConfig } from './resource.ts';
import type { Clock } from './time.ts';
import { TokenValidator } from './token.ts';
import * as vocabulary from './vocabulary.ts';

/** Where an issuer publishes its metadata (OIDC Discovery 1.0 §4.1). */
const OPENID_CONFIGURATION_PATH = '/.well-known/openid-configuration';

const serverMetadata: json.Decoder<ServerMetadata> = json.object({
  issuer: json.string,
  authorization_endpoint: json.url,
  token_endpoint: json.url,
  revocation_endpoint: json.url,
  userinfo_endpoint: json.url,
  pushed_authorization_request_endpoint: json.optional(json.url),
  require_pushed_authorization_requests: json.withDefault(json.boolean, false),
  end_session_endpoint: json.url,
  jwks_uri: json.url,
  service_documentation: json.url,
  scopes_supported: json.known(vocabulary.SCOPES),
  response_types_supported: json.known(vocabulary.RESPONSE_TYPES),
  response_modes_supported: json.known(vocabulary.RESPONSE_MODES),
  grant_types_supported: json.known(vocabulary.GRANT_TYPES),
  token_endpoint_auth_methods_supported: json.known(vocabulary.CLIENT_AUTH_METHODS),
  revocation_endpoint_auth_methods_supported: json.known(vocabulary.CLIENT_AUTH_METHODS),
  // Absent means no PKCE support (RFC 8414 §2), refused with a precise reason.
  code_challenge_methods_supported: json.withDefault(
    json.known(vocabulary.CODE_CHALLENGE_METHODS),
    []
  ),
  subject_types_supported: json.known(vocabulary.SUBJECT_TYPES),
  id_token_signing_alg_values_supported: json.known(vocabulary.ALGORITHMS),
  claims_supported: json.known(vocabulary.CLAIMS),
  acr_values_supported: json.withDefault(json.known(vocabulary.ACR), []),
  claims_parameter_supported: json.boolean,
  request_parameter_supported: json.boolean,
  request_uri_parameter_supported: json.boolean,
  authorization_response_iss_parameter_supported: json.boolean,
  backchannel_logout_supported: json.withDefault(json.boolean, false),
  backchannel_logout_session_supported: json.withDefault(json.boolean, false)
});

/** Options for {@link Issuer.discover}. */
export type IssuerOptions = {
  /** Sends every request to auth; the global `fetch` by default. */
  fetch?: Fetch;
  /** Reads time for every check; `Date.now` by default. Pin it in tests. */
  clock?: Clock;
};

/**
 * A discovered issuer: its checked metadata, signing keys, `fetch` and clock. Share
 * one per process: resources and clients share its key cache.
 *
 * ```ts
 * const issuer = await Issuer.discover('https://auth.piquel.fr');
 * const notes = issuer.resource({ identifier: 'notes-api', scopes: defineScopes('notes:read') });
 * ```
 */
export class Issuer {
  /** The checked metadata. */
  readonly metadata: ServerMetadata;
  /** The issuer's signing keys. */
  readonly keys: KeyCache;
  /** @internal Requests to auth's endpoints. */
  readonly http: Http;
  /** @internal The clock every check reads. */
  readonly clock: Clock;
  /** @internal Validates the issuer's tokens. */
  readonly tokens: TokenValidator;

  private constructor(metadata: ServerMetadata, options: IssuerOptions) {
    this.metadata = metadata;
    this.http = new Http(options.fetch);
    this.clock = options.clock ?? Date.now;
    this.keys = new KeyCache(metadata.jwks_uri, options);
    const algorithms = vocabulary.ALGORITHMS.filter((algorithm) =>
      metadata.id_token_signing_alg_values_supported.includes(algorithm)
    );
    this.tokens = new TokenValidator(metadata.issuer, algorithms, this.keys, this.clock);
  }

  /**
   * Fetches and checks `issuer`'s metadata. The returned `issuer` must equal the
   * configured one exactly, without normalization (`issuer_mismatch`), `S256` PKCE
   * must be supported (`pkce_unsupported`), and every endpoint must use `https`
   * (`invalid_document`). Advertised values this version does not know are dropped.
   */
  static async discover(issuer: string, options: IssuerOptions = {}): Promise<Issuer> {
    if (!URL.canParse(issuer) || new URL(issuer).protocol !== 'https:' || /[?#]/.test(issuer)) {
      throw new AuthError(
        { code: 'discovery' },
        `issuer ${JSON.stringify(issuer)} must be an https URL without query or fragment`
      );
    }
    const url = `${issuer.replace(/\/+$/, '')}${OPENID_CONFIGURATION_PATH}`;
    const reply = (await new Http(options.fetch).get(url)).ok();
    return new Issuer(Issuer.#check(issuer, reply), options);
  }

  /** Parses a metadata document and checks it belongs to `issuer`. */
  static #check(issuer: string, reply: Reply): ServerMetadata {
    let metadata: ServerMetadata;
    try {
      metadata = serverMetadata(reply.json(), 'metadata');
    } catch (error) {
      throw new AuthError(
        { code: 'discovery', reason: 'invalid_document' },
        'issuer metadata is invalid',
        { cause: error }
      );
    }
    if (metadata.issuer !== issuer) {
      throw new AuthError(
        { code: 'discovery', reason: 'issuer_mismatch' },
        `metadata names issuer ${JSON.stringify(metadata.issuer)}, expected ${JSON.stringify(issuer)}`
      );
    }
    if (!metadata.code_challenge_methods_supported.includes('S256')) {
      throw new AuthError(
        { code: 'discovery', reason: 'pkce_unsupported' },
        'the issuer does not support PKCE with S256'
      );
    }
    const endpoints = {
      authorization_endpoint: metadata.authorization_endpoint,
      token_endpoint: metadata.token_endpoint,
      revocation_endpoint: metadata.revocation_endpoint,
      userinfo_endpoint: metadata.userinfo_endpoint,
      end_session_endpoint: metadata.end_session_endpoint,
      jwks_uri: metadata.jwks_uri,
      pushed_authorization_request_endpoint: metadata.pushed_authorization_request_endpoint
    };
    // Credentials and keys must not cross the network in the clear (OIDC Discovery 1.0 §3).
    for (const [name, endpoint] of Object.entries(endpoints)) {
      if (endpoint !== undefined && new URL(endpoint).protocol !== 'https:') {
        throw new AuthError(
          { code: 'discovery', reason: 'invalid_document' },
          `issuer metadata's ${name} does not use https`
        );
      }
    }
    return metadata;
  }

  /** The issuer identifier, exactly as tokens carry it in `iss`. */
  get issuer(): string {
    return this.metadata.issuer;
  }

  /** Validates access tokens for the resource `config` describes. */
  resource<const S extends string = never, X = undefined>(
    config: ResourceConfig<S, X>
  ): Resource<S, X> {
    return new Resource(this.tokens, config);
  }
}
