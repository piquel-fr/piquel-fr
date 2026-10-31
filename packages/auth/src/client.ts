/**
 * Login: the authorization code flow with PKCE, pushed when the issuer supports it,
 * then refresh, revocation, `UserInfo` and logout.
 */
import * as base64 from './base64.ts';
import { asciiLowercase, stepUpRequirement } from './challenge.ts';
import { CLIENT_ID, scope, userInfo } from './claims.ts';
import { AuthError } from './error.ts';
import type { Reply } from './http.ts';
import type { Issuer } from './issuer.ts';
import * as json from './json.ts';
import type { ErrorResponse, Prompt, StepUpRequirement, UserInfo } from './protocol.ts';
import { Scopes } from './scope.ts';
import type { IdToken, LogoutToken } from './token.ts';
import { ACR } from './vocabulary.ts';

/** Random bytes in `state`, `nonce` and the PKCE verifier: 256 bits, a 43-character verifier. */
const RANDOM_BYTES = 32;

/** A registered client. */
export type ClientConfig = {
  /** The client's ID. */
  clientId: string;
  /** A confidential client's secret, sent with HTTP Basic. A public client has none. */
  clientSecret?: string | undefined;
  /** Its registered callback, exactly as registered. */
  redirectUri: string;
};

/** What to ask for in an authorization request. `openid` is always requested. */
export type AuthorizeRequest = {
  /** Scopes to request besides `openid`. */
  scopes?: readonly string[];
  /** `prompt`, such as `login` to force a fresh sign-in. */
  prompt?: Prompt;
  /**
   * The authentication to ask for, sent as `acr_values` and `max_age`, such as one a
   * step-up challenge names. {@link Client.complete} fails unless the ID token meets it.
   */
  stepUp?: StepUpRequirement;
};

/**
 * A login waiting for its callback. It holds the PKCE verifier, so store it
 * server-side, keyed by `state`, and pass it to {@link Client.complete} once. It is
 * plain JSON.
 */
export type PendingLogin = {
  /** Issuer the login was started with. */
  issuer: string;
  /** Client that started the login, the only one that may complete it. */
  clientId: string;
  /** The callback the code is bound to. */
  redirectUri: string;
  /** Client value auth returns unchanged. */
  state: string;
  /** Value the ID token must echo. */
  nonce: string;
  /** PKCE verifier proving this client started the login. */
  verifier: string;
  /** The authentication asked for, which the ID token must meet. */
  stepUp: StepUpRequirement;
};

/** @internal Reads back a {@link PendingLogin} stored as JSON. */
export const pendingLogin: json.Decoder<PendingLogin> = json.object({
  issuer: json.string,
  clientId: json.string,
  redirectUri: json.string,
  state: json.string,
  nonce: json.string,
  verifier: json.string,
  stepUp: json.object({
    acr_values: json.optional(json.oneOf(ACR)),
    max_age: json.optional(json.integer(0, 0xffff_ffff))
  })
});

/** Tokens from a code exchange or refresh. */
export type Tokens = {
  /** The access token, to send as a bearer credential. */
  accessToken: string;
  /** When the access token expires, in milliseconds since the epoch, by `expires_in`. */
  expiresAt: number;
  /** Granted scopes. */
  scopes: Scopes;
  /** The validated ID token, when `openid` was granted. */
  idToken?: IdToken;
  /**
   * A refresh token, when `offline_access` was granted. Keep it server-side. Auth
   * rotates it on every refresh, and revokes the whole family if an old one is reused.
   */
  refreshToken?: string;
};

const errorResponse: json.Decoder<ErrorResponse> = json.object({
  error: json.string,
  // Printable ASCII without `"` or `\` (RFC 6749 §5.2).
  error_description: json.optional(
    json.matching(/^[\x20\x21\x23-\x5b\x5d-\x7e]*$/, 'a description')
  )
});

const tokenResponse = json.object({
  access_token: json.string,
  token_type: json.string,
  expires_in: json.integer(0, 0xffff_ffff),
  scope,
  id_token: json.optional(json.string),
  refresh_token: json.optional(json.string)
});

const pushedAuthorization = json.object({ request_uri: json.matching(/^\S+$/, 'a request URI') });

/** Form-encodes a value, as RFC 6749 §2.3.1 asks for Basic credentials. */
function formEncoded(value: string): string {
  return new URLSearchParams({ value }).toString().slice('value='.length);
}

/**
 * Signs users in with one issuer as one client, from {@link Issuer.client}:
 *
 * ```ts
 * const client = issuer.client({ clientId: 'notes-web', clientSecret, redirectUri });
 * // 1. Redirect the browser to `url`; keep `pending` server-side under its state.
 * const { url, pending } = await client.authorize({ scopes: ['profile'] });
 * // 2. On the callback, take the pending login back, once, and complete it.
 * const tokens = await client.complete(pending, new URL(request.url).searchParams);
 * ```
 */
export class Client {
  /** The issuer it signs in with. */
  readonly issuer: Issuer;
  /** Its registration, without the secret, which stays out of logs. */
  readonly config: Readonly<Omit<ClientConfig, 'clientSecret'>>;
  readonly #secret: string | undefined;

  private constructor(issuer: Issuer, config: ClientConfig) {
    const { clientSecret, ...registration } = config;
    if (!CLIENT_ID.test(registration.clientId)) throw new TypeError('clientId must be a client ID');
    if (!URL.canParse(registration.redirectUri)) {
      throw new TypeError('redirectUri must be a URL');
    }
    this.issuer = issuer;
    this.config = { ...registration, redirectUri: new URL(registration.redirectUri).href };
    this.#secret = clientSecret;
  }

  /** @internal Use {@link Issuer.client}. */
  static from(issuer: Issuer, config: ClientConfig): Client {
    return new Client(issuer, config);
  }

  /**
   * Starts a login: the URL to send the browser to, and the pending login to store
   * until the callback. When the issuer advertises a pushed authorization request
   * endpoint (RFC 9126), the request is pushed there, and the URL carries only
   * `client_id` and the `request_uri`, as clients registered with `--require-par`
   * need; a refused push throws an `oauth` error. `audience` is never sent: auth then
   * picks the client's default resource.
   */
  async authorize(request: AuthorizeRequest = {}): Promise<{ url: string; pending: PendingLogin }> {
    const scopes = Scopes.checked([...(request.scopes ?? []), 'openid']);
    const pending: PendingLogin = {
      issuer: this.issuer.issuer,
      clientId: this.config.clientId,
      redirectUri: this.config.redirectUri,
      state: base64.random(RANDOM_BYTES),
      nonce: base64.random(RANDOM_BYTES),
      verifier: base64.random(RANDOM_BYTES),
      // Only the requirement, should a whole parsed challenge be passed.
      stepUp: stepUpRequirement(request.stepUp ?? {})
    };
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(pending.verifier)
    );
    const parameters: Record<string, string> = {
      response_type: 'code',
      client_id: pending.clientId,
      redirect_uri: pending.redirectUri,
      scope: scopes.toString(),
      state: pending.state,
      nonce: pending.nonce,
      code_challenge: base64.encode(new Uint8Array(digest)),
      code_challenge_method: 'S256'
    };
    if (request.prompt !== undefined) parameters.prompt = request.prompt;
    if (pending.stepUp.acr_values !== undefined) parameters.acr_values = pending.stepUp.acr_values;
    if (pending.stepUp.max_age !== undefined) parameters.max_age = String(pending.stepUp.max_age);
    const url = new URL(this.issuer.metadata.authorization_endpoint);
    const endpoint = this.issuer.metadata.pushed_authorization_request_endpoint;
    if (endpoint === undefined) {
      for (const [name, value] of Object.entries(parameters)) url.searchParams.append(name, value);
    } else {
      const reply = await this.#post(endpoint, parameters);
      const pushed = Client.#read('pushed authorization', reply, pushedAuthorization, 201);
      url.searchParams.append('client_id', pending.clientId);
      url.searchParams.append('request_uri', pushed.request_uri);
    }
    return { url: url.href, pending };
  }

  /**
   * Completes a login from its callback's query parameters. They are checked before
   * the code goes anywhere, in order: `state` (`state_mismatch`); RFC 9207 `iss`,
   * which must be the issuer's (`issuer_mismatch`), and present when the issuer
   * advertises it (`missing_issuer`), error responses included; an `error` becomes an
   * `oauth` error; then `code` (`missing_code`). A `state`, `iss` or `code` sent
   * twice fails its check (RFC 6749 §3.1); an error response only ever fails. The code is then exchanged, and the ID token validated
   * against the pending login's `nonce` and `max_age`. It must meet the login's
   * step-up requirement (`insufficient_user_authentication`), so a step-up login
   * that falls short fails instead of being asked for again.
   */
  async complete(pending: PendingLogin, callback: URLSearchParams): Promise<Tokens> {
    const code = this.#check(pending, callback);
    const reply = await this.#post(this.issuer.metadata.token_endpoint, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: pending.redirectUri,
      code_verifier: pending.verifier
    });
    const tokens = await this.#tokens(reply, pending.nonce, pending.stepUp.max_age);
    // `openid` was requested, so a response without an ID token names no user.
    if (tokens.idToken === undefined) {
      throw new AuthError({ code: 'network' }, 'the token endpoint returned no ID token');
    }
    tokens.idToken.requireAuthentication(pending.stepUp);
    return tokens;
  }

  /**
   * Redeems a refresh token. The response carries a new one; the old one must not be
   * used again. A returned ID token is validated, but has no pending login to compare
   * with: a caller holding the previous ID token must check that `sub` is unchanged
   * (OIDC Core §12.2).
   */
  async refresh(refreshToken: string): Promise<Tokens> {
    const reply = await this.#post(this.issuer.metadata.token_endpoint, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    });
    return this.#tokens(reply, undefined, undefined);
  }

  /** Revokes a refresh token and its whole family (RFC 7009). */
  async revoke(refreshToken: string): Promise<void> {
    const reply = await this.#post(this.issuer.metadata.revocation_endpoint, {
      token: refreshToken
    });
    // A success's body carries nothing and is ignored (RFC 7009 §2.2).
    if (reply.status === 200) return;
    Client.#read('revocation', reply, (value) => value);
  }

  /** Reads the user's claims with an access token. */
  async userinfo(accessToken: string): Promise<UserInfo> {
    const url = this.issuer.metadata.userinfo_endpoint;
    const reply = await this.issuer.http.get(url, { authorization: `Bearer ${accessToken}` });
    return Client.#read('userinfo', reply, userInfo);
  }

  /**
   * The RP-initiated logout URL: auth ends the browser session, then sends the
   * browser to `postLogout`, which must be registered for this client. Without one,
   * auth shows its own page.
   */
  logoutUrl(idToken: IdToken, postLogout?: string): string {
    const url = new URL(this.issuer.metadata.end_session_endpoint);
    url.searchParams.append('id_token_hint', idToken.token);
    url.searchParams.append('client_id', this.config.clientId);
    if (postLogout !== undefined) url.searchParams.append('post_logout_redirect_uri', postLogout);
    return url.href;
  }

  /**
   * Validates a back-channel logout token auth posted to this client (OIDC
   * Back-Channel Logout 1.0 §2.6): checked like an ID token, with `typ` `logout+jwt`
   * and an `aud` naming only this client, then valid for at most 10 minutes, with the
   * logout event, no `nonce`, and `sub` or `sid`. Rejecting a `jti` seen before is
   * left to the caller. A `keys` or `network` error is the server's failure: answer
   * 503 so auth retries, and 400 for any other.
   */
  logoutToken(token: string): Promise<LogoutToken> {
    return this.issuer.tokens.logoutToken(token, this.config.clientId);
  }

  /**
   * The callback checks, in order, returning the code. The code and verifier go only
   * to the client and issuer that started the login.
   */
  #check(pending: PendingLogin, callback: URLSearchParams): string {
    const fail = (
      reason: 'state_mismatch' | 'issuer_mismatch' | 'missing_issuer' | 'missing_code',
      message: string
    ) => new AuthError({ code: 'callback', reason }, message);
    const [state, ...otherStates] = callback.getAll('state');
    const foreign =
      pending.issuer !== this.issuer.issuer || pending.clientId !== this.config.clientId;
    if (foreign || state !== pending.state || otherStates.length > 0) {
      throw fail('state_mismatch', 'the authorization response does not belong to this login');
    }
    const [iss, ...otherIssuers] = callback.getAll('iss');
    if (iss === undefined && this.issuer.metadata.authorization_response_iss_parameter_supported) {
      throw fail('missing_issuer', 'the authorization response has no iss parameter');
    }
    if ((iss !== undefined && iss !== pending.issuer) || otherIssuers.length > 0) {
      throw fail('issuer_mismatch', `the authorization response comes from ${String(iss)}`);
    }
    const error = callback.get('error');
    if (error !== null) {
      const description = callback.get('error_description');
      const response: ErrorResponse =
        description === null ? { error } : { error, error_description: description };
      throw new AuthError({ code: 'oauth', response }, `the authorization failed with ${error}`);
    }
    const [code, ...otherCodes] = callback.getAll('code');
    if (code === undefined || otherCodes.length > 0) {
      throw fail('missing_code', 'the authorization response has no code');
    }
    return code;
  }

  /**
   * Posts a form, authenticating as this client: HTTP Basic for a confidential client,
   * `client_id` in the form for a public one.
   */
  #post(url: string, form: Record<string, string>): Promise<Reply> {
    const { clientId } = this.config;
    if (this.#secret === undefined) {
      return this.issuer.http.post(url, { ...form, client_id: clientId });
    }
    const credentials = btoa(`${formEncoded(clientId)}:${formEncoded(this.#secret)}`);
    return this.issuer.http.post(url, form, { authorization: `Basic ${credentials}` });
  }

  /** Checks a token response and validates its ID token. */
  async #tokens(
    reply: Reply,
    nonce: string | undefined,
    maxAge: number | undefined
  ): Promise<Tokens> {
    const response = Client.#read('token', reply, tokenResponse);
    if (asciiLowercase(response.token_type) !== 'bearer') {
      throw new AuthError(
        { code: 'network' },
        `the token endpoint issued a ${response.token_type} token`
      );
    }
    const tokens: Tokens = {
      accessToken: response.access_token,
      expiresAt: this.issuer.clock() + response.expires_in * 1000,
      scopes: Scopes.parse(response.scope) ?? Scopes.of([])
    };
    if (response.id_token !== undefined) {
      tokens.idToken = await this.issuer.tokens.idToken(
        response.id_token,
        this.config.clientId,
        nonce,
        maxAge
      );
    }
    if (response.refresh_token !== undefined) tokens.refreshToken = response.refresh_token;
    return tokens;
  }

  /**
   * Reads a success body with `decoder`, or throws the OAuth error of a failed
   * request (RFC 6749 §5.2) as an `oauth` error. Any other answer is a `network` error.
   */
  static #read<T>(endpoint: string, reply: Reply, decoder: json.Decoder<T>, success = 200): T {
    const unexpected = (cause?: unknown) =>
      new AuthError(
        { code: 'network' },
        `the ${endpoint} endpoint answered HTTP ${String(reply.status)} with an unexpected body`,
        { cause }
      );
    let body: unknown;
    try {
      body = reply.json();
    } catch (error) {
      throw unexpected(error);
    }
    let response: ErrorResponse;
    try {
      if (reply.status === success) return decoder(body, endpoint);
      response = errorResponse(body, endpoint);
    } catch (error) {
      throw unexpected(error);
    }
    throw new AuthError(
      { code: 'oauth', response },
      `the ${endpoint} endpoint rejected the request with ${response.error}`
    );
  }
}
