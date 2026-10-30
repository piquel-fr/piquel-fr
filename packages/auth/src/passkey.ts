/**
 * Passkey sign-in on an application's own page, through WebAuthn related origins:
 * the page posts a pushed request's `request_uri` to auth, runs the assertion auth
 * describes, and gets the authorization response back as JSON, without leaving the
 * page. These calls send no cookies and get none, so the sign-in leaves no session
 * at auth that a later `prompt=none` could find.
 */
import * as base64 from './base64.ts';
import type { Reply } from './http.ts';
import type { Issuer } from './issuer.ts';
import * as json from './json.ts';
import { type Platform, platform } from './platform.ts';

/** Where a passkey sign-in on the page stopped. */
export type PasskeyStep =
  /** The browser lacks related origins; nothing was sent. */
  | 'unsupported'
  /** `POST /webauthn/related/start`, which claims the request. */
  | 'start'
  /** `navigator.credentials.get()`: cancelled, timed out or refused. */
  | 'prompt'
  /** `POST /webauthn/related/finish`, which consumes the request. */
  | 'finish';

/** The authorization response a passkey sign-in ends with, checked as a callback's query is. */
export type PasskeyAuthorization = { code: string; state: string; iss: string };

/**
 * A passkey sign-in on the page that did not finish. The user can still sign in on
 * auth's pages: with the same `request_uri` when it is {@link PasskeyError.unclaimed},
 * and otherwise with a freshly pushed request, since auth may have claimed this one.
 */
export class PasskeyError extends Error {
  override name = 'PasskeyError';
  /** Where it stopped. */
  readonly step: PasskeyStep;
  /**
   * Whether auth answered `interaction_required`: this sign-in needs auth's pages,
   * such as a request with `prompt=consent`, or a passkey that falls short of its
   * `acr_values`.
   */
  readonly interactionRequired: boolean;

  private constructor(
    step: PasskeyStep,
    message: string,
    options: { cause?: unknown; interactionRequired?: boolean }
  ) {
    super(message, { cause: options.cause });
    this.step = step;
    this.interactionRequired = options.interactionRequired ?? false;
  }

  /** @internal A failure at `step`. */
  static at(
    step: PasskeyStep,
    message: string,
    options: { cause?: unknown; interactionRequired?: boolean } = {}
  ): PasskeyError {
    return new PasskeyError(step, message, options);
  }

  /**
   * Whether auth left the request unclaimed, so the redirect can still use its
   * `request_uri`: the browser lacks related origins, or start refused it with
   * `interaction_required`.
   */
  get unclaimed(): boolean {
    return this.step === 'unsupported' || (this.step === 'start' && this.interactionRequired);
  }
}

/** A credential descriptor, its ID in base64url. */
const descriptor = json.object({
  type: json.string,
  id: json.refine('base64url', base64.decode),
  transports: json.optional(json.array(json.string))
});

/** The options of the assertion start describes, its byte fields in base64url. */
const requestOptions: json.Decoder<PublicKeyCredentialRequestOptions> = (value, path) => {
  const bytes = json.object({
    challenge: json.refine('base64url', base64.decode),
    allowCredentials: json.optional(json.array(descriptor))
  })(value, path);
  // The other members (`rpId`, `timeout`, `userVerification`, ...) go to the
  // browser as auth wrote them, and the browser checks them.
  return { ...(value as object), ...bytes } as PublicKeyCredentialRequestOptions;
};

const started = json.object({
  ceremony_id: json.string,
  public_key: json.object({ publicKey: requestOptions })
});

const finished: json.Decoder<PasskeyAuthorization> = json.object({
  code: json.string,
  state: json.string,
  iss: json.string
});

/**
 * Runs the passkey sign-in for a pushed request's `request_uri`, on a page whose
 * origin auth approved for the request's client, and returns the authorization
 * response. Check it and redeem its code as a callback's, with
 * `Client.complete(pending, new URLSearchParams(authorization))`. A sign-in that
 * does not finish throws a {@link PasskeyError}.
 *
 * `BrowserClient.signInWithPasskey` runs it with every fallback. A server-side login
 * can push the request itself, hand the page only the `request_uri`, and complete
 * the response the page posts back.
 */
export function authorizeWithPasskey(
  issuer: Issuer,
  requestUri: string
): Promise<PasskeyAuthorization> {
  return new PasskeyCeremony(issuer, platform()).run(requestUri);
}

/** @internal The ceremony against one issuer, with the page's APIs. */
export class PasskeyCeremony {
  readonly #issuer: Issuer;
  readonly #platform: Platform;

  constructor(issuer: Issuer, platform: Platform) {
    this.#issuer = issuer;
    this.#platform = platform;
  }

  /** Starts, prompts and finishes, as {@link authorizeWithPasskey} describes. */
  async run(requestUri: string): Promise<PasskeyAuthorization> {
    const capabilities = await this.#platform.capabilities();
    if (capabilities.relatedOrigins !== true) {
      throw PasskeyError.at('unsupported', 'this browser cannot use passkeys on related origins');
    }
    const start = await this.#post('start', { request_uri: requestUri }, started);
    let credential: Credential | null;
    try {
      credential = await this.#platform.credentials.get({ publicKey: start.public_key.publicKey });
    } catch (error) {
      throw PasskeyError.at('prompt', 'the passkey prompt failed', { cause: error });
    }
    if (credential?.type !== 'public-key') {
      throw PasskeyError.at('prompt', 'the passkey prompt returned no passkey');
    }
    return this.#post(
      'finish',
      {
        ceremony_id: start.ceremony_id,
        credential: PasskeyCeremony.#serialize(credential as PublicKeyCredential)
      },
      finished
    );
  }

  /**
   * Posts `body` as JSON to `step`'s route without cookies, and reads the answer with
   * `decoder`. Every failure is a {@link PasskeyError} of `step`.
   */
  async #post<T>(step: 'start' | 'finish', body: unknown, decoder: json.Decoder<T>): Promise<T> {
    const url = this.#issuer.url(`/webauthn/related/${step}`);
    const failed = (message: string, options: { cause?: unknown; interactionRequired?: boolean }) =>
      PasskeyError.at(step, `the passkey ${step} failed: ${message}`, options);
    let reply: Reply;
    try {
      reply = await this.#issuer.http.send(url, {
        method: 'POST',
        credentials: 'omit',
        headers: { 'content-type': 'application/json', 'x-piquel-csrf': '1' },
        body: JSON.stringify(body)
      });
    } catch (error) {
      throw failed('auth could not be reached', { cause: error });
    }
    let answer: unknown;
    try {
      answer = reply.json();
      if (reply.status === 200) return decoder(answer, step);
    } catch (error) {
      if (reply.status === 200) throw failed('auth answered unexpectedly', { cause: error });
    }
    // Auth's browser routes refuse with `{error, code}`, `error` a readable message;
    // a proxy in the way may answer anything.
    const member = (name: string) => {
      const value = json.isObject(answer) ? answer[name] : undefined;
      return typeof value === 'string' ? value : undefined;
    };
    throw failed(member('error') ?? `auth answered HTTP ${String(reply.status)}`, {
      interactionRequired: member('code') === 'interaction_required'
    });
  }

  /** The assertion as finish reads it, its byte fields in base64url. */
  static #serialize(credential: PublicKeyCredential) {
    const encode = (buffer: ArrayBuffer) => base64.encode(new Uint8Array(buffer));
    const response = credential.response as AuthenticatorAssertionResponse;
    return {
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: encode(response.authenticatorData),
        clientDataJSON: encode(response.clientDataJSON),
        signature: encode(response.signature),
        userHandle: response.userHandle === null ? null : encode(response.userHandle)
      },
      clientExtensionResults: credential.getClientExtensionResults()
    };
  }
}
