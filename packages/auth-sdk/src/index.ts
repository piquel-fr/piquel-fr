/**
 * Browser-side SDK for the piquel auth service, shared by auth-web and piquel-web:
 * a typed API client, WebAuthn passkey ceremonies, step-up and redirect helpers.
 * Shared presentation styles are exported separately as `@piquel/auth-sdk/style.css`.
 */
export type Provider = 'github' | 'google';
export type PasskeyKind = 'standard' | 'google_password_manager';
export type Session = { user: { id: string; username: string; display_name: string } };
export type Configuration = {
  settings_url: string;
  /** Frontend origins, such as https://piquel.fr, that sign-in may return to. */
  frontend_origins: string[];
  providers: Provider[];
  invite_required: boolean;
};
export const providerName = (provider: Provider) => (provider === 'github' ? 'GitHub' : 'Google');

/** The action needs a passkey confirmation of the session at most `maxAge` seconds old. */
export class StepUpRequired extends Error {
  constructor(
    message: string,
    readonly maxAge: number
  ) {
    super(message);
    this.name = 'StepUpRequired';
  }
}

/** The auth cookie remains HttpOnly on the auth host, including for settings requests. */
export class AuthApi {
  constructor(readonly origin = '') {}
  async request<T = void>(path: string, method = 'GET', body?: unknown): Promise<T> {
    const response = await fetch(`${this.origin}${path}`, {
      method,
      credentials: 'include',
      headers: method === 'GET' ? {} : { 'content-type': 'application/json', 'x-piquel-csrf': '1' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    if (!response.ok) throw await this.failure(response);
    return response.status === 204 ? (undefined as T) : (response.json() as Promise<T>);
  }
  /** Turns a failed response into an error whose message the page can show as is. */
  private async failure(response: Response): Promise<Error> {
    const problem: unknown = await response.json().catch(() => null);
    const text = (name: string): string | null => {
      if (!problem || typeof problem !== 'object') return null;
      const value = (problem as Record<string, unknown>)[name];
      return typeof value === 'string' ? value : null;
    };
    // Browser endpoints send `error` as a readable message. OAuth endpoints send a
    // code in `error` and what to fix in `error_description`.
    const error = text('error');
    const description = text('error_description');
    const maxAge = (problem as Record<string, unknown> | null)?.max_age;
    if (text('code') === 'step_up_required' && typeof maxAge === 'number')
      return new StepUpRequired(error ?? 'Confirm with your passkey to continue.', maxAge);
    const protocolErrors: Record<string, string> = {
      invalid_request:
        'This sign-in request is invalid or expired. Start again from the application.',
      invalid_token: 'Please sign in again.',
      access_denied: 'Sign-in was cancelled or access was declined.',
      login_required: 'Please sign in again.',
      consent_required: 'Review the application’s requested access to continue.',
      server_error: 'Sign-in is temporarily unavailable. Please try again.',
      temporarily_unavailable: 'Sign-in is temporarily unavailable. Please try again.'
    };
    const protocolMessage = error === null ? undefined : protocolErrors[error];
    return new Error(
      response.status === 429
        ? 'Too many attempts. Wait a moment and try again.'
        : protocolMessage
          ? description && response.status < 500
            ? `${protocolMessage} (${description})`
            : protocolMessage
          : (description ??
            error ??
            (response.status === 401
              ? 'Please sign in again.'
              : 'This action could not be completed. Please try again.'))
    );
  }
  async form(path: string, body: URLSearchParams): Promise<{ redirect_url: string }> {
    const response = await fetch(`${this.origin}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'x-piquel-csrf': '1' },
      body
    });
    if (!response.ok) throw await this.failure(response);
    return response.json() as Promise<{ redirect_url: string }>;
  }
}

type EncodedDescriptor = Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string };
type CreationOptions = Omit<
  PublicKeyCredentialCreationOptions,
  'challenge' | 'user' | 'excludeCredentials'
> & {
  challenge: string;
  user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string };
  excludeCredentials?: EncodedDescriptor[];
};
type RequestOptions = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string;
  allowCredentials?: EncodedDescriptor[];
};
type Ceremony<T> = { ceremony_id: string; public_key: { publicKey: T } };
function decode(value: string): ArrayBuffer {
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
    .buffer;
}
function encode(value: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
function descriptor(value: EncodedDescriptor): PublicKeyCredentialDescriptor {
  return { ...value, id: decode(value.id) };
}
export function passkeysAvailable(): boolean {
  return typeof window !== 'undefined' && window.isSecureContext && 'PublicKeyCredential' in window;
}

/** All ceremonies run on the auth origin; serialized WebAuthn wrappers contain publicKey. */
export class Passkeys {
  constructor(readonly api: AuthApi) {}
  /** Signs in, which also confirms the new session for actions that need a passkey. */
  authenticate(username?: string): Promise<void> {
    return this.assert('/webauthn/authenticate', username ? { username } : {});
  }
  /** Confirms the current session with a passkey, for actions that need a recent one. */
  confirm(): Promise<void> {
    return this.assert('/account/passkeys/confirm', {});
  }
  /** Runs an assertion ceremony against `path`'s start and finish endpoints. */
  private async assert(path: string, body: object): Promise<void> {
    const start = await this.api.request<Ceremony<RequestOptions>>(`${path}/start`, 'POST', body);
    const options = start.public_key.publicKey;
    const credential = (await navigator.credentials.get({
      publicKey: {
        ...options,
        challenge: decode(options.challenge),
        allowCredentials: options.allowCredentials?.map(descriptor)
      }
    })) as PublicKeyCredential | null;
    if (!credential) throw new Error('Passkey verification was cancelled.');
    const response = credential.response as AuthenticatorAssertionResponse;
    await this.api.request(`${path}/finish`, 'POST', {
      ceremony_id: start.ceremony_id,
      credential: {
        id: credential.id,
        rawId: encode(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: encode(response.authenticatorData),
          clientDataJSON: encode(response.clientDataJSON),
          signature: encode(response.signature),
          userHandle: response.userHandle ? encode(response.userHandle) : null
        },
        clientExtensionResults: credential.getClientExtensionResults()
      }
    });
  }
  /**
   * Creates an account when `account` is given, else enrolls a key for the signed-in user.
   * `pending_signup` attaches the pending social identity the signup page displayed.
   */
  async register(
    friendlyName: string,
    account?: { username: string; invitation?: string; pending_signup?: string },
    kind: PasskeyKind = 'standard'
  ): Promise<void> {
    const path = account ? '/webauthn/register' : '/account/passkeys/enroll';
    const start = await this.api.request<Ceremony<CreationOptions>>(`${path}/start`, 'POST', {
      ...account,
      passkey_kind: kind
    });
    const options = start.public_key.publicKey;
    const credential = (await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge: decode(options.challenge),
        user: { ...options.user, id: decode(options.user.id) },
        excludeCredentials: options.excludeCredentials?.map(descriptor)
      }
    })) as PublicKeyCredential | null;
    if (!credential) throw new Error('Passkey creation was cancelled.');
    const response = credential.response as AuthenticatorAttestationResponse;
    await this.api.request(`${path}/finish`, 'POST', {
      ceremony_id: start.ceremony_id,
      friendly_name: friendlyName,
      credential: {
        id: credential.id,
        rawId: encode(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: encode(response.attestationObject),
          clientDataJSON: encode(response.clientDataJSON),
          transports: response.getTransports()
        },
        clientExtensionResults: credential.getClientExtensionResults()
      }
    });
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof DOMException
    ? 'The passkey request was cancelled or unavailable. Try again or use another device.'
    : error instanceof Error
      ? error.message
      : 'Something went wrong. Please try again.';
}
/** Session storage entry for an action waiting on auth's /confirm page. */
const STEP_UP_STORAGE_KEY = 'piquel.step_up';
/** How long after leaving for /confirm an action may still resume. */
const STEP_UP_RESUME_MS = 5 * 60 * 1000;
type PendingStepUp = { key: string; argument: string; started_at: number };

/**
 * Runs named actions that may need a recent passkey confirmation. On the auth origin
 * it confirms inline and retries once. Elsewhere it saves the action in this tab,
 * sends the user to auth's /confirm page, and `resume` runs it once on return.
 * Actions take one string argument, such as the ID of the passkey to remove.
 */
export class StepUp<Key extends string> {
  constructor(
    private readonly passkeys: Passkeys,
    private readonly actions: Record<Key, (argument: string) => Promise<void>>
  ) {}
  async run(key: Key, argument = ''): Promise<void> {
    try {
      await this.actions[key](argument);
      return;
    } catch (error) {
      if (!(error instanceof StepUpRequired)) throw error;
    }
    const authOrigin = this.passkeys.api.origin || window.location.origin;
    if (authOrigin === window.location.origin) {
      await this.passkeys.confirm();
      return this.actions[key](argument);
    }
    const pending: PendingStepUp = { key, argument, started_at: Date.now() };
    sessionStorage.setItem(STEP_UP_STORAGE_KEY, JSON.stringify(pending));
    const { origin, pathname, search } = window.location;
    const query = new URLSearchParams({ return_to: `${origin}${pathname}${search}` });
    window.location.assign(`${authOrigin}/confirm?${query}`);
    // The page is unloading: keep the caller busy instead of reporting a result.
    return new Promise<never>(() => undefined);
  }
  /**
   * Runs the action saved before /confirm once, if it started in this tab less than
   * five minutes ago. If the user came back without confirming, it does nothing.
   */
  async resume(): Promise<void> {
    const saved = sessionStorage.getItem(STEP_UP_STORAGE_KEY);
    if (saved === null) return;
    sessionStorage.removeItem(STEP_UP_STORAGE_KEY);
    const pending = JSON.parse(saved) as PendingStepUp;
    if (Date.now() - pending.started_at > STEP_UP_RESUME_MS || !(pending.key in this.actions))
      return;
    try {
      await this.actions[pending.key as Key](pending.argument);
    } catch (error) {
      if (!(error instanceof StepUpRequired)) throw error;
    }
  }
}

/**
 * Returns `value` when the auth service accepts it as `return_to`, else the settings
 * URL: a path on the auth origin, or a URL on a frontend origin without credentials.
 * Neither may contain a fragment, backslash or control character. Never throws, and
 * keeps paths relative so social-login start accepts them.
 */
export function safeDestination(value: string | null, config: Configuration): string {
  if (!value || value.length > 2048 || /[\\#\p{Cc}]/u.test(value) || value.startsWith('//'))
    return config.settings_url;
  if (value.startsWith('/')) return value;
  try {
    const url = new URL(value);
    if (!url.username && !url.password && config.frontend_origins.includes(url.origin))
      return url.href;
  } catch {
    // Neither a path nor an absolute URL.
  }
  return config.settings_url;
}
