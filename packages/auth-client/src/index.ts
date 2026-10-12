/**
 * Browser-side SDK for the piquel auth service, shared by auth-web and piquel-web:
 * a typed API client, WebAuthn passkey ceremonies and redirect helpers.
 * Shared presentation styles are exported separately as `@piquel/auth-client/style.css`.
 */
export type Provider = 'github' | 'google';
export type PasskeyKind = 'standard' | 'google_password_manager';
export type Session = {
  user: { id: string; username: string; display_name: string };
  management_expires_at: string | null;
};
export type Configuration = {
  settings_url: string;
  providers: Provider[];
  invite_required: boolean;
};
export const providerName = (provider: Provider) => (provider === 'github' ? 'GitHub' : 'Google');

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
    if (!response.ok) {
      const problem: unknown = await response.json().catch(() => null);
      const message =
        problem &&
        typeof problem === 'object' &&
        'error' in problem &&
        typeof problem.error === 'string'
          ? problem.error
          : null;
      const protocolErrors: Record<string, string> = {
        invalid_request:
          'This sign-in request is invalid or expired. Start again from the application.',
        access_denied: 'Sign-in was cancelled or access was declined.',
        login_required: 'Please sign in again.',
        consent_required: 'Review the application’s requested access to continue.',
        server_error: 'Sign-in is temporarily unavailable. Please try again.',
        temporarily_unavailable: 'Sign-in is temporarily unavailable. Please try again.'
      };
      throw new Error(
        response.status === 401
          ? 'Please sign in again.'
          : response.status === 429
            ? 'Too many attempts. Wait a moment and try again.'
            : message
              ? (protocolErrors[message] ?? message)
              : 'This action could not be completed. Please try again.'
      );
    }
    return response.status === 204 ? (undefined as T) : response.json();
  }
  async form(path: string, body: URLSearchParams): Promise<{ redirect_url: string }> {
    const response = await fetch(`${this.origin}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'x-piquel-csrf': '1' },
      body
    });
    if (!response.ok) throw new Error('This request has expired. Please start again.');
    return response.json();
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
  async authenticate(username?: string, manage = false): Promise<void> {
    const path = manage ? '/account/passkeys/authorize' : '/webauthn/authenticate';
    const start = await this.api.request<Ceremony<RequestOptions>>(
      `${path}/start`,
      'POST',
      username ? { username } : {}
    );
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
  async register(
    friendlyName: string,
    account?: { username: string; invitation?: string },
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
export function safeDestination(value: string | null, settingsUrl: string): string {
  if (!value) return settingsUrl;
  const candidate = new URL(value, window.location.origin);
  if (
    candidate.origin === window.location.origin &&
    value.startsWith('/') &&
    !value.startsWith('//')
  )
    return candidate.href;
  return candidate.href === new URL(settingsUrl).href ? candidate.href : settingsUrl;
}
