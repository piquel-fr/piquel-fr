/**
 * Browser-side SDK for the piquel auth service, for pages on the auth origin: auth-web's
 * sign-in pages use it, and auth's server-rendered pages load it as their only script.
 * A typed API client, WebAuthn passkey ceremonies and the sign-in redirect check.
 * Shared presentation styles are exported separately as `@piquel/auth-sdk/style.css`.
 */
export type Provider = 'github' | 'google';
export type PasskeyKind = 'standard' | 'google_password_manager';
export type Session = { user: { id: string; username: string; display_name: string } };
/** auth's public `/config`: what its sign-in pages offer. */
export type Configuration = {
  invite_required: boolean;
  providers: Provider[];
  /** The account settings' path, where sign-in goes without another destination. */
  settings_url: string;
};
export const providerName = (provider: Provider) => (provider === 'github' ? 'GitHub' : 'Google');

/** A failed auth request, with a message the page can show as is. */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** The action needs a passkey confirmation of the session at most `maxAge` seconds old. */
export class StepUpRequired extends ApiError {
  constructor(
    message: string,
    status: number,
    readonly maxAge: number
  ) {
    super(message, status);
    this.name = 'StepUpRequired';
  }
}

/** Calls auth's JSON API from a page on the auth origin, with its HttpOnly session cookie. */
export class AuthApi {
  async request<T = void>(path: string, method = 'GET', body?: unknown): Promise<T> {
    const response = await fetch(path, {
      method,
      headers: method === 'GET' ? {} : { 'content-type': 'application/json', 'x-piquel-csrf': '1' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    if (!response.ok) throw await this.failure(response);
    return response.status === 204 ? (undefined as T) : (response.json() as Promise<T>);
  }
  /** Turns a failed response into an error whose message the page can show as is. */
  private async failure(response: Response): Promise<ApiError> {
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
      return new StepUpRequired(
        error ?? 'Confirm with your passkey to continue.',
        response.status,
        maxAge
      );
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
    return new ApiError(
      response.status === 429
        ? (error ?? 'Too many attempts. Wait a moment and try again.')
        : protocolMessage
          ? description && response.status < 500
            ? `${protocolMessage} (${description})`
            : protocolMessage
          : (description ??
            error ??
            (response.status === 401
              ? 'Please sign in again.'
              : 'This action could not be completed. Please try again.')),
      response.status
    );
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
  constructor(private readonly api: AuthApi) {}
  /** Signs in, which also confirms the new session for actions that need a passkey. */
  authenticate(username?: string): Promise<void> {
    return this.assert('/webauthn/authenticate', username ? { username } : {});
  }
  /** Confirms the current session with a passkey, for actions that need a recent one. */
  confirm(): Promise<void> {
    return this.assert('/account/passkeys/confirm', {});
  }
  /**
   * Runs `action`; if it needs a recent passkey confirmation, confirms the session
   * with a passkey, then runs it once more.
   */
  async withConfirmation<T>(action: () => Promise<T>): Promise<T> {
    try {
      return await action();
    } catch (error) {
      if (!(error instanceof StepUpRequired)) throw error;
    }
    await this.confirm();
    return action();
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

/**
 * Returns `value` when the auth service accepts it as `return_to`, else the settings
 * path: a path on the auth origin, without a fragment, backslash or control character.
 * Never throws.
 */
export function safeDestination(value: string | null, config: Configuration): string {
  if (!value || value.length > 2048 || /[\\#\p{Cc}]/u.test(value)) return config.settings_url;
  // One leading `/` makes it a path on the auth origin; `//` would leave it.
  return value.startsWith('/') && !value.startsWith('//') ? value : config.settings_url;
}

/**
 * Wires auth's server-rendered pages, which load this module as their only script and
 * mark what needs it:
 * - a form marked `data-submit-once` ignores a second submission, such as a double
 *   click, while the first is under way. Its buttons stay enabled, so the clicked one
 *   still sends its value.
 * - a form marked `data-passkey-confirm` confirms the session with a passkey, then
 *   posts it with `form.submit()`, which sends no button's value: its action and
 *   every other value come from its inputs, never from the button.
 * - a form marked `data-passkey-enroll` adds a passkey named by its `friendly_name`,
 *   confirming first if it must, then posts, so its page says so. Its button starts
 *   disabled until passkeys are known to work here.
 * - a form marked `data-fragment-form` copies the link's fragment into its
 *   `data-fragment` inputs as it posts, then drops the fragment from the address. It
 *   shows, with its button enabled, while the link has every value; otherwise the
 *   page's `data-fragment-missing` notice shows instead.
 * - a `data-copy` button copies the text of the element its value names, and says
 *   whether it did, for a moment, in the `role="status"` element just before it. It
 *   starts hidden, and shows once the browser can write to the clipboard.
 * - an element marked `data-replace-url` makes its value the page's address: a page
 *   answering a form with what only it may show, such as a secret, then reloads by
 *   `GET`, never posting the form again.
 * A form's `data-unavailable` note says why its button is disabled, and hides once
 * it is enabled. Its `data-passkey-error` element says why a ceremony failed.
 */
function wire(document: Document): void {
  const passkeys = new Passkeys(new AuthApi());
  const fragment = () => new URLSearchParams(window.location.hash.slice(1));
  const inputs = (form: HTMLFormElement) =>
    form.querySelectorAll<HTMLInputElement>('input[data-fragment]');
  /** Runs `ceremony` once at a time for `form`, saying why it failed. */
  const run = (form: HTMLFormElement, ceremony: () => Promise<void>) => {
    if (form.dataset.busy) return;
    form.dataset.busy = 'true';
    ceremony().catch((cause: unknown) => {
      delete form.dataset.busy;
      const alert = form.querySelector<HTMLElement>('[data-passkey-error]');
      if (!alert) return;
      alert.textContent = errorMessage(cause);
      alert.hidden = false;
    });
  };
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.hasAttribute('data-submit-once')) {
      if (form.dataset.submitted) event.preventDefault();
      else form.dataset.submitted = 'true';
    }
    if (form.hasAttribute('data-passkey-confirm')) {
      event.preventDefault();
      run(form, async () => {
        await passkeys.confirm();
        form.submit();
      });
    }
    if (form.hasAttribute('data-passkey-enroll')) {
      event.preventDefault();
      const data = new FormData(form);
      const name =
        form.querySelector<HTMLInputElement>('input[name="friendly_name"]')?.value.trim() ?? '';
      const kind =
        data.get('passkey_kind') === 'google_password_manager'
          ? 'google_password_manager'
          : 'standard';
      run(form, async () => {
        await passkeys.withConfirmation(() => passkeys.register(name, undefined, kind));
        form.submit();
      });
    }
    if (form.hasAttribute('data-fragment-form')) {
      for (const input of inputs(form))
        input.value = fragment().get(input.dataset.fragment ?? '') ?? '';
      const { pathname, search } = window.location;
      window.history.replaceState(null, '', `${pathname}${search}`);
    }
  });
  /** Enables `form`'s buttons, or disables them, showing the note on why. */
  const enable = (form: HTMLFormElement, enabled = true) => {
    form.querySelector<HTMLElement>('[data-unavailable]')?.toggleAttribute('hidden', enabled);
    for (const button of form.querySelectorAll('button')) button.disabled = !enabled;
  };
  if (passkeysAvailable())
    for (const form of document.querySelectorAll<HTMLFormElement>('form[data-passkey-enroll]'))
      enable(form);
  /** Shows each fragment form while the link has every value, or the notice that it does not. */
  const showFragmentForms = () => {
    for (const form of document.querySelectorAll<HTMLFormElement>('form[data-fragment-form]')) {
      const complete = [...inputs(form)].every((input) =>
        fragment().get(input.dataset.fragment ?? '')
      );
      form.hidden = !complete;
      enable(form, complete);
      document
        .querySelector<HTMLElement>('[data-fragment-missing]')
        ?.toggleAttribute('hidden', complete);
    }
  };
  showFragmentForms();
  // Following a link that differs only in its fragment does not reload the page.
  window.addEventListener('hashchange', showFragmentForms);
  if ('clipboard' in navigator)
    for (const button of document.querySelectorAll<HTMLButtonElement>('button[data-copy]')) {
      const status = button.previousElementSibling;
      let cleared: ReturnType<typeof setTimeout> | undefined;
      /** Says `message` in the button's status for a moment. */
      const say = (message: string) => {
        if (!status) return;
        status.textContent = message;
        clearTimeout(cleared);
        cleared = setTimeout(() => (status.textContent = ''), 2000);
      };
      button.hidden = false;
      button.addEventListener('click', () => {
        const text = document.getElementById(button.dataset.copy ?? '')?.textContent ?? '';
        navigator.clipboard.writeText(text).then(
          () => {
            say('Copied');
          },
          () => {
            say('Could not copy: select the text instead');
          }
        );
      });
    }
  const replaced = document.querySelector<HTMLElement>('[data-replace-url]')?.dataset.replaceUrl;
  if (replaced) window.history.replaceState(null, '', replaced);
}

// Without a document, as during SvelteKit's server render, there is nothing to wire.
if (typeof document !== 'undefined') wire(document);
