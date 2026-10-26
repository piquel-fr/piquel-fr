/**
 * The script of auth's server-rendered pages, which load it as their only script. It
 * runs the WebAuthn passkey ceremonies their forms ask for, and wires their forms by
 * their attributes. It exports nothing: auth embeds it, and the pages' stylesheet, by
 * their paths.
 */
type PasskeyKind = 'standard' | 'google_password_manager';

/** The action needs a passkey confirmation of the session first. */
class StepUpRequired extends Error {}

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

/**
 * The passkey ceremonies, which all run on the auth origin against its JSON routes,
 * with its HttpOnly session cookie. Serialized WebAuthn wrappers contain `publicKey`.
 */
class Passkeys {
  /** Whether this browser can run a ceremony here. */
  static available(): boolean {
    return window.isSecureContext && 'PublicKeyCredential' in window;
  }
  /** What a page says when a ceremony failed with `error`. */
  static message(error: unknown): string {
    return error instanceof DOMException
      ? 'The passkey request was cancelled or unavailable. Try again or use another device.'
      : error instanceof Error
        ? error.message
        : 'Something went wrong. Please try again.';
  }
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
    const start = await this.post<Ceremony<CreationOptions>>(`${path}/start`, {
      ...account,
      passkey_kind: kind
    });
    const options = start.public_key.publicKey;
    const credential = (await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge: Passkeys.decode(options.challenge),
        user: { ...options.user, id: Passkeys.decode(options.user.id) },
        excludeCredentials: options.excludeCredentials?.map((value) => Passkeys.descriptor(value))
      }
    })) as PublicKeyCredential | null;
    if (!credential) throw new Error('Passkey creation was cancelled.');
    const response = credential.response as AuthenticatorAttestationResponse;
    await this.post(`${path}/finish`, {
      ceremony_id: start.ceremony_id,
      friendly_name: friendlyName,
      credential: {
        id: credential.id,
        rawId: Passkeys.encode(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: Passkeys.encode(response.attestationObject),
          clientDataJSON: Passkeys.encode(response.clientDataJSON),
          transports: response.getTransports()
        },
        clientExtensionResults: credential.getClientExtensionResults()
      }
    });
  }
  /** Runs an assertion ceremony against `path`'s start and finish endpoints. */
  private async assert(path: string, body: object): Promise<void> {
    const start = await this.post<Ceremony<RequestOptions>>(`${path}/start`, body);
    const options = start.public_key.publicKey;
    const credential = (await navigator.credentials.get({
      publicKey: {
        ...options,
        challenge: Passkeys.decode(options.challenge),
        allowCredentials: options.allowCredentials?.map((value) => Passkeys.descriptor(value))
      }
    })) as PublicKeyCredential | null;
    if (!credential) throw new Error('Passkey verification was cancelled.');
    const response = credential.response as AuthenticatorAssertionResponse;
    await this.post(`${path}/finish`, {
      ceremony_id: start.ceremony_id,
      credential: {
        id: credential.id,
        rawId: Passkeys.encode(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: Passkeys.encode(response.authenticatorData),
          clientDataJSON: Passkeys.encode(response.clientDataJSON),
          signature: Passkeys.encode(response.signature),
          userHandle: response.userHandle ? Passkeys.encode(response.userHandle) : null
        },
        clientExtensionResults: credential.getClientExtensionResults()
      }
    });
  }
  /**
   * Posts `body` as JSON to the ceremony route `path`. A failure throws an error whose
   * message the page can show as is: the route's own, as `StepUpRequired` when the
   * session must confirm first.
   */
  private async post<T = void>(path: string, body: unknown): Promise<T> {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-piquel-csrf': '1' },
      body: JSON.stringify(body)
    });
    if (response.ok)
      return response.status === 204 ? (undefined as T) : (response.json() as Promise<T>);
    // Auth's browser routes send `{error, code?}`, `error` being a readable message;
    // a proxy in the way may send anything.
    const problem: unknown = await response.json().catch(() => null);
    const value = (name: string): unknown =>
      problem && typeof problem === 'object' ? (problem as Record<string, unknown>)[name] : null;
    const error = value('error');
    const message =
      typeof error === 'string'
        ? error
        : response.status === 429
          ? 'Too many attempts. Wait a moment and try again.'
          : 'This action could not be completed. Please try again.';
    throw value('code') === 'step_up_required' ? new StepUpRequired(message) : new Error(message);
  }
  private static decode(value: string): ArrayBuffer {
    return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) =>
      c.charCodeAt(0)
    ).buffer;
  }
  private static encode(value: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(value)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }
  private static descriptor(value: EncodedDescriptor): PublicKeyCredentialDescriptor {
    return { ...value, id: Passkeys.decode(value.id) };
  }
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
 * - a form marked `data-passkey-sign-in` signs in with a passkey, of the account its
 *   `username` names, or one the browser offers when it names none, then posts, so its
 *   page sends the browser on.
 * - a form marked `data-passkey-register` creates an account with its first passkey,
 *   from its `username`, `friendly_name`, `passkey_kind`, `invitation` and
 *   `pending_signup`, then posts, so its page sends the browser on.
 * - a form marked `data-passkey-enroll` adds a passkey named by its `friendly_name`,
 *   confirming first if it must, then posts, so its page says so.
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
 * A sign-in, register or enroll form's button starts disabled until passkeys are known
 * to work here; its `data-unavailable` note says why, and hides once it is enabled.
 * While a passkey form's ceremony runs, the form is busy: its button is disabled and
 * says so, and its `data-passkey-error` element, which says why the last one failed,
 * hides.
 */
function wire(document: Document): void {
  const passkeys = new Passkeys();
  const fragment = () => new URLSearchParams(window.location.hash.slice(1));
  const inputs = (form: HTMLFormElement) =>
    form.querySelectorAll<HTMLInputElement>('input[data-fragment]');
  /** The trimmed value `data` holds for `name`, or `undefined` when it holds none. */
  const field = (data: FormData, name: string) => {
    const value = data.get(name);
    return typeof value === 'string' && value.trim() ? value.trim() : undefined;
  };
  /** Where `data` asks to save a new passkey. */
  const kind = (data: FormData): PasskeyKind =>
    data.get('passkey_kind') === 'google_password_manager' ? 'google_password_manager' : 'standard';
  /** Runs `ceremony` once at a time for `form`, busy while it runs, saying why it failed. */
  const run = (form: HTMLFormElement, ceremony: () => Promise<void>) => {
    if (form.dataset.busy) return;
    const alert = form.querySelector<HTMLElement>('[data-passkey-error]');
    const button = form.querySelector('button');
    const label = button?.textContent ?? '';
    const busy = (waiting: boolean) => {
      form.setAttribute('aria-busy', String(waiting));
      if (waiting) form.dataset.busy = 'true';
      else delete form.dataset.busy;
      if (!button) return;
      button.disabled = waiting;
      button.textContent = waiting ? 'Waiting for your passkey…' : label;
    };
    if (alert) alert.hidden = true;
    busy(true);
    ceremony().catch((cause: unknown) => {
      busy(false);
      if (!alert) return;
      alert.textContent = Passkeys.message(cause);
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
    if (form.hasAttribute('data-passkey-sign-in')) {
      event.preventDefault();
      const username = field(new FormData(form), 'username');
      run(form, async () => {
        await passkeys.authenticate(username);
        form.submit();
      });
    }
    if (form.hasAttribute('data-passkey-register')) {
      event.preventDefault();
      const data = new FormData(form);
      const account = {
        username: field(data, 'username') ?? '',
        invitation: field(data, 'invitation'),
        pending_signup: field(data, 'pending_signup')
      };
      run(form, async () => {
        await passkeys.register(field(data, 'friendly_name') ?? '', account, kind(data));
        form.submit();
      });
    }
    if (form.hasAttribute('data-passkey-enroll')) {
      event.preventDefault();
      const data = new FormData(form);
      run(form, async () => {
        await passkeys.withConfirmation(() =>
          passkeys.register(field(data, 'friendly_name') ?? '', undefined, kind(data))
        );
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
  if (Passkeys.available())
    for (const form of document.querySelectorAll<HTMLFormElement>(
      'form[data-passkey-sign-in], form[data-passkey-register], form[data-passkey-enroll]'
    ))
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

wire(document);
