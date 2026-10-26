/**
 * The passkey script: the one script of auth's server-rendered pages. It runs the
 * WebAuthn passkey ceremonies their forms ask for, and wires their forms by their
 * attributes. It exports nothing, and nothing compiles it: auth embeds this file as
 * it is, under a path naming its content, and `tsc` only checks its JSDoc types.
 */

/** @typedef {'standard' | 'google_password_manager'} PasskeyKind */

/** The action needs a passkey confirmation of the session first. */
class StepUpRequired extends Error {}

/** @typedef {Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }} EncodedDescriptor */
/**
 * @typedef {Omit<
 *   PublicKeyCredentialCreationOptions,
 *   'challenge' | 'user' | 'excludeCredentials'
 * > & {
 *   challenge: string;
 *   user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string };
 *   excludeCredentials?: EncodedDescriptor[];
 * }} CreationOptions
 */
/**
 * @typedef {Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
 *   challenge: string;
 *   allowCredentials?: EncodedDescriptor[];
 * }} RequestOptions
 */
/**
 * @template T
 * @typedef {{ ceremony_id: string; public_key: { publicKey: T } }} Ceremony
 */

/**
 * The passkey ceremonies, which all run on the auth origin against its JSON routes,
 * with its HttpOnly session cookie. Serialized WebAuthn wrappers contain `publicKey`.
 */
class Passkeys {
  /**
   * Whether this browser can run a ceremony here.
   * @returns {boolean}
   */
  static available() {
    return window.isSecureContext && 'PublicKeyCredential' in window;
  }
  /**
   * What a page says when a ceremony failed with `error`.
   * @param {unknown} error
   * @returns {string}
   */
  static message(error) {
    return error instanceof DOMException
      ? 'The passkey request was cancelled or unavailable. Try again or use another device.'
      : error instanceof Error
        ? error.message
        : 'Something went wrong. Please try again.';
  }
  /**
   * Signs in, which also confirms the new session for actions that need a passkey.
   * @param {string} [username]
   * @returns {Promise<void>}
   */
  authenticate(username) {
    return this.#assert('/webauthn/authenticate', username ? { username } : {});
  }
  /**
   * Confirms the current session with a passkey, for actions that need a recent one.
   * @returns {Promise<void>}
   */
  confirm() {
    return this.#assert('/account/passkeys/confirm', {});
  }
  /**
   * Runs `action`; if it needs a recent passkey confirmation, confirms the session
   * with a passkey, then runs it once more.
   * @template T
   * @param {() => Promise<T>} action
   * @returns {Promise<T>}
   */
  async withConfirmation(action) {
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
   * @param {string} friendlyName
   * @param {{ username: string; invitation?: string; pending_signup?: string }} [account]
   * @param {PasskeyKind} [kind]
   * @returns {Promise<void>}
   */
  async register(friendlyName, account, kind = 'standard') {
    const path = account ? '/webauthn/register' : '/account/passkeys/enroll';
    /** @type {Ceremony<CreationOptions>} */
    const start = await this.#post(`${path}/start`, { ...account, passkey_kind: kind });
    const options = start.public_key.publicKey;
    const credential = /** @type {PublicKeyCredential | null} */ (
      await navigator.credentials.create({
        publicKey: {
          ...options,
          challenge: Passkeys.#decode(options.challenge),
          user: { ...options.user, id: Passkeys.#decode(options.user.id) },
          excludeCredentials: options.excludeCredentials?.map((value) =>
            Passkeys.#descriptor(value)
          )
        }
      })
    );
    if (!credential) throw new Error('Passkey creation was cancelled.');
    const response = /** @type {AuthenticatorAttestationResponse} */ (credential.response);
    await this.#post(`${path}/finish`, {
      ceremony_id: start.ceremony_id,
      friendly_name: friendlyName,
      credential: {
        id: credential.id,
        rawId: Passkeys.#encode(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: Passkeys.#encode(response.attestationObject),
          clientDataJSON: Passkeys.#encode(response.clientDataJSON),
          transports: response.getTransports()
        },
        clientExtensionResults: credential.getClientExtensionResults()
      }
    });
  }
  /**
   * Runs an assertion ceremony against `path`'s start and finish endpoints.
   * @param {string} path
   * @param {object} body
   * @returns {Promise<void>}
   */
  async #assert(path, body) {
    /** @type {Ceremony<RequestOptions>} */
    const start = await this.#post(`${path}/start`, body);
    const options = start.public_key.publicKey;
    const credential = /** @type {PublicKeyCredential | null} */ (
      await navigator.credentials.get({
        publicKey: {
          ...options,
          challenge: Passkeys.#decode(options.challenge),
          allowCredentials: options.allowCredentials?.map((value) => Passkeys.#descriptor(value))
        }
      })
    );
    if (!credential) throw new Error('Passkey verification was cancelled.');
    const response = /** @type {AuthenticatorAssertionResponse} */ (credential.response);
    await this.#post(`${path}/finish`, {
      ceremony_id: start.ceremony_id,
      credential: {
        id: credential.id,
        rawId: Passkeys.#encode(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: Passkeys.#encode(response.authenticatorData),
          clientDataJSON: Passkeys.#encode(response.clientDataJSON),
          signature: Passkeys.#encode(response.signature),
          userHandle: response.userHandle ? Passkeys.#encode(response.userHandle) : null
        },
        clientExtensionResults: credential.getClientExtensionResults()
      }
    });
  }
  /**
   * Posts `body` as JSON to the ceremony route `path`. A failure throws an error whose
   * message the page can show as is: the route's own, as `StepUpRequired` when the
   * session must confirm first.
   * @template [T=void]
   * @param {string} path
   * @param {unknown} body
   * @returns {Promise<T>}
   */
  async #post(path, body) {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-piquel-csrf': '1' },
      body: JSON.stringify(body)
    });
    if (response.ok)
      return response.status === 204
        ? /** @type {T} */ (undefined)
        : /** @type {Promise<T>} */ (response.json());
    // Auth's browser routes send `{error, code?}`, `error` being a readable message;
    // a proxy in the way may send anything.
    /** @type {unknown} */
    const problem = await response.json().catch(() => null);
    /**
     * @param {string} name
     * @returns {unknown}
     */
    const value = (name) =>
      problem && typeof problem === 'object'
        ? /** @type {Record<string, unknown>} */ (problem)[name]
        : null;
    const error = value('error');
    const message =
      typeof error === 'string'
        ? error
        : response.status === 429
          ? 'Too many attempts. Wait a moment and try again.'
          : 'This action could not be completed. Please try again.';
    throw value('code') === 'step_up_required' ? new StepUpRequired(message) : new Error(message);
  }
  /**
   * The bytes `value` encodes in unpadded base64url.
   * @param {string} value
   * @returns {ArrayBuffer}
   */
  static #decode(value) {
    return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) =>
      c.charCodeAt(0)
    ).buffer;
  }
  /**
   * `value` in unpadded base64url.
   * @param {ArrayBuffer} value
   * @returns {string}
   */
  static #encode(value) {
    return btoa(String.fromCharCode(...new Uint8Array(value)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }
  /**
   * The credential descriptor `value` encodes.
   * @param {EncodedDescriptor} value
   * @returns {PublicKeyCredentialDescriptor}
   */
  static #descriptor(value) {
    return { ...value, id: Passkeys.#decode(value.id) };
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
 * @param {Document} document
 * @returns {void}
 */
function wire(document) {
  const passkeys = new Passkeys();
  const fragment = () => new URLSearchParams(window.location.hash.slice(1));
  /** @param {HTMLFormElement} form */
  const inputs = (form) =>
    /** @type {NodeListOf<HTMLInputElement>} */ (form.querySelectorAll('input[data-fragment]'));
  /**
   * The trimmed value `data` holds for `name`, or `undefined` when it holds none.
   * @param {FormData} data
   * @param {string} name
   */
  const field = (data, name) => {
    const value = data.get(name);
    return typeof value === 'string' && value.trim() ? value.trim() : undefined;
  };
  /**
   * Where `data` asks to save a new passkey.
   * @param {FormData} data
   * @returns {PasskeyKind}
   */
  const kind = (data) =>
    data.get('passkey_kind') === 'google_password_manager' ? 'google_password_manager' : 'standard';
  /**
   * Runs `ceremony` once at a time for `form`, busy while it runs, saying why it failed.
   * @param {HTMLFormElement} form
   * @param {() => Promise<void>} ceremony
   */
  const run = (form, ceremony) => {
    if (form.dataset.busy) return;
    const alert = /** @type {HTMLElement | null} */ (form.querySelector('[data-passkey-error]'));
    const button = form.querySelector('button');
    const label = button?.textContent ?? '';
    /** @param {boolean} waiting */
    const busy = (waiting) => {
      form.setAttribute('aria-busy', String(waiting));
      if (waiting) form.dataset.busy = 'true';
      else delete form.dataset.busy;
      if (!button) return;
      button.disabled = waiting;
      button.textContent = waiting ? 'Waiting for your passkey…' : label;
    };
    if (alert) alert.hidden = true;
    busy(true);
    ceremony().catch((/** @type {unknown} */ cause) => {
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
  /**
   * Enables `form`'s buttons, or disables them, showing the note on why.
   * @param {HTMLFormElement} form
   * @param {boolean} [enabled]
   */
  const enable = (form, enabled = true) => {
    form.querySelector('[data-unavailable]')?.toggleAttribute('hidden', enabled);
    for (const button of form.querySelectorAll('button')) button.disabled = !enabled;
  };
  if (Passkeys.available())
    for (const form of /** @type {NodeListOf<HTMLFormElement>} */ (
      document.querySelectorAll(
        'form[data-passkey-sign-in], form[data-passkey-register], form[data-passkey-enroll]'
      )
    ))
      enable(form);
  /** Shows each fragment form while the link has every value, or the notice that it does not. */
  const showFragmentForms = () => {
    for (const form of /** @type {NodeListOf<HTMLFormElement>} */ (
      document.querySelectorAll('form[data-fragment-form]')
    )) {
      const complete = [...inputs(form)].every((input) =>
        fragment().get(input.dataset.fragment ?? '')
      );
      form.hidden = !complete;
      enable(form, complete);
      document.querySelector('[data-fragment-missing]')?.toggleAttribute('hidden', complete);
    }
  };
  showFragmentForms();
  // Following a link that differs only in its fragment does not reload the page.
  window.addEventListener('hashchange', showFragmentForms);
  if ('clipboard' in navigator)
    for (const button of /** @type {NodeListOf<HTMLButtonElement>} */ (
      document.querySelectorAll('button[data-copy]')
    )) {
      const status = button.previousElementSibling;
      /** @type {ReturnType<typeof setTimeout> | undefined} */
      let cleared;
      /**
       * Says `message` in the button's status for a moment.
       * @param {string} message
       */
      const say = (message) => {
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
  const replaced = /** @type {HTMLElement | null} */ (document.querySelector('[data-replace-url]'))
    ?.dataset.replaceUrl;
  if (replaced) window.history.replaceState(null, '', replaced);
}

wire(document);
