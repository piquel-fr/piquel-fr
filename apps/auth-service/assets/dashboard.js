/**
 * The admin dashboard's script, its only one. It spares a change the trip to auth's
 * handoff page and back: it confirms the dashboard with a passkey in a dialog on the
 * page instead, then goes on. Every page works without it, going there and back. It
 * exports nothing, and nothing compiles it: auth embeds this file as it is, under a
 * path naming its content, and `tsc` only checks its JSDoc types.
 *
 * The frame's dialog, `#passkey-confirmation`, says how long the confirmation lasts:
 * `data-confirmed-for` seconds from when the page loaded, of which a change's page
 * needs `data-form-time` left to show its form. Once too little is left:
 * - a click on a link marked `data-confirm-first`, to a change's page, opens the
 *   dialog, then follows the link;
 * - a form in the page's `<main>` posting, a change, opens the dialog, then posts,
 *   unless it is marked `data-unconfirmed`, as a change that needs no
 *   confirmation, such as writing a draft announcement, is; a button of it marked
 *   `data-confirms`, such as the draft's "Send", still asks.
 * The dialog names what it confirms, from the link's or form's `data-confirming`:
 * the change, and what it acts on, so two pages left open are told apart.
 * The dialog's `data-passkey-confirm` button runs the passkey ceremony for the
 * dashboard's origin, which auth lists as a related origin of its RP ID: the
 * dialog's `data-confirmation-start` starts it, and its `data-confirmation-finish`
 * takes the assertion, which confirms the dashboard. The ceremony starts as the
 * dialog opens, so the button's click reaches the browser's passkey prompt at
 * once, as Safari needs. Closing the dialog drops the change.
 *
 * A browser that cannot run the ceremony on the dashboard's origin goes on at once,
 * and so does one whose ceremony does not start, such as when the session ended,
 * or which refuses the dashboard's origin for auth's RP ID, such as when it cannot
 * read auth's related origins: the change's page then confirms on auth's handoff
 * page.
 */

/**
 * A started confirmation, as auth's ceremonies answer (see `passkey.js`).
 * @typedef {Ceremony<PublicKeyCredentialRequestOptionsJSON>} Confirmation
 */

/**
 * Whether this browser runs a passkey ceremony for a related origin, reading its
 * options as JSON, which the dashboard's needs.
 * @returns {Promise<boolean>}
 */
async function capable() {
  if (!window.isSecureContext || !('PublicKeyCredential' in window)) return false;
  const credentials =
    /** @type {{ getClientCapabilities?: () => Promise<{ relatedOrigins?: boolean }> }} */ (
      /** @type {unknown} */ (PublicKeyCredential)
    );
  if (!credentials.getClientCapabilities || !('parseRequestOptionsFromJSON' in PublicKeyCredential))
    return false;
  const capabilities = await credentials
    .getClientCapabilities()
    .catch(() => /** @type {{ relatedOrigins?: boolean }} */ ({}));
  return capabilities.relatedOrigins === true;
}

/**
 * Posts `body` as JSON to the dashboard's `path`, and resolves to its answer: none
 * when it has no content. A refusal throws its message.
 * @template [T=void]
 * @param {string} path
 * @param {unknown} [body]
 * @returns {Promise<T>}
 */
async function post(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {})
  });
  if (response.ok)
    return response.status === 204
      ? /** @type {T} */ (undefined)
      : /** @type {Promise<T>} */ (response.json());
  // The dashboard's JSON routes refuse with `{error}`, a readable message.
  /** @type {unknown} */
  const problem = await response.json().catch(() => null);
  const error = problem && typeof problem === 'object' && 'error' in problem && problem.error;
  throw new Error(
    typeof error === 'string'
      ? error
      : 'The passkey could not confirm the dashboard. Please try again.'
  );
}

/**
 * Wires the dashboard page `document`, as above.
 * @param {Document} document
 * @returns {void}
 */
function wire(document) {
  const dialog = document.getElementById('passkey-confirmation');
  const button = dialog?.querySelector('button[data-passkey-confirm]');
  const alert = dialog?.querySelector('[data-passkey-error]');
  const confirming = dialog?.querySelector('[data-confirming]');
  if (
    !dialog ||
    !(button instanceof HTMLButtonElement) ||
    !(alert instanceof HTMLElement) ||
    !(confirming instanceof HTMLElement)
  )
    return;
  const { confirmationStart: start = '', confirmationFinish: finish = '' } = dialog.dataset;
  /** When the confirmation ends, on `performance.now()`'s clock. */
  const ends = performance.now() + Number(dialog.dataset.confirmedFor ?? 0) * 1000;
  const formTime = Number(dialog.dataset.formTime ?? 0) * 1000;
  /**
   * Whether the confirmation still has `ahead` milliseconds left.
   * @param {number} ahead
   */
  const confirmed = (ahead) => performance.now() + ahead < ends;
  /** Whether the dialog can confirm here, once known: until then, it does not. */
  let usable = false;
  void capable().then((answer) => {
    usable = answer;
  });
  /**
   * The change the dialog is open for: what goes on once confirmed, and its
   * ceremony, started as the dialog opened, or again after a try failed.
   * @type {{ then: () => void; started: Promise<Confirmation> } | undefined}
   */
  let change;
  /**
   * The form posting once confirmed, which the submit listener lets through.
   * @type {HTMLFormElement | undefined}
   */
  let confirmedForm;
  const label = button.textContent;
  /** @param {boolean} waiting */
  const busy = (waiting) => {
    button.disabled = waiting;
    button.textContent = waiting ? 'Waiting for your passkey…' : label;
  };
  /**
   * Closes the dialog and goes on with `pending`, unless the dialog was closed
   * meanwhile, or opened for another change.
   * @param {{ then: () => void }} pending
   */
  const goOn = (pending) => {
    if (change !== pending) return;
    change = undefined;
    dialog.hidePopover();
    pending.then();
  };
  /**
   * Goes on with `pending` at once if its ceremony does not start: its page then
   * confirms on auth's handoff page.
   * @param {{ then: () => void; started: Promise<Confirmation> }} pending
   */
  const unlessStarted = (pending) => {
    pending.started.catch(() => {
      goOn(pending);
    });
  };
  /**
   * Opens the dialog for the change `then` makes once confirmed, which `what`
   * names, if anything does. Answers whether it opened: where it cannot confirm,
   * the change goes on as it is.
   * @param {() => void} then
   * @param {string | undefined} what
   * @returns {boolean}
   */
  const confirm = (then, what) => {
    if (!usable) return false;
    change = { then, started: post(start) };
    unlessStarted(change);
    const named = confirming.firstElementChild;
    if (named) named.textContent = what ?? '';
    confirming.hidden = !what;
    alert.hidden = true;
    busy(false);
    dialog.showPopover();
    return true;
  };
  dialog.addEventListener('toggle', (event) => {
    if (/** @type {ToggleEvent} */ (event).newState === 'closed') change = undefined;
  });
  button.addEventListener('click', () => {
    const pending = change;
    if (!pending) return;
    busy(true);
    alert.hidden = true;
    pending.started
      .then(async (ceremony) => {
        // A dialog closed meanwhile confirms nothing.
        if (change !== pending) return;
        const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
          ceremony.public_key.publicKey
        );
        const credential = /** @type {PublicKeyCredential | null} */ (
          await navigator.credentials.get({ publicKey })
        );
        if (!credential) throw new Error('Passkey verification was cancelled.');
        if (change !== pending) return;
        await post(finish, { ceremony_id: ceremony.ceremony_id, credential: credential.toJSON() });
        goOn(pending);
      })
      .catch((/** @type {unknown} */ cause) => {
        if (change !== pending) return;
        // The browser refuses the dashboard's origin for auth's RP ID.
        if (cause instanceof DOMException && cause.name === 'SecurityError') {
          usable = false;
          goOn(pending);
          return;
        }
        busy(false);
        alert.textContent =
          cause instanceof DOMException
            ? 'The passkey request was cancelled or unavailable. Try again or use another device.'
            : cause instanceof Error
              ? cause.message
              : 'Something went wrong. Please try again.';
        alert.hidden = false;
        // A ceremony serves one try.
        pending.started = post(start);
        unlessStarted(pending);
      });
  });
  document.addEventListener('click', (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const link = /** @type {HTMLAnchorElement | null} */ (target.closest('a[data-confirm-first]'));
    // A click opening the link elsewhere, such as in a new tab, goes on as it is.
    const plain =
      event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey;
    if (!link || !plain || confirmed(formTime)) return;
    const opened = confirm(() => {
      window.location.assign(link.href);
    }, link.dataset.confirming);
    if (opened) event.preventDefault();
  });
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || form.method !== 'post') return;
    if (form === confirmedForm) {
      confirmedForm = undefined;
      return;
    }
    const submitter = event.submitter;
    const unconfirmed =
      form.hasAttribute('data-unconfirmed') && !submitter?.hasAttribute('data-confirms');
    if (!form.closest('main') || unconfirmed || confirmed(0)) return;
    const opened = confirm(() => {
      // Its submit event runs within the call, or not at all if it is invalid.
      confirmedForm = form;
      form.requestSubmit(submitter);
      confirmedForm = undefined;
    }, form.dataset.confirming);
    if (opened) event.preventDefault();
  });
}

wire(document);
