//! What the pages ask of the browser beyond the vocabulary of Topcoat's runtime
//! expressions: passkeys, the clipboard, local storage, the address bar and popovers.
//!
//! Each is a [`Browser`] method returning an [`Expr`] whose JavaScript calls one
//! browser API, through `raw!`, so a component's handlers stay Rust and name what
//! they do. An expression whose JavaScript resolves later evaluates to a promise:
//! its method says so, and a handler awaits it in its own `raw!`, such as
//! `raw!("await ${copied}", false)`, since only the handler's own code is async.
//! Their Rust side never runs: the server only evaluates expressions that render,
//! and handlers run in the browser alone.

use serde::Serialize;
use topcoat::runtime::{Event, Expr, Signal, expr, record};

/// A passkey ceremony auth runs for a form, as [`Browser::ceremony`] sends it.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct CeremonyRequest {
    /// The route starting it, which answers its `WebAuthn` options.
    pub(crate) start: String,
    /// The route finishing it, which takes the browser's credential; without one,
    /// the form posts the proof itself, in the input `fill` names.
    pub(crate) finish: Option<String>,
    /// Whether it creates a passkey, rather than proving one.
    pub(crate) create: bool,
    /// The form's fields the start takes, each sent when it holds a value.
    pub(crate) fields: &'static [&'static str],
    /// The form's fields the finish takes besides the credential.
    pub(crate) finish_fields: &'static [&'static str],
    /// What the start takes besides the form's fields, such as a recovery link's
    /// token, which no input holds so the form's post never sends it again.
    pub(crate) fixed: serde_json::Map<String, serde_json::Value>,
    /// Where the session confirms with a passkey first, when the finish asks for
    /// a recent confirmation, before the ceremony runs once more.
    pub(crate) confirm: Option<(String, String)>,
    /// The input that receives the answer before the form posts: the finish's
    /// field `field`, or the whole proof without a finish.
    pub(crate) fill: Option<Fill>,
    /// Whether the form posts once the ceremony is done.
    pub(crate) submit: bool,
    /// Whether it only starts, resolving to what the start answered, for a later
    /// run to go on with.
    pub(crate) start_only: bool,
}

impl CeremonyRequest {
    /// Proving a passkey in the ceremony `start` starts and `finish` finishes,
    /// for no form; with `start_only`, only starting it.
    pub(crate) fn assertion(start: &str, finish: &str, start_only: bool) -> Self {
        Self {
            start: start.to_owned(),
            finish: Some(finish.to_owned()),
            create: false,
            fields: &[],
            finish_fields: &[],
            fixed: serde_json::Map::new(),
            confirm: None,
            fill: None,
            submit: false,
            start_only,
        }
    }
}

/// The input a [`CeremonyRequest`] fills from the ceremony's answer.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Fill {
    /// The input's name.
    pub(crate) input: &'static str,
    /// The answer's field it takes, or the whole answer without one.
    pub(crate) field: Option<&'static str>,
}

/// Why a ceremony did not complete, as [`Browser::ceremony`] resolves to it.
#[record]
#[derive(Clone, Debug)]
pub(crate) struct Refusal {
    /// What the page says.
    pub(crate) message: String,
    /// Whether this browser refused to run it here at all, such as for an origin
    /// its relying party does not list: the page goes on without it.
    pub(crate) unsupported: bool,
}

/// An `async` event handler, as an `@event` attribute takes it: a method returning
/// one cannot name the future it returns.
pub(crate) trait AsyncHandler: FnOnce(Event) -> Self::Running {
    /// What it returns: the handler, running.
    type Running: Future<Output = ()>;
}

impl<F: FnOnce(Event) -> R, R: Future<Output = ()>> AsyncHandler for F {
    type Running = R;
}

/// The browser's APIs, as runtime expressions.
pub(crate) struct Browser;

impl Browser {
    /// Whether this browser can run passkey ceremonies on this page, reading their
    /// options as JSON.
    pub(crate) fn passkeys() -> Expr<bool> {
        expr!(raw!(
            "cx.hydrate(window.isSecureContext && 'PublicKeyCredential' in window && 'parseRequestOptionsFromJSON' in PublicKeyCredential)",
            false
        ))
    }

    /// Runs `request` for the form whose ID is `form`, if any, reading its fields,
    /// then posts the form unless `request` says not to. A promise of what it
    /// answered: the start's answer, as JSON, when `request` only starts it, and
    /// nothing otherwise, since the page goes on; or why it did not complete. When
    /// `started` evaluates to such a start's answer, the ceremony goes on with it
    /// rather than starting again, so a click reaches the browser's passkey prompt
    /// at once, as Safari needs.
    pub(crate) fn ceremony(
        form: Option<&str>,
        request: &CeremonyRequest,
        started: Expr<String>,
    ) -> Expr<Result<String, Refusal>> {
        let form = form.unwrap_or_default().to_owned();
        // A request serializes: its fields are strings, string lists and JSON maps.
        let request = serde_json::to_string(request).unwrap_or_default();
        expr!(raw!(
            r#"(async (form, request, started) => {
                const post = async (path, body) => {
                    const response = await fetch(path, {
                        method: 'POST',
                        headers: { 'content-type': 'application/json', 'x-piquel-csrf': '1' },
                        body: JSON.stringify(body)
                    });
                    if (response.ok) return response.status === 204 ? null : response.json();
                    // Auth's routes refuse with `{error, code?}`, `error` readable; a
                    // proxy in the way may send anything.
                    const problem = await response.json().catch(() => null);
                    const error = typeof problem?.error === 'string' ? problem.error
                        : response.status === 429 ? 'Too many attempts. Wait a moment and try again.'
                        : 'This action could not be completed. Please try again.';
                    throw Object.assign(new Error(error), { stepUp: problem?.code === 'step_up_required' });
                };
                const data = form ? new FormData(form) : new FormData();
                const values = (names) => Object.fromEntries(names
                    .map((name) => [name, String(data.get(name) ?? '').trim()])
                    .filter(([, value]) => value));
                const body = () => ({ ...request.fixed, ...values(request.fields) });
                const prove = async (start, body, create) => {
                    const answer = started ?? await post(start, body);
                    // A start serves one try.
                    started = undefined;
                    const options = answer.public_key.publicKey;
                    const credential = create
                        ? await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) })
                        : await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) });
                    if (!credential) throw new Error('The passkey request was cancelled.');
                    return { ceremony_id: answer.ceremony_id, credential: credential.toJSON() };
                };
                const run = async () => {
                    const proof = await prove(request.start, body(), request.create);
                    return request.finish
                        ? post(request.finish, { ...values(request.finish_fields), ...proof })
                        : proof;
                };
                try {
                    if (request.start_only)
                        return cx.ok(cx.hydrate(JSON.stringify(await post(request.start, body()))));
                    let answer;
                    try {
                        answer = await run();
                    } catch (error) {
                        if (!error.stepUp || !request.confirm) throw error;
                        const [start, finish] = request.confirm;
                        await post(finish, await prove(start, {}, false));
                        answer = await run();
                    }
                    if (request.fill) {
                        const value = request.fill.field ? answer?.[request.fill.field] : answer;
                        form.elements.namedItem(request.fill.input).value =
                            typeof value === 'string' ? value : JSON.stringify(value);
                    }
                    if (request.submit) form.submit();
                    return cx.ok(cx.hydrate(''));
                } catch (error) {
                    return cx.err(cx.record({
                        message: cx.hydrate(error instanceof DOMException
                            ? 'The passkey request was cancelled or unavailable. Try again or use another device.'
                            : error instanceof Error ? error.message : 'Something went wrong. Please try again.'),
                        unsupported: cx.hydrate(error instanceof DOMException && error.name === 'SecurityError')
                    }));
                }
            })(
                document.getElementById(String(${form})),
                JSON.parse(String(${request})),
                String(${started}) ? JSON.parse(String(${started})) : undefined
            )"#,
            Ok(String::new())
        ))
    }

    /// Whether this browser lets the page write to the clipboard.
    pub(crate) fn clipboard() -> Expr<bool> {
        expr!(raw!("cx.hydrate('clipboard' in navigator)", false))
    }

    /// Copies the text of the element whose ID is `source`. A promise of whether
    /// it did.
    pub(crate) fn copy(source: &str) -> Expr<bool> {
        let source = source.to_owned();
        expr!(raw!(
            "navigator.clipboard.writeText(document.getElementById(String(${source}))?.textContent ?? '').then(() => cx.hydrate(true), () => cx.hydrate(false))",
            false
        ))
    }

    /// A promise that resolves after a moment: as long as a status, such as
    /// "Copied", shows before it clears.
    pub(crate) fn moment() -> Expr<()> {
        expr!(raw!(
            "new Promise((resolve) => setTimeout(resolve, 2000))",
            ()
        ))
    }

    /// Whether this browser dismissed `key`, keeping it in local storage. One that
    /// keeps none, or refuses, as when storage is blocked, dismissed nothing.
    pub(crate) fn dismissed(key: &str) -> Expr<bool> {
        let key = key.to_owned();
        expr!(raw!(
            "cx.hydrate((() => { try { return Boolean(localStorage.getItem(String(${key}))); } catch { return false; } })())",
            false
        ))
    }

    /// Keeps `key` dismissed in local storage, where the browser allows it.
    pub(crate) fn dismiss(key: &str) -> Expr<()> {
        let key = key.to_owned();
        expr!(raw!(
            "(() => { try { localStorage.setItem(String(${key}), '1'); } catch {} })()",
            ()
        ))
    }

    /// Gives the focus to the page's heading, as when what had it disappears.
    pub(crate) fn focus_heading() -> Expr<()> {
        expr!(raw!(
            "(() => { const heading = document.querySelector('h1'); heading?.setAttribute('tabindex', '-1'); heading?.focus(); })()",
            ()
        ))
    }

    /// Makes `url` the page's address, so reloading it fetches that page by `GET`.
    pub(crate) fn replace_url(url: &str) -> Expr<()> {
        let url = url.to_owned();
        expr!(raw!("history.replaceState(null, '', String(${url}))", ()))
    }

    /// The link's fragment, without its `#`.
    pub(crate) fn fragment() -> Expr<String> {
        expr!(raw!("cx.hydrate(location.hash.slice(1))", String::new()))
    }

    /// Drops the fragment from the page's address.
    pub(crate) fn drop_fragment() -> Expr<()> {
        expr!(raw!(
            "history.replaceState(null, '', location.pathname + location.search)",
            ()
        ))
    }

    /// Whether the fragment `fragment` evaluates to holds a value for each of
    /// `names`.
    pub(crate) fn fragment_holds(names: &[&str], fragment: Expr<String>) -> Expr<bool> {
        let names = names.join(" ");
        expr!(raw!(
            "cx.hydrate(String(${names}).split(' ').every((name) => new URLSearchParams(String(${fragment})).get(name)))",
            false
        ))
    }

    /// Copies the fragment's values into the inputs of the form whose ID is `form`
    /// that name them in `data-fragment`.
    pub(crate) fn fill_from_fragment(form: &str) -> Expr<()> {
        let form = form.to_owned();
        expr!(raw!(
            "(() => { const values = new URLSearchParams(location.hash.slice(1)); for (const input of document.getElementById(String(${form})).querySelectorAll('input[data-fragment]')) input.value = values.get(input.dataset.fragment) ?? ''; })()",
            ()
        ))
    }

    /// Sets `fragment` to the link's fragment whenever it changes: following a
    /// link that differs only in its fragment does not reload the page.
    pub(crate) fn follow_fragment(fragment: Signal<String>) -> Expr<()> {
        expr!(raw!(
            "addEventListener('hashchange', () => ${fragment}.set(cx.hydrate(location.hash.slice(1))))",
            ()
        ))
    }

    /// Tells the browser's password manager the handle `name` and the display name
    /// `display_name` of the account whose ID is `user`, so its passkeys show them
    /// after a change (the `WebAuthn` Signal API). Does nothing where unsupported.
    pub(crate) fn signal_account(user: &str, name: &str, display_name: &str) -> Expr<()> {
        let (user, name, display_name) =
            (user.to_owned(), name.to_owned(), display_name.to_owned());
        expr!(raw!(
            r#"(() => {
                if (!window.isSecureContext || !('PublicKeyCredential' in window)) return;
                // Passkeys carry the account ID's 16 bytes as their user handle.
                const bytes = String(${user}).replace(/-/g, '').match(/../g) ?? [];
                PublicKeyCredential.signalCurrentUserDetails?.({
                    rpId: location.hostname,
                    userId: btoa(String.fromCharCode(...bytes.map((byte) => parseInt(byte, 16))))
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
                    name: String(${name}),
                    displayName: String(${display_name})
                }).catch(() => undefined);
            })()"#,
            ()
        ))
    }

    /// Whether this browser runs a passkey ceremony for a related origin, which
    /// the dashboard's needs. A promise.
    pub(crate) fn related_origins() -> Expr<bool> {
        expr!(raw!(
            "(async () => window.isSecureContext && 'PublicKeyCredential' in window && 'parseRequestOptionsFromJSON' in PublicKeyCredential && (await PublicKeyCredential.getClientCapabilities?.().catch(() => ({})))?.relatedOrigins === true)().then((capable) => cx.hydrate(Boolean(capable)))",
            false
        ))
    }

    /// The milliseconds since the page loaded.
    pub(crate) fn since_load() -> Expr<f64> {
        expr!(raw!("cx.hydrate(performance.now())", 0.0))
    }

    /// Shows the popover whose ID is `popover`.
    pub(crate) fn show(popover: &str) -> Expr<()> {
        let popover = popover.to_owned();
        expr!(raw!(
            "document.getElementById(String(${popover}))?.showPopover()",
            ()
        ))
    }

    /// Whether the popover whose ID is `popover` shows.
    pub(crate) fn shown(popover: &str) -> Expr<bool> {
        let popover = popover.to_owned();
        expr!(raw!(
            "cx.hydrate(document.getElementById(String(${popover}))?.matches(':popover-open') ?? false)",
            false
        ))
    }

    /// Goes on with the change `change` evaluates to, as a dashboard's click
    /// marked it: `a:` and the link it follows, or `b:` for the button marked
    /// `data-pending`, whose form it posts with that button.
    pub(crate) fn go_on(change: Expr<String>) -> Expr<()> {
        expr!(raw!(
            r#"((change) => {
                if (change.startsWith('a:')) return location.assign(change.slice(2));
                const button = document.querySelector('[data-pending]');
                button?.removeAttribute('data-pending');
                button?.form?.requestSubmit(button);
            })(String(${change}))"#,
            ()
        ))
    }

    /// Hides the popover whose ID is `popover`.
    pub(crate) fn hide(popover: &str) -> Expr<()> {
        let popover = popover.to_owned();
        expr!(raw!(
            "document.getElementById(String(${popover}))?.hidePopover()",
            ()
        ))
    }
}
