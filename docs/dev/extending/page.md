# Adding a page or route to auth

This guide adds a server-rendered page to auth.piquel.fr, such as a settings
tab, or a JSON route of the account API. [Rust conventions](../rust-conventions.md#applications-and-routes)
describes how pages and routes work; this page is the order you change them in.

The examples add a hypothetical Recovery codes tab to the settings. The admin
dashboard's pages follow [adding an administrative operation](admin-operation.md#5-add-the-dashboard-page)
instead: they are routes of the admin listener, not auth's pages.

## What you'll have at the end

- A page at its own path, which shows itself on `GET` and makes its form's
  change on `POST`, under auth's security layer: its request budget, its
  Content-Security-Policy and the rule that only auth's own pages post forms
  to it.
- Its strings, forms and queries in `piquel-ui`, so a field's name is written
  once.
- A change that needs a recent passkey asks for one before the form posts.
- Tests through the whole service, and in a real browser.

## Before you start

- The operation the page runs exists as a service method, such as an
  `AccountService` operation. A page only finds who acts, calls the service and
  renders. To add a setting, follow [adding an account setting](account-setting.md),
  which comes back here for the page.
- Decide which kind of page it is:
  - **An account page**, a settings tab or a developer console page, for a
    signed-in owner. It implements `AccountPage`, which serves every account
    page the same way.
  - **A page of its own**, such as the sign-in or recovery pages, for a browser
    that may be signed out. It has its own handlers.

## 1. Name its path

Add the path to `routes::page` in `apps/auth-service/src/routes.rs`: under
`page::settings` for a settings tab, `page::developers` for a console page, or
directly in `page` for a page of its own. Then add it to `page::ALL`, whose
length grows by one:

```rust
/// Recovery codes.
pub(crate) const CODES: &str = "/settings/codes";
```

The security layer classifies a request as a page by the route template it
matched, against `page::ALL` (`Endpoint::classify` in
`apps/auth-service/src/security/endpoint.rs`), so a path missing from it gets no
page budget and no request context.

## 2. Describe what its forms send

In `piquel-ui` (`crates/ui/src/<area>/`), beside the page's component, declare:

- **its change**, an internally tagged enum that names itself in the hidden
  `action` field, with fields that deserialize from text:

  ```rust
  #[derive(Clone, Debug, Serialize, Deserialize)]
  #[serde(tag = "action", rename_all = "snake_case")]
  pub enum CodesChange {
      /// Replaces the account's codes.
      Regenerate,
  }
  ```

- **its query**, the rows a link opens, a `Default` struct that implements
  `Query`, as `ConnectedAppsState` does;
- **its notice**, a variant of `Notice` in `crates/ui/src/form.rs`, with its
  sentence in `Notice::message`, which the page says once after a change.

List the change and the query in the `fields!` block of `crates/ui/src/form.rs`,
so forms and links can send them, and export them from `crates/ui/src/lib.rs`.

## 3. Render it

Write the page as a `#[component]` in the same module. It takes plain rows and
URLs, never the service's types, and builds each form with `change_form`.
A settings page's component takes an `Audience`, so the admin dashboard can
render the same section for an administrator:

```rust
change_form(
    action: page,
    change: CodesChange::Regenerate,
    label: "Regenerate",
    confirm: audience.confirms(),
)
```

Every string the page shows is in `piquel-ui`. A new settings tab also adds a
`Tab` variant, with its label, in `crates/ui/src/settings/mod.rs`.

## 4. Write its handler

**An account page** implements `AccountPage` (`apps/auth-service/src/web/account.rs`)
in its own module, such as `apps/auth-service/src/web/settings/codes.rs`. Model
it on `ConnectedApps` in `web/settings/connected.rs`:

- `SECTION`, `PATH` and `TITLE`, and the `Change` and `Row` types of step 2;
- `reopened`: the row a refused change shows open again, with what was typed;
- `apply`: makes the change as the `Owner`, through the service, and answers
  `Applied::Done(Notice::…)`, or another `Applied` to go elsewhere or reveal a
  secret;
- `render`: reads through `reader.viewer()`, or `reader.owner()` for what only
  the owner may read, and answers with `web.settings_page(...)`, or
  `web.console_page(...)` for a console page.

Then export it from `web/settings/mod.rs` (or `web/developers/mod.rs`), add
`Self::entry::<settings::Codes>()` to `WebApplication::pages` in
`apps/auth-service/src/web/mod.rs`, whose length grows by one, and for a new
tab, its entry in `TABS`.

**A page of its own** has two handlers in an `impl WebApplication` block, under
`apps/auth-service/src/web/auth/`: one for `GET`, taking `&Cx`, and one for
`POST`, taking `&Cx` and the `Body`, each returning `Result<Response, Failure>`.
Add them to `WebApplication::pages` with `page!`, and its title to `Title` in
`crates/ui/src/layout/html.rs`:

```rust
page!(
    RECOVER_UNDO,
    Title::UndoRecovery.as_str(),
    Self::undo_recovery,
    Self::undo_recovery_change,
),
```

It renders with `self.render(cx, status, title, targets, view)`, in the narrow
shell of a signed-out page. `targets` are the URLs its forms may redirect to,
which the page's `form-action` must name.

A handler never sets a flow or session cookie itself, and never sends messages
to other systems; see [Rust conventions](../rust-conventions.md#applications-and-routes).

## 5. Ask for a passkey confirmation

A change that needs a recent passkey checks it in its service operation, under
the account lock, with `Owner::lock_confirmed` or `Subject::lock_confirmed`.
The page only asks for it first:

- the component passes `confirm: audience.confirms()` to `change_form`, which
  marks the form `data-passkey-confirm` while the session has no recent
  confirmation, so the passkey script confirms before it posts;
- a change posted anyway fails with `step_up_required`, and
  `WebApplication::submit` renders the page again with the row open, asking
  once more.

## 6. Leave caching alone

Every response is `Cache-Control: no-store, no-transform` unless its handler
wraps it in `Cached(CacheClass::Immutable, …)` or `Cached(CacheClass::Public { … }, …)`
(`apps/auth-service/src/security/http.rs`). Pages are never cached: they show
the account and its secrets. Only content that never changes at its URL, such as
a profile picture, is `Immutable`, and only credential-free data the same for
every caller is `Public`. A response that sets a cookie, or isn't a `200`, stays
`no-store` whatever its handler asks.

## Adding a JSON route

The account API's routes are axum routes, not pages:

1. Name the path in its feature's module of `routes.rs`, under `/account/`,
   which `Endpoint::classify` gives the account API's budget and same-origin
   rule. A path anywhere else is `Endpoint::Other` unless you classify it.
2. Add the handler to its feature's `XApplication`, whose `routes(self)` mounts
   it. A shared setting is an arm of `AccountApplication::route` instead (see
   [adding an account setting](account-setting.md#3-serve-it-on-the-account-api)).
   A new application is merged in `AuthConfig::router`
   (`apps/auth-service/src/lib.rs`).
3. Extract who acts: `Viewer` for a read, `Subject` for a shared change, `Owner`
   for the owner's alone, or `ConfirmedOwner` and `ConfirmedSubject` when the
   change needs a recent passkey: they answer `step_up_required` before the
   path or body is read.
4. Return the feature's error. Its `From` into `ApiError`, in its `error.rs`,
   sets the status and the message.

## Test it

Test the page through the whole service, in `tests.rs` beside its module, such as
`apps/auth-service/src/web/settings/tests.rs`. `Replicas::new()` builds two
replicas on one database, `Browser::new_account` signs a browser up, and
`browser.visit` and `browser.post` show the page and post its change:

```rust
let removed = browser.post(&replicas, settings::APPS, &remove).await;
assert_eq!(redirect(&removed), settings::APPS);
assert_eq!(cookie(&removed, BrowserCookie::Notice).0, "app_removed");
```

These tests need a database, so they are `#[ignore = "requires TEST_DATABASE_URL"]`
and run with `just db test`.

Then check the page in Chromium, with the real binary and a virtual
authenticator: add a test to the spec of its area in `tests/browser/`, such as
`settings.spec.ts`, and update the spec's top comment if it now covers more.
Run `just web test-browser` against running servers, as the
[browser tests' README](https://github.com/piquel-fr/piquel-fr/blob/main/tests/browser/README.md)
sets them up. To see the page yourself, deploy the checkout with `just preview`.

## Document it

- Describe the task the page does in the user guide, through each surface that
  can do it, as [changing the documentation](../documentation.md#writing) says.
- If the guide shows the page, add a spec to `tests/browser/screenshots/` and run
  `just docs screenshots`: screenshots are generated, never taken by hand.
- A page on a new path is part of auth's surface: add it to
  [auth, account and admin surfaces](../architecture/surfaces.md).
- Give the feature to every surface it applies to: the CLI, the dashboard and the
  SDKs ([every surface gets the feature](../contributing.md#every-surface-gets-the-feature)).
