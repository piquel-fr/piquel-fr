//! The components, layouts and stylesheet of auth.piquel.fr's server-rendered
//! pages. The admin dashboard serves the stylesheet too, under its own.
//!
//! Components render plain data: `piquel-common` identifiers, vocabularies and
//! events, and plain rows a page fills from what the service returns. They take
//! every URL as a prop, since only the router serving a request resolves its own
//! paths, and know nothing of the domain, the database or HTTP. Auth's page handlers
//! resolve who acts, call the service, and render the result with these.
//!
//! Nothing here uses Topcoat's browser runtime, `suspense`, `live!` or `asset!`: they
//! need inline scripts or `'unsafe-eval'`, which auth's pages forbid.
//!
//! ```
//! use topcoat::{context::Cx, view::{ViewExt, view}};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> topcoat::Result<()> {
//! let cx = Cx::default();
//! let html = view! { cx =>
//!     piquel_ui::document(title: "Sign out", stylesheet: "/assets/style.css",
//!         script: "/assets/passkey.js", home: "/settings",
//!         piquel_ui::logout(action: "/logout", fields: &[("client_id", "notes")], keep: "/login")
//!     )
//! }
//! .single()
//! .await?
//! .render(&cx);
//! assert!(html.contains(r#"<input type="hidden" name="client_id" value="notes">"#));
//! # Ok(())
//! # }
//! ```

/// The admin dashboard, and auth's page handing administrators off to it.
mod admin;
/// Files pages link, embedded under paths naming their content: the stylesheet.
mod asset;
/// An OIDC client's status, facts, settings form and secrets, which the console
/// shows and the admin dashboard will.
mod clients;
/// The developer console.
mod developers;
/// What forms and links send, what a page says of a change, and the parts of
/// every form.
mod form;
/// The document around every page, and the parts pages share.
mod layout;
/// The sign-in pages.
mod login;
/// The pages of OAuth and `OpenID` Connect flows.
mod oidc;
/// Account recovery: the pages its links open, and what the account's pages ask
/// of it.
mod recovery;
/// The account's settings.
mod settings;

pub use admin::{
    AdministratorRow, EventRow, HandoffProof, HandoffQuery, InvitationRow, SessionRow,
    Tab as DashboardTab, UserRow, administrator_list, client_list, dashboard_change,
    dashboard_failure, dashboard_frame, dashboard_signed_out, event_list, event_rows,
    handoff_proof, invitation_created, invitation_list, no_access, user_page, user_search,
};
pub use asset::{Asset, STYLESHEET};
pub use clients::{
    ClientDraft, ClientRow, ClientStatus, Connection, FieldError, Grace, Revealed, ScopeChoice,
    SecretRow,
};
pub use developers::{
    AppChange, AppLink, AppSettingsState, AppTab, MISSING, NewAppChange, NewAppState, Registered,
    SecretsChange, SecretsState, app_header, app_secrets, app_settings, apps, back_to_apps,
    new_app, overview,
};
pub use form::{Alert, Checkbox, Lines, Messages, Notice, OUT_OF_DATE, Query, QueryError};
pub use layout::{Area, Section, Title, account, document, intro, signed_out};
pub use login::{
    CallbackError, LinkKind, LoginChange, LoginQuery, PendingDestination, SignedIn, Step, sign_in,
};
pub use oidc::{Onward, consent, failure, logout, onward};
pub use recovery::{
    RecoverChange, RecoverStep, Recovery, RecoveryPasskey, RecoveryStage, UndoChange, UndoStep,
    recover, recovery_banner, recovery_prompt, undo_recovery,
};
pub use settings::{
    ConnectedAppChange, ConnectedAppRow, ConnectedAppsState, DeviceChange, DeviceRow, EmailChange,
    EmailRow, EmailsState, HistoryChange, HistoryPage, HistoryRow, HistoryState, Holdings,
    ProviderRow, SignInChange, SignInState, Tab, addresses, connected_apps, devices, history,
    settings_tabs, sign_in_methods, verified, verify,
};
