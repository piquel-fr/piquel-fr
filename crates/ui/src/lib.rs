//! The components, layouts, stylesheet and typefaces of auth.sourceorigin.dev's
//! server-rendered pages. The admin dashboard serves them too, under its own
//! origin, and shares the shell: a sidebar beside the page, a status bar below
//! it, and the theme and sidebar preferences a cookie keeps.
//!
//! Components render plain data: `sourceorigin-common` identifiers, vocabularies and
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
//!     sourceorigin_ui::document(title: "Sign out", stylesheet: "/assets/style.css",
//!         scripts: &["/assets/passkey.js"],
//!         sourceorigin_ui::auth_shell(home: "/settings", policies: sourceorigin_ui::Policies::PATHS,
//!             sourceorigin_ui::logout(action: "/logout", fields: &[("client_id", "notes")], keep: "/login")
//!         )
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
/// Files pages link, embedded in the executable: the stylesheet and the
/// typefaces.
mod asset;
/// An OIDC client's status, facts, settings form and secrets, which the console
/// and the admin dashboard show.
mod clients;
/// The developer console.
mod developers;
/// The emails Origin Auth sends: what each says, as blocks, and their HTML and
/// plain-text bodies.
mod email;
/// What forms and links send, what a page says of a change, and the parts of
/// every form.
mod form;
/// The icons the pages draw inline.
mod icons;
/// The document around every page, and the frames pages share.
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
    AccountPages, Action, AdminAnnouncementRow, AdminClientRow, AdminOverview, AdministratorRow,
    AlertCard, Change, ClientChanges, ClientPage, Confirmation as DashboardConfirmation, Dashboard,
    DeliveryRow, DraftActions, EventRow, FoundAccount, HandlesPage, HandoffProof, HandoffQuery,
    InvitationRow, Measure, MessagePreview, NewClientForm, OperatorDraft, Problem, RecoveryKey,
    RecoveryRow, RecoveryStanding, Registration, ReleasedRow, ReservationRow, ReservedHolder,
    SearchAction, SessionRow, SigningKeyRow, Tab as DashboardTab, Target, UserRow,
    account_settings, admin_overview, administrator_list, alert_list, alert_update_fields,
    announcement_form, announcement_list, announcement_page, audit_page, client_created,
    client_list, client_page, client_registration, client_secrets, dashboard_change,
    dashboard_failure, dashboard_frame, dashboard_signed_out, delivery_list, event_list,
    event_rows, grant_search, handle_list, handoff_proof, invitation_created, invitation_list,
    message_page, no_access, previous_alerts, recovery_list, reserved_handle_choice,
    signing_key_list, signing_key_rotation, user_page, user_search,
};
pub use asset::{Asset, FONTS, STYLESHEET};
pub use clients::{
    ClientDraft, ClientRow, ClientStatus, Connection, FieldError, Grace, Revealed, ScopeChoice,
    SecretRow,
};
pub use developers::{
    AppChange, AppLink, AppSettingsState, AppTab, MISSING, NewAppChange, NewAppState, Registered,
    SecretsChange, SecretsState, app_header, app_secrets, app_settings, apps, back_to_apps,
    new_app, overview,
};
pub use email::{Block, EmailContent, Inline, Mail, email_preview};
pub use form::{
    Alert, Checkbox, Lines, Messages, Notice, OUT_OF_DATE, Query, QueryError, TOO_LARGE,
};
pub use layout::{
    AccountNav, Crumb, Destination, Group, Health, Pager, PasskeySignal, Policies,
    PreferenceChange, Preferences, SOURCE, Search, SearchPage, Section, Shortcut, ShortcutKind,
    Sidebar, Theme, Title, Who, account, auth_shell, document, error_page, search_results,
    signed_out, site_shell,
};
pub use login::{
    CallbackError, Invited, LinkKind, LoginChange, LoginQuery, PendingDestination, SignedIn, Step,
    sign_in,
};
pub use oidc::{LogoutNotice, Onward, consent, failure, logout, onward};
pub use recovery::{
    RecoverChange, RecoverStep, Recovery, RecoveryPasskey, RecoveryStage, UndoChange, UndoStep,
    recover, recovery_banner, recovery_prompt, undo_recovery,
};
pub use settings::{
    AccountOverview, Audience, CROP_SIZE, CROP_X, CROP_Y, ConnectedAppChange, ConnectedAppRow,
    ConnectedAppsState, DataChange, DataState, DeviceChange, DeviceRow, EmailChange, EmailRow,
    EmailsState, HistoryChange, HistoryPage, HistoryRow, HistoryState, Holdings, InboxChange,
    InboxPage, InboxRow, InboxState, NotificationPage, NotificationState, OverviewLinks,
    PASTE_WHOLE_LINK, PICTURE_FIELD, PICTURE_TYPES, ProfileChange, ProfileDialog, ProfilePages,
    ProfileState, ProviderRow, SignInChange, SignInState, SignOutStep, Tab, UnsubscribeStep,
    account_data, account_deleted, account_overview, addresses, connected_apps, devices, history,
    inbox, known_devices, notification, profile_settings, sign_in_methods, sign_out_everywhere,
    unsubscribe, verified, verify,
};
