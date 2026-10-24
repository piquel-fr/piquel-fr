//! The components and layouts of auth.piquel.fr's server-rendered pages.
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
//!     piquel_ui::document(title: "Sign out", stylesheet: "/assets/style.css", home: "/",
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

/// The document around every page, and the parts pages share.
mod layout;
/// The pages of OAuth and `OpenID` Connect flows.
mod oidc;
/// The account's settings.
mod settings;

pub use layout::{Area, Title, document, intro};
pub use oidc::{consent, failure, logout, onward};
pub use settings::{
    DeviceChange, DeviceRow, EmailChange, EmailRow, EmailsState, HistoryChange, HistoryPage,
    HistoryRow, HistoryState, Holdings, Messages, Notice, OUT_OF_DATE, ProviderRow, Query,
    SignInChange, SignInState, Tab, account, addresses, devices, history, settings_frame,
    sign_in_methods, signed_out, verified, verify,
};
