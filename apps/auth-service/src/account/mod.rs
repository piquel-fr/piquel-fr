//! What can be done to an account, as [`AccountService`] operations on the
//! account and who acts on it: an [`Owner`], only for what the owner alone may
//! do; a [`Subject`], for changes any administrator may also make; or a
//! [`Viewer`], for reads. The owner's routes run them with the owner of their
//! session cookie, and the `account` command with the operator at the terminal.
//! The admin dashboard calls them in-process, as an administrator.
//!
//! The rule for sharing: administrators may view, edit and remove, but never add
//! a way to sign in or to receive the account's email, which would let them take
//! the account over. Adding a passkey, linking an identity, adding an address
//! and reporting a history entry take an [`Owner`], which only the session cookie
//! builds, so an administrator cannot call them. Verifying an address is
//! authorized by its link's token instead, and takes the signed-in owner only if
//! there is one, to refuse a browser signed in to another account. The owner's
//! clients, which administrators manage through `AdminService`, are the owner's
//! too.

/// Failures of the account operations.
mod error;
/// The account acted on, and who acts on it.
mod subject;

pub(crate) use error::AccountError;
pub(crate) use subject::{ConfirmedOwner, ConfirmedSubject, Owner, Subject, Viewer};

use crate::{
    emails::EmailView,
    federation::FederationError,
    handles,
    history::{HistoryPage, HistoryQuery},
    operations::operations,
    passkey::Rename,
    routes::{emails, federation, history, passkey, sessions},
    security::{RequestContext, SessionError},
    sessions::{Revoked, SessionItem},
};
use axum::{
    Json, Router,
    extract::{FromRef, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{MethodRouter, delete, get, patch, post},
};
use chrono::{DateTime, Utc};
use piquel_common::{
    EmailId, Handle, PasskeyId, SessionId,
    protocol::api::{Identity, Passkey},
};
use piquel_repository::{Database, StoredUser};

operations! {
    /// Every shared settings operation. The owner's router maps each to its
    /// route, and the `account` command has a command for each, which a CLI test
    /// checks.
    pub(crate) enum AccountOperation {
        /// List the account's passkeys.
        ListPasskeys,
        /// Rename a passkey.
        RenamePasskey,
        /// Remove a passkey, keeping at least one, and sign the account out
        /// elsewhere.
        RevokePasskey,
        /// List the account's linked social identities.
        ListIdentities,
        /// Unlink a social identity, and sign the account out elsewhere.
        UnlinkIdentity,
        /// List the account's email addresses.
        ListEmails,
        /// Make a verified address the primary one.
        MakeEmailPrimary,
        /// Remove an email address.
        RemoveEmail,
        /// List the account's sessions.
        ListSessions,
        /// Sign one session out.
        RevokeSession,
        /// Sign every other session out.
        RevokeOtherSessions,
        /// Page through the account's security history.
        ViewHistory,
    }
}

/// Every account settings operation, on any account. The owner's routes run them
/// all, and the `account` command the shared ones. An operation only the owner may
/// run takes the [`Owner`] it acts as, a shared change the [`Subject`] it acts on,
/// and a read the [`Viewer`] it shows. Each operation lives with its setting in the
/// passkey, federation, emails, sessions, history or clients module.
#[derive(Clone)]
pub(crate) struct AccountService {
    /// Accounts, their settings and events.
    pub(crate) database: Database,
}

impl AccountService {
    /// Operates on `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// The owner of the browser session the request's `headers` carry, if any,
    /// acting from `context`: how a server-rendered page, which has no extractors,
    /// finds who acts. It records the session's activity, as the extractors do.
    pub(crate) async fn owner(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
    ) -> Result<Option<Owner>, AccountError> {
        Ok(Owner::resolve(&self.database, context, headers).await?)
    }

    /// The account's handle and display name. A session whose account is gone
    /// reads as signed out.
    pub(crate) async fn profile(&self, viewer: &Viewer) -> Result<Profile, AccountError> {
        viewer.authorize(&self.database).await?;
        Ok(self
            .database
            .users()
            .find_by_id(viewer.user())
            .await?
            .map(Profile::from)
            .ok_or(SessionError::Missing)?)
    }
}

/// The account as auth's pages show it to the browser signed in to it: in the
/// account's bar, on the sign-in and undo pages, and in its handle's settings.
pub(crate) struct Profile {
    /// Its handle, the login name.
    pub(crate) handle: Handle,
    /// When the owner may change the handle again, if not yet.
    pub(crate) handle_changeable_at: Option<DateTime<Utc>>,
    /// The name shown to the user and to relying parties.
    pub(crate) display_name: String,
}

impl From<StoredUser> for Profile {
    /// Keeps what the account's pages show.
    fn from(user: StoredUser) -> Self {
        let changeable_at = user.handle_changed_at + handles::COOLDOWN;
        Self {
            handle: user.handle,
            handle_changeable_at: (changeable_at > Utc::now()).then_some(changeable_at),
            display_name: user.display_name,
        }
    }
}

/// The owner's routes for the shared settings, at `/account`.
#[derive(Clone)]
pub(crate) struct AccountApplication {
    /// The operations behind the routes.
    service: AccountService,
}

impl FromRef<AccountApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &AccountApplication) -> Self {
        application.service.database.clone()
    }
}

impl AccountApplication {
    /// Serves the shared settings of the signed-in owner from `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self {
            service: AccountService::new(database),
        }
    }

    /// Returns every shared route at its `/account/…` path, with this
    /// application as state.
    pub(crate) fn routes(self) -> Router {
        AccountOperation::ALL
            .iter()
            .map(|operation| Self::route(*operation))
            .fold(Router::new(), |router, (path, method)| {
                router.route(path, method)
            })
            .with_state(self)
    }

    /// The path and method serving `operation`. Methods on one path merge, here
    /// and with the owner-only methods of the same path.
    fn route(operation: AccountOperation) -> (&'static str, MethodRouter<Self>) {
        type Op = AccountOperation;
        match operation {
            Op::ListPasskeys => (passkey::LIST, get(Self::passkeys)),
            Op::RenamePasskey => (passkey::ITEM, patch(Self::rename_passkey)),
            Op::RevokePasskey => (passkey::ITEM, delete(Self::revoke_passkey)),
            Op::ListIdentities => (federation::IDENTITIES, get(Self::identities)),
            Op::UnlinkIdentity => (federation::IDENTITY, delete(Self::unlink_identity)),
            Op::ListEmails => (emails::LIST, get(Self::emails)),
            Op::MakeEmailPrimary => (emails::PRIMARY, post(Self::make_primary_email)),
            Op::RemoveEmail => (emails::ITEM, delete(Self::remove_email)),
            Op::ListSessions => (sessions::LIST, get(Self::sessions)),
            Op::RevokeSession => (sessions::ITEM, delete(Self::revoke_session)),
            Op::RevokeOtherSessions => (sessions::REVOKE_OTHERS, post(Self::revoke_other_sessions)),
            Op::ViewHistory => (history::LIST, get(Self::history)),
        }
    }

    /// Lists the account's active passkeys.
    async fn passkeys(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<Passkey>>, AccountError> {
        Ok(Json(app.service.passkeys(&viewer).await?))
    }

    /// Renames a passkey. A name grants nothing, so the owner's session is enough.
    async fn rename_passkey(
        State(app): State<Self>,
        subject: Subject,
        Path(id): Path<PasskeyId>,
        Json(input): Json<Rename>,
    ) -> Result<StatusCode, AccountError> {
        app.service
            .rename_passkey(&subject, id, input.friendly_name)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Removes a passkey, keeping at least one.
    async fn revoke_passkey(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(id): Path<PasskeyId>,
    ) -> Result<StatusCode, AccountError> {
        app.service.revoke_passkey(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists the account's linked social identities.
    async fn identities(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<Identity>>, AccountError> {
        Ok(Json(app.service.identities(&viewer).await?))
    }

    /// Unlinks the provider the path names.
    async fn unlink_identity(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(provider): Path<String>,
    ) -> Result<StatusCode, AccountError> {
        let provider = provider
            .parse()
            .map_err(FederationError::UnsupportedProvider)?;
        app.service.unlink_identity(&subject, provider).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists the account's addresses, primary first.
    async fn emails(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<EmailView>>, AccountError> {
        Ok(Json(app.service.emails(&viewer).await?))
    }

    /// Makes a verified address the primary one.
    async fn make_primary_email(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(id): Path<EmailId>,
    ) -> Result<StatusCode, AccountError> {
        app.service.make_primary_email(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Removes an address.
    async fn remove_email(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(id): Path<EmailId>,
    ) -> Result<StatusCode, AccountError> {
        app.service.remove_email(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists the account's active sessions, most recently active first.
    async fn sessions(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<SessionItem>>, AccountError> {
        Ok(Json(app.service.sessions(&viewer).await?))
    }

    /// Signs one session out.
    async fn revoke_session(
        State(app): State<Self>,
        subject: Subject,
        Path(id): Path<SessionId>,
    ) -> Result<StatusCode, AccountError> {
        app.service.revoke_session(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Signs every other session out, and says how many there were.
    async fn revoke_other_sessions(
        State(app): State<Self>,
        subject: Subject,
    ) -> Result<Json<Revoked>, AccountError> {
        Ok(Json(app.service.revoke_other_sessions(&subject).await?))
    }

    /// Returns a page of the account's history, newest first.
    async fn history(
        State(app): State<Self>,
        viewer: Viewer,
        Query(query): Query<HistoryQuery>,
    ) -> Result<Json<HistoryPage>, AccountError> {
        Ok(Json(app.service.history(&viewer, query.before).await?))
    }
}

/// Database-backed scenarios of administrators acting on another account.
#[cfg(test)]
mod tests;
