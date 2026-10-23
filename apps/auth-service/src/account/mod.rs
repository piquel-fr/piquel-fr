//! Account settings any administrator may also change: one router, mounted twice.
//!
//! The owner reaches it at `/account` on the public listener, with their browser
//! session and under the browser policy. An administrator reaches the same routes
//! at `/users/{user_id}/account` on the private admin listener, with an admin API
//! token, a recent passkey and a reason for every change. Handlers take the
//! [`Subject`] they act on rather than a session, and run the same
//! [`AccountService`] operations the `account` command runs.
//!
//! The rule for sharing: administrators may view, edit and remove, but never add
//! a way to sign in or to receive the account's email, which would let them take
//! the account over. Routes that add one, the owner's own reports, and the owner's
//! clients, which administrators manage through the admin API, stay with their
//! modules and on the owner mount only.

/// Failures of the shared operations.
mod error;
/// The account acted on, who acts, and how each mount authenticates them.
mod subject;

pub(crate) use error::AccountError;
pub(crate) use subject::{ActingAs, ConfirmedSubject, Subject};

use crate::{
    admin::AdminTokens,
    emails::EmailView,
    federation::FederationError,
    history::{HistoryPage, HistoryQuery},
    operations::operations,
    passkey::Rename,
    routes::{emails, federation, history, passkey, sessions},
    sessions::{Revoked, SessionItem},
};
use axum::{
    Json, Router,
    extract::{FromRef, Path, Query, State},
    http::StatusCode,
    routing::{MethodRouter, delete, get, patch, post},
};
use piquel_common::{
    EmailId, PasskeyId, SessionId,
    protocol::api::{Identity, Passkey},
};
use piquel_repository::Database;
use serde::Deserialize;
use subject::Mount;

operations! {
    /// Every shared settings operation. The shared router maps each to its route,
    /// served on both mounts, and the `account` command has a command for each,
    /// which a CLI test checks.
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

/// Every shared settings operation, on any account: what both mounts and the
/// `account` command run. Each operation takes the [`Subject`] it acts on, and
/// lives with its setting in the passkey, federation, emails, sessions or history
/// module.
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
}

/// The shared settings routes on one mount.
#[derive(Clone)]
pub(crate) struct AccountApplication {
    /// The operations behind the routes.
    service: AccountService,
    /// The mount, which decides who acts.
    mount: Mount,
}

/// The `{id}` of a shared route's path, read by name, since the admin mount's
/// path also holds the account's `{user_id}`.
#[derive(Deserialize)]
struct Item<T> {
    /// The passkey, address or session.
    id: T,
}

/// The `{provider}` of an identity's path, read by name like [`Item`].
#[derive(Deserialize)]
struct IdentityPath {
    /// The provider's name.
    provider: String,
}

impl FromRef<AccountApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &AccountApplication) -> Self {
        application.service.database.clone()
    }
}

impl AccountApplication {
    /// The routes at `/account`, for the signed-in owner.
    pub(crate) const fn owner(database: Database) -> Self {
        Self {
            service: AccountService::new(database),
            mount: Mount::Owner,
        }
    }

    /// The routes at `/users/{user_id}/account`, for administrators whose tokens
    /// `tokens` checks.
    pub(crate) fn admin(database: Database, tokens: AdminTokens) -> Self {
        Self {
            service: AccountService::new(database),
            mount: Mount::Admin(tokens),
        }
    }

    /// Returns every shared route at its `/account/…` path, with this
    /// application as state. The admin listener nests them under `/users/{user_id}`.
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
        subject: Subject,
    ) -> Result<Json<Vec<Passkey>>, AccountError> {
        Ok(Json(app.service.passkeys(&subject).await?))
    }

    /// Renames a passkey. A name grants nothing, so the owner's session is enough.
    async fn rename_passkey(
        State(app): State<Self>,
        subject: Subject,
        Path(Item { id }): Path<Item<PasskeyId>>,
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
        Path(Item { id }): Path<Item<PasskeyId>>,
    ) -> Result<StatusCode, AccountError> {
        app.service.revoke_passkey(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists the account's linked social identities.
    async fn identities(
        State(app): State<Self>,
        subject: Subject,
    ) -> Result<Json<Vec<Identity>>, AccountError> {
        Ok(Json(app.service.identities(&subject).await?))
    }

    /// Unlinks the provider the path names.
    async fn unlink_identity(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(IdentityPath { provider }): Path<IdentityPath>,
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
        subject: Subject,
    ) -> Result<Json<Vec<EmailView>>, AccountError> {
        Ok(Json(app.service.emails(&subject).await?))
    }

    /// Makes a verified address the primary one.
    async fn make_primary_email(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(Item { id }): Path<Item<EmailId>>,
    ) -> Result<StatusCode, AccountError> {
        app.service.make_primary_email(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Removes an address.
    async fn remove_email(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(Item { id }): Path<Item<EmailId>>,
    ) -> Result<StatusCode, AccountError> {
        app.service.remove_email(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists the account's active sessions, most recently active first.
    async fn sessions(
        State(app): State<Self>,
        subject: Subject,
    ) -> Result<Json<Vec<SessionItem>>, AccountError> {
        Ok(Json(app.service.sessions(&subject).await?))
    }

    /// Signs one session out.
    async fn revoke_session(
        State(app): State<Self>,
        subject: Subject,
        Path(Item { id }): Path<Item<SessionId>>,
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
        subject: Subject,
        Query(query): Query<HistoryQuery>,
    ) -> Result<Json<HistoryPage>, AccountError> {
        Ok(Json(app.service.history(&subject, query.before).await?))
    }
}

/// Database-backed scenarios of the admin mount.
#[cfg(test)]
mod tests;
