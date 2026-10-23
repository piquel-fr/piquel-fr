//! The signed-in user's data export and account deletion, and the deletion steps
//! settings, the admin API, the CLI and the purge job share.
//!
//! Deleting an account first schedules it: the account can no longer sign in, and
//! its sessions and grants end. For [`GRACE_PERIOD_DAYS`], a passkey sign-in
//! offers to restore it instead of signing in. The purge job then deletes it with
//! everything that identifies its person and the clients it manages, and retires
//! its handle.
use crate::ClientRegistry;
use crate::routes;
use crate::security::{self, ApiError, BrowserCookie, RequestContext};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    AccountStatus, AuthenticationMethod, ClientId, UserId,
    events::{Actor, DomainEvent, EventContext, RevocationReason},
};
use piquel_crypto::Secret;
use piquel_repository::{Database, DatabaseTransaction, StoredUser};
use serde::{Deserialize, Serialize};

/// Account failures and their browser response mapping.
mod error;
/// The account's data, as its owner downloads it.
mod export;

pub use error::AccountError;
use export::AccountExport;

/// How long an account scheduled for deletion can still be restored.
const GRACE_PERIOD_DAYS: i64 = 30;
/// How long a restore token, handed out by a passkey sign-in, stays valid.
const RESTORE_TOKEN_MINUTES: i64 = 5;

/// The data export and account deletion endpoints.
#[derive(Clone)]
pub(crate) struct AccountApplication {
    /// Accounts and everything an export reads.
    database: Database,
}

/// The body of [`routes::account::DELETION`].
#[derive(Deserialize)]
struct DeletionRequest {
    /// The account's username, typed by the user to confirm.
    confirm_username: String,
}

/// The answer to a scheduled deletion.
#[derive(Serialize)]
struct DeletionNotice {
    /// When the account is purged, unless it is restored first.
    purge_after: DateTime<Utc>,
}

/// What a passkey sign-in to an account scheduled for deletion returns instead of
/// a session: `{"deletion_scheduled": {"purge_after": …}, "restore_token": …}`.
#[derive(Serialize)]
pub(crate) struct RestoreOffer {
    /// The scheduled deletion.
    deletion_scheduled: DeletionNotice,
    /// Restores the account and signs in through [`routes::account::RESTORE`].
    restore_token: String,
}

/// The body of [`routes::account::RESTORE`].
#[derive(Deserialize)]
struct RestoreRequest {
    /// The token of a [`RestoreOffer`].
    restore_token: String,
}

impl AccountApplication {
    /// Serves the account endpoints from `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Returns the export, deletion and restore endpoints with this application as state.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::account::EXPORT, get(Self::export))
            .route(routes::account::DELETION, post(Self::schedule))
            .route(routes::account::RESTORE, post(Self::restore_with_token))
            .with_state(self)
    }

    /// Locks the administrator list, then the account, to schedule or purge its
    /// deletion: the order grants take them in. Refuses the last active
    /// administrator, so someone is always left to administer.
    ///
    /// # Errors
    /// Fails when the account does not exist or is the last active administrator.
    pub(crate) async fn lock_deletable(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
    ) -> Result<StoredUser, AccountError> {
        tx.administrators().lock().await?;
        let user = Self::lock(tx, user_id).await?;
        if user.status == AccountStatus::Active
            && tx.administrators().contains(user_id).await?
            && !tx.administrators().others_active(user_id).await?
        {
            return Err(AccountError::LastAdministrator);
        }
        Ok(user)
    }

    /// Locks the account `user_id`, in any status.
    ///
    /// # Errors
    /// Fails when the account does not exist.
    pub(crate) async fn lock(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
    ) -> Result<StoredUser, AccountError> {
        tx.users()
            .find_by_id_for_update(user_id)
            .await?
            .ok_or(AccountError::NotFound)
    }

    /// Schedules the deletion of the active account `user`, which
    /// [`Self::lock_deletable`] locked: it stops signing in, and every session and
    /// refresh grant ends, recorded as `context` says. Returns when it will be purged.
    ///
    /// # Errors
    /// Fails when the account is not active.
    pub(crate) async fn schedule_deletion(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user: &StoredUser,
    ) -> Result<DateTime<Utc>, AccountError> {
        if user.status != AccountStatus::Active {
            return Err(AccountError::NotActive);
        }
        tx.users()
            .set_status(user.id, AccountStatus::Deleting)
            .await?;
        let purge_after = Utc::now() + Duration::days(GRACE_PERIOD_DAYS);
        tx.deletions().schedule(user.id, purge_after).await?;
        let scheduled = DomainEvent::AccountDeletionScheduled { purge_after };
        tx.record(context, Some(user.id), scheduled).await?;
        security::Session::end_all(tx, context, user.id, RevocationReason::AccountDeletion).await?;
        Ok(purge_after)
    }

    /// Reactivates `user`, which is locked and scheduled for deletion, recorded as
    /// `context` says. It keeps its verified emails throughout, so nobody can have
    /// claimed them meanwhile.
    ///
    /// # Errors
    /// Fails when the account is not scheduled for deletion.
    pub(crate) async fn restore(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user: &StoredUser,
    ) -> Result<(), AccountError> {
        if user.status != AccountStatus::Deleting || !tx.deletions().cancel(user.id).await? {
            return Err(AccountError::NotScheduled);
        }
        tx.users()
            .set_status(user.id, AccountStatus::Active)
            .await?;
        tx.record(context, Some(user.id), DomainEvent::AccountRestored {})
            .await?;
        Ok(())
    }

    /// Deletes `user`, which [`Self::lock_deletable`] locked, in any status, as
    /// `context` says: ends its sessions and grants, which tells their clients,
    /// deletes the clients it manages, then purges it.
    ///
    /// # Errors
    /// Fails when persistence fails.
    pub(crate) async fn purge(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user: &StoredUser,
    ) -> Result<(), AccountError> {
        security::Session::end_all(tx, context, user.id, RevocationReason::AccountDeletion).await?;
        // Each becomes a tombstone without an owner, so its ID is never reused.
        // Their families are locked together first, in the one order every
        // statement locks families in.
        let owned: Vec<ClientId> = (tx.oidc().list_owned_clients(user.id).await?)
            .into_iter()
            .map(|client| client.id)
            .collect();
        tx.tokens().lock_client_families(&owned).await?;
        let mut clients = ClientRegistry::new(tx, context.clone());
        for client in &owned {
            clients.delete(client).await?;
        }
        if !tx.deletions().purge(user.id).await? {
            return Err(AccountError::NotFound);
        }
        // Recorded once the account is gone, so the personal data of the request
        // that purged it is not stored.
        tx.record(context, Some(user.id), DomainEvent::AccountPurged {})
            .await?;
        Ok(())
    }

    /// Answers a verified passkey sign-in to `user_id`, an account scheduled for
    /// deletion that `tx` locked, with a single-use token that restores it and
    /// signs in, valid for [`RESTORE_TOKEN_MINUTES`]. Commits `tx`.
    ///
    /// # Errors
    /// Fails when the account is not scheduled for deletion.
    pub(crate) async fn offer_restore(
        mut tx: DatabaseTransaction<'_>,
        user_id: UserId,
    ) -> Result<Json<RestoreOffer>, AccountError> {
        let token = Secret::generate()?;
        let deletion = tx
            .deletions()
            .issue_restore_token(
                user_id,
                token.digest().as_bytes(),
                Utc::now() + Duration::minutes(RESTORE_TOKEN_MINUTES),
            )
            .await?
            .ok_or(AccountError::NotScheduled)?;
        tx.commit().await?;
        Ok(Json(RestoreOffer {
            deletion_scheduled: DeletionNotice {
                purge_after: deletion.purge_after,
            },
            restore_token: token.encoded(),
        }))
    }

    /// Downloads every record of the account as a JSON attachment. It holds IP and
    /// email addresses, so it needs a recent passkey confirmation, rechecked in the
    /// snapshot, and is recorded.
    async fn export(
        State(app): State<Self>,
        context: RequestContext,
        confirmed: security::Confirmed,
    ) -> Result<Response, ApiError> {
        let session = &confirmed.0;
        let mut tx = app.database.begin_snapshot().await?;
        confirmed.lock(&mut tx).await?;
        let export = AccountExport::read(&mut tx, session.user_id, session.id).await?;
        tx.record(
            &context.user(session),
            Some(session.user_id),
            DomainEvent::AccountExported {},
        )
        .await?;
        tx.commit().await?;
        let disposition = format!("attachment; filename=\"{}\"", export.file_name());
        Ok(([(header::CONTENT_DISPOSITION, disposition)], Json(export)).into_response())
    }

    /// Schedules the account's deletion once the user typed its username, after a
    /// recent passkey confirmation. Signs every browser out, this one included.
    async fn schedule(
        State(app): State<Self>,
        context: RequestContext,
        confirmed: security::Confirmed,
        Json(input): Json<DeletionRequest>,
    ) -> Result<Response, ApiError> {
        let session = &confirmed.0;
        let mut tx = app.database.begin().await?;
        let user = Self::lock_deletable(&mut tx, session.user_id).await?;
        confirmed.lock(&mut tx).await?;
        if input.confirm_username != user.username {
            return Err(AccountError::UsernameMismatch.into());
        }
        let purge_after = Self::schedule_deletion(&mut tx, &context.user(session), &user).await?;
        tx.commit().await?;
        let mut response = Json(DeletionNotice { purge_after }).into_response();
        BrowserCookie::Session
            .clear_on(&mut response)
            .map_err(ApiError::internal)?;
        Ok(response)
    }

    /// Restores the account a [`RestoreOffer`]'s token names and signs this
    /// browser in to it. The token proves a passkey sign-in at most
    /// [`RESTORE_TOKEN_MINUTES`] ago, so a stolen session cannot restore anything.
    async fn restore_with_token(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        Json(input): Json<RestoreRequest>,
    ) -> Result<Response, ApiError> {
        let digest = Secret::parse(&input.restore_token)
            .map_err(|_| AccountError::RestoreExpired)?
            .digest();
        let user_id = app
            .database
            .deletions()
            .find_by_restore_token(digest.as_bytes())
            .await?
            .ok_or(AccountError::RestoreExpired)?;
        let mut tx = app.database.begin().await?;
        let user = Self::lock(&mut tx, user_id).await?;
        // Checked again under the account lock, which restoring takes too, so the
        // token restores at most once.
        if tx
            .deletions()
            .find_by_restore_token(digest.as_bytes())
            .await?
            != Some(user_id)
        {
            return Err(AccountError::RestoreExpired.into());
        }
        let actor = context.actor(Actor::User {
            user_id,
            session_id: None,
        });
        Self::restore(&mut tx, &actor, &user).await?;
        let secret = security::Session::sign_in(
            &mut tx,
            context,
            &headers,
            user_id,
            AuthenticationMethod::Passkey,
        )
        .await?;
        tx.commit().await?;
        let mut response = StatusCode::NO_CONTENT.into_response();
        BrowserCookie::Session
            .set_on(&mut response, &secret)
            .map_err(ApiError::internal)?;
        Ok(response)
    }
}

/// Supplies the shared database boundary to browser-session extractors.
impl axum::extract::FromRef<AccountApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &AccountApplication) -> Self {
        application.database.clone()
    }
}

/// Database-backed export, deletion, restore and purge scenarios.
#[cfg(test)]
mod tests;
