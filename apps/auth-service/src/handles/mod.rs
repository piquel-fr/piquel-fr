//! Handles: whether one is free, and the renames signup, settings and the admin
//! operations share.
use crate::routes;
use crate::security::{self, ApiError, RequestContext};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, put},
};
use chrono::{Duration, Utc};
use piquel_common::{Handle, Personal, UserId, events::DomainEvent, protocol::api::ErrorBody};
use piquel_repository::{Database, DatabaseError, DatabaseTransaction, StoredUser};
use serde::{Deserialize, Serialize};

/// Refusals and their response mapping.
mod error;
pub use error::HandlesError;

/// How long a handle stays before its account may change it again. Settings
/// renames wait for it; operators do not.
const COOLDOWN: Duration = Duration::days(30);

/// Handle availability and the signed-in account's renames.
#[derive(Clone)]
pub(crate) struct HandleApplication {
    /// Accounts, their handles and events.
    database: Database,
}

/// The body of a rename. The handle stays a string, so an invalid one gets the
/// handle rules' message rather than a JSON rejection.
#[derive(Deserialize)]
struct HandleChange {
    /// The requested handle, trimmed and lowercased before it is checked.
    handle: String,
}

/// The account's handle after a rename.
#[derive(Serialize)]
struct HandleView {
    /// The new handle.
    handle: Handle,
}

/// Whether a handle can be claimed: `{"available": true}`, or `false` with the
/// error and `handle_*` code claiming it would fail with.
#[derive(Serialize)]
struct Availability {
    /// Whether a claim would succeed now.
    available: bool,
    /// Why not, when it would not.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    refusal: Option<ErrorBody>,
}

impl HandleApplication {
    /// Serves handles from `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Returns the handle endpoints with this application as state.
    ///
    /// A rename needs a recent passkey confirmation: the handle is the login name.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::handles::ACCOUNT, put(Self::rename_own))
            .route(routes::handles::AVAILABILITY, get(Self::availability))
            .with_state(self)
    }

    /// Says whether the signed-in account, or anyone at signup, could take `handle`.
    /// A signed-in account may take back its own released handles. It answers
    /// which handles exist, as signup does, so it is throttled like sign-in.
    async fn availability(
        State(app): State<Self>,
        security::OptionalSession(session): security::OptionalSession,
        Path(handle): Path<String>,
    ) -> Result<Json<Availability>, ApiError> {
        let user = session.map(|session| session.user_id);
        let refusal = match Self::check(&app.database, &handle, user).await {
            Ok(_) => None,
            Err(error @ HandlesError::Database(_)) => return Err(error.into()),
            Err(error) => Some(ApiError::from(error).body()),
        };
        Ok(Json(Availability {
            available: refusal.is_none(),
            refusal,
        }))
    }

    /// Parses `input` and checks that `user`, or a new account, may take it: it is
    /// valid, unreserved and free.
    pub(crate) async fn check(
        database: &Database,
        input: &str,
        user: Option<UserId>,
    ) -> Result<Handle, HandlesError> {
        let handle = Handle::parse(input)?;
        handle.ensure_unreserved()?;
        Self::claimable(database, &handle, user).await?;
        Ok(handle)
    }

    /// Fails with the reason `user`, or a new account, cannot take `handle`, from the
    /// one row sharing its skeleton: taken, retired, a look-alike, or already theirs.
    /// An account may take back a handle it released.
    pub(crate) async fn claimable(
        database: &Database,
        handle: &Handle,
        user: Option<UserId>,
    ) -> Result<(), HandlesError> {
        let Some(holder) = database.handles().holder(handle).await? else {
            return Ok(());
        };
        let own = user.is_some() && holder.user_id == user;
        if holder.handle != *handle {
            return Err(HandlesError::Confusable(holder.handle));
        }
        match (own, holder.released_at, holder.user_id) {
            (true, None, _) => Err(HandlesError::Current),
            (true, Some(_), _) => Ok(()),
            (false, None, Some(_)) => Err(HandlesError::Taken),
            // Released, or the current handle of a purged account.
            (false, _, _) => Err(HandlesError::Retired),
        }
    }

    /// Gives the account `user`, locked in `tx`, the handle `handle`, and returns
    /// `tx` with the event to record. On refusal, `tx` is rolled back first, so the
    /// reason is looked up on `database` without holding a second connection.
    pub(crate) async fn rename<'a>(
        database: &Database,
        mut tx: DatabaseTransaction<'a>,
        user: &StoredUser,
        handle: Handle,
    ) -> Result<(DatabaseTransaction<'a>, DomainEvent), HandlesError> {
        if user.handle == handle {
            return Err(HandlesError::Current);
        }
        let renamed = match tx.rename_handle(user.id, &handle).await {
            Ok(renamed) => renamed,
            Err(DatabaseError::Conflict(_)) => false,
            Err(error) => return Err(error.into()),
        };
        if !renamed {
            tx.rollback().await?;
            return Err(Self::refusal(database, &handle, Some(user.id)).await);
        }
        let changed = DomainEvent::HandleChanged {
            old: Personal::Value(user.handle.to_string()),
            new: Personal::Value(handle),
        };
        Ok((tx, changed))
    }

    /// Why a claim of `handle` by `user`, or a new account, failed. Callers roll
    /// back first. A concurrent claim that has since rolled back reads as taken.
    pub(crate) async fn refusal(
        database: &Database,
        handle: &Handle,
        user: Option<UserId>,
    ) -> HandlesError {
        match Self::claimable(database, handle, user).await {
            Ok(()) => HandlesError::Taken,
            Err(error) => error,
        }
    }

    /// Changes the signed-in account's handle, at most once per [`COOLDOWN`]. The
    /// profile version is bumped, so relying parties refresh `preferred_username`.
    async fn rename_own(
        State(app): State<Self>,
        context: RequestContext,
        confirmed: security::Confirmed,
        Json(input): Json<HandleChange>,
    ) -> Result<Json<HandleView>, ApiError> {
        let session = &confirmed.0;
        let handle = Handle::parse(&input.handle).map_err(HandlesError::from)?;
        handle.ensure_unreserved().map_err(HandlesError::from)?;
        let mut tx = app.database.begin().await?;
        confirmed.lock(&mut tx).await?;
        // Already locked by the confirmation check, which does not return the account.
        let user = tx
            .users()
            .find_active_by_id_for_update(session.user_id)
            .await?
            .ok_or(security::SessionError::Missing)?;
        let retry_after = user.handle_changed_at + COOLDOWN;
        if retry_after > Utc::now() && user.handle != handle {
            return Err(HandlesError::Cooldown { retry_after }.into());
        }
        let (mut tx, changed) = Self::rename(&app.database, tx, &user, handle.clone()).await?;
        tx.record(&context.user(session), Some(user.id), changed)
            .await?;
        tx.commit().await?;
        Ok(Json(HandleView { handle }))
    }
}

/// Supplies the shared database boundary to browser-session extractors.
impl axum::extract::FromRef<HandleApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &HandleApplication) -> Self {
        application.database.clone()
    }
}

/// Database-backed availability and rename scenarios.
#[cfg(test)]
mod tests;
