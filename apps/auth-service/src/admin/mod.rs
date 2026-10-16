//! The admin API: thin HTTP adapters over [`AdminOperations`].
//!
//! Routes exist only when `AUTH_ADMIN_URL` is set, and only the admin origin may call
//! them. Reads take [`Admin`] and mutations [`ConfirmedAdmin`], so non-administrators
//! get the same 404 as an unknown path. Administrator rights themselves are granted
//! and revoked only through the CLI.
use crate::{
    AuthConfig, routes,
    security::{Admin, ApiError, ConfirmedAdmin},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use piquel_repository::{Actor, AuditFilter, Database, StoredInvitation};

/// Admin failures and their browser response mapping.
mod error;
/// The operations shared by the admin API and the CLI.
mod operations;
/// Validated inputs and the admin API's bodies.
mod types;

pub use error::AdminError;
pub use operations::AdminOperations;
pub(crate) use types::Reason;
use types::{
    AuditPage, AuditSearch, ClientView, CreateInvitation, DisableUser, UserDetail, UserPage,
    UserSearch,
};
pub use types::{CreatedInvitation, InviteExpiry};

/// Admin API routes and the operations behind them.
#[derive(Clone)]
pub(crate) struct AdminApplication {
    /// Every administrative operation.
    operations: AdminOperations,
    /// Database read by the admin session extractors.
    database: Database,
    /// Invitation routes exist only while signup requires invitations.
    invitations: bool,
}

impl AdminApplication {
    /// Builds the admin API from the auth origin and admission policy.
    pub(crate) fn new(database: Database, config: &AuthConfig) -> Self {
        Self {
            operations: AdminOperations::new(database.clone(), config.passkey.origin.clone()),
            database,
            invitations: config.passkey.invite_required,
        }
    }

    /// Returns every admin endpoint with this application as state.
    pub(crate) fn routes(self) -> Router {
        let mut router = Router::new()
            .route(routes::admin::USERS, get(Self::search_users))
            .route(routes::admin::USER, get(Self::view_user))
            .route(routes::admin::USER_DISABLE, post(Self::disable_user))
            .route(routes::admin::USER_ENABLE, post(Self::enable_user))
            .route(
                routes::admin::USER_SESSIONS_REVOKE,
                post(Self::revoke_user_sessions),
            )
            .route(routes::admin::SESSION, delete(Self::revoke_session))
            .route(routes::admin::CLIENTS, get(Self::list_clients))
            .route(routes::admin::CLIENT, get(Self::client))
            .route(routes::admin::AUDIT, get(Self::audit));
        if self.invitations {
            router = router
                .route(
                    routes::admin::INVITATIONS,
                    get(Self::list_invitations).post(Self::create_invitation),
                )
                .route(routes::admin::INVITATION, delete(Self::revoke_invitation));
        }
        // Applies to the routes above. Without it an unsupported method would answer
        // 405 before any session check, revealing the path to non-administrators.
        router
            .method_not_allowed_fallback(Self::unsupported_method)
            .with_state(self)
    }

    /// Answers 405 to administrators only; everyone else gets the admin rejection.
    fn unsupported_method(_: Admin) -> std::future::Ready<StatusCode> {
        std::future::ready(StatusCode::METHOD_NOT_ALLOWED)
    }

    /// Searches accounts by ID, username, display name or email.
    async fn search_users(
        State(app): State<Self>,
        _: Admin,
        Query(search): Query<UserSearch>,
    ) -> Result<Json<UserPage>, ApiError> {
        Ok(Json(
            app.operations
                .search_users(&search.q, search.cursor)
                .await?,
        ))
    }

    /// Describes one account, recording that the administrator viewed it.
    async fn view_user(
        State(app): State<Self>,
        Admin(session): Admin,
        Path(id): Path<UserId>,
    ) -> Result<Json<UserDetail>, ApiError> {
        Ok(Json(
            app.operations
                .view_user(&Actor::admin(&session), id)
                .await?,
        ))
    }

    /// Disables an account and ends its sessions and refresh grants.
    async fn disable_user(
        State(app): State<Self>,
        ConfirmedAdmin(session): ConfirmedAdmin,
        Path(id): Path<UserId>,
        Json(input): Json<DisableUser>,
    ) -> Result<StatusCode, ApiError> {
        let reason = Reason::parse(input.reason)?;
        app.operations
            .disable_user(&Actor::admin(&session), id, &reason)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Reactivates a disabled account.
    async fn enable_user(
        State(app): State<Self>,
        ConfirmedAdmin(session): ConfirmedAdmin,
        Path(id): Path<UserId>,
    ) -> Result<StatusCode, ApiError> {
        app.operations
            .enable_user(&Actor::admin(&session), id)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Ends every session and refresh grant of an account.
    async fn revoke_user_sessions(
        State(app): State<Self>,
        ConfirmedAdmin(session): ConfirmedAdmin,
        Path(id): Path<UserId>,
    ) -> Result<StatusCode, ApiError> {
        app.operations
            .revoke_user_sessions(&Actor::admin(&session), id)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Ends one session and its refresh grants.
    async fn revoke_session(
        State(app): State<Self>,
        ConfirmedAdmin(session): ConfirmedAdmin,
        Path(id): Path<SessionId>,
    ) -> Result<StatusCode, ApiError> {
        app.operations
            .revoke_session(&Actor::admin(&session), id)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists invitations without their secrets.
    async fn list_invitations(
        State(app): State<Self>,
        _: Admin,
    ) -> Result<Json<Vec<StoredInvitation>>, ApiError> {
        Ok(Json(app.operations.list_invitations().await?))
    }

    /// Creates an invitation and returns its link, which is shown only this once.
    async fn create_invitation(
        State(app): State<Self>,
        ConfirmedAdmin(session): ConfirmedAdmin,
        input: Option<Json<CreateInvitation>>,
    ) -> Result<(StatusCode, Json<CreatedInvitation>), ApiError> {
        let Json(input) = input.unwrap_or_default();
        Ok((
            StatusCode::CREATED,
            Json(
                app.operations
                    .create_invitation(&Actor::admin(&session), input.expires_in)
                    .await?,
            ),
        ))
    }

    /// Revokes an unredeemed invitation.
    async fn revoke_invitation(
        State(app): State<Self>,
        ConfirmedAdmin(session): ConfirmedAdmin,
        Path(id): Path<TokenId>,
    ) -> Result<StatusCode, ApiError> {
        app.operations
            .revoke_invitation(&Actor::admin(&session), id)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists every OIDC client.
    async fn list_clients(
        State(app): State<Self>,
        _: Admin,
    ) -> Result<Json<Vec<ClientView>>, ApiError> {
        Ok(Json(app.operations.list_clients().await?))
    }

    /// Describes one OIDC client.
    async fn client(
        State(app): State<Self>,
        _: Admin,
        Path(id): Path<String>,
    ) -> Result<Json<ClientView>, ApiError> {
        Ok(Json(app.operations.client(&id).await?))
    }

    /// Pages through the audit log, newest first.
    async fn audit(
        State(app): State<Self>,
        _: Admin,
        Query(search): Query<AuditSearch>,
    ) -> Result<Json<AuditPage>, ApiError> {
        Ok(Json(
            app.operations
                .audit(AuditFilter {
                    user_id: search.user,
                    action: search.action,
                    before: search.before,
                })
                .await?,
        ))
    }
}

/// Supplies the shared database boundary to the admin session extractors.
impl axum::extract::FromRef<AdminApplication> for Database {
    /// Shares persistence with the session extractors without duplicating lookups.
    fn from_ref(application: &AdminApplication) -> Self {
        application.database.clone()
    }
}

#[cfg(test)]
mod tests;
