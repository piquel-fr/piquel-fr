//! The admin API: thin HTTP adapters over [`AdminService`], served only on the
//! private admin listener.
//!
//! The dashboard calls it with an administrator's access token. Reads take
//! [`Admin`] and mutations [`ConfirmedAdmin`], which answer RFC 6750 and RFC 9470
//! challenges, so the dashboard signs the administrator in again when a mutation
//! needs a fresh passkey.
use crate::{AuthConfig, routes::admin};
use axum::{
    Json, Router,
    extract::{FromRef, Path, Query, State},
    http::StatusCode,
    routing::{MethodRouter, delete, get, post},
};
use piquel_admin_api::{
    Administrator, Client, CreateInvitation, CreatedInvitation, DisableUser, EventPage,
    EventSearch, GrantAdministrator, Invitation, UserDetail, UserPage, UserSearch,
};
use piquel_common::{SessionId, TokenId, UserId, config::Origin};
use piquel_repository::Database;

/// The administrators the API serves, and how their tokens are checked.
mod caller;
/// Admin failures and their response mapping.
mod error;
/// The list of operations both the API and the CLI cover.
mod operation;
/// The service shared by the admin API and the CLI.
mod service;
/// Validated inputs.
mod types;

pub use caller::Operator;
use caller::{Admin, AdminTokens, ConfirmedAdmin};
pub use error::AdminError;
pub(crate) use operation::AdminOperation;
pub use service::AdminService;
pub use types::{
    GracePeriod, HandleIssue, HandleProblem, InvalidLifetime, InviteExpiry, Reason, UserRef,
};

/// Admin API routes and the service behind them.
#[derive(Clone)]
pub(crate) struct AdminApplication {
    /// Every administrative operation.
    service: AdminService,
    /// Authenticates each request's administrator.
    tokens: AdminTokens,
    /// Auth's origin, whose registration page invitations link to.
    origin: Origin,
    /// Invitation routes exist only while signup requires invitations.
    invitations: bool,
}

impl FromRef<AdminApplication> for AdminTokens {
    /// Shares the token checks with the extractors.
    fn from_ref(application: &AdminApplication) -> Self {
        application.tokens.clone()
    }
}

impl AdminApplication {
    /// Builds the admin API from auth's issuer, keys and admission policy.
    pub(crate) fn new(database: Database, config: &AuthConfig) -> Self {
        Self {
            service: AdminService::new(database.clone()),
            tokens: AdminTokens {
                keys: config.oidc.keys.clone(),
                issuer: config.oidc.origin.serialized(),
                database,
            },
            origin: config.passkey.origin.clone(),
            invitations: config.passkey.invite_required,
        }
    }

    /// Returns every admin endpoint with this application as state: one route
    /// per operation the API serves. Methods on one path merge.
    pub(crate) fn routes(self) -> Router {
        AdminOperation::ALL
            .iter()
            .filter_map(|operation| self.route(*operation))
            .fold(Router::new(), |router, (path, method)| {
                router.route(path, method)
            })
            .with_state(self)
    }

    /// The path and method serving `operation`, or `None` if only the CLI runs it.
    /// Invitations are served only while signup requires them.
    fn route(&self, operation: AdminOperation) -> Option<(&'static str, MethodRouter<Self>)> {
        type Op = AdminOperation;
        Some(match operation {
            Op::SearchUsers => (admin::USERS, get(Self::search_users)),
            Op::ViewUser => (admin::USER, get(Self::view_user)),
            Op::DisableUser => (admin::USER_DISABLE, post(Self::disable_user)),
            Op::EnableUser => (admin::USER_ENABLE, post(Self::enable_user)),
            Op::RevokeUserSessions => (admin::USER_SESSIONS, delete(Self::revoke_user_sessions)),
            Op::RevokeSession => (admin::SESSION, delete(Self::revoke_session)),
            Op::ListInvitations if self.invitations => {
                (admin::INVITATIONS, get(Self::list_invitations))
            }
            Op::CreateInvitation if self.invitations => {
                (admin::INVITATIONS, post(Self::create_invitation))
            }
            Op::RevokeInvitation if self.invitations => {
                (admin::INVITATION, delete(Self::revoke_invitation))
            }
            Op::ListClients => (admin::CLIENTS, get(Self::list_clients)),
            Op::ViewClient => (admin::CLIENT, get(Self::client)),
            Op::ListEvents => (admin::EVENTS, get(Self::events)),
            Op::ListAdministrators => (admin::ADMINISTRATORS, get(Self::list_administrators)),
            Op::GrantAdministrator => (admin::ADMINISTRATORS, post(Self::grant_administrator)),
            Op::RevokeAdministrator => (admin::ADMINISTRATOR, delete(Self::revoke_administrator)),
            // Client changes, handles and the delivery queue are CLI-only, for now.
            Op::ListInvitations
            | Op::CreateInvitation
            | Op::RevokeInvitation
            | Op::CreateClient
            | Op::ApplyClient
            | Op::UpdateClient
            | Op::EnableClient
            | Op::DisableClient
            | Op::SuspendClient
            | Op::UnsuspendClient
            | Op::DeleteClient
            | Op::RotateClientSecret
            | Op::CheckHandles
            | Op::RenameHandle
            | Op::ListDeliveries
            | Op::RetryDelivery
            | Op::CancelDelivery => return None,
        })
    }

    /// Searches accounts by ID, username, display name or email.
    async fn search_users(
        State(app): State<Self>,
        Admin(operator): Admin,
        Query(search): Query<UserSearch>,
    ) -> Result<Json<UserPage>, AdminError> {
        Ok(Json(
            app.service
                .search_users(&operator, &search.q, search.cursor)
                .await?,
        ))
    }

    /// Describes one account, recording that the administrator viewed it.
    async fn view_user(
        State(app): State<Self>,
        Admin(operator): Admin,
        Path(id): Path<UserId>,
    ) -> Result<Json<UserDetail>, AdminError> {
        Ok(Json(app.service.view_user(&operator, id).await?))
    }

    /// Disables an account and ends its sessions and refresh grants.
    async fn disable_user(
        State(app): State<Self>,
        ConfirmedAdmin(operator): ConfirmedAdmin,
        Path(id): Path<UserId>,
        Json(input): Json<DisableUser>,
    ) -> Result<StatusCode, AdminError> {
        let reason = Reason::parse(input.reason)?;
        app.service.disable_user(&operator, id, reason).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Reactivates a disabled account.
    async fn enable_user(
        State(app): State<Self>,
        ConfirmedAdmin(operator): ConfirmedAdmin,
        Path(id): Path<UserId>,
    ) -> Result<StatusCode, AdminError> {
        app.service.enable_user(&operator, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Ends every session and refresh grant of an account.
    async fn revoke_user_sessions(
        State(app): State<Self>,
        ConfirmedAdmin(operator): ConfirmedAdmin,
        Path(id): Path<UserId>,
    ) -> Result<StatusCode, AdminError> {
        app.service.revoke_user_sessions(&operator, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Ends one session and its refresh grants.
    async fn revoke_session(
        State(app): State<Self>,
        ConfirmedAdmin(operator): ConfirmedAdmin,
        Path(id): Path<SessionId>,
    ) -> Result<StatusCode, AdminError> {
        app.service.revoke_session(&operator, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists invitations without their secrets.
    async fn list_invitations(
        State(app): State<Self>,
        Admin(operator): Admin,
    ) -> Result<Json<Vec<Invitation>>, AdminError> {
        Ok(Json(app.service.list_invitations(&operator).await?))
    }

    /// Creates an invitation and returns its link, which is shown only this once.
    async fn create_invitation(
        State(app): State<Self>,
        ConfirmedAdmin(operator): ConfirmedAdmin,
        input: Option<Json<CreateInvitation>>,
    ) -> Result<(StatusCode, Json<CreatedInvitation>), AdminError> {
        let expires_in = match input.and_then(|Json(input)| input.expires_in) {
            Some(expires_in) => expires_in.parse()?,
            None => InviteExpiry::default(),
        };
        Ok((
            StatusCode::CREATED,
            Json(
                app.service
                    .create_invitation(&operator, &app.origin, expires_in)
                    .await?,
            ),
        ))
    }

    /// Revokes an unredeemed invitation.
    async fn revoke_invitation(
        State(app): State<Self>,
        ConfirmedAdmin(operator): ConfirmedAdmin,
        Path(id): Path<TokenId>,
    ) -> Result<StatusCode, AdminError> {
        app.service.revoke_invitation(&operator, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists every OIDC client.
    async fn list_clients(
        State(app): State<Self>,
        Admin(operator): Admin,
    ) -> Result<Json<Vec<Client>>, AdminError> {
        Ok(Json(app.service.list_clients(&operator).await?))
    }

    /// Describes one OIDC client.
    async fn client(
        State(app): State<Self>,
        Admin(operator): Admin,
        Path(id): Path<String>,
    ) -> Result<Json<Client>, AdminError> {
        Ok(Json(app.service.client(&operator, &id).await?))
    }

    /// Pages through domain events, newest first.
    async fn events(
        State(app): State<Self>,
        Admin(operator): Admin,
        Query(search): Query<EventSearch>,
    ) -> Result<Json<EventPage>, AdminError> {
        Ok(Json(app.service.events(&operator, search).await?))
    }

    /// Lists every administrator.
    async fn list_administrators(
        State(app): State<Self>,
        Admin(operator): Admin,
    ) -> Result<Json<Vec<Administrator>>, AdminError> {
        Ok(Json(app.service.list_administrators(&operator).await?))
    }

    /// Makes an active account an administrator.
    async fn grant_administrator(
        State(app): State<Self>,
        ConfirmedAdmin(operator): ConfirmedAdmin,
        Json(input): Json<GrantAdministrator>,
    ) -> Result<StatusCode, AdminError> {
        app.service
            .grant_administrator(&operator, input.user_id)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Removes another administrator's rights.
    async fn revoke_administrator(
        State(app): State<Self>,
        ConfirmedAdmin(operator): ConfirmedAdmin,
        Path(id): Path<UserId>,
    ) -> Result<StatusCode, AdminError> {
        app.service.revoke_administrator(&operator, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }
}

/// Admin API scenarios, and the harness the shared settings' tests also use.
#[cfg(test)]
pub(crate) mod tests;
