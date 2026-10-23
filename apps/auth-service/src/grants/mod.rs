//! The applications the signed-in user has granted access, and removing that access.
//! Its scenarios run with the OIDC flow tests, which issue the grants they remove.
use crate::oidc::DescribedScope;
use crate::routes;
use crate::security::{self, ApiError, RequestContext};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
};
use chrono::{DateTime, Utc};
use piquel_common::{
    ClientId,
    events::{DomainEvent, GrantRevocation},
    protocol::oauth::Scope,
};
use piquel_repository::{Database, StoredGrant};
use serde::Serialize;

/// The account's connected applications.
#[derive(Clone)]
pub(crate) struct GrantApplication {
    /// Grants, refresh families and codes.
    database: Database,
}

/// An application the user granted access, as [`routes::grants::LIST`] returns it.
#[derive(Serialize)]
struct ConnectedApp {
    /// Client ID, to remove its access.
    client_id: ClientId,
    /// The name its consent screen shows.
    name: String,
    /// Whether Piquel makes it. First-party apps are granted access without the
    /// consent screen, again on their next sign-in after a removal.
    first_party: bool,
    /// What it can read, `offline_access` aside.
    scopes: Vec<DescribedScope>,
    /// Whether it can act while the user is away, with refresh tokens.
    offline_access: bool,
    /// When the user granted access, since any earlier removal.
    granted_at: DateTime<Utc>,
    /// When it last signed the user in or refreshed its tokens.
    last_used_at: DateTime<Utc>,
}

impl From<StoredGrant> for ConnectedApp {
    /// Moves `offline_access` out of the scopes, into what the client may do with it.
    fn from(grant: StoredGrant) -> Self {
        let (offline, scopes): (Vec<_>, Vec<_>) = grant
            .scopes
            .into_iter()
            .partition(|scope| scope == Scope::OfflineAccess.as_str());
        Self {
            client_id: grant.client_id,
            name: grant.client_name,
            first_party: grant.trusted,
            scopes: scopes.into_iter().map(Into::into).collect(),
            offline_access: grant.allow_refresh && !offline.is_empty(),
            granted_at: grant.granted_at,
            last_used_at: grant.last_used_at,
        }
    }
}

impl GrantApplication {
    /// Serves the connected applications from `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Returns both connected-application endpoints with this application as state.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::grants::LIST, get(Self::list))
            .route(routes::grants::ITEM, delete(Self::revoke))
            .with_state(self)
    }

    /// Lists the enabled applications the account granted access, most recently
    /// used first.
    async fn list(
        State(app): State<Self>,
        security::Session(session): security::Session,
    ) -> Result<Json<Vec<ConnectedApp>>, ApiError> {
        let grants = app.database.oidc().list_grants(session.user_id).await?;
        Ok(Json(grants.into_iter().map(Into::into).collect()))
    }

    /// Removes an application's access in one transaction: its grants, refresh
    /// families and outstanding codes, recorded as a `ConsentRevoked` and one
    /// `GrantRevoked` per family. Access tokens it already holds are not revoked and
    /// expire within minutes.
    ///
    /// A session is enough, without a passkey confirmation: this only removes access.
    /// The user's sessions stay signed in, since other applications share them.
    async fn revoke(
        State(app): State<Self>,
        context: RequestContext,
        security::Session(session): security::Session,
        Path(client_id): Path<ClientId>,
    ) -> Result<StatusCode, ApiError> {
        let mut tx = app.database.begin().await?;
        let session = security::Session::lock(&mut tx, &session).await?;
        let families = tx
            .oidc()
            .revoke_grants(session.user_id, &client_id)
            .await?
            .ok_or_else(|| ApiError::not_found("This app does not have access to your account."))?;
        let context = context.user(&session);
        let revoked = families
            .into_iter()
            .map(|family_id| DomainEvent::GrantRevoked {
                client_id: client_id.clone(),
                family_id,
                reason: GrantRevocation::UserRevoked,
            });
        for event in std::iter::once(DomainEvent::ConsentRevoked {
            client_id: client_id.clone(),
        })
        .chain(revoked)
        {
            tx.record(&context, Some(session.user_id), event).await?;
        }
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT)
    }
}

/// Supplies the shared database boundary to browser-session extractors.
impl axum::extract::FromRef<GrantApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &GrantApplication) -> Self {
        application.database.clone()
    }
}
