//! Pending and linked social identities: signup, linking, listing and unlinking.

use super::{FederationApplication, FederationFlow, Provider};
use crate::security::{self, ApiError, BrowserCookie};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use piquel_auth_protocol::{TokenId, UserId};
use piquel_repository::{Database, DatabaseTransaction, InsertExternalIdentity, PendingFederation};
use serde::Serialize;

/// Verifies that `id`, sent only by the social signup page, names this browser's
/// current pending signup. Registration without it never reads pending state.
pub(crate) async fn pending_signup(
    database: &Database,
    headers: &HeaderMap,
    id: TokenId,
) -> Result<TokenId, ApiError> {
    let expired = || ApiError::bad_request("This signup has expired. Please start again.");
    let browser = BrowserCookie::FederationPending
        .read(headers)
        .ok_or_else(expired)?;
    let pending = database
        .federation()
        .pending(&browser.digest())
        .await?
        .filter(|pending| pending.id == id)
        .ok_or_else(expired)?;
    if pending.link_user_id.is_some() {
        return Err(ApiError::forbidden(
            "Use a passkey for your existing account to link this provider.",
        ));
    }
    Ok(id)
}
/// Called only inside the transaction that creates the account and first key.
pub(crate) async fn attach_signup(
    tx: &mut DatabaseTransaction<'_>,
    pending_id: TokenId,
    headers: &HeaderMap,
    user_id: UserId,
) -> Result<(), ApiError> {
    let browser = BrowserCookie::FederationPending
        .read(headers)
        .ok_or_else(ApiError::unauthorized)?;
    let pending = tx
        .federation()
        .consume_pending(pending_id, &browser.digest())
        .await?;
    if pending.link_user_id.is_some() || tx.passkeys().list_active(user_id).await?.is_empty() {
        return Err(ApiError::forbidden(
            "Create your first passkey before continuing.",
        ));
    }
    if let Some(email) = &pending.email {
        if tx.emails().find_active_verified(email).await?.is_some() {
            return Err(ApiError::forbidden(
                "This email belongs to an existing account. Sign in with its passkey to link this provider.",
            ));
        }
        tx.federation().set_first_email(user_id, email).await?;
    }
    tx.federation()
        .insert_identity(&pending.identity(user_id))
        .await?;
    FederationFlow::audit(tx, user_id, "federation.link", &pending.provider).await
}
// Identity policy stays in this application, rather than the persistence model.
pub(super) trait PendingIdentity {
    fn identity(&self, user_id: UserId) -> InsertExternalIdentity;
}
impl PendingIdentity for PendingFederation {
    fn identity(&self, user_id: UserId) -> InsertExternalIdentity {
        InsertExternalIdentity {
            id: TokenId::new(),
            user_id,
            provider: self.provider.clone(),
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            linked_email: self.email.clone(),
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum PendingKind {
    /// Social-first signup, attached only by a registration naming its `id`.
    Signup,
    /// Email match: any session of the matching account may confirm it.
    Link,
    /// Started from settings: only the initiating session may confirm it.
    ExplicitLink,
}
#[derive(Serialize)]
pub(super) struct PendingView {
    id: TokenId,
    kind: PendingKind,
    provider: String,
    email: Option<String>,
    display_name: String,
    return_to: String,
}
pub(super) async fn pending_view(
    State(app): State<FederationApplication>,
    headers: HeaderMap,
) -> Result<Json<PendingView>, ApiError> {
    let browser = BrowserCookie::FederationPending
        .read(&headers)
        .ok_or_else(ApiError::unauthorized)?;
    let pending = app
        .database
        .federation()
        .pending(&browser.digest())
        .await?
        .ok_or_else(|| {
            ApiError::bad_request("This sign-in attempt has expired. Please start again.")
        })?;
    Ok(Json(PendingView {
        id: pending.id,
        kind: match (pending.link_user_id, pending.link_session_id) {
            (None, _) => PendingKind::Signup,
            (Some(_), None) => PendingKind::Link,
            (Some(_), Some(_)) => PendingKind::ExplicitLink,
        },
        provider: pending.provider,
        email: pending.email,
        display_name: pending.display_name,
        return_to: pending.return_to,
    }))
}
pub(super) async fn confirm_link(
    State(app): State<FederationApplication>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = security::management(&app.database, &headers).await?;
    let browser = BrowserCookie::FederationPending
        .read(&headers)
        .ok_or_else(ApiError::unauthorized)?;
    let mut tx = app.database.begin().await?;
    tx.users()
        .find_active_by_id_for_update(session.user_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    if !tx.sessions().management_active(session.id).await? {
        return Err(ApiError::forbidden(
            "Confirm with a passkey to change authentication settings.",
        ));
    }
    let pending = tx
        .federation()
        .pending(&browser.digest())
        .await?
        .ok_or_else(|| {
            ApiError::bad_request("This sign-in attempt has expired. Please start again.")
        })?;
    if pending.link_user_id != Some(session.user_id)
        || pending.link_session_id.is_some_and(|id| id != session.id)
    {
        return Err(ApiError::forbidden(
            "Sign in with a passkey for the account this provider should be linked to.",
        ));
    }
    let pending = tx
        .federation()
        .consume_pending(pending.id, &browser.digest())
        .await?;
    if tx.passkeys().list_active(session.user_id).await?.is_empty() {
        return Err(ApiError::forbidden("A passkey is required to continue."));
    }
    // A duplicate callback can only confirm the identical subject for this account.
    match tx
        .federation()
        .find_active(&pending.issuer, &pending.subject)
        .await?
    {
        Some(identity) if identity.user_id == session.user_id => {}
        Some(_) => {
            return Err(ApiError::forbidden(
                "This provider account is already linked to another Piquel account.",
            ));
        }
        None => {
            tx.federation()
                .insert_identity(&pending.identity(session.user_id))
                .await?;
        }
    }
    if let Some(email) = &pending.email {
        tx.federation()
            .set_first_email(session.user_id, email)
            .await?;
    }
    FederationFlow::audit(
        &mut tx,
        session.user_id,
        "federation.link",
        &pending.provider,
    )
    .await?;
    tx.commit().await?;
    let mut response = Json(serde_json::json!({"return_to":pending.return_to})).into_response();
    FederationFlow::append(&mut response, &BrowserCookie::FederationPending.clear())?;
    Ok(response)
}
pub(super) async fn cancel(
    State(app): State<FederationApplication>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(browser) = BrowserCookie::FederationPending.read(&headers) {
        app.database
            .federation()
            .cancel_pending(&browser.digest())
            .await?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    FederationFlow::append(&mut response, &BrowserCookie::FederationPending.clear())?;
    Ok(response)
}
#[derive(Serialize)]
pub(super) struct SocialIdentityView {
    provider: String,
    linked_email: Option<String>,
}
pub(super) async fn list_identities(
    State(app): State<FederationApplication>,
    headers: HeaderMap,
) -> Result<Json<Vec<SocialIdentityView>>, ApiError> {
    let session = security::session(&app.database, &headers).await?;
    Ok(Json(
        app.database
            .federation()
            .list_active(session.user_id)
            .await?
            .into_iter()
            .map(|identity| SocialIdentityView {
                provider: identity.provider,
                linked_email: identity.linked_email,
            })
            .collect(),
    ))
}
pub(super) async fn unlink(
    State(app): State<FederationApplication>,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let provider = Provider::parse(&provider)?;
    let session = security::management(&app.database, &headers).await?;
    let mut tx = app.database.begin().await?;
    tx.users()
        .find_active_by_id_for_update(session.user_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    if !tx.sessions().management_active(session.id).await? {
        return Err(ApiError::forbidden(
            "Confirm with a passkey to change authentication settings.",
        ));
    }
    if !tx
        .federation()
        .unlink(session.user_id, provider.name())
        .await?
    {
        return Err(ApiError::bad_request(
            "This provider is not linked to your account.",
        ));
    }
    tx.sessions()
        .revoke_other(session.user_id, session.id)
        .await?;
    FederationFlow::audit(
        &mut tx,
        session.user_id,
        "federation.unlink",
        provider.name(),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
