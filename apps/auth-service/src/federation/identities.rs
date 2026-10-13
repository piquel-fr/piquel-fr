//! Pending and linked social identities: signup, linking, listing and unlinking.

use super::{FederationApplication, FederationError, Provider};
use crate::security::{self, ApiError, BrowserCookie};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use piquel_auth_protocol::{TokenId, UserId};
use piquel_repository::{
    AuditAction, Database, DatabaseTransaction, InsertExternalIdentity, PendingFederation,
    StoredSession,
};
use serde::Serialize;

impl FederationApplication {
    /// Verifies that the signup ID shown by the social page belongs to this browser.
    /// Registration without an explicit ID never reads pending social evidence.
    pub(crate) async fn pending_signup(
        database: &Database,
        headers: &HeaderMap,
        id: TokenId,
    ) -> Result<TokenId, FederationError> {
        let browser = BrowserCookie::FederationPending
            .read(headers)
            .ok_or(FederationError::PendingSignupExpired)?;
        let pending = database
            .federation()
            .pending(browser.digest().as_bytes())
            .await?
            .filter(|pending| pending.id == id)
            .ok_or(FederationError::PendingSignupExpired)?;
        if pending.link_user_id.is_some() {
            return Err(FederationError::SignupRequiresLink);
        }
        Ok(id)
    }

    /// Attaches verified signup evidence only inside account-and-first-passkey creation.
    pub(crate) async fn attach_signup(
        tx: &mut DatabaseTransaction<'_>,
        pending_id: TokenId,
        headers: &HeaderMap,
        user_id: UserId,
    ) -> Result<(), FederationError> {
        let browser = BrowserCookie::FederationPending
            .read(headers)
            .ok_or(FederationError::Unauthorized)?;
        let pending = tx
            .federation()
            .consume_pending(pending_id, browser.digest().as_bytes())
            .await?;
        if pending.link_user_id.is_some() || tx.passkeys().list_active(user_id).await?.is_empty() {
            return Err(FederationError::FirstPasskeyRequired);
        }
        if let Some(email) = &pending.email
            && tx.emails().find_active_verified(email).await?.is_some()
        {
            return Err(FederationError::EmailAlreadyOwned);
        }
        // Claim identity before email, matching link confirmation's lock order to avoid deadlocks.
        tx.federation()
            .insert_identity(&Self::identity(&pending, user_id))
            .await?;
        if let Some(email) = &pending.email {
            tx.federation().set_first_email(user_id, email).await?;
        }
        Ok(tx
            .audit_events()
            .record(user_id, AuditAction::FederationLink, Some(pending.provider))
            .await?)
    }

    /// Builds a new link from already verified, browser-bound provider evidence.
    pub(super) fn identity(pending: &PendingFederation, user_id: UserId) -> InsertExternalIdentity {
        InsertExternalIdentity {
            id: TokenId::new(),
            user_id,
            provider: pending.provider,
            issuer: pending.issuer.clone(),
            subject: pending.subject.clone(),
            linked_email: pending.email.clone(),
        }
    }

    /// Shows verified provider evidence so the browser can choose signup or explicit linking.
    pub(super) async fn pending_view(
        State(app): State<Self>,
        headers: HeaderMap,
    ) -> Result<Json<PendingView>, ApiError> {
        Ok(Json(app.pending(&headers).await?))
    }

    /// Reads this browser's pending evidence and classifies its required confirmation.
    async fn pending(&self, headers: &HeaderMap) -> Result<PendingView, FederationError> {
        let browser = BrowserCookie::FederationPending
            .read(headers)
            .ok_or(FederationError::Unauthorized)?;
        let pending = self
            .database
            .federation()
            .pending(browser.digest().as_bytes())
            .await?
            .ok_or(FederationError::PendingSignInExpired)?;
        Ok(PendingView {
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
        })
    }

    /// Confirms a pending identity using a passkey-authorized account session.
    pub(super) async fn confirm_link(
        State(app): State<Self>,
        security::ManagementSession(session): security::ManagementSession,
        headers: HeaderMap,
    ) -> Result<Response, ApiError> {
        Ok(app.link(&session, &headers).await?)
    }

    /// Claims an identity atomically after rechecking its account and management grant.
    async fn link(
        &self,
        session: &StoredSession,
        headers: &HeaderMap,
    ) -> Result<Response, FederationError> {
        let browser = BrowserCookie::FederationPending
            .read(headers)
            .ok_or(FederationError::Unauthorized)?;
        let mut tx = self.database.begin().await?;
        tx.users()
            .find_active_by_id_for_update(session.user_id)
            .await?
            .ok_or(FederationError::Unauthorized)?;
        if !tx.sessions().management_active(session.id).await? {
            return Err(FederationError::ManagementExpired);
        }
        let pending = tx
            .federation()
            .pending(browser.digest().as_bytes())
            .await?
            .ok_or(FederationError::PendingSignInExpired)?;
        if pending.link_user_id != Some(session.user_id)
            || pending.link_session_id.is_some_and(|id| id != session.id)
        {
            return Err(FederationError::LinkAccountMismatch);
        }
        let pending = tx
            .federation()
            .consume_pending(pending.id, browser.digest().as_bytes())
            .await?;
        if tx.passkeys().list_active(session.user_id).await?.is_empty() {
            return Err(FederationError::LinkRequiresPasskey);
        }
        // Repeated callbacks may confirm only the identical subject on this account.
        match tx
            .federation()
            .find_active(&pending.issuer, &pending.subject)
            .await?
        {
            Some(identity) if identity.user_id == session.user_id => {}
            Some(_) => return Err(FederationError::IdentityAlreadyLinked),
            None => {
                tx.federation()
                    .insert_identity(&Self::identity(&pending, session.user_id))
                    .await?;
            }
        }
        if let Some(email) = &pending.email {
            tx.federation()
                .set_first_email(session.user_id, email)
                .await?;
        }
        tx.audit_events()
            .record(
                session.user_id,
                AuditAction::FederationLink,
                Some(pending.provider),
            )
            .await?;
        tx.commit().await?;
        let mut response = Json(LinkResponse {
            return_to: pending.return_to,
        })
        .into_response();
        BrowserCookie::FederationPending.clear_on(&mut response)?;
        Ok(response)
    }

    /// Discards any pending social flow for this browser.
    pub(super) async fn cancel(
        State(app): State<Self>,
        headers: HeaderMap,
    ) -> Result<Response, ApiError> {
        Ok(app.cancel_pending(&headers).await?)
    }

    /// Removes browser-bound pending evidence and clears its cookie even when absent.
    async fn cancel_pending(&self, headers: &HeaderMap) -> Result<Response, FederationError> {
        if let Some(browser) = BrowserCookie::FederationPending.read(headers) {
            self.database
                .federation()
                .cancel_pending(browser.digest().as_bytes())
                .await?;
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        BrowserCookie::FederationPending.clear_on(&mut response)?;
        Ok(response)
    }

    /// Lists active social identities belonging to the authenticated account.
    pub(super) async fn list_identities(
        State(app): State<Self>,
        security::Session(session): security::Session,
    ) -> Result<Json<Vec<SocialIdentityView>>, ApiError> {
        Ok(Json(
            app.database
                .federation()
                .list_active(session.user_id)
                .await
                .map_err(FederationError::from)?
                .into_iter()
                .map(|identity| SocialIdentityView {
                    provider: identity.provider,
                    linked_email: identity.linked_email,
                })
                .collect(),
        ))
    }

    /// Removes an account's provider link after passkey authorization.
    pub(super) async fn unlink(
        State(app): State<Self>,
        Path(provider): Path<String>,
        security::ManagementSession(session): security::ManagementSession,
    ) -> Result<StatusCode, ApiError> {
        app.unlink_identity(
            &session,
            provider
                .parse()
                .map_err(FederationError::UnsupportedProvider)?,
        )
        .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Serializes unlink against sign-in and linking, then revokes other browser sessions.
    async fn unlink_identity(
        &self,
        session: &StoredSession,
        provider: Provider,
    ) -> Result<(), FederationError> {
        let mut tx = self.database.begin().await?;
        tx.users()
            .find_active_by_id_for_update(session.user_id)
            .await?
            .ok_or(FederationError::Unauthorized)?;
        if !tx.sessions().management_active(session.id).await? {
            return Err(FederationError::ManagementExpired);
        }
        if !tx.federation().unlink(session.user_id, provider).await? {
            return Err(FederationError::IdentityNotLinked);
        }
        tx.sessions()
            .revoke_other(session.user_id, session.id)
            .await?;
        tx.audit_events()
            .record(
                session.user_id,
                AuditAction::FederationUnlink,
                Some(provider),
            )
            .await?;
        Ok(tx.commit().await?)
    }
}

/// Confirmation required before pending provider evidence can become an identity.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum PendingKind {
    /// Social-first signup attached only by registration naming its ID.
    Signup,
    /// Email match; a passkey session of the matching account can confirm it.
    Link,
    /// Settings-initiated linking requires the initiating passkey session.
    ExplicitLink,
}

/// Browser-visible pending provider evidence.
#[derive(Serialize)]
pub(super) struct PendingView {
    /// Evidence ID which social signup must name explicitly.
    id: TokenId,
    /// Whether the browser must register or confirm a link.
    kind: PendingKind,
    /// Verified identity provider.
    provider: Provider,
    /// Optional verified contact address.
    email: Option<String>,
    /// Bounded provider profile name for onboarding.
    display_name: String,
    /// Validated continuation retained from authorization start.
    return_to: String,
}

/// Continuation returned after successful explicit linking.
#[derive(Serialize)]
struct LinkResponse {
    /// Stored, validated continuation for the browser.
    return_to: String,
}

/// Account settings view of an active social identity.
#[derive(Serialize)]
pub(super) struct SocialIdentityView {
    /// Linked provider.
    provider: Provider,
    /// Optional contact address observed at linking time.
    linked_email: Option<String>,
}
