//! Pending and linked social identities: signup, linking, listing and unlinking.

use super::{FederationApplication, FederationError, Provider};
use crate::account::{AccountError, AccountService, ConfirmedOwner, Owner, Subject, Viewer};
use crate::security::{ApiError, BrowserCookie};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use piquel_common::{
    Personal, TokenId, UserId,
    events::{DomainEvent, EventContext, RevocationReason},
    protocol::api::Identity,
};
use piquel_crypto::Secret;
use piquel_repository::{Database, DatabaseTransaction, InsertExternalIdentity, PendingFederation};
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
        context: &EventContext,
        pending_id: TokenId,
        headers: &HeaderMap,
        user_id: UserId,
    ) -> Result<(), FederationError> {
        let browser = BrowserCookie::FederationPending
            .read(headers)
            .ok_or(FederationError::PendingBrowserMissing)?;
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
            .record(context, Some(user_id), Self::linked(&pending))
            .await?)
    }

    /// The event recording that `pending`'s identity was linked.
    fn linked(pending: &PendingFederation) -> DomainEvent {
        DomainEvent::IdentityLinked {
            provider: pending.provider,
            subject: Personal::Value(pending.subject.clone()),
        }
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
            .ok_or(FederationError::PendingBrowserMissing)?;
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

    /// Links the identity this browser's pending evidence holds to the owner's
    /// account, then clears the evidence's cookie and says where to continue.
    pub(super) async fn confirm_link(
        State(app): State<Self>,
        owner: ConfirmedOwner,
        headers: HeaderMap,
    ) -> Result<Response, ApiError> {
        let browser = BrowserCookie::FederationPending
            .read(&headers)
            .ok_or(FederationError::PendingBrowserMissing)?;
        let return_to = AccountService::new(app.database.clone())
            .link_identity(&owner, &browser)
            .await?;
        let mut response = Json(LinkResponse { return_to }).into_response();
        BrowserCookie::FederationPending
            .clear_on(&mut response)
            .map_err(FederationError::from)?;
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
}

/// Linked identities any administrator may also manage: listing and unlinking.
/// Linking adds a way to sign in, so only the owner can.
impl AccountService {
    /// Links the identity in the pending evidence of the browser holding
    /// `pending`, its cookie's secret, to the owner's account, once they confirmed
    /// with a passkey, and returns where the browser continues. The evidence must
    /// name this account, and this session when settings started the link. The
    /// account must keep a passkey, and a repeated callback may confirm only the
    /// identity already linked here.
    pub(crate) async fn link_identity(
        &self,
        owner: &Owner,
        pending: &Secret,
    ) -> Result<String, AccountError> {
        let user = owner.user();
        let mut tx = self.database.begin().await?;
        owner.lock_confirmed(&mut tx).await?;
        let digest = pending.digest();
        let evidence = tx
            .federation()
            .pending(digest.as_bytes())
            .await?
            .ok_or(FederationError::PendingSignInExpired)?;
        if evidence.link_user_id != Some(user)
            || evidence
                .link_session_id
                .is_some_and(|id| id != owner.session().id)
        {
            return Err(FederationError::LinkAccountMismatch.into());
        }
        let evidence = tx
            .federation()
            .consume_pending(evidence.id, digest.as_bytes())
            .await?;
        if tx.passkeys().list_active(user).await?.is_empty() {
            return Err(FederationError::LinkRequiresPasskey.into());
        }
        match tx
            .federation()
            .find_active(&evidence.issuer, &evidence.subject)
            .await?
        {
            Some(identity) if identity.user_id == user => {}
            Some(_) => return Err(FederationError::IdentityAlreadyLinked.into()),
            None => {
                tx.federation()
                    .insert_identity(&FederationApplication::identity(&evidence, user))
                    .await?;
                tx.record(
                    &owner.context(),
                    Some(user),
                    FederationApplication::linked(&evidence),
                )
                .await?;
            }
        }
        if let Some(email) = &evidence.email {
            tx.federation().set_first_email(user, email).await?;
        }
        tx.commit().await?;
        Ok(evidence.return_to)
    }

    /// Lists the account's active social identities.
    pub(crate) async fn identities(&self, viewer: &Viewer) -> Result<Vec<Identity>, AccountError> {
        viewer.authorize(&self.database).await?;
        let identities = self
            .database
            .federation()
            .list_active(viewer.user())
            .await?;
        Ok(identities.into_iter().map(Into::into).collect())
    }

    /// Unlinks the account's identity at `provider`, serialized with sign-in and
    /// linking by the account lock, then signs the account out elsewhere.
    pub(crate) async fn unlink_identity(
        &self,
        subject: &Subject,
        provider: Provider,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        subject.lock_confirmed(&mut tx).await?;
        if !tx.federation().unlink(subject.user(), provider).await? {
            return Err(FederationError::IdentityNotLinked.into());
        }
        let context = subject.context();
        tx.record(
            &context,
            Some(subject.user()),
            DomainEvent::IdentityUnlinked { provider },
        )
        .await?;
        tx.revoke_sessions(
            &context,
            subject.user(),
            subject.others(),
            &RevocationReason::IdentityUnlinked,
        )
        .await?;
        subject.commit(tx).await
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
