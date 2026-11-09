//! The one check of a client's current policy that an authorization runs before
//! each step that acts for the client: leading the browser on to it, consuming its
//! request, completing it inline on its own page, and exchanging its code. An
//! operator or owner may change the client at any time in between, so each step
//! checks the registration as it is now, never as it was when the request began.

use super::{OAuthCode, OAuthError, Reject};
use sourceorigin_common::ClientId;
use sourceorigin_repository::{
    ConsumedAuthorizationCode, Database, DatabaseTransaction, StoredAuthorizationRequest,
    StoredOidcClient,
};
use thiserror::Error;

/// A client's registration, as an authorization step checks it. [`Self::share`]
/// reads it with the client's row share-locked in the step's transaction, so no
/// change to the client commits between the check and the step's commit: the
/// change waits for the step, or the step waits for the change and sees it.
/// [`Self::read`] reads it without a lock, for steps that only lead the browser
/// on; the step that issues a code checks again under the lock.
pub(crate) struct ClientPolicy(StoredOidcClient);

/// What a client's current registration no longer allows.
#[derive(Debug, Error)]
pub(crate) enum PolicyRefusal {
    /// The client is unknown, disabled, suspended or deleted.
    #[error("the client is no longer registered and enabled")]
    Unavailable,
    /// The redirect URI was removed from the client.
    #[error("the redirect URI is no longer registered for this client")]
    RedirectUri,
    /// A scope was removed from the client.
    #[error("the client may no longer request these scopes")]
    Scopes,
    /// The audience was removed from the client.
    #[error("the client may no longer request tokens for this audience")]
    Audience,
    /// The client must now push its requests, and this one came through the browser.
    #[error("the client must now push its authorization requests (RFC 9126)")]
    PushRequired,
    /// Only trusted clients complete sign-ins on their own pages.
    #[error("the client is no longer trusted to sign users in on its own pages")]
    Untrusted,
    /// The page's origin is no longer approved for the client.
    #[error("the page's origin is no longer approved for this client")]
    Origin,
}

impl ClientPolicy {
    /// Client `id`'s policy, its row share-locked until `tx` ends.
    pub(crate) async fn share(
        tx: &mut DatabaseTransaction<'_>,
        id: &ClientId,
    ) -> Result<Self, OAuthError> {
        Self::found(tx.oidc().share_client(id).await?)
    }

    /// Client `id`'s policy, read without a lock.
    pub(crate) async fn read(database: &Database, id: &ClientId) -> Result<Self, OAuthError> {
        Self::found(database.oidc().find_client(id.as_str()).await?)
    }

    /// Refuses an unknown client as [`PolicyRefusal::Unavailable`].
    fn found(client: Option<StoredOidcClient>) -> Result<Self, OAuthError> {
        client
            .map(Self)
            .ok_or_else(|| PolicyRefusal::Unavailable.reject(OAuthCode::InvalidRequest))
    }

    /// The registration checked.
    pub(crate) const fn client(&self) -> &StoredOidcClient {
        &self.0
    }

    /// Whether the client still allows `request`: as a code it may issue, and, when
    /// it now requires pushed requests, only if the client pushed it.
    pub(crate) fn allows(&self, request: &StoredAuthorizationRequest) -> Result<(), PolicyRefusal> {
        self.allows_grant(&request.redirect_uri, &request.scopes, &request.audience)?;
        if self.0.require_pushed_authorization_requests && !request.pushed {
            return Err(PolicyRefusal::PushRequired);
        }
        Ok(())
    }

    /// Whether the client still allows redeeming `code`. Pushing concerns only the
    /// request the code came from, which no longer travels through the browser.
    pub(crate) fn allows_code(
        &self,
        code: &ConsumedAuthorizationCode,
    ) -> Result<(), PolicyRefusal> {
        self.allows_grant(&code.redirect_uri, &code.scopes, &code.audience)
    }

    /// Whether the client still allows completing `request` on its own page, which
    /// only a trusted client does, from an origin approved for it: `approved` is the
    /// client the page's origin is approved for now, if any.
    pub(crate) fn allows_inline(
        &self,
        request: &StoredAuthorizationRequest,
        approved: Option<&ClientId>,
    ) -> Result<(), PolicyRefusal> {
        self.allows(request)?;
        if !self.0.trusted {
            return Err(PolicyRefusal::Untrusted);
        }
        if approved != Some(&self.0.id) {
            return Err(PolicyRefusal::Origin);
        }
        Ok(())
    }

    /// Whether the enabled client may still send a code for `scopes` and
    /// `audience` to `redirect_uri`.
    fn allows_grant(
        &self,
        redirect_uri: &str,
        scopes: &[String],
        audience: &str,
    ) -> Result<(), PolicyRefusal> {
        let client = &self.0;
        if !client.enabled {
            return Err(PolicyRefusal::Unavailable);
        }
        if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
            return Err(PolicyRefusal::RedirectUri);
        }
        if !scopes
            .iter()
            .all(|scope| client.allowed_scopes.contains(scope))
        {
            return Err(PolicyRefusal::Scopes);
        }
        if !client
            .allowed_audiences
            .iter()
            .any(|allowed| allowed == audience)
        {
            return Err(PolicyRefusal::Audience);
        }
        Ok(())
    }
}

impl PolicyRefusal {
    /// Rejects the step with `code`, describing what the client no longer allows.
    pub(crate) fn reject(self, code: OAuthCode) -> OAuthError {
        code.reject_with(self.to_string(), self)
    }
}
