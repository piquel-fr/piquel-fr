//! Pushed authorization requests completed by a passkey sign-in on an application's
//! own page, from an approved related origin. The page gets the code as JSON
//! instead of through the redirect URI; it is useless without the PKCE verifier.

use super::{OAuthCode, OidcApplication, policy::ClientPolicy};
use crate::security::ApiError;
use serde::{Deserialize, Serialize};
use sourceorigin_common::{ClientId, TokenId, UserId, clients::RelatedOrigin};
use sourceorigin_repository::{DatabaseTransaction, StoredSession};

/// A pushed request an inline sign-in claimed, kept in its ceremony. It holds the
/// digests its renewed secret is accepted under, which complete it, but never the
/// secret itself.
#[derive(Serialize, Deserialize)]
pub(crate) struct InlineClaim {
    /// The authorization request.
    id: TokenId,
    /// The digests of its renewed secret, one per accepted digest key.
    digests: Vec<Vec<u8>>,
    /// The account its `id_token_hint` names, whose passkeys alone may sign in.
    pub(crate) hinted_user_id: Option<UserId>,
}

/// The authorization response (RFC 9207), returned as JSON to the page.
#[derive(Serialize)]
pub(crate) struct InlineResponse {
    /// The authorization code, redeemable with the request's PKCE verifier.
    code: String,
    /// The request's `state`.
    state: String,
    /// This issuer.
    iss: String,
}

impl OidcApplication {
    /// Claims `client_id`'s pushed request `request_uri` for an inline sign-in,
    /// inside `tx`. A request whose prompt needs auth's pages, `consent` or `none`,
    /// is refused with `interaction_required`. The caller then drops `tx`, so the
    /// request stays unclaimed and the client can still send the browser to auth
    /// with it.
    pub(crate) async fn claim_inline(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        client_id: &ClientId,
        request_uri: &str,
    ) -> Result<InlineClaim, ApiError> {
        let (opaque, request) = self
            .claim(tx.oidc(), client_id.as_str(), request_uri)
            .await?;
        if request.interaction.forces_consent() || request.interaction.is_silent() {
            return Err(ApiError::interaction_required(
                "This sign-in request needs Origin Auth's own pages.",
            ));
        }
        Ok(InlineClaim {
            id: opaque.id,
            digests: self.accepted_digests(&opaque),
            hinted_user_id: request.hinted_user_id,
        })
    }

    /// Consumes `client_id`'s claimed request inside `tx` and issues its code to
    /// `session`, which the inline passkey sign-in on the page at `origin` just
    /// created, if it meets the request's requirements as the redirect flow's would.
    /// A new session meets any `prompt=login` and `max_age`, and the sign-in accepted
    /// only the hinted account's passkeys. A recovered passkey during its probation
    /// does not confirm the session, so it meets no `acr_values=phr`: the page then
    /// sends the browser to auth, whose answer the client understands. While the
    /// account has a recovery that can still be undone, it sends the browser to auth
    /// too, whose sign-in asks whether it was the owner's. The client is
    /// share-locked and must still allow the request, be trusted and have `origin`
    /// approved, so a change made during the ceremony applies to it.
    pub(crate) async fn complete_inline(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        claim: &InlineClaim,
        session: &StoredSession,
        client_id: &ClientId,
        origin: &RelatedOrigin,
    ) -> Result<InlineResponse, ApiError> {
        let policy = ClientPolicy::share(tx, client_id).await?;
        let request = tx
            .oidc()
            .consume_authorization_request(claim.id, &claim.digests)
            .await?;
        let approved = tx.oidc().related_origin_client(origin.as_str()).await?;
        policy
            .allows_inline(&request, approved.as_ref())
            .map_err(|refusal| refusal.reject(OAuthCode::InvalidRequest))?;
        if !Self::satisfies(&request, session) {
            return Err(ApiError::interaction_required(
                "This sign-in does not meet what the application asked for.",
            ));
        }
        // The question needs auth's pages, which the redirect flow shows.
        if Self::undoable_recovery(tx, session.user_id)
            .await?
            .is_some()
        {
            return Err(ApiError::interaction_required(
                "This account has a recovery that can still be undone. Sign in on Origin Auth's pages to continue.",
            ));
        }
        let code = self.issue_code(tx, &request, session).await?;
        Ok(InlineResponse {
            code: code.encoded(),
            state: request.client_state,
            iss: self.issuer.clone(),
        })
    }
}
