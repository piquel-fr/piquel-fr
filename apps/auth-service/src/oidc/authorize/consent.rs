//! The consent page's decision on a pending authorization, whether it may be
//! skipped, and the code an approved authorization issues.

use super::UNKNOWN_TRANSACTION;
use crate::{
    oidc::{
        AUTHORIZATION_CODE_MINUTES, OAuthCode, OAuthError, OidcApplication, OpaqueToken, Reject,
        TokenPrefix, policy::ClientPolicy,
    },
    security::{RequestContext, Session, SessionError},
};
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use piquel_common::{Handle, UserId, events::DomainEvent};
use piquel_repository::{
    DatabaseTransaction, InsertAuthorizationCode, SessionAuthentication,
    StoredAuthorizationRequest, StoredSession,
};
use serde::Deserialize;
use url::Url;

/// The consent page's answer for a pending authorization, as its form posts it.
#[derive(Deserialize)]
pub(crate) struct AuthorizationDecision {
    /// Opaque pending authorization token.
    pub(super) transaction: String,
    /// Whether the user approved.
    pub(super) decision: ConsentDecision,
}

impl AuthorizationDecision {
    /// The pending authorization decided on.
    pub(crate) fn transaction(&self) -> &str {
        &self.transaction
    }
}

/// A pending authorization as the consent page shows it: who asks, and who would
/// answer.
pub(crate) struct ConsentRequest {
    /// The request.
    pub(crate) request: StoredAuthorizationRequest,
    /// The handle of the account that registered the client, which nobody
    /// verified; `None` for a client operators registered.
    pub(crate) registered_by: Option<Handle>,
    /// The handle of the account the browser is signed in to, which would approve.
    pub(crate) account: Handle,
}

/// Consent choice posted by the consent page.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConsentDecision {
    /// Save consent and issue a one-use code.
    Approve,
    /// Return `access_denied` without saving consent.
    Deny,
    /// Any other value. Caught here so it is answered with `invalid_request` rather
    /// than the form extractor's 422.
    #[serde(other)]
    Unsupported,
}

impl OidcApplication {
    /// The pending authorization the consent page shows, once the browser's session
    /// meets its requirements, with who registered its client and who is signed in.
    pub(crate) async fn consent(
        &self,
        headers: &HeaderMap,
        transaction: &str,
    ) -> Result<ConsentRequest, OAuthError> {
        let session = Session::required(&self.database, headers).await?;
        let request = self.find_authorization_request(transaction).await?;
        Self::require_authorization_session(&request, &session)?;
        let client = ClientPolicy::read(&self.database, &request.client_id).await?;
        let registered_by = match client.client().owner_id {
            Some(owner) => Some(self.handle(owner).await?.ok_or_else(Self::unregistered)?),
            None => None,
        };
        let account = self
            .handle(session.user_id)
            .await?
            .ok_or(SessionError::Missing)?;
        Ok(ConsentRequest {
            request,
            registered_by,
            account,
        })
    }

    /// The current handle of account `user`, or `None` once it is purged.
    async fn handle(&self, user: UserId) -> Result<Option<Handle>, OAuthError> {
        let user = self.database.users().find_by_id(user).await?;
        Ok(user.map(|user| user.handle))
    }

    /// Refuses a request whose client's owner is gone since it was found.
    fn unregistered() -> OAuthError {
        OAuthCode::InvalidRequest.reject("the client is no longer registered")
    }

    /// Consumes the pending authorization and returns the client redirect: an error
    /// for a denial, or a new authorization code. Explicit decisions come from the
    /// consent page, whose request is `consent`, and save and record consent;
    /// implicit ones must already be allowed.
    pub(crate) async fn decide(
        &self,
        headers: &HeaderMap,
        input: AuthorizationDecision,
        consent: Option<RequestContext>,
    ) -> Result<Url, OAuthError> {
        let session = Session::required(&self.database, headers).await?;
        let pending = self.find_authorization_request(&input.transaction).await?;
        if consent.is_none() && !self.can_authorize(&pending, &session).await? {
            return Err(
                OAuthCode::InvalidRequest.reject("this authorization needs the user's consent")
            );
        }
        let opaque = OpaqueToken::parse(TokenPrefix::AuthorizationRequest, &input.transaction)?;
        let digests = self.accepted_digests(&opaque)?;
        let mut transaction = self.database.begin().await?;
        // An approval locks the account first: before writing consent, whose row's
        // foreign key would otherwise take a key-share lock that deadlocks with a
        // concurrent login, and before the client, which an owner changing it locks
        // after their account. The session is read again under the lock, so a
        // consent that waited while its session ended, signed out or revoked, is not
        // saved after it.
        if input.decision == ConsentDecision::Approve {
            Session::lock(&mut transaction, &session).await?;
        }
        // Checked again under the client's lock, so no change to the client commits
        // between this check and the code.
        let policy = ClientPolicy::share(&mut transaction, &pending.client_id).await?;
        let request = transaction
            .oidc()
            .consume_authorization_request(opaque.id, &digests)
            .await
            .map_err(|error| {
                OAuthError::database(error, OAuthCode::InvalidRequest, UNKNOWN_TRANSACTION)
            })?;
        policy
            .allows(&request)
            .map_err(|refusal| refusal.reject(OAuthCode::InvalidRequest))?;
        Self::require_authorization_session(&request, &session)?;
        let redirect = Url::parse(&request.redirect_uri)?;
        let client_redirect = self.client_redirect(&redirect, &request.client_state);
        let redirect = match input.decision {
            ConsentDecision::Unsupported => {
                return Err(OAuthCode::InvalidRequest.reject("decision must be approve or deny"));
            }
            ConsentDecision::Deny => OAuthCode::AccessDenied
                .redirect_url(&client_redirect, "the user denied the request"),
            ConsentDecision::Approve => {
                if let Some(context) = consent {
                    transaction
                        .oidc()
                        .save_consent(
                            session.user_id,
                            &request.client_id,
                            &request.audience,
                            &request.scopes,
                        )
                        .await?;
                    transaction
                        .record(
                            &context.user(&session),
                            Some(session.user_id),
                            DomainEvent::ConsentGranted {
                                client_id: request.client_id.clone(),
                                scopes: request.scopes.clone(),
                            },
                        )
                        .await?;
                }
                let code = self
                    .issue_code(&mut transaction, &request, &session)
                    .await?;
                client_redirect.url(&[("code", &code.encoded())])
            }
        };
        transaction.commit().await?;
        Ok(redirect)
    }

    /// Issues a code for the consumed `request` to `session` inside `transaction`.
    pub(in crate::oidc) async fn issue_code(
        &self,
        transaction: &mut DatabaseTransaction<'_>,
        request: &StoredAuthorizationRequest,
        session: &StoredSession,
    ) -> Result<OpaqueToken, OAuthError> {
        let code = OpaqueToken::new(TokenPrefix::AuthorizationCode)?;
        let (secret_digest, digest_key) = self.token_digest(&code)?;
        transaction
            .oidc()
            .insert_code(&InsertAuthorizationCode {
                id: code.id,
                secret_digest,
                digest_key,
                client_id: request.client_id.clone(),
                user_id: session.user_id,
                session_id: session.id,
                redirect_uri: request.redirect_uri.clone(),
                pkce_challenge: request.pkce_challenge.clone(),
                nonce: request.nonce.clone(),
                scopes: request.scopes.clone(),
                audience: request.audience.clone(),
                authentication: SessionAuthentication::from(session),
                expires_at: Utc::now() + Duration::minutes(AUTHORIZATION_CODE_MINUTES),
            })
            .await?;
        Ok(code)
    }

    /// Whether the authorization may skip the consent page: the client is trusted or
    /// the user already consented, and the request did not ask for `prompt=consent`.
    pub(super) async fn can_authorize(
        &self,
        request: &StoredAuthorizationRequest,
        session: &StoredSession,
    ) -> Result<bool, OAuthError> {
        if request.interaction.forces_consent() {
            return Ok(false);
        }
        let client = ClientPolicy::read(&self.database, &request.client_id).await?;
        Ok(client.client().trusted
            || self
                .database
                .oidc()
                .consented(
                    session.user_id,
                    &request.client_id,
                    &request.audience,
                    &request.scopes,
                )
                .await?)
    }
}
