//! Authorization requests, pushed or from the browser, login/consent continuation
//! and the consent decision.

/// The consent decision, and the code an approved authorization issues.
mod consent;
/// Authorization request parameters and their validation.
mod parameters;
/// Pushed authorization requests (RFC 9126) and claiming them.
mod pushed;
/// Whether a session meets a pending authorization's sign-in requirements.
mod requirements;

pub(crate) use consent::AuthorizationDecision;
use consent::ConsentDecision;
use parameters::AuthorizationParameters;

use super::{
    OAuthCode, OAuthError, OidcApplication, OpaqueToken, Reject, TokenPrefix, policy::ClientPolicy,
};
use crate::{
    routes,
    security::{RequestContext, Session},
};
use axum::{
    Form,
    extract::{
        Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::HeaderMap,
    response::Redirect,
};
use serde::{Deserialize, Serialize};
use sourceorigin_common::{RecoveryId, protocol::claims::Acr};
use sourceorigin_repository::StoredAuthorizationRequest;
use sourceorigin_ui::{Checkbox, LoginQuery};
use url::Url;

/// Rejection of a pending authorization that cannot be found.
const UNKNOWN_TRANSACTION: &str = "transaction is unknown, expired or already used";
/// Rejection of a `prompt=none` request without a suitable sign-in.
const SILENT_LOGIN_REQUIRED: &str = "prompt=none was requested, but the user must sign in first";

/// A pending authorization, by its opaque token: the one the browser returns with
/// after signing in, or the consent page shows.
#[derive(Serialize, Deserialize)]
pub(crate) struct TransactionQuery {
    /// Opaque pending authorization token.
    pub(crate) transaction: String,
}

impl sourceorigin_ui::Query for TransactionQuery {}

/// Whether the browser answered the question a sign-in for an application asks
/// while the account has a recovery that can still be undone: was it the
/// owner's? Only the sign-in page's form answers it, so no link can skip it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryQuestion {
    /// Not yet: a sign-in for the authorization asks it before going on.
    Unanswered,
    /// The browser said yes to this recovery's question, and goes on. A question
    /// about another recovery, as another account's, is still asked.
    Answered(RecoveryId),
}

/// A pending authorization, as the sign-in page continuing it sees it.
pub(crate) struct AuthorizationView {
    /// The class the sign-in must reach, if the application asked for one.
    pub(crate) target_acr: Option<Acr>,
    /// Where the application receives the browser: the registered redirect URI the
    /// request named.
    pub(crate) redirect_uri: Url,
}

impl OidcApplication {
    /// Starts an authorization by GET query or form POST: validates it, stores it as
    /// a pending transaction, then sends the browser to login, consent or the client.
    /// A `request_uri` continues a pushed request instead.
    pub(super) async fn authorize(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        // `Form` reads the query string of GET requests.
        form: Result<Form<AuthorizationParameters>, FormRejection>,
    ) -> Result<Redirect, OAuthError> {
        let Form(q) = form.map_err(|error| {
            OAuthCode::InvalidRequest.reject_with(
                format!("authorization request is malformed: {error}"),
                error,
            )
        })?;
        let client_id = q.client_id.as_deref().unwrap_or_default();
        if let Some(request_uri) = &q.request_uri {
            let next = app
                .claim_pushed(context, &headers, client_id, request_uri)
                .await?;
            return Ok(Redirect::to(next.as_str()));
        }
        let client = app
            .database
            .oidc()
            .find_client(client_id)
            .await?
            .filter(|client| client.enabled)
            .ok_or_else(|| {
                OAuthCode::InvalidRequest.reject("client_id is not a registered, enabled client")
            })?;
        let redirect = q.redirect_uri(&client)?;
        // The redirect URI is now verified, so rejections go back to the client.
        let client_redirect = app.client_redirect(&redirect, &q.state);
        let back = |error: OAuthError| error.redirected(&client_redirect);
        if client.require_pushed_authorization_requests {
            return Err(back(OAuthCode::InvalidRequest.reject(
                "this client must push its authorization requests and send their request_uri",
            )));
        }
        let validated = q.validate(&app, &client, false).map_err(back)?;
        let request = &validated.request;
        let session = Session::resolve(&app.database, context, &headers).await?;
        let requires_login = session.as_ref().is_none_or(|session| {
            !Self::session_satisfies(
                session,
                request.interaction.forces_login(),
                request.max_age,
                request.hinted_user_id,
                request.target_acr,
                None,
            )
        });
        if request.interaction.is_silent() && requires_login {
            return Err(back(OAuthCode::LoginRequired.reject(SILENT_LOGIN_REQUIRED)));
        }
        let target_acr = request.target_acr;
        let transaction = validated.store(&app).await?;
        let next = if requires_login {
            app.sign_in_page(transaction, target_acr)?
        } else {
            app.continue_authorization(context, &headers, transaction, RecoveryQuestion::Unanswered)
                .await?
        };
        Ok(Redirect::to(next.as_str()))
    }

    /// Resumes an authorization after the browser signs in.
    pub(super) async fn resume(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        query: Result<Query<TransactionQuery>, QueryRejection>,
    ) -> Result<Redirect, OAuthError> {
        let Query(q) = query.map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with(format!("resume request is malformed: {error}"), error)
        })?;
        let next = app
            .continue_authorization(
                context,
                &headers,
                q.transaction,
                RecoveryQuestion::Unanswered,
            )
            .await?;
        Ok(Redirect::to(next.as_str()))
    }

    /// The pending authorization `transaction`, as the sign-in page continuing it sees
    /// it: what it may offer and where its forms may lead. The token is all it takes:
    /// the browser is not signed in yet.
    pub(crate) async fn authorization(
        &self,
        transaction: &str,
    ) -> Result<AuthorizationView, OAuthError> {
        let request = self.find_authorization_request(transaction).await?;
        Ok(AuthorizationView {
            target_acr: request.target_acr,
            redirect_uri: Url::parse(&request.redirect_uri)?,
        })
    }

    /// Finds a live pending authorization by its opaque token, while its client
    /// still allows it. Every page and redirect continuing an authorization starts
    /// here, so none leads the browser to a redirect URI, or for a request, that
    /// the client no longer allows: such a request explains itself on auth's page
    /// instead.
    async fn find_authorization_request(
        &self,
        value: &str,
    ) -> Result<StoredAuthorizationRequest, OAuthError> {
        let opaque = OpaqueToken::parse(TokenPrefix::AuthorizationRequest, value)?;
        let digests = self.accepted_digests(&opaque);
        let request = self
            .database
            .oidc()
            .find_authorization_request(opaque.id, &digests)
            .await?
            .ok_or_else(|| OAuthCode::InvalidRequest.reject(UNKNOWN_TRANSACTION))?;
        ClientPolicy::read(&self.database, &request.client_id)
            .await?
            .allows(&request)
            .map_err(|refusal| refusal.reject(OAuthCode::InvalidRequest))?;
        Ok(request)
    }

    /// The sign-in page continuing the pending authorization `transaction`. A target
    /// `acr` is named too, so the page offers only methods reaching it.
    fn sign_in_page(
        &self,
        transaction: String,
        target_acr: Option<Acr>,
    ) -> Result<Url, OAuthError> {
        let query = LoginQuery {
            transaction: Some(transaction),
            acr: target_acr,
            ..LoginQuery::default()
        };
        self.page(routes::page::LOGIN, &query)
    }

    /// Where the browser goes on from a stored authorization: to sign-in if the session
    /// falls short, straight to the client if consent is already given, otherwise to
    /// consent. `prompt=none` returns an error to the client instead of showing a page.
    /// Looking the session up records its activity, so single sign-on keeps it current.
    /// The sign-in pages call it once the browser signed in, and every other sign-in,
    /// a provider's or a restore, goes on through it by resuming the authorization.
    /// A sign-in for this authorization first goes to the sign-in page's question
    /// about the account's recovery that can still be undone, until `recovery` says
    /// the browser answered it.
    pub(crate) async fn continue_authorization(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
        transaction: String,
        recovery: RecoveryQuestion,
    ) -> Result<Url, OAuthError> {
        let request = self.find_authorization_request(&transaction).await?;
        let silent = request.interaction.is_silent();
        let redirect = Url::parse(&request.redirect_uri)?;
        let client_redirect = self.client_redirect(&redirect, &request.client_state);
        let back =
            |code: OAuthCode, description| code.reject(description).redirected(&client_redirect);
        let session = Session::resolve(&self.database, context, headers).await?;
        // A passkey just signed in for this request without confirming the
        // session, as a recovered passkey does during its probation: signing in
        // again would not help, so the client hears it instead of looping.
        if session
            .as_ref()
            .is_some_and(|session| Self::falls_short_after_signing_in(&request, session))
        {
            return Err(back(
                OAuthCode::UnmetAuthenticationRequirements,
                "this account cannot meet the requested acr_values for now",
            ));
        }
        let session = session
            .filter(|session| Self::require_authorization_session(&request, session).is_ok());
        let Some(session) = session else {
            if silent {
                return Err(back(OAuthCode::LoginRequired, SILENT_LOGIN_REQUIRED));
            }
            return self.sign_in_page(transaction, request.target_acr);
        };
        // A silent request shows no page, and only another tab's sign-in in the
        // instant since it started could have signed in for it.
        if !silent && Self::signed_in_for(&request, &session) {
            let mut tx = self.database.begin().await?;
            let undoable = Self::undoable_recovery(&mut tx, session.user_id).await?;
            tx.commit().await?;
            if let Some(id) = undoable
                && recovery != RecoveryQuestion::Answered(id)
            {
                let query = LoginQuery {
                    transaction: Some(transaction),
                    recovery: Checkbox(true),
                    ..LoginQuery::default()
                };
                return self.page(routes::page::LOGIN, &query);
            }
        }
        if self.can_authorize(&request, &session).await? {
            let input = AuthorizationDecision {
                transaction,
                decision: ConsentDecision::Approve,
            };
            return self.decide(headers, input, None).await;
        }
        if silent {
            return Err(back(
                OAuthCode::ConsentRequired,
                "prompt=none was requested, but the user must consent first",
            ));
        }
        self.page(routes::page::CONSENT, &TransactionQuery { transaction })
    }
}

/// Prompt, `max_age` and consent decision parsing.
#[cfg(test)]
mod tests;
