//! Authorization requests, login/consent continuation and the consent decision.

use super::{
    AUTHORIZATION_CODE_MINUTES, AUTHORIZATION_REQUEST_MINUTES, Claim, CodeChallengeMethod,
    MAX_STATE_BYTES, OAuthCode, OAuthError, OidcApplication, OpaqueToken, Prompt, Reject,
    ResponseMode, ResponseType, Scopes, TokenPrefix,
};
use crate::{routes, security::Session};
use axum::{
    Form, Json,
    extract::{
        Path, Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::HeaderMap,
    response::Redirect,
};
use chrono::{DateTime, Duration, Utc};
use piquel_auth_protocol::UserId;
use piquel_repository::{
    InsertAuthorizationCode, InsertAuthorizationRequest, StoredAuthorizationRequest, StoredSession,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

/// Rejection of a pending authorization that cannot be found.
const UNKNOWN_TRANSACTION: &str = "transaction is unknown, expired or already used";
/// Rejection of a `prompt=none` request without a suitable sign-in.
const SILENT_LOGIN_REQUIRED: &str = "prompt=none was requested, but the user must sign in first";

/// Authorization request parameters. None of them is trusted, and errors are not
/// redirected, until `redirect_uri` matches the client's registration.
#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct AuthorizeQuery {
    /// Must be `code`.
    response_type: String,
    /// Client making the request.
    client_id: String,
    /// Where to send the result; must exactly match a registered URI.
    redirect_uri: String,
    /// Requested scopes, space-separated.
    scope: String,
    /// Client value returned unchanged with the result.
    state: String,
    /// Client value echoed in the ID token.
    nonce: Option<String>,
    /// PKCE challenge the code exchange must answer.
    code_challenge: String,
    /// Must be `S256`.
    code_challenge_method: String,
    /// Resource the access token is for; defaults to the client's first audience.
    audience: Option<String>,
    /// Space-separated [`Prompt`] values.
    prompt: Option<String>,
    /// Maximum seconds since sign-in; zero forces a fresh sign-in.
    max_age: Option<i64>,
    /// Previously issued ID token naming the expected account.
    id_token_hint: Option<String>,
    /// Signed request object; rejected as unsupported.
    request: Option<String>,
    /// Request object reference; rejected as unsupported.
    request_uri: Option<String>,
    /// Must be `query` when present.
    response_mode: Option<String>,
}

impl AuthorizeQuery {
    /// Rejects unsupported parameters and returns the account named by a verified
    /// `id_token_hint`.
    fn hinted_user_id(&self, app: &OidcApplication) -> Result<Option<UserId>, OAuthError> {
        if self.request.is_some() {
            return Err(OAuthCode::RequestNotSupported
                .reject("request objects are not supported; send the parameters directly"));
        }
        if self.request_uri.is_some() {
            return Err(OAuthCode::RequestUriNotSupported
                .reject("request_uri is not supported; send the parameters directly"));
        }
        if let Some(mode) = &self.response_mode {
            match mode.parse::<ResponseMode>().map_err(|error| {
                OAuthCode::InvalidRequest.reject_with(
                    format!("response_mode must be {}", ResponseMode::Query),
                    error,
                )
            })? {
                ResponseMode::Query => {}
            }
        }
        let Some(hint) = &self.id_token_hint else {
            return Ok(None);
        };
        // An expired ID token still identifies the account.
        let claims = app
            .keys
            .verify_id_token_hint(hint, &app.issuer)
            .map_err(|error| {
                OAuthCode::InvalidRequest
                    .reject_with(format!("id_token_hint is invalid: {error}"), error)
            })?;
        if claims[Claim::Audience.as_str()] != self.client_id {
            return Err(
                OAuthCode::InvalidRequest.reject("id_token_hint was issued to another client")
            );
        }
        if claims
            .get(Claim::ExpiresAt.as_str())
            .and_then(Value::as_i64)
            .is_none()
        {
            return Err(OAuthCode::InvalidRequest.reject("id_token_hint has no numeric exp claim"));
        }
        claims
            .get(Claim::Subject.as_str())
            .and_then(Value::as_str)
            .ok_or_else(|| OAuthCode::InvalidRequest.reject("id_token_hint has no sub claim"))?
            .parse()
            .map(Some)
            .map_err(|error| {
                OAuthCode::InvalidRequest
                    .reject_with("id_token_hint sub claim is not an account ID", error)
            })
    }

    /// Checks the response type, PKCE challenge and `state`, then parses the scopes.
    fn scopes(&self) -> Result<Scopes, OAuthError> {
        match self
            .response_type
            .parse::<ResponseType>()
            .map_err(|error| {
                OAuthCode::InvalidRequest.reject_with(
                    format!("response_type must be {}", ResponseType::Code),
                    error,
                )
            })? {
            ResponseType::Code => {}
        }
        match self
            .code_challenge_method
            .parse::<CodeChallengeMethod>()
            .map_err(|error| {
                OAuthCode::InvalidRequest.reject_with(
                    format!(
                        "code_challenge_method must be {}",
                        CodeChallengeMethod::S256
                    ),
                    error,
                )
            })? {
            CodeChallengeMethod::S256 => {}
        }
        if self.state.len() > MAX_STATE_BYTES {
            return Err(OAuthCode::InvalidRequest
                .reject(format!("state must be at most {MAX_STATE_BYTES} bytes")));
        }
        if !piquel_crypto::Pkce::valid_challenge(&self.code_challenge) {
            return Err(OAuthCode::InvalidRequest
                .reject("code_challenge must be a base64url SHA-256 digest, 43 characters long"));
        }
        Scopes::parse(&self.scope)
    }

    /// Checks `nonce` and `max_age`, then parses `prompt`.
    fn prompts(&self) -> Result<Prompts, OAuthError> {
        if self
            .nonce
            .as_ref()
            .is_some_and(|nonce| nonce.is_empty() || nonce.len() > MAX_STATE_BYTES)
        {
            return Err(OAuthCode::InvalidRequest
                .reject(format!("nonce must be 1 to {MAX_STATE_BYTES} bytes")));
        }
        if self.max_age.is_some_and(|age| age < 0) {
            return Err(OAuthCode::InvalidRequest.reject("max_age cannot be negative"));
        }
        Prompts::parse(self.prompt.as_deref().unwrap_or_default())
    }
}

/// What the consent page shows about a pending authorization.
#[derive(Serialize)]
pub(super) struct AuthorizationTransactionView {
    /// Client's registered display name.
    client_name: String,
    /// Requested scopes.
    scopes: Vec<String>,
    /// Resource the access token is for.
    audience: String,
}

/// The consent page's answer for a pending authorization.
#[derive(Deserialize)]
pub(super) struct AuthorizationDecision {
    /// Opaque pending authorization token.
    transaction: String,
    /// Whether the user approved.
    decision: ConsentDecision,
}

/// Pending authorization the browser returns with after signing in.
#[derive(Deserialize)]
pub(super) struct ResumeQuery {
    /// Opaque pending authorization token.
    transaction: String,
}

/// Consent choice posted by the auth frontend.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConsentDecision {
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
    /// Starts an authorization by GET query or form POST: validates it, stores it as
    /// a pending transaction, then sends the browser to login, consent or the client.
    pub(super) async fn authorize(
        State(app): State<Self>,
        headers: HeaderMap,
        // `Form` reads the query string of GET requests.
        form: Result<Form<AuthorizeQuery>, FormRejection>,
    ) -> Result<Redirect, OAuthError> {
        let Form(q) = form.map_err(|error| {
            OAuthCode::InvalidRequest.reject_with(
                format!("authorization request is malformed: {error}"),
                error,
            )
        })?;
        let client = app
            .database
            .oidc()
            .find_client(&q.client_id)
            .await?
            .filter(|client| client.enabled)
            .ok_or_else(|| {
                OAuthCode::InvalidRequest.reject("client_id is not a registered, enabled client")
            })?;
        if !client.redirect_uris.contains(&q.redirect_uri) {
            return Err(OAuthCode::InvalidRequest
                .reject("redirect_uri is not registered for this client; it must match exactly"));
        }
        let redirect = Url::parse(&q.redirect_uri).map_err(|error| {
            OAuthCode::InvalidRequest.reject_with("redirect_uri is not a valid URL", error)
        })?;
        // The redirect URI is now verified, so rejections go back to the client.
        let client_redirect = app.client_redirect(&redirect, &q.state);
        let back = |error: OAuthError| error.redirected(&client_redirect);
        let hinted_user_id = q.hinted_user_id(&app).map_err(back)?;
        let scopes = q.scopes().map_err(back)?;
        if !scopes.allowed_by(&client.allowed_scopes) {
            return Err(back(
                OAuthCode::InvalidScope.reject("scope includes values this client may not request"),
            ));
        }
        let audience = q
            .audience
            .clone()
            .or_else(|| client.allowed_audiences.first().cloned())
            .filter(|audience| client.allowed_audiences.contains(audience))
            .ok_or_else(|| {
                back(OAuthCode::InvalidTarget.reject("audience is not registered for this client"))
            })?;
        let prompts = q.prompts().map_err(back)?;
        let session = Session::optional(&app.database, &headers).await?;
        let requires_login = session.as_ref().is_none_or(|session| {
            !Self::session_satisfies(
                session,
                prompts.force_login,
                q.max_age,
                hinted_user_id,
                None,
            )
        });
        if prompts.silent && requires_login {
            return Err(back(OAuthCode::LoginRequired.reject(SILENT_LOGIN_REQUIRED)));
        }
        let opaque = OpaqueToken::new(TokenPrefix::AuthorizationRequest)?;
        let transaction = opaque.encoded();
        app.database
            .oidc()
            .insert_authorization_request(&InsertAuthorizationRequest {
                id: opaque.id,
                secret_digest: app.token_digest(&opaque)?.as_bytes().to_vec(),
                client_id: q.client_id,
                redirect_uri: q.redirect_uri,
                client_state: q.state,
                pkce_challenge: q.code_challenge,
                nonce: q.nonce,
                scopes: scopes.into_stored(),
                audience,
                force_consent: prompts.force_consent,
                force_login: prompts.force_login,
                max_age: q.max_age,
                hinted_user_id,
                expires_at: Utc::now() + Duration::minutes(AUTHORIZATION_REQUEST_MINUTES),
            })
            .await?;
        if requires_login {
            return Ok(app.continuation_page(routes::page::LOGIN, &transaction));
        }
        app.continue_authorization(&headers, transaction, prompts.silent)
            .await
    }

    /// Resumes an authorization after the browser signs in.
    pub(super) async fn resume(
        State(app): State<Self>,
        headers: HeaderMap,
        query: Result<Query<ResumeQuery>, QueryRejection>,
    ) -> Result<Redirect, OAuthError> {
        let Query(q) = query.map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with(format!("resume request is malformed: {error}"), error)
        })?;
        app.continue_authorization(&headers, q.transaction, false)
            .await
    }

    /// Describes a pending authorization to the consent page.
    pub(super) async fn authorization_transaction(
        State(app): State<Self>,
        headers: HeaderMap,
        Path(transaction): Path<String>,
    ) -> Result<Json<AuthorizationTransactionView>, OAuthError> {
        let session = Session::required(&app.database, &headers).await?;
        let request = app.find_authorization_request(&transaction).await?;
        Self::require_authorization_session(&request, &session)?;
        Ok(Json(AuthorizationTransactionView {
            client_name: request.client_display_name,
            scopes: request.scopes,
            audience: request.audience,
        }))
    }

    /// Records the consent page's decision and returns the client redirect as JSON.
    pub(super) async fn authorization_decision(
        State(app): State<Self>,
        headers: HeaderMap,
        form: Result<Form<AuthorizationDecision>, FormRejection>,
    ) -> Result<Json<Value>, OAuthError> {
        app.require_same_origin(&headers)?;
        let Form(input) = form.map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with(format!("consent decision is malformed: {error}"), error)
        })?;
        let redirect = app.decide(&headers, input, true).await?;
        Ok(Json(json!({"redirect_url":redirect.as_str()})))
    }

    /// Consumes the pending authorization and returns the client redirect: an error
    /// for a denial, or a new authorization code. `explicit` decisions come from the
    /// consent page and save consent; implicit ones must already be allowed.
    async fn decide(
        &self,
        headers: &HeaderMap,
        input: AuthorizationDecision,
        explicit: bool,
    ) -> Result<Url, OAuthError> {
        let session = Session::required(&self.database, headers).await?;
        let pending = self.find_authorization_request(&input.transaction).await?;
        if !explicit && !self.can_authorize(&pending, &session).await? {
            return Err(
                OAuthCode::InvalidRequest.reject("this authorization needs the user's consent")
            );
        }
        let opaque = OpaqueToken::parse(TokenPrefix::AuthorizationRequest, &input.transaction)?;
        let digest = self.token_digest(&opaque)?;
        let mut transaction = self.database.begin().await?;
        let request = transaction
            .oidc()
            .consume_authorization_request(opaque.id, digest.as_bytes())
            .await
            .map_err(|error| {
                OAuthError::database(error, OAuthCode::InvalidRequest, UNKNOWN_TRANSACTION)
            })?;
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
                // Lock the account before writing consent: the consent row's foreign key
                // would otherwise take a key-share lock that deadlocks with a concurrent login.
                transaction
                    .users()
                    .find_active_by_id_for_update(session.user_id)
                    .await?
                    .ok_or_else(|| OAuthCode::InvalidToken.reject("this account is disabled"))?;
                if explicit {
                    transaction
                        .oidc()
                        .save_consent(
                            session.user_id,
                            &request.client_id,
                            &request.audience,
                            &request.scopes,
                        )
                        .await?;
                }
                let code = OpaqueToken::new(TokenPrefix::AuthorizationCode)?;
                transaction
                    .oidc()
                    .insert_code(&InsertAuthorizationCode {
                        id: code.id,
                        secret_digest: self.token_digest(&code)?.as_bytes().to_vec(),
                        client_id: request.client_id,
                        user_id: session.user_id,
                        session_id: session.id,
                        redirect_uri: request.redirect_uri,
                        pkce_challenge: request.pkce_challenge,
                        nonce: request.nonce,
                        scopes: request.scopes,
                        audience: request.audience,
                        expires_at: Utc::now() + Duration::minutes(AUTHORIZATION_CODE_MINUTES),
                    })
                    .await?;
                client_redirect.url(&[("code", &code.encoded())])
            }
        };
        transaction.commit().await?;
        Ok(redirect)
    }

    /// Finds a live pending authorization by its opaque token.
    async fn find_authorization_request(
        &self,
        value: &str,
    ) -> Result<StoredAuthorizationRequest, OAuthError> {
        let opaque = OpaqueToken::parse(TokenPrefix::AuthorizationRequest, value)?;
        let digest = self.token_digest(&opaque)?;
        self.database
            .oidc()
            .find_authorization_request(opaque.id, digest.as_bytes())
            .await?
            .ok_or_else(|| OAuthCode::InvalidRequest.reject(UNKNOWN_TRANSACTION))
    }

    /// Requires the session to meet the pending authorization's requirements.
    fn require_authorization_session(
        request: &StoredAuthorizationRequest,
        session: &StoredSession,
    ) -> Result<(), OAuthError> {
        if Self::session_satisfies(
            session,
            request.force_login,
            request.max_age,
            request.hinted_user_id,
            Some(request.created_at),
        ) {
            Ok(())
        } else {
            Err(OAuthCode::InvalidToken.reject(
                "this sign-in does not meet the authorization's requirements; sign in again",
            ))
        }
    }

    /// Whether a session meets an authorization's sign-in requirements: the hinted
    /// account, `max_age`, and a fresh sign-in for `prompt=login` or `max_age=0`.
    /// Only signing in after the request was stored (`created_at`) counts as fresh.
    fn session_satisfies(
        session: &StoredSession,
        force_login: bool,
        max_age: Option<i64>,
        hinted_user_id: Option<UserId>,
        created_at: Option<DateTime<Utc>>,
    ) -> bool {
        let fresh = created_at.is_some_and(|created_at| session.authenticated_at >= created_at);
        let within_max_age = max_age.is_none_or(|age| {
            if age == 0 {
                return fresh;
            }
            age >= 0
                && Utc::now()
                    .signed_duration_since(session.authenticated_at)
                    .num_seconds()
                    <= age
        });
        (fresh || !force_login)
            && within_max_age
            && hinted_user_id.is_none_or(|subject| subject == session.user_id)
    }

    /// Redirects to an auth frontend page, passing the pending authorization along.
    fn continuation_page(&self, page: &str, transaction: &str) -> Redirect {
        Redirect::to(&format!("{}{page}?transaction={transaction}", self.issuer))
    }

    /// Sends the browser on from a stored authorization: to login if the session falls
    /// short, straight to the client if consent is already given, otherwise to consent.
    /// `silent` (`prompt=none`) returns an error to the client instead of showing a page.
    async fn continue_authorization(
        &self,
        headers: &HeaderMap,
        transaction: String,
        silent: bool,
    ) -> Result<Redirect, OAuthError> {
        let request = self.find_authorization_request(&transaction).await?;
        let redirect = Url::parse(&request.redirect_uri)?;
        let client_redirect = self.client_redirect(&redirect, &request.client_state);
        let back =
            |code: OAuthCode, description| code.reject(description).redirected(&client_redirect);
        let session = Session::optional(&self.database, headers)
            .await?
            .filter(|session| Self::require_authorization_session(&request, session).is_ok());
        let Some(session) = session else {
            if silent {
                return Err(back(OAuthCode::LoginRequired, SILENT_LOGIN_REQUIRED));
            }
            return Ok(self.continuation_page(routes::page::LOGIN, &transaction));
        };
        if self.can_authorize(&request, &session).await? {
            let input = AuthorizationDecision {
                transaction,
                decision: ConsentDecision::Approve,
            };
            let redirect = self.decide(headers, input, false).await?;
            return Ok(Redirect::to(redirect.as_str()));
        }
        if silent {
            return Err(back(
                OAuthCode::ConsentRequired,
                "prompt=none was requested, but the user must consent first",
            ));
        }
        Ok(self.continuation_page(routes::page::CONSENT, &transaction))
    }

    /// Whether the authorization may skip the consent page: the client is trusted or
    /// the user already consented, and the request did not ask for `prompt=consent`.
    async fn can_authorize(
        &self,
        request: &StoredAuthorizationRequest,
        session: &StoredSession,
    ) -> Result<bool, OAuthError> {
        if request.force_consent {
            return Ok(false);
        }
        let client = self
            .database
            .oidc()
            .find_client(&request.client_id)
            .await?
            .ok_or_else(|| {
                OAuthCode::InvalidRequest.reject("the client is no longer registered")
            })?;
        Ok(client.trusted
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

/// Browser interaction required by a request's `prompt` values.
#[derive(Default)]
struct Prompts {
    /// `none`: fail instead of showing login or consent pages.
    silent: bool,
    /// `login` or `select_account`: sign in again even with a session.
    force_login: bool,
    /// `consent`: ask for consent even for trusted or already consented clients.
    force_consent: bool,
}

impl Prompts {
    /// Parses space-separated prompt values. `none` cannot be combined with others.
    fn parse(value: &str) -> Result<Self, OAuthError> {
        let mut policy = Self::default();
        for prompt in value.split_ascii_whitespace() {
            match prompt.parse().map_err(|error| {
                let supported = Prompt::ALL.map(Prompt::as_str).join(", ");
                OAuthCode::InvalidRequest
                    .reject_with(format!("prompt values must be among: {supported}"), error)
            })? {
                Prompt::None => policy.silent = true,
                Prompt::Login | Prompt::SelectAccount => policy.force_login = true,
                Prompt::Consent => policy.force_consent = true,
            }
        }
        if policy.silent && (policy.force_login || policy.force_consent) {
            return Err(OAuthCode::InvalidRequest
                .reject("prompt=none cannot be combined with other prompt values"));
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    //! Prompt and consent decision parsing.
    use super::*;
    /// Duplicates are allowed, flags follow the values, and `none` stands alone.
    #[test]
    fn prompts_enforce_interaction_policy() {
        let silent = Prompts::parse(Prompt::None.as_str()).expect("silent prompt");
        assert!(silent.silent);
        assert!(!silent.force_login && !silent.force_consent);
        let interactive =
            Prompts::parse("login consent select_account login").expect("interaction prompts");
        assert!(!interactive.silent);
        assert!(interactive.force_login && interactive.force_consent);
        assert!(Prompts::parse("none login").is_err());
        assert!(Prompts::parse("unrecognized").is_err());
        assert!(Prompts::parse("").is_ok());
    }
    /// Known decisions parse; unknown ones become `Unsupported` instead of failing.
    #[test]
    fn consent_decisions_are_closed() {
        for (wire, expected) in [
            ("approve", ConsentDecision::Approve),
            ("deny", ConsentDecision::Deny),
        ] {
            let input = serde_json::json!({"transaction":"pending", "decision":wire});
            let parsed: AuthorizationDecision = serde_json::from_value(input).expect("decision");
            assert_eq!(parsed.decision, expected);
        }
        let unsupported: AuthorizationDecision = serde_json::from_value(
            serde_json::json!({"transaction":"pending", "decision":"arbitrary"}),
        )
        .expect("unknown choice preserves handler rejection");
        assert_eq!(unsupported.decision, ConsentDecision::Unsupported);
    }
}
