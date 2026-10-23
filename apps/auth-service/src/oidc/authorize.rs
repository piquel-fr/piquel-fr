//! Authorization requests, pushed or from the browser, login/consent continuation
//! and the consent decision.

use super::{
    AUTHORIZATION_CODE_MINUTES, AUTHORIZATION_REQUEST_MINUTES, Claim, CodeChallengeMethod,
    DescribedScope, MAX_STATE_BYTES, OAuthCode, OAuthError, OidcApplication, OpaqueToken,
    PUSHED_REQUEST_SECONDS, Prompt, Reject, ResponseMode, ResponseType, Scopes, TokenPrefix,
};
use crate::{
    routes,
    security::{RequestContext, Session},
};
use axum::{
    Form, Json,
    extract::{
        Path, Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::Redirect,
};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    UserId,
    events::DomainEvent,
    protocol::{claims::Acr, step_up::StepUpRequirement},
};
use piquel_repository::{
    Approval, InsertAuthorizationCode, InsertAuthorizationRequest, OidcRepository,
    SessionAuthentication, StoredAuthorizationRequest, StoredOidcClient, StoredSession,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

/// Rejection of a pending authorization that cannot be found.
const UNKNOWN_TRANSACTION: &str = "transaction is unknown, expired or already used";
/// Rejection of a `prompt=none` request without a suitable sign-in.
const SILENT_LOGIN_REQUIRED: &str = "prompt=none was requested, but the user must sign in first";
/// Rejection of a `request_uri` that cannot be claimed.
const UNKNOWN_REQUEST_URI: &str =
    "request_uri is unknown, expired, already used or issued to another client";
/// Prefix of a pushed request's `request_uri` (RFC 9126 §2.2), followed by the
/// pushed request's [`OpaqueToken`].
const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Authorization request parameters, from the browser or pushed by the client.
/// None of them is trusted, and errors are not redirected, until `redirect_uri`
/// matches the client's registration.
#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct AuthorizationParameters {
    /// Must be `code`.
    response_type: String,
    /// Client making the request. A pushing client authenticated with HTTP Basic
    /// may leave it out.
    client_id: Option<String>,
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
    /// Space-separated [`Acr`] values, most preferred first; unknown ones are ignored.
    acr_values: Option<String>,
    /// Previously issued ID token naming the expected account.
    id_token_hint: Option<String>,
    /// Signed request object; rejected as unsupported.
    request: Option<String>,
    /// Reference to a pushed request, which replaces every other parameter but
    /// `client_id`. Client-hosted request objects are not supported.
    request_uri: Option<String>,
    /// Must be `query` when present.
    response_mode: Option<String>,
}

impl AuthorizationParameters {
    /// The redirect URI, which must be registered for `client`. Until it is, errors
    /// cannot be redirected.
    fn redirect_uri(&self, client: &StoredOidcClient) -> Result<Url, OAuthError> {
        if !client.redirect_uris.contains(&self.redirect_uri) {
            return Err(OAuthCode::InvalidRequest
                .reject("redirect_uri is not registered for this client; it must match exactly"));
        }
        Url::parse(&self.redirect_uri).map_err(|error| {
            OAuthCode::InvalidRequest.reject_with("redirect_uri is not a valid URL", error)
        })
    }

    /// Validates every other parameter against `client`'s registration, the same
    /// way for browser and pushed requests, and returns the pending authorization
    /// to store under the returned token. Errors are not redirected.
    fn validate(
        &self,
        app: &OidcApplication,
        client: &StoredOidcClient,
        pushed: bool,
    ) -> Result<(OpaqueToken, InsertAuthorizationRequest), OAuthError> {
        let hinted_user_id = self.hinted_user_id(app, client)?;
        let scopes = self.scopes()?;
        if !scopes.allowed_by(&client.allowed_scopes) {
            return Err(
                OAuthCode::InvalidScope.reject("scope includes values this client may not request")
            );
        }
        let audience = self
            .audience
            .clone()
            .or_else(|| client.allowed_audiences.first().cloned())
            .filter(|audience| client.allowed_audiences.contains(audience))
            .ok_or_else(|| {
                OAuthCode::InvalidTarget.reject("audience is not registered for this client")
            })?;
        let prompts = self.prompts()?;
        let lifetime = if pushed {
            Duration::seconds(PUSHED_REQUEST_SECONDS)
        } else {
            Duration::minutes(AUTHORIZATION_REQUEST_MINUTES)
        };
        let token = OpaqueToken::new(TokenPrefix::AuthorizationRequest)?;
        let request = InsertAuthorizationRequest {
            id: token.id,
            secret_digest: app.token_digest(&token)?.as_bytes().to_vec(),
            pushed,
            client_id: client.id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            client_state: self.state.clone(),
            pkce_challenge: self.code_challenge.clone(),
            nonce: self.nonce.clone(),
            scopes: scopes.into_stored(),
            audience,
            force_consent: prompts.force_consent,
            force_login: prompts.force_login,
            prompt_none: prompts.silent,
            max_age: self.max_age,
            hinted_user_id,
            target_acr: self.acr_values.as_deref().and_then(Acr::select),
            expires_at: Utc::now() + lifetime,
        };
        Ok((token, request))
    }

    /// Rejects unsupported parameters and returns the account named by a verified
    /// `id_token_hint`, which must have been issued to `client`.
    fn hinted_user_id(
        &self,
        app: &OidcApplication,
        client: &StoredOidcClient,
    ) -> Result<Option<UserId>, OAuthError> {
        if self.request.is_some() {
            return Err(OAuthCode::RequestNotSupported
                .reject("request objects are not supported; send the parameters directly"));
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
        if claims[Claim::Audience.as_str()] != client.id.as_str() {
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

/// The pushed authorization endpoint's answer (RFC 9126 §2.2).
#[derive(Serialize)]
pub(super) struct PushedAuthorization {
    /// What the browser brings to the authorization endpoint, with `client_id`.
    request_uri: String,
    /// Seconds until `request_uri` expires.
    expires_in: i64,
}

/// What the consent page shows about a pending authorization.
#[derive(Serialize)]
pub(super) struct AuthorizationTransactionView {
    /// Client's registered display name.
    client_name: String,
    /// Requested scopes.
    scopes: Vec<DescribedScope>,
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
    /// A `request_uri` continues a pushed request instead.
    pub(super) async fn authorize(
        State(app): State<Self>,
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
            return app.claim_pushed(&headers, client_id, request_uri).await;
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
        let (opaque, request) = q.validate(&app, &client, false).map_err(back)?;
        let session = Session::optional(&app.database, &headers).await?;
        let requires_login = session.as_ref().is_none_or(|session| {
            !Self::session_satisfies(
                session,
                request.force_login,
                request.max_age,
                request.hinted_user_id,
                request.target_acr,
                None,
            )
        });
        if request.prompt_none && requires_login {
            return Err(back(OAuthCode::LoginRequired.reject(SILENT_LOGIN_REQUIRED)));
        }
        app.database
            .oidc()
            .insert_authorization_request(&request)
            .await?;
        let transaction = opaque.encoded();
        if requires_login {
            return Ok(app.continuation_page(
                routes::page::LOGIN,
                &transaction,
                request.target_acr,
            ));
        }
        app.continue_authorization(&headers, transaction).await
    }

    /// Stores a request pushed by an authenticated client (RFC 9126 §2), validated
    /// as at the authorization endpoint, and returns the `request_uri` the browser
    /// brings there. Every error is JSON: nothing goes through the browser.
    pub(super) async fn push_authorization(
        State(app): State<Self>,
        headers: HeaderMap,
        form: Result<Form<AuthorizationParameters>, FormRejection>,
    ) -> Result<(StatusCode, Json<PushedAuthorization>), OAuthError> {
        let Form(q) = form.map_err(|error| {
            OAuthCode::InvalidRequest.reject_with(
                format!("pushed authorization request is malformed: {error}"),
                error,
            )
        })?;
        let client = app
            .authenticate_client(&headers, q.client_id.as_deref())
            .await?;
        if q.request_uri.is_some() {
            return Err(OAuthCode::InvalidRequest.reject("request_uri cannot be pushed"));
        }
        q.redirect_uri(&client)?;
        let (opaque, request) = q.validate(&app, &client, true)?;
        app.database
            .oidc()
            .insert_authorization_request(&request)
            .await?;
        Ok((
            StatusCode::CREATED,
            Json(PushedAuthorization {
                request_uri: format!("{REQUEST_URI_PREFIX}{}", opaque.encoded()),
                expires_in: PUSHED_REQUEST_SECONDS,
            }),
        ))
    }

    /// Continues a pushed request from its `request_uri` (RFC 9126 §4). Only
    /// `client_id` can claim it, and only once; the request's other parameters are
    /// ignored, so none can override a pushed one. From then on, the browser carries
    /// a fresh transaction, as for a request it sent itself.
    async fn claim_pushed(
        &self,
        headers: &HeaderMap,
        client_id: &str,
        request_uri: &str,
    ) -> Result<Redirect, OAuthError> {
        let unknown = || OAuthCode::InvalidRequestUri.reject(UNKNOWN_REQUEST_URI);
        // RFC 9126 §5: a pushed `request_uri` works whatever
        // `request_uri_parameter_supported` says, so the parameter is supported and
        // a client-hosted one is invalid rather than `request_uri_not_supported`.
        let token = request_uri
            .strip_prefix(REQUEST_URI_PREFIX)
            .ok_or_else(|| {
                OAuthCode::InvalidRequestUri
                    .reject("request_uri must come from the pushed authorization endpoint")
            })?;
        let pushed =
            OpaqueToken::parse(TokenPrefix::AuthorizationRequest, token).map_err(|error| {
                OAuthCode::InvalidRequestUri.reject_with(UNKNOWN_REQUEST_URI, error)
            })?;
        let opaque = pushed.renewed()?;
        self.database
            .oidc()
            .claim_pushed_authorization_request(
                pushed.id,
                self.token_digest(&pushed)?.as_bytes(),
                client_id,
                self.token_digest(&opaque)?.as_bytes(),
                Utc::now() + Duration::minutes(AUTHORIZATION_REQUEST_MINUTES),
            )
            .await?
            .ok_or_else(unknown)?;
        self.continue_authorization(headers, opaque.encoded()).await
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
        app.continue_authorization(&headers, q.transaction).await
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
            scopes: request.scopes.into_iter().map(Into::into).collect(),
            audience: request.audience,
        }))
    }

    /// Records the consent page's decision and returns the client redirect as JSON.
    pub(super) async fn authorization_decision(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        form: Result<Form<AuthorizationDecision>, FormRejection>,
    ) -> Result<Json<Value>, OAuthError> {
        app.require_same_origin(&headers)?;
        let Form(input) = form.map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with(format!("consent decision is malformed: {error}"), error)
        })?;
        let redirect = app.decide(&headers, input, Some(context)).await?;
        Ok(Json(json!({"redirect_url":redirect.as_str()})))
    }

    /// Consumes the pending authorization and returns the client redirect: an error
    /// for a denial, or a new authorization code under the user's grant to the
    /// client, which an approval creates or extends. Explicit decisions come from the
    /// consent page, whose request is `consent`, and record consent; implicit ones
    /// must already be allowed.
    async fn decide(
        &self,
        headers: &HeaderMap,
        input: AuthorizationDecision,
        consent: Option<RequestContext>,
    ) -> Result<Url, OAuthError> {
        let session = Session::required(&self.database, headers).await?;
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
                // Lock the account before writing the grant: the grant row's foreign key
                // would otherwise take a key-share lock that deadlocks with a concurrent
                // login, and grant writes serialize on it.
                transaction
                    .users()
                    .find_active_by_id_for_update(session.user_id)
                    .await?
                    .ok_or_else(|| OAuthCode::InvalidToken.reject("this account is disabled"))?;
                // Checked under the lock, so a revocation committed since the browser
                // was sent on cannot be granted again without consent.
                if consent.is_none()
                    && !Self::can_authorize(&mut transaction.oidc(), &request, session.user_id)
                        .await?
                {
                    return Err(OAuthCode::InvalidRequest
                        .reject("this authorization needs the user's consent"));
                }
                let approval = if consent.is_some() {
                    Approval::Consented
                } else {
                    Approval::Implicit
                };
                let grant_generation = transaction
                    .oidc()
                    .grant(
                        session.user_id,
                        &request.client_id,
                        &request.audience,
                        &request.scopes,
                        approval,
                    )
                    .await?;
                if let Some(context) = consent {
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
                        authentication: SessionAuthentication::from(&session),
                        grant_generation,
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
            request.target_acr,
            Some(request.started_at),
        ) {
            Ok(())
        } else {
            Err(OAuthCode::InvalidToken.reject(
                "this sign-in does not meet the authorization's requirements; sign in again",
            ))
        }
    }

    /// Whether a session meets an authorization's sign-in requirements: the hinted
    /// account, a fresh authentication for `prompt=login` or `max_age=0`, and the
    /// target `acr` and a positive `max_age` as a [`StepUpRequirement`], the rule
    /// resources and auth's own settings apply. Ages count from the session's
    /// `auth_time`, and only authenticating after the request started (`started_at`:
    /// when stored, or claimed if pushed) counts as fresh. A negative `max_age` is
    /// never met.
    fn session_satisfies(
        session: &StoredSession,
        force_login: bool,
        max_age: Option<i64>,
        hinted_user_id: Option<UserId>,
        target_acr: Option<Acr>,
        started_at: Option<DateTime<Utc>>,
    ) -> bool {
        let authentication = SessionAuthentication::from(session);
        let fresh = started_at.is_some_and(|started_at| authentication.auth_time >= started_at);
        let (force_login, max_age) = match max_age {
            // Requests reject negative ages, so one stored anyway is never met.
            Some(age) if age < 0 => return false,
            // `max_age=0` asks for a sign-in after the request, as `prompt=login` does.
            Some(0) => (true, None),
            // An age past `u32` excludes no sign-in.
            age => (
                force_login,
                age.map(|age| u32::try_from(age).unwrap_or(u32::MAX)),
            ),
        };
        let requirement = StepUpRequirement {
            acr: target_acr,
            max_age,
        };
        (fresh || !force_login)
            && requirement
                .check(
                    Some(&authentication.acr),
                    Some(authentication.auth_time),
                    Utc::now(),
                )
                .is_ok()
            && hinted_user_id.is_none_or(|subject| subject == session.user_id)
    }

    /// Redirects to an auth frontend page, passing the pending authorization along.
    /// A target `acr` is named too, so the login page offers only methods reaching it.
    fn continuation_page(
        &self,
        page: &str,
        transaction: &str,
        target_acr: Option<Acr>,
    ) -> Redirect {
        let target = target_acr
            .map(|acr| format!("&acr={acr}"))
            .unwrap_or_default();
        Redirect::to(&format!(
            "{}{page}?transaction={transaction}{target}",
            self.issuer
        ))
    }

    /// Sends the browser on from a stored authorization: to login if the session falls
    /// short, straight to the client if consent is already given, otherwise to consent.
    /// `prompt=none` returns an error to the client instead of showing a page.
    async fn continue_authorization(
        &self,
        headers: &HeaderMap,
        transaction: String,
    ) -> Result<Redirect, OAuthError> {
        let request = self.find_authorization_request(&transaction).await?;
        let silent = request.prompt_none;
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
            return Ok(self.continuation_page(
                routes::page::LOGIN,
                &transaction,
                request.target_acr,
            ));
        };
        if Self::can_authorize(&mut self.database.oidc(), &request, session.user_id).await? {
            let input = AuthorizationDecision {
                transaction,
                decision: ConsentDecision::Approve,
            };
            let redirect = self.decide(headers, input, None).await?;
            return Ok(Redirect::to(redirect.as_str()));
        }
        if silent {
            return Err(back(
                OAuthCode::ConsentRequired,
                "prompt=none was requested, but the user must consent first",
            ));
        }
        Ok(self.continuation_page(routes::page::CONSENT, &transaction, None))
    }

    /// Whether `user`'s authorization may skip the consent page: the client is trusted
    /// or the user already consented, and the request did not ask for `prompt=consent`.
    async fn can_authorize(
        oidc: &mut OidcRepository<'_>,
        request: &StoredAuthorizationRequest,
        user: UserId,
    ) -> Result<bool, OAuthError> {
        if request.force_consent {
            return Ok(false);
        }
        let client = oidc
            .find_client(request.client_id.as_str())
            .await?
            .ok_or_else(|| {
                OAuthCode::InvalidRequest.reject("the client is no longer registered")
            })?;
        Ok(client.trusted
            || oidc
                .consented(user, &request.client_id, &request.audience, &request.scopes)
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
    //! Prompt, `max_age` and consent decision parsing.
    use super::*;
    use piquel_common::{AuthenticationMethod, SessionId};
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
    /// `max_age` holds up to its boundary at authorize too. `0` needs a sign-in after
    /// the request, a negative age is never met, and one past `u32` limits nothing.
    #[test]
    fn max_age_bounds_the_session_authentication() {
        let now = Utc::now();
        let session = StoredSession {
            id: SessionId::new(),
            user_id: UserId::new(),
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: now - Duration::days(1),
            expires_at: now + Duration::days(1),
            last_seen_at: now,
            revoked_at: None,
            passkey_confirmed_at: Some(now - Duration::seconds(300)),
        };
        let satisfies = |max_age, started_at| {
            OidcApplication::session_satisfies(
                &session,
                false,
                Some(max_age),
                None,
                None,
                started_at,
            )
        };
        assert!(satisfies(310, None));
        assert!(!satisfies(290, None));
        assert!(satisfies(i64::MAX, None));
        assert!(!satisfies(-1, None));
        assert!(!satisfies(0, None));
        assert!(!satisfies(0, Some(now - Duration::seconds(200))));
        assert!(satisfies(0, Some(now - Duration::seconds(400))));
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
