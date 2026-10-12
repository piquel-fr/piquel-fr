//! Browser-bound social authentication. Email suggests linking; it never authorizes it.

use crate::{
    email::normalize,
    security::{self, ApiError, BrowserCookie, BrowserSecret},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use piquel_auth_protocol::{AuthenticationMethod, SessionId, TokenId, UserId};
use piquel_configuration::{SecretBytes, SecretReference};
use piquel_repository::{
    AppendAuditEvent, Database, DatabaseTransaction, InsertExternalIdentity,
    InsertFederationTransaction, PendingFederation,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc, time::Duration as StdDuration};
use thiserror::Error;
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
    GitHub,
    Google,
}
impl Provider {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "github" => Ok(Self::GitHub),
            "google" => Ok(Self::Google),
            _ => Err(ApiError::bad_request(
                "This sign-in provider is not supported.",
            )),
        }
    }
    const fn name(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Google => "google",
        }
    }
    const fn issuer(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com",
            Self::Google => "https://accounts.google.com",
        }
    }
    const fn authorization_endpoint(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com/login/oauth/authorize",
            Self::Google => "https://accounts.google.com/o/oauth2/v2/auth",
        }
    }
}

/// OAuth application credentials; each provider may be omitted independently.
#[derive(Clone, Debug)]
pub struct ProviderConfiguration {
    /// Client identifier assigned by GitHub or Google.
    pub client_id: String,
    /// Secret reference resolved and validated during startup.
    pub client_secret: SecretReference,
}

struct ResolvedProvider {
    client_id: String,
    client_secret: SecretBytes,
}
impl ProviderConfiguration {
    fn resolve(
        self,
        provider: &'static str,
    ) -> Result<ResolvedProvider, FederationConfigurationError> {
        let secret = self.client_secret.resolve().map_err(|source| {
            FederationConfigurationError::Secret {
                provider,
                source: source.into(),
            }
        })?;
        std::str::from_utf8(secret.expose_secret()).map_err(|source| {
            FederationConfigurationError::Secret {
                provider,
                source: source.into(),
            }
        })?;
        Ok(ResolvedProvider {
            client_id: self.client_id,
            client_secret: secret,
        })
    }
}

#[derive(Clone)]
struct Endpoints {
    github_token: String,
    github_user: String,
    github_emails: String,
    google_token: String,
    google_keys: String,
}
impl Default for Endpoints {
    fn default() -> Self {
        Self {
            github_token: "https://github.com/login/oauth/access_token".into(),
            github_user: "https://api.github.com/user".into(),
            github_emails: "https://api.github.com/user/emails?per_page=100".into(),
            google_token: "https://oauth2.googleapis.com/token".into(),
            google_keys: "https://www.googleapis.com/oauth2/v3/certs".into(),
        }
    }
}

/// Social login and explicit linking, backed exclusively by `PostgreSQL`.
#[derive(Clone)]
pub struct FederationApplication {
    database: Database,
    base_url: Url,
    providers: Arc<HashMap<&'static str, ResolvedProvider>>,
    client: reqwest::Client,
    endpoints: Endpoints,
    settings_url: Option<Url>,
}
impl FederationApplication {
    /// Build independently optional providers with bounded, non-redirecting HTTP.
    ///
    /// # Errors
    /// Rejects invalid origins, client identifiers, secrets, or HTTP client configuration.
    pub fn new(
        database: Database,
        base_url: &Url,
        github: Option<ProviderConfiguration>,
        google: Option<ProviderConfiguration>,
    ) -> Result<Self, FederationConfigurationError> {
        if !Self::secure_or_loopback(base_url)
            || base_url.host_str().is_none()
            || base_url.path() != "/"
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
        {
            return Err(FederationConfigurationError::Invalid);
        }
        let providers: HashMap<_, _> = [("github", github), ("google", google)]
            .into_iter()
            .filter_map(|(name, config)| config.map(|config| (name, config)))
            .collect();
        if providers
            .values()
            .any(|config| config.client_id.is_empty() || config.client_id.len() > 512)
        {
            return Err(FederationConfigurationError::Invalid);
        }
        let providers = providers
            .into_iter()
            .map(|(name, config)| config.resolve(name).map(|config| (name, config)))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            database,
            base_url: base_url.clone(),
            providers: Arc::new(providers),
            endpoints: Endpoints::default(),
            settings_url: None,
            client: reqwest::Client::builder()
                .timeout(StdDuration::from_secs(8))
                .connect_timeout(StdDuration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("piquel-auth")
                .build()
                .map_err(FederationConfigurationError::Http)?,
        })
    }
    fn secure_or_loopback(url: &Url) -> bool {
        url.scheme() == "https"
            || (url.scheme() == "http" && piquel_configuration::PublicUrl::has_loopback_host(url))
    }
    /// Allow only the configured settings page as an external continuation.
    ///
    /// # Errors
    /// Rejects insecure non-loopback URLs, user information, and fragments.
    pub fn with_settings_url(
        mut self,
        settings_url: &Url,
    ) -> Result<Self, FederationConfigurationError> {
        if !Self::secure_or_loopback(settings_url)
            || settings_url.host_str().is_none()
            || !settings_url.username().is_empty()
            || settings_url.password().is_some()
            || settings_url.fragment().is_some()
        {
            return Err(FederationConfigurationError::Invalid);
        }
        self.settings_url = Some(settings_url.clone());
        Ok(self)
    }
    fn return_to(&self, value: Option<&str>) -> Result<String, ApiError> {
        if let Some(value) = value
            && self
                .settings_url
                .as_ref()
                .is_some_and(|url| url.as_str() == value)
        {
            return Ok(value.into());
        }
        validate_return_to(value)
    }
    fn failed_callback(&self, error: &str, return_to: &str) -> Result<Response, ApiError> {
        let mut destination = self.base_url.join("login").map_err(ApiError::internal)?;
        destination
            .query_pairs_mut()
            .append_pair("error", error)
            .append_pair("return_to", return_to);
        let mut response = Redirect::to(destination.as_str()).into_response();
        FederationFlow::append(&mut response, &BrowserCookie::Federation.clear())?;
        Ok(response)
    }
    fn callback_url(&self, provider: Provider) -> String {
        format!("{}login/{}/callback", self.base_url, provider.name())
    }
}
/// A configured callback origin or provider is invalid.
#[derive(Debug, Error)]
pub enum FederationConfigurationError {
    /// Invalid callback origin or provider identifier.
    #[error("invalid federation configuration")]
    Invalid,
    /// An enabled provider has an unreadable or invalid UTF-8 secret.
    #[error("invalid {provider} client secret")]
    Secret {
        /// Provider whose credentials could not be loaded.
        provider: &'static str,
        /// Underlying reference or encoding failure, without secret contents.
        #[source]
        source: anyhow::Error,
    },
    /// Failed to initialize the provider HTTP client.
    #[error("could not initialize federation HTTP client")]
    Http(#[source] reqwest::Error),
}

pub(super) fn routes(app: FederationApplication) -> Router {
    Router::new()
        .route("/login/providers", get(providers))
        .route("/login/{provider}/start", post(start))
        .route("/login/{provider}/callback", get(callback))
        .route("/login/social/pending", get(pending_view))
        .route("/login/social/link", post(confirm_link))
        .route("/login/social/cancel", post(cancel))
        .route("/account/social-identities", get(list_identities))
        .route("/account/social-identities/{provider}", delete(unlink))
        .with_state(app)
}
async fn providers(State(app): State<FederationApplication>) -> Json<Vec<&'static str>> {
    Json(
        ["github", "google"]
            .into_iter()
            .filter(|name| app.providers.contains_key(name))
            .collect(),
    )
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StartMode {
    #[default]
    Login,
    Link,
}
#[derive(Default, Deserialize)]
struct StartInput {
    return_to: Option<String>,
    #[serde(default)]
    mode: StartMode,
}
async fn start(
    State(app): State<FederationApplication>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Json(input): Json<StartInput>,
) -> Result<Response, ApiError> {
    let provider = Provider::parse(&provider)?;
    let config = app
        .providers
        .get(provider.name())
        .ok_or_else(|| ApiError::bad_request("This sign-in provider is not configured."))?;
    let session = match input.mode {
        StartMode::Login => None,
        StartMode::Link => Some(security::management(&app.database, &headers).await?),
    };
    let state = BrowserSecret::new();
    let nonce = BrowserSecret::new().encoded();
    let verifier = BrowserSecret::new().encoded();
    let browser = BrowserSecret::new();
    let return_to = app.return_to(input.return_to.as_deref())?;
    app.database
        .federation()
        .insert_transaction(&InsertFederationTransaction {
            id: TokenId::new(),
            provider: provider.name().into(),
            state_digest: state.digest(),
            browser_digest: browser.digest(),
            nonce: nonce.clone(),
            pkce_verifier: verifier.clone(),
            return_to,
            link_user_id: session.as_ref().map(|s| s.user_id),
            link_session_id: session.as_ref().map(|s| s.id),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await?;
    let mut url = Url::parse(provider.authorization_endpoint()).map_err(ApiError::internal)?;
    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &app.callback_url(provider))
        .append_pair("response_type", "code")
        .append_pair(
            "scope",
            match provider {
                Provider::GitHub => "read:user user:email",
                Provider::Google => "openid email profile",
            },
        )
        .append_pair("state", &state.encoded())
        .append_pair(
            "code_challenge",
            &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        )
        .append_pair("code_challenge_method", "S256");
    if provider == Provider::Google {
        url.query_pairs_mut()
            .append_pair("nonce", &nonce)
            .append_pair("prompt", "select_account");
    }
    let mut response = Json(serde_json::json!({"redirect_url":url.as_str()})).into_response();
    FederationFlow::append(&mut response, &BrowserCookie::Federation.set(&browser))?;
    Ok(response)
}
#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}
async fn callback(
    State(app): State<FederationApplication>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let provider = Provider::parse(&provider)?;
    let browser = BrowserCookie::Federation
        .read(&headers)
        .ok_or_else(ApiError::unauthorized)?;
    let state = query
        .state
        .as_deref()
        .and_then(BrowserSecret::parse)
        .ok_or_else(|| {
            ApiError::bad_request(
                "This sign-in attempt is invalid or has expired. Please start again.",
            )
        })?;
    // Consume state even on provider cancellation; it cannot be replayed later.
    let flow = app
        .database
        .federation()
        .consume_transaction(provider.name(), &state.digest(), &browser.digest())
        .await?;
    if query.error.is_some() {
        return app.failed_callback("social_cancelled", &flow.return_to);
    }
    let Some(code) = query
        .code
        .filter(|code| !code.is_empty() && code.len() <= 2048)
    else {
        return app.failed_callback("social_failed", &flow.return_to);
    };
    let identity = match app
        .exchange(provider, &code, &flow.pkce_verifier, &flow.nonce)
        .await
    {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(
                ?error,
                provider = provider.name(),
                "provider sign-in failed"
            );
            return app.failed_callback("social_failed", &flow.return_to);
        }
    };
    if let Some(user_id) = flow.link_user_id {
        let session = security::session(&app.database, &headers).await?;
        if session.user_id != user_id || Some(session.id) != flow.link_session_id {
            return Err(ApiError::forbidden(
                "Your session changed. Please start linking this provider again.",
            ));
        }
        if let Some(existing) = app
            .database
            .federation()
            .find_active(provider.issuer(), &identity.subject)
            .await?
            && existing.user_id != user_id
        {
            return Err(ApiError::forbidden(
                "This provider account is already linked to another Piquel account.",
            ));
        }
        return app
            .pending_response(
                provider,
                identity,
                flow.return_to,
                Some(user_id),
                flow.link_session_id,
            )
            .await;
    }
    app.finish_login(provider, identity, flow.return_to).await
}
impl FederationApplication {
    /// Complete an existing subject's login, or retain evidence for explicit onboarding/linking.
    async fn finish_login(
        &self,
        provider: Provider,
        identity: VerifiedIdentity,
        return_to: String,
    ) -> Result<Response, ApiError> {
        let mut tx = self.database.begin().await?;
        if let Some(existing) = tx
            .federation()
            .find_active(provider.issuer(), &identity.subject)
            .await?
        {
            tx.users()
                .find_active_by_id_for_update(existing.user_id)
                .await?
                .ok_or_else(ApiError::unauthorized)?;
            // Recheck the subject after locking the account: unlink takes the same lock.
            let current = tx
                .federation()
                .find_active(provider.issuer(), &identity.subject)
                .await?
                .ok_or_else(ApiError::unauthorized)?;
            if current.id != existing.id
                || tx
                    .passkeys()
                    .list_active(existing.user_id)
                    .await?
                    .is_empty()
            {
                return Err(ApiError::unauthorized());
            }
            let cookie = security::create_session(
                &mut tx,
                existing.user_id,
                AuthenticationMethod::Federation,
            )
            .await?;
            tx.federation().record_login(existing.id).await?;
            FederationFlow::audit(
                &mut tx,
                existing.user_id,
                "federation.login",
                provider.name(),
            )
            .await?;
            tx.commit().await?;
            let mut response = Redirect::to(&return_to).into_response();
            FederationFlow::append(&mut response, &cookie)?;
            FederationFlow::append(&mut response, &BrowserCookie::Federation.clear())?;
            return Ok(response);
        }
        let owner = match &identity.email {
            Some(email) => tx
                .emails()
                .find_active_verified(email)
                .await?
                .map(|email| email.user_id),
            None => None,
        };
        tx.rollback().await?;
        self.pending_response(provider, identity, return_to, owner, None)
            .await
    }
    async fn pending_response(
        &self,
        provider: Provider,
        identity: VerifiedIdentity,
        return_to: String,
        link_user_id: Option<UserId>,
        link_session_id: Option<SessionId>,
    ) -> Result<Response, ApiError> {
        let browser = BrowserSecret::new();
        self.database
            .federation()
            .insert_pending(&PendingFederation {
                id: TokenId::new(),
                browser_digest: browser.digest(),
                provider: provider.name().into(),
                issuer: provider.issuer().into(),
                subject: identity.subject,
                email: identity.email,
                display_name: identity.display_name,
                return_to,
                link_user_id,
                link_session_id,
                expires_at: Utc::now() + Duration::minutes(10),
            })
            .await?;
        let mut response = Redirect::to(if link_user_id.is_some() {
            "/login?social=link"
        } else {
            "/login?social=signup"
        })
        .into_response();
        FederationFlow::append(
            &mut response,
            &BrowserCookie::FederationPending.set(&browser),
        )?;
        FederationFlow::append(&mut response, &BrowserCookie::Federation.clear())?;
        Ok(response)
    }
}
fn validate_return_to(value: Option<&str>) -> Result<String, ApiError> {
    let value = value.unwrap_or("/");
    let base = Url::parse("https://auth.piquel.fr/").map_err(ApiError::internal)?;
    let joined = base
        .join(value)
        .map_err(|_| ApiError::bad_request("This return address is not allowed."))?;
    if value.len() > 2048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || joined.origin() != base.origin()
        || joined.fragment().is_some()
    {
        return Err(ApiError::bad_request("This return address is not allowed."));
    }
    Ok(value.into())
}

pub(crate) async fn pending_signup(
    database: &Database,
    headers: &HeaderMap,
) -> Result<Option<PendingFederation>, ApiError> {
    let Some(browser) = BrowserCookie::FederationPending.read(headers) else {
        return Ok(None);
    };
    let pending = database
        .federation()
        .pending(&browser.digest())
        .await?
        .ok_or_else(|| ApiError::bad_request("This signup has expired. Please start again."))?;
    if pending.link_user_id.is_some() {
        return Err(ApiError::forbidden(
            "Use a passkey for your existing account to link this provider.",
        ));
    }
    Ok(Some(pending))
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
trait PendingIdentity {
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
async fn pending_view(
    State(app): State<FederationApplication>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
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
    Ok(Json(
        serde_json::json!({"kind":if pending.link_user_id.is_some(){"link"}else{"signup"},"provider":pending.provider,"email":pending.email,"display_name":pending.display_name,"return_to":pending.return_to}),
    ))
}
async fn confirm_link(
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
async fn cancel(
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
struct SocialIdentityView {
    provider: String,
    linked_email: Option<String>,
}
async fn list_identities(
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
async fn unlink(
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

struct VerifiedIdentity {
    subject: String,
    email: Option<String>,
    display_name: String,
}
impl FederationApplication {
    async fn exchange(
        &self,
        provider: Provider,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ApiError> {
        let config = self
            .providers
            .get(provider.name())
            .ok_or_else(|| ApiError::bad_request("This sign-in provider is not configured."))?;
        let secret = std::str::from_utf8(config.client_secret.expose_secret())
            .map_err(ApiError::internal)?;
        let callback = self.callback_url(provider);
        let endpoint = match provider {
            Provider::GitHub => &self.endpoints.github_token,
            Provider::Google => &self.endpoints.google_token,
        };
        let response = self
            .client
            .post(endpoint)
            .header(header::ACCEPT, "application/json")
            .form(&[
                ("client_id", config.client_id.as_str()),
                ("client_secret", secret),
                ("code", code),
                ("redirect_uri", &callback),
                ("code_verifier", verifier),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(ApiError::internal)?;
        let identity = match provider {
            Provider::GitHub => self.github_identity(response).await?,
            Provider::Google => {
                self.google_identity(response, &config.client_id, nonce)
                    .await?
            }
        };
        if identity.subject.is_empty() || identity.subject.len() > 255 {
            return Err(ApiError::bad_request(
                "The provider returned an invalid account identifier.",
            ));
        }
        Ok(identity)
    }
    async fn github_identity(
        &self,
        response: reqwest::Response,
    ) -> Result<VerifiedIdentity, ApiError> {
        let token: GithubToken = Self::json(response).await?;
        if token.access_token.is_empty() || token.access_token.len() > 8192 {
            return Err(ApiError::bad_request(
                "The provider sign-in could not be verified. Please try again.",
            ));
        }
        let user: GithubUser = Self::json(
            self.client
                .get(&self.endpoints.github_user)
                .bearer_auth(&token.access_token)
                .send()
                .await
                .map_err(ApiError::internal)?,
        )
        .await?;
        let response = self
            .client
            .get(&self.endpoints.github_emails)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(ApiError::internal)?;
        let emails: Vec<GithubEmail> = if response.status() == StatusCode::FORBIDDEN {
            Vec::new()
        } else {
            Self::json(response).await?
        };
        let email = emails
            .iter()
            .find(|email| email.verified && email.primary)
            .and_then(|email| normalize(&email.email).ok())
            .map(|email| email.as_str().to_owned());
        if user.id == 0 {
            return Err(ApiError::bad_request(
                "The provider returned an invalid account identifier.",
            ));
        }
        Ok(VerifiedIdentity {
            subject: user.id.to_string(),
            email,
            display_name: user
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(user.login)
                .chars()
                .take(80)
                .collect(),
        })
    }
    async fn google_identity(
        &self,
        response: reqwest::Response,
        client_id: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ApiError> {
        let token: GoogleToken = Self::json(response).await?;
        if token.id_token.len() > 8192 {
            return Err(ApiError::bad_request(
                "The provider sign-in could not be verified. Please try again.",
            ));
        }
        let header = decode_header(&token.id_token).map_err(|_| {
            ApiError::bad_request("The provider sign-in could not be verified. Please try again.")
        })?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::bad_request(
                "The provider sign-in could not be verified. Please try again.",
            ));
        }
        let kid = header.kid.ok_or_else(|| {
            ApiError::bad_request("The provider sign-in could not be verified. Please try again.")
        })?;
        let jwks: GoogleJwks = Self::json(
            self.client
                .get(&self.endpoints.google_keys)
                .send()
                .await
                .map_err(ApiError::internal)?,
        )
        .await?;
        let jwk = jwks
            .keys
            .into_iter()
            .find(|key| {
                key.kid == kid
                    && key.kty == "RSA"
                    && key.alg.as_deref().is_none_or(|alg| alg == "RS256")
                    && key.key_use.as_deref().is_none_or(|usage| usage == "sig")
            })
            .ok_or_else(|| {
                ApiError::bad_request(
                    "The provider sign-in could not be verified. Please try again.",
                )
            })?;
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|_| {
            ApiError::bad_request("The provider sign-in could not be verified. Please try again.")
        })?;
        let claims = Self::verify_google_token(&token.id_token, &key, client_id, nonce)?;
        let email = claims
            .email
            .filter(|_| claims.email_verified)
            .and_then(|email| normalize(&email).ok())
            .map(|email| email.as_str().to_owned());
        Ok(VerifiedIdentity {
            subject: claims.sub,
            email,
            display_name: claims
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| "Google user".into())
                .chars()
                .take(80)
                .collect(),
        })
    }
    fn verify_google_token(
        token: &str,
        key: &DecodingKey,
        client_id: &str,
        nonce: &str,
    ) -> Result<GoogleClaims, ApiError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        validation.set_audience(&[client_id]);
        validation.set_issuer(&[Provider::Google.issuer(), "accounts.google.com"]);
        validation.leeway = 30;
        let claims = decode::<GoogleClaims>(token, key, &validation)
            .map_err(|_| {
                ApiError::bad_request(
                    "The provider sign-in could not be verified. Please try again.",
                )
            })?
            .claims;
        if !matches!(
            claims.iss.as_str(),
            "https://accounts.google.com" | "accounts.google.com"
        ) || !claims.aud.only_contains(client_id)
            || claims.nonce != nonce
            || claims.sub.is_empty()
            || claims.exp <= Utc::now().timestamp()
            || claims.iat > Utc::now().timestamp() + 30
            || claims.azp.as_deref().is_some_and(|azp| azp != client_id)
        {
            return Err(ApiError::bad_request(
                "The provider sign-in could not be verified. Please try again.",
            ));
        }
        Ok(claims)
    }
    /// Bound even chunked provider responses before parsing them.
    async fn json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, ApiError> {
        let mut response = response.error_for_status().map_err(ApiError::internal)?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(ApiError::internal)? {
            if body.len() + chunk.len() > 65536 {
                return Err(ApiError::bad_request(
                    "The provider returned an unexpected response. Please try again.",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| {
            ApiError::bad_request("The provider returned an unexpected response. Please try again.")
        })
    }
}
#[derive(Deserialize)]
struct GithubToken {
    access_token: String,
}
#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    name: Option<String>,
    login: String,
}
#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    verified: bool,
    primary: bool,
}
#[derive(Deserialize)]
struct GoogleToken {
    id_token: String,
}
#[derive(Clone, Deserialize)]
struct GoogleClaims {
    iss: String,
    aud: GoogleAudience,
    sub: String,
    exp: i64,
    iat: i64,
    nonce: String,
    azp: Option<String>,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    name: Option<String>,
}
#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum GoogleAudience {
    Single(String),
    Multiple(Vec<String>),
}
impl GoogleAudience {
    fn only_contains(&self, client_id: &str) -> bool {
        match self {
            Self::Single(value) => value == client_id,
            Self::Multiple(values) => {
                !values.is_empty() && values.iter().all(|value| value == client_id)
            }
        }
    }
}
#[derive(Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}
#[derive(Deserialize)]
struct GoogleJwk {
    kid: String,
    kty: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: String,
    e: String,
}

struct FederationFlow;
impl FederationFlow {
    fn append(response: &mut Response, cookie: &str) -> Result<(), ApiError> {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(cookie).map_err(ApiError::internal)?,
        );
        Ok(())
    }
    async fn audit(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        action: &str,
        provider: &str,
    ) -> Result<(), ApiError> {
        tx.audit_events()
            .append(&AppendAuditEvent {
                id: TokenId::new(),
                user_id: Some(user_id),
                action: action.into(),
                outcome: "success".into(),
                request_metadata: serde_json::json!({"provider":provider}),
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "federation_tests.rs"]
mod tests;
