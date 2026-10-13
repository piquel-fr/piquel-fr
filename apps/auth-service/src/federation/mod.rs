//! Browser-bound social authentication. Email suggests linking; it never authorizes it.

use crate::config::{FederationConfig, ProviderConfig};
use crate::routes;
use crate::security::{self, ApiError, BrowserCookie, OptionalSession, SessionError};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use chrono::{Duration, Utc};
use piquel_auth_protocol::{
    AuthenticationMethod, Provider, SessionId, TokenId, UserId,
    oauth::{CodeChallengeMethod, ResponseType},
};
use piquel_common::{ConfigurationError, ErrorChain, Origin, SecretBytes};
use piquel_crypto::Pkce;
use piquel_crypto::Secret;
use piquel_repository::{
    AuditAction, Database, InsertFederationTransaction, PendingFederation, StoredSession,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc, time::Duration as StdDuration};
use url::Url;

/// Domain failures and their browser response mapping.
mod error;
/// Pending evidence, signup attachment, linking and unlinking.
mod identities;
pub use error::FederationConfigError;
use error::{FederationError, InvalidReturnTo};
/// Provider protocol facts and verified identity exchange.
mod providers;
use providers::{ProviderEndpoints, VerifiedIdentity};

/// Lifetime of a started flow and of pending provider evidence.
const FLOW_LIFETIME: Duration = Duration::minutes(10);
/// Maximum length of a provider authorization code.
const MAX_CODE_BYTES: usize = 2048;
/// Maximum length of a `return_to` address.
const MAX_RETURN_TO_BYTES: usize = 2048;
/// Maximum duration of a provider HTTP request.
const HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(8);
/// Maximum duration of a provider connection attempt.
const HTTP_CONNECT_TIMEOUT: StdDuration = StdDuration::from_secs(3);
/// Identifies this service to provider APIs.
const HTTP_USER_AGENT: &str = "piquel-auth";
/// Where the browser goes after sign-in when no `return_to` is given.
const DEFAULT_RETURN_TO: &str = "/";

piquel_common::str_enum! {
    /// Failed-callback reasons, sent to the login page as its `error` query parameter.
    enum CallbackError {
        /// The provider declined or cancelled authorization.
        Cancelled = "social_cancelled",
        /// The returned authorization could not be verified.
        Failed = "social_failed",
    }
}
piquel_common::str_enum! {
    /// What the login page asks of a browser holding pending provider evidence,
    /// sent as its `social` query parameter.
    enum PendingDestination {
        /// A passkey must confirm the matching account.
        Link = "link",
        /// A first passkey must create the account.
        Signup = "signup",
    }
}

/// A validated `return_to`: the settings URL or a path on the auth origin.
struct ReturnTo(String);
impl ReturnTo {
    /// Accepts the exact settings URL, or a path that cannot leave the auth origin.
    fn parse(value: Option<&str>, settings_url: &Url) -> Result<Self, InvalidReturnTo> {
        let value = value.unwrap_or(DEFAULT_RETURN_TO);
        if value == settings_url.as_str() {
            return Ok(Self(value.into()));
        }
        // One leading `/` makes this a path on the current origin.
        if !value.starts_with('/') {
            return Err(InvalidReturnTo::External(settings_url.clone()));
        }
        if value.starts_with("//") {
            return Err(InvalidReturnTo::ProtocolRelative);
        }
        if value.contains('\\') {
            return Err(InvalidReturnTo::Backslash);
        }
        if value.contains('#') {
            return Err(InvalidReturnTo::Fragment);
        }
        if value.chars().any(char::is_control) {
            return Err(InvalidReturnTo::ControlCharacter);
        }
        if value.len() > MAX_RETURN_TO_BYTES {
            return Err(InvalidReturnTo::TooLong(value.len()));
        }
        Ok(Self(value.into()))
    }
}

/// Provider credentials with a resolved, redacted secret.
struct ResolvedProvider {
    /// Provider-assigned OAuth client identifier.
    client_id: String,
    /// Resolved client secret, validated as UTF-8 at startup.
    client_secret: SecretBytes,
}

impl ProviderConfig {
    /// Resolves secret text with the provider's explicit variable name in diagnostics.
    fn resolve(&self, provider: Provider) -> Result<ResolvedProvider, ConfigurationError> {
        let (_, variable) = Self::variables(provider);
        let secret = self.client_secret.resolve().map_err(|source| {
            variable.error("must resolve through env://NAME or file://PATH", source)
        })?;
        secret
            .utf8()
            .map_err(|source| variable.error("must contain UTF-8 text", source))?;
        Ok(ResolvedProvider {
            client_id: self.client_id.clone(),
            client_secret: secret,
        })
    }
}

/// Social login and explicit linking, backed exclusively by `PostgreSQL`.
#[derive(Clone)]
pub struct FederationApplication {
    /// Shared persistence boundary.
    database: Database,
    /// Validated callback origin.
    origin: Origin,
    /// Enabled providers keyed by the shared protocol vocabulary.
    providers: Arc<BTreeMap<Provider, ResolvedProvider>>,
    /// Bounded client that refuses provider redirects.
    client: reqwest::Client,
    /// Exhaustive provider facts; back-channel endpoints can be replaced by test fixtures.
    endpoints: BTreeMap<Provider, ProviderEndpoints>,
    /// Only allowed external continuation.
    settings_url: Url,
}

impl FederationApplication {
    /// Builds configured providers and a bounded HTTP client from validated settings.
    pub(crate) fn new(
        database: Database,
        config: &FederationConfig,
    ) -> Result<Self, FederationConfigError> {
        let providers = config
            .providers
            .iter()
            .map(|(&provider, config)| config.resolve(provider).map(|config| (provider, config)))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            database,
            origin: config.origin.clone(),
            providers: Arc::new(providers),
            endpoints: Provider::ALL
                .into_iter()
                .map(|provider| (provider, ProviderEndpoints::new(provider)))
                .collect(),
            settings_url: config.settings_url.as_url().clone(),
            client: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .connect_timeout(HTTP_CONNECT_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(HTTP_USER_AGENT)
                .build()
                .map_err(FederationConfigError::Http)?,
        })
    }

    /// Redirects a consumed callback to the login page with its stored continuation.
    fn failed_callback(
        &self,
        error: CallbackError,
        return_to: &str,
    ) -> Result<Response, FederationError> {
        let mut destination = self.origin.as_url().clone();
        destination.set_path(routes::page::LOGIN);
        destination
            .query_pairs_mut()
            .append_pair("error", error.as_str())
            .append_pair("return_to", return_to);
        let mut response = Redirect::to(destination.as_str()).into_response();
        BrowserCookie::Federation.clear_on(&mut response)?;
        Ok(response)
    }

    /// Computes the provider's callback from the configured auth origin.
    fn callback_url(&self, provider: Provider) -> String {
        self.origin
            .join(&routes::federation::CALLBACK.replace("{provider}", provider.as_str()))
    }

    /// Returns all social authentication and identity-management routes.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::federation::PROVIDERS, get(Self::providers))
            .route(routes::federation::START, post(Self::start))
            .route(routes::federation::CALLBACK, get(Self::callback))
            .route(routes::federation::PENDING, get(Self::pending_view))
            .route(routes::federation::LINK, post(Self::confirm_link))
            .route(routes::federation::CANCEL, post(Self::cancel))
            .route(routes::federation::IDENTITIES, get(Self::list_identities))
            .route(routes::federation::IDENTITY, delete(Self::unlink))
            .with_state(self)
    }

    /// Lists enabled providers in shared protocol vocabulary order.
    fn providers(State(app): State<Self>) -> std::future::Ready<Json<Vec<Provider>>> {
        std::future::ready(Json(
            Provider::ALL
                .into_iter()
                .filter(|provider| app.providers.contains_key(provider))
                .collect(),
        ))
    }

    /// Starts a browser-bound authorization request, optionally for explicit linking.
    async fn start(
        State(app): State<Self>,
        Path(provider): Path<String>,
        OptionalSession(session): OptionalSession,
        Json(input): Json<StartInput>,
    ) -> Result<Response, ApiError> {
        Ok(app
            .start_flow(
                provider
                    .parse()
                    .map_err(FederationError::UnsupportedProvider)?,
                input,
                session,
            )
            .await?)
    }

    /// Persists one-use state and constructs the provider's authorization redirect.
    async fn start_flow(
        &self,
        provider: Provider,
        input: StartInput,
        session: Option<StoredSession>,
    ) -> Result<Response, FederationError> {
        let config = self
            .providers
            .get(&provider)
            .ok_or(FederationError::ProviderNotConfigured)?;
        let endpoints = &self.endpoints[&provider];
        let session = match input.mode {
            StartMode::Login => None,
            StartMode::Link => Some(
                security::Session::authorize_management(
                    &self.database,
                    session.ok_or(SessionError::Missing)?,
                )
                .await?,
            ),
        };
        let state = Secret::generate()?;
        let nonce = Secret::generate()?.encoded();
        let verifier = Secret::generate()?.encoded();
        let browser = Secret::generate()?;
        let return_to = ReturnTo::parse(input.return_to.as_deref(), &self.settings_url)?;
        self.database
            .federation()
            .insert_transaction(&InsertFederationTransaction {
                id: TokenId::new(),
                provider,
                state_digest: state.digest().as_bytes().to_vec(),
                browser_digest: browser.digest().as_bytes().to_vec(),
                nonce: nonce.clone(),
                pkce_verifier: verifier.clone(),
                return_to: return_to.0,
                link_user_id: session.as_ref().map(|session| session.user_id),
                link_session_id: session.as_ref().map(|session| session.id),
                expires_at: Utc::now() + FLOW_LIFETIME,
            })
            .await?;
        let mut url = Url::parse(endpoints.authorization)?;
        url.query_pairs_mut()
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &self.callback_url(provider))
            .append_pair("response_type", ResponseType::Code.as_str())
            .append_pair("scope", &endpoints.scopes.join(" "))
            .append_pair("state", &state.encoded())
            .append_pair("code_challenge", &Pkce::challenge(&verifier)?)
            .append_pair("code_challenge_method", CodeChallengeMethod::S256.as_str());
        endpoints.identity.extend_authorization(&mut url, &nonce);
        let mut response = Json(StartResponse {
            redirect_url: url.as_str(),
        })
        .into_response();
        BrowserCookie::Federation.set_on(&mut response, &browser)?;
        Ok(response)
    }

    /// Converts provider callbacks into a verified login or pending identity.
    async fn callback(
        State(app): State<Self>,
        Path(provider): Path<String>,
        OptionalSession(session): OptionalSession,
        headers: HeaderMap,
        Query(query): Query<CallbackQuery>,
    ) -> Result<Response, ApiError> {
        Ok(app
            .complete_callback(
                provider
                    .parse()
                    .map_err(FederationError::UnsupportedProvider)?,
                &headers,
                query,
                session,
            )
            .await?)
    }

    /// Consumes state before exchange or cancellation so every callback is single-use.
    async fn complete_callback(
        &self,
        provider: Provider,
        headers: &HeaderMap,
        query: CallbackQuery,
        session: Option<StoredSession>,
    ) -> Result<Response, FederationError> {
        let browser = BrowserCookie::Federation
            .read(headers)
            .ok_or(FederationError::FlowBrowserMissing)?;
        let state = query
            .state
            .as_deref()
            .and_then(|value| Secret::parse(value).ok())
            .ok_or(FederationError::InvalidAttempt)?;
        // Cancellation consumes state too; returning to the browser never leaves replayable evidence.
        let flow = self
            .database
            .federation()
            .consume_transaction(
                provider,
                state.digest().as_bytes(),
                browser.digest().as_bytes(),
            )
            .await?;
        if query.error.is_some() {
            return self.failed_callback(CallbackError::Cancelled, &flow.return_to);
        }
        let Some(code) = query
            .code
            .filter(|code| !code.is_empty() && code.len() <= MAX_CODE_BYTES)
        else {
            return self.failed_callback(CallbackError::Failed, &flow.return_to);
        };
        let identity = match self
            .exchange(provider, &code, &flow.pkce_verifier, &flow.nonce)
            .await
        {
            Ok(identity) => identity,
            Err(error) => {
                tracing::warn!(error = %ErrorChain(&error), provider = provider.as_str(), "provider sign-in failed");
                return self.failed_callback(CallbackError::Failed, &flow.return_to);
            }
        };
        if let Some(user_id) = flow.link_user_id {
            let session = session.ok_or(SessionError::Missing)?;
            if session.user_id != user_id || Some(session.id) != flow.link_session_id {
                return Err(FederationError::SessionChanged);
            }
            if let Some(existing) = self
                .database
                .federation()
                .find_active(self.endpoints[&provider].issuer, &identity.subject)
                .await?
                && existing.user_id != user_id
            {
                return Err(FederationError::IdentityAlreadyLinked);
            }
            return self
                .pending_response(
                    provider,
                    identity,
                    flow.return_to,
                    Some(user_id),
                    flow.link_session_id,
                )
                .await;
        }
        self.finish_login(provider, identity, flow.return_to).await
    }

    /// Logs in a known subject or retains verified evidence for explicit onboarding/linking.
    async fn finish_login(
        &self,
        provider: Provider,
        identity: VerifiedIdentity,
        return_to: String,
    ) -> Result<Response, FederationError> {
        let issuer = self.endpoints[&provider].issuer;
        let mut tx = self.database.begin().await?;
        if let Some(existing) = tx
            .federation()
            .find_active(issuer, &identity.subject)
            .await?
        {
            tx.users()
                .find_active_by_id_for_update(existing.user_id)
                .await?
                .ok_or(FederationError::LinkedAccountUnavailable)?;
            // Unlink takes this same account lock; recheck after acquiring it.
            let current = tx
                .federation()
                .find_active(issuer, &identity.subject)
                .await?
                .ok_or(FederationError::LinkedAccountUnavailable)?;
            if current.id != existing.id
                || tx
                    .passkeys()
                    .list_active(existing.user_id)
                    .await?
                    .is_empty()
            {
                return Err(FederationError::LinkedAccountUnavailable);
            }
            let session = security::Session::create(
                &mut tx,
                existing.user_id,
                AuthenticationMethod::Federation,
            )
            .await?;
            tx.federation().record_login(existing.id).await?;
            tx.audit_events()
                .record(
                    existing.user_id,
                    AuditAction::FederationLogin,
                    Some(provider),
                )
                .await?;
            tx.commit().await?;
            let mut response = Redirect::to(&return_to).into_response();
            BrowserCookie::Session.set_on(&mut response, &session)?;
            BrowserCookie::Federation.clear_on(&mut response)?;
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

    /// Retains verified evidence without creating an account or authentication session.
    async fn pending_response(
        &self,
        provider: Provider,
        identity: VerifiedIdentity,
        return_to: String,
        link_user_id: Option<UserId>,
        link_session_id: Option<SessionId>,
    ) -> Result<Response, FederationError> {
        let browser = Secret::generate()?;
        self.database
            .federation()
            .insert_pending(&PendingFederation {
                id: TokenId::new(),
                browser_digest: browser.digest().as_bytes().to_vec(),
                provider,
                issuer: self.endpoints[&provider].issuer.into(),
                subject: identity.subject,
                email: identity.email,
                display_name: identity.display_name,
                return_to,
                link_user_id,
                link_session_id,
                expires_at: Utc::now() + FLOW_LIFETIME,
            })
            .await?;
        let destination = if link_user_id.is_some() {
            PendingDestination::Link
        } else {
            PendingDestination::Signup
        };
        let mut response =
            Redirect::to(&format!("{}?social={destination}", routes::page::LOGIN)).into_response();
        BrowserCookie::FederationPending.set_on(&mut response, &browser)?;
        BrowserCookie::Federation.clear_on(&mut response)?;
        Ok(response)
    }
}

/// Whether authorization starts a login or a link to the current account.
#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StartMode {
    /// Authenticate a provider subject without assuming an existing session.
    #[default]
    Login,
    /// Bind the verified provider subject to the initiating management session.
    Link,
}

/// Browser input for a new authorization request.
#[derive(Default, Deserialize)]
struct StartInput {
    /// Requested continuation, checked against the application's URL policy.
    return_to: Option<String>,
    /// Account-linking intent; an omitted value starts an ordinary login.
    #[serde(default)]
    mode: StartMode,
}

/// Authorization destination returned to the browser.
#[derive(Serialize)]
struct StartResponse<'a> {
    /// Provider URL containing browser-bound state and PKCE challenge.
    redirect_url: &'a str,
}

/// Provider callback parameters; untrusted until bound to consumed state.
#[derive(Deserialize)]
struct CallbackQuery {
    /// Single-use provider authorization code.
    code: Option<String>,
    /// Encoded state bound to the initiating browser.
    state: Option<String>,
    /// A provider-reported denial or cancellation; its contents never reach the browser.
    error: Option<String>,
}

/// Supplies the shared database boundary to browser-session extractors.
impl axum::extract::FromRef<FederationApplication> for Database {
    /// Clones the application's persistence handle for extraction.
    fn from_ref(application: &FederationApplication) -> Self {
        application.database.clone()
    }
}

#[cfg(test)]
mod tests;
