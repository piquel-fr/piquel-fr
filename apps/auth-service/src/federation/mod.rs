//! Browser-bound social authentication. Email suggests linking; it never authorizes it.

use crate::account::Owner;
use crate::config::{FederationConfig, ProviderConfig};
use crate::routes;
use crate::security::{
    self, ApiError, BrowserCookie, OptionalSession, RequestContext, SessionError,
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use chrono::{Duration, Utc};
use piquel_common::{
    AuthenticationMethod, ErrorChain, Provider, SessionId, TokenId, UserId,
    config::{ConfigurationError, Origin, SecretBytes},
    events::{Actor, SignInFailure},
    protocol::oauth::{CodeChallengeMethod, ResponseType},
};
use piquel_crypto::Pkce;
use piquel_crypto::Secret;
use piquel_repository::{
    Database, DatabaseTransaction, InsertFederationTransaction, PendingFederation,
    StoredExternalIdentity, StoredSession,
};
use piquel_ui::{CallbackError, LoginQuery, PendingDestination, Query as _};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration as StdDuration};
use url::Url;

/// Domain failures and their browser response mapping.
mod error;
/// Pending evidence, signup attachment, linking and unlinking.
mod identities;
pub use error::FederationConfigError;
pub(crate) use error::FederationError;
use error::InvalidReturnTo;
pub(crate) use identities::{PendingKind, PendingView};
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
/// Where the browser goes after sign-in when no `return_to` is given: the account's
/// settings.
const DEFAULT_RETURN_TO: &str = routes::page::settings::HOME;

/// A validated `return_to`: a path on the auth origin, the account's settings by
/// default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReturnTo(String);
impl ReturnTo {
    /// Accepts a path that cannot leave the auth origin. Absolute URLs are refused,
    /// even auth's own: its pages send paths.
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, InvalidReturnTo> {
        let value = value.unwrap_or(DEFAULT_RETURN_TO);
        if value.len() > MAX_RETURN_TO_BYTES {
            return Err(InvalidReturnTo::TooLong(value.len()));
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
        // One leading `/` makes this a path on the current origin.
        if value.starts_with("//") {
            return Err(InvalidReturnTo::ProtocolRelative);
        }
        if !value.starts_with('/') {
            return Err(InvalidReturnTo::NotAPath);
        }
        Ok(Self(value.into()))
    }

    /// The path.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ReturnTo {
    /// The account's settings.
    fn default() -> Self {
        Self(DEFAULT_RETURN_TO.to_owned())
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

/// What a federation operation changed in the browser's flow cookies, which the
/// response answering it carries. Only federation makes one, so a page never names
/// a flow cookie or holds its secret.
#[must_use = "the browser's flow cookie changes only once a response carries it"]
pub(crate) struct FlowCookie(Flow);

/// The change a [`FlowCookie`] makes.
enum Flow {
    /// A provider sign-in or link started, bound to the browser by the secret its
    /// [`BrowserCookie::Federation`] holds until the callback.
    Started(Secret),
    /// The browser's pending evidence is gone, linked or cancelled, so its
    /// [`BrowserCookie::FederationPending`] goes too, even when none was left.
    Settled,
}

impl FlowCookie {
    /// Adds the `Set-Cookie` header making the change to `response`, an axum
    /// response or a page's, keeping any other cookies being set.
    pub(crate) fn set_on<B>(
        self,
        response: &mut axum::http::Response<B>,
    ) -> Result<(), FederationError> {
        match self.0 {
            Flow::Started(browser) => BrowserCookie::Federation.set_on(response, &browser)?,
            Flow::Settled => BrowserCookie::FederationPending.clear_on(response)?,
        }
        Ok(())
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
        let client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(HTTP_USER_AGENT)
            .build()
            .map_err(FederationConfigError::Http)?;
        Ok(Self {
            database,
            origin: config.origin.clone(),
            providers: Arc::new(providers),
            endpoints: Provider::ALL
                .into_iter()
                .map(|provider| Ok((provider, ProviderEndpoints::new(provider, &client)?)))
                .collect::<Result<_, FederationConfigError>>()?,
            client,
        })
    }

    /// Redirects a consumed callback to the login page with its stored continuation.
    fn failed_callback(
        &self,
        error: CallbackError,
        return_to: &str,
    ) -> Result<Response, FederationError> {
        let query = LoginQuery {
            error: Some(error),
            return_to: Some(return_to.to_owned()),
            ..LoginQuery::default()
        };
        let destination = self.origin.as_url().join(&query.on(routes::page::LOGIN)?)?;
        let mut response = Redirect::to(destination.as_str()).into_response();
        BrowserCookie::Federation.clear_on(&mut response)?;
        Ok(response)
    }

    /// Computes the provider's callback from the configured auth origin.
    fn callback_url(&self, provider: Provider) -> String {
        self.origin
            .join(&routes::federation::CALLBACK.replace("{provider}", provider.as_str()))
    }

    /// Returns the providers' callback. The sign-in pages start, link and cancel
    /// social sign-ins in-process; listing and unlinking identities are shared
    /// settings, which [`AccountService`] serves.
    ///
    /// [`AccountService`]: crate::account::AccountService
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::federation::CALLBACK, get(Self::callback))
            .with_state(self)
    }

    /// The enabled providers, in the shared vocabulary's order.
    pub(crate) fn enabled(&self) -> impl Iterator<Item = Provider> + '_ {
        Provider::ALL
            .into_iter()
            .filter(|provider| self.providers.contains_key(provider))
    }

    /// The authorization endpoints of the enabled providers, which starting a
    /// sign-in or link sends the browser to; a page's `form-action` names their
    /// origins.
    pub(crate) fn authorization_endpoints(&self) -> Result<Vec<Url>, url::ParseError> {
        self.enabled()
            .map(|provider| Url::parse(self.endpoints[&provider].authorization))
            .collect()
    }

    /// Starts linking `provider` to the owner's account from a settings page, which
    /// the browser comes back to at `return_to`, a path on auth. Returns where to
    /// send the browser, and the cookie the response sending it there carries.
    pub(crate) async fn start_link(
        &self,
        owner: &Owner,
        provider: Provider,
        return_to: &str,
    ) -> Result<(Url, FlowCookie), FederationError> {
        let return_to = ReturnTo::parse(Some(return_to))?;
        self.authorization(provider, Some(owner.session()), return_to)
            .await
    }

    /// Starts signing a browser in at `provider` from a sign-in page, which the
    /// browser comes back to at `return_to`, a path on auth, unless the provider's
    /// identity is new. Returns where to send the browser, and the cookie its
    /// response carries.
    pub(crate) async fn start_sign_in(
        &self,
        provider: Provider,
        return_to: &str,
    ) -> Result<(Url, FlowCookie), FederationError> {
        let return_to = ReturnTo::parse(Some(return_to))?;
        self.authorization(provider, None, return_to).await
    }

    /// Persists one-use state for a sign-in, or a link to the account of the `link`
    /// session, returning to `return_to`. Returns the provider's authorization URL
    /// and the cookie binding the state to the browser.
    async fn authorization(
        &self,
        provider: Provider,
        link: Option<&StoredSession>,
        return_to: ReturnTo,
    ) -> Result<(Url, FlowCookie), FederationError> {
        let config = self
            .providers
            .get(&provider)
            .ok_or(FederationError::ProviderNotConfigured)?;
        let endpoints = &self.endpoints[&provider];
        let state = Secret::generate()?;
        let nonce = Secret::generate()?.encoded();
        let verifier = Secret::generate()?.encoded();
        let browser = Secret::generate()?;
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
                link_user_id: link.map(|session| session.user_id),
                link_session_id: link.map(|session| session.id),
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
        Ok((url, FlowCookie(Flow::Started(browser))))
    }

    /// Converts provider callbacks into a verified login or pending identity.
    async fn callback(
        State(app): State<Self>,
        context: RequestContext,
        Path(provider): Path<String>,
        OptionalSession(session): OptionalSession,
        headers: HeaderMap,
        Query(query): Query<CallbackQuery>,
    ) -> Result<Response, ApiError> {
        Ok(app
            .complete_callback(
                context,
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
        context: RequestContext,
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
                if let Some(reason) = error.sign_in_failure() {
                    context
                        .record_sign_in_failure(
                            &self.database,
                            Actor::Anonymous,
                            None,
                            AuthenticationMethod::Federation,
                            reason,
                        )
                        .await?;
                }
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
        self.finish_login(context, headers, provider, identity, flow.return_to)
            .await
    }

    /// Logs in a known subject or retains verified evidence for explicit onboarding/linking.
    async fn finish_login(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
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
            let user_id = existing.user_id;
            let session = match Self::sign_in_linked(tx, context, headers, existing).await {
                Ok(session) => session,
                Err(FederationError::Session(SessionError::PasskeyRequired)) => {
                    return self.failed_callback(CallbackError::PasskeyRequired, &return_to);
                }
                Err(error @ FederationError::LinkedAccountUnavailable) => {
                    context
                        .record_sign_in_failure(
                            &self.database,
                            Actor::Anonymous,
                            Some(user_id),
                            AuthenticationMethod::Federation,
                            SignInFailure::AccountUnavailable,
                        )
                        .await?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
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

    /// Signs this browser in to the account `existing` is linked to and returns the
    /// session's cookie secret. The account must still be active, linked and hold a passkey, which is
    /// rechecked under the account lock that unlinking also takes.
    async fn sign_in_linked(
        mut tx: DatabaseTransaction<'_>,
        context: RequestContext,
        headers: &HeaderMap,
        existing: StoredExternalIdentity,
    ) -> Result<Secret, FederationError> {
        tx.users()
            .find_active_by_id_for_update(existing.user_id)
            .await?
            .ok_or(FederationError::LinkedAccountUnavailable)?;
        let current = tx
            .federation()
            .find_active(&existing.issuer, &existing.subject)
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
        let session = security::Session::sign_in(
            &mut tx,
            context,
            headers,
            existing.user_id,
            security::Credential::Federation,
        )
        .await?;
        tx.federation().record_login(existing.id).await?;
        tx.commit().await?;
        Ok(session)
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
        let query = LoginQuery {
            social: Some(destination),
            ..LoginQuery::default()
        };
        let mut response = Redirect::to(&query.on(routes::page::LOGIN)?).into_response();
        BrowserCookie::FederationPending.set_on(&mut response, &browser)?;
        BrowserCookie::Federation.clear_on(&mut response)?;
        Ok(response)
    }
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
