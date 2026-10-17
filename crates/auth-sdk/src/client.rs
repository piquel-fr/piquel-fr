//! Login: the authorization code flow with PKCE, then refresh, revocation, `UserInfo`
//! and logout.

use crate::{
    IdToken, Issuer, TokenError,
    http::{Authorization, NetworkError, Reply},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use piquel_auth_protocol::{
    ClientId,
    claims::UserInfo,
    oauth::{CodeChallengeMethod, ErrorResponse, GrantType, Prompt, ResponseType, Scope, Scopes},
    sdk::{ErrorCategory, ErrorReason, SdkError},
    step_up::StepUpRequirement,
};
use rand::{RngCore, rngs::OsRng};
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use thiserror::Error;
use url::Url;

/// Random bytes in `state`, `nonce` and the PKCE verifier: 256 bits, which encode to
/// a 43-character verifier, the shortest RFC 7636 allows.
const RANDOM_BYTES: usize = 32;

/// An auth endpoint failed or answered with an OAuth error.
///
/// ```no_run
/// # async fn run(client: piquel_auth::Client, refresh: piquel_auth::RefreshToken) {
/// use piquel_auth::{OAuthError, protocol::oauth::ErrorCode};
///
/// match client.refresh(&refresh).await {
///     Ok(tokens) => println!("access token valid until {}", tokens.expires_at),
///     // The grant is over: sign the user in again.
///     Err(OAuthError::Rejected { response, .. }) if response.error == ErrorCode::InvalidGrant => {}
///     Err(error) => eprintln!("refresh failed: {error}"),
/// }
/// # }
/// ```
#[derive(Debug, Error)]
pub enum OAuthError {
    /// The endpoint could not be reached.
    #[error(transparent)]
    Network(#[from] NetworkError),
    /// The endpoint rejected the request (RFC 6749 §5.2).
    #[error("the {endpoint} endpoint rejected the request with {}", .response.error)]
    Rejected {
        /// Which endpoint answered.
        endpoint: &'static str,
        /// HTTP status.
        status: u16,
        /// The OAuth error.
        response: ErrorResponse,
    },
    /// The endpoint answered outside the OAuth protocol.
    #[error("the {endpoint} endpoint answered HTTP {status} with an unexpected body")]
    UnexpectedResponse {
        /// Which endpoint answered.
        endpoint: &'static str,
        /// HTTP status.
        status: u16,
        /// Why the body did not parse.
        #[source]
        source: Option<serde_json::Error>,
    },
    /// The token endpoint returned an ID token that failed validation.
    #[error("the token endpoint returned an invalid ID token")]
    IdToken(#[source] TokenError),
}

impl OAuthError {
    /// The shared SDK error code.
    #[must_use]
    pub const fn code(&self) -> SdkError {
        match self {
            Self::Network(_) | Self::UnexpectedResponse { .. } => {
                SdkError::category(ErrorCategory::Network)
            }
            Self::Rejected { .. } => SdkError::category(ErrorCategory::OAuth),
            Self::IdToken(error) => error.code(),
        }
    }
}

/// An authorization response failed, or its code could not be exchanged.
///
/// ```
/// use piquel_auth::{
///     LoginError,
///     protocol::sdk::{ErrorCategory, ErrorReason, SdkError},
/// };
///
/// let mixed_up = LoginError::IssuerMismatch {
///     expected: "https://auth.piquel.fr".into(),
///     found: "https://evil.example".into(),
/// };
/// assert_eq!(
///     mixed_up.code(),
///     SdkError::new(ErrorCategory::Callback, ErrorReason::IssuerMismatch)
/// );
/// ```
#[derive(Debug, Error)]
pub enum LoginError {
    /// `state` is not the pending login's: the response belongs to another attempt.
    #[error("authorization response state does not match this login")]
    StateMismatch,
    /// The pending login was started by another client or with another issuer, so
    /// its code and verifier must not be sent here.
    #[error("the pending login belongs to another client or issuer")]
    ForeignLogin,
    /// `iss` names another issuer: a mix-up attack (RFC 9207 §2.4).
    #[error("authorization response comes from {found:?}, expected {expected:?}")]
    IssuerMismatch {
        /// The pending login's issuer.
        expected: String,
        /// The response's `iss`.
        found: String,
    },
    /// `iss` is missing although the issuer advertises it (RFC 9207 §2.4).
    #[error("authorization response has no iss parameter")]
    MissingIssuer,
    /// The issuer refused the authorization, for example because the user declined.
    #[error("authorization failed with {error}")]
    Denied {
        /// The OAuth error code.
        error: String,
        /// What the issuer says went wrong.
        description: Option<String>,
    },
    /// A successful response has no `code`.
    #[error("authorization response has no code")]
    MissingCode,
    /// The code exchange failed.
    #[error(transparent)]
    Exchange(#[from] OAuthError),
}

impl LoginError {
    /// The shared SDK error code.
    #[must_use]
    pub const fn code(&self) -> SdkError {
        let reason = match self {
            Self::Denied { .. } => return SdkError::category(ErrorCategory::OAuth),
            Self::Exchange(error) => return error.code(),
            Self::StateMismatch | Self::ForeignLogin => ErrorReason::StateMismatch,
            Self::IssuerMismatch { .. } => ErrorReason::IssuerMismatch,
            Self::MissingIssuer => ErrorReason::MissingIssuer,
            Self::MissingCode => ErrorReason::MissingCode,
        };
        SdkError::new(ErrorCategory::Callback, reason)
    }
}

/// How the client authenticates at the token and revocation endpoints.
///
/// ```
/// use piquel_auth::Credentials;
///
/// let secret = Credentials::Secret("a-confidential-client-secret".to_owned().into());
/// // Secrets are never printed.
/// assert_eq!(format!("{secret:?}"), "Secret(REDACTED)");
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub enum Credentials {
    /// A public client, identified by its ID alone.
    None,
    /// A confidential client's secret, sent with HTTP Basic.
    Secret(SecretString),
}

impl fmt::Debug for Credentials {
    /// Names the method, never the secret.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::None => "None",
            Self::Secret(_) => "Secret(REDACTED)",
        })
    }
}

/// A registered client.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// The client's ID.
    pub client_id: ClientId,
    /// How it authenticates.
    pub credentials: Credentials,
    /// Its registered callback, exactly as registered.
    pub redirect_uri: Url,
}

/// What to ask for in an authorization request. `openid` is always requested.
///
/// ```
/// use piquel_auth::{AuthorizeRequest, protocol::oauth::Prompt};
///
/// // Profile claims, a refresh token, and a sign-in within the last five minutes.
/// let request = AuthorizeRequest {
///     scopes: "profile offline_access".parse()?,
///     max_age: Some(300),
///     prompt: Some(Prompt::Login),
///     ..AuthorizeRequest::default()
/// };
/// # Ok::<(), piquel_auth::protocol::oauth::InvalidScope>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct AuthorizeRequest {
    /// Scopes to request besides `openid`.
    pub scopes: Scopes,
    /// `prompt`, such as [`Prompt::Login`] to force a fresh sign-in.
    pub prompt: Option<Prompt>,
    /// The authentication to ask for, sent as `acr_values` and `max_age`, such as the
    /// one a step-up challenge names. Its `max_age` is checked against the ID token's
    /// `auth_time`.
    pub step_up: StepUpRequirement,
}

/// Declares a credential string that is never printed and serializes as itself, so
/// a server-side session can store it.
macro_rules! credential {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name(SecretString);

        impl $name {
            /// Wraps a token as issued.
            #[must_use]
            pub fn new(token: String) -> Self {
                Self(token.into())
            }

            /// The token, to send to auth.
            #[must_use]
            pub fn expose(&self) -> &str {
                self.0.expose_secret()
            }
        }

        impl fmt::Debug for $name {
            /// Never prints the token.
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(REDACTED)"))
            }
        }

        impl Serialize for $name {
            /// Writes the token, for server-side storage only.
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.expose())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            /// Reads a stored token.
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer).map(Self::new)
            }
        }
    };
}

credential!(
    /// An access token as issued, to send as a bearer credential.
    ///
    /// ```
    /// use piquel_auth::BearerToken;
    ///
    /// let token = BearerToken::new("eyJ...".into());
    /// assert_eq!(token.expose(), "eyJ...");
    /// assert_eq!(format!("{token:?}"), "BearerToken(REDACTED)");
    /// ```
    BearerToken
);
credential!(
    /// A refresh token. Keep it server-side: it must never reach a browser.
    ///
    /// ```
    /// use piquel_auth::RefreshToken;
    ///
    /// let token = RefreshToken::new("prt_v1_example".into());
    /// // Serializes as itself, for a server-side session store, and never prints.
    /// assert_eq!(serde_json::to_string(&token)?, r#""prt_v1_example""#);
    /// assert_eq!(format!("{token:?}"), "RefreshToken(REDACTED)");
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    RefreshToken
);

/// Tokens from a code exchange or refresh.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tokens {
    /// The access token.
    pub access_token: BearerToken,
    /// When the access token expires, by the token endpoint's `expires_in`.
    pub expires_at: DateTime<Utc>,
    /// Granted scopes.
    pub scopes: Scopes,
    /// The validated ID token, when `openid` was granted.
    pub id_token: Option<IdToken>,
    /// A refresh token, when `offline_access` was granted. Auth rotates it on every
    /// refresh, and revokes the whole family if an old one is reused.
    pub refresh_token: Option<RefreshToken>,
}

/// A login waiting for its callback. Store it server-side, keyed by [`Self::state`],
/// and pass it to [`Client::complete`], which consumes it so a callback completes at
/// most once.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingLogin {
    /// Issuer the login was started with.
    issuer: String,
    /// Client that started the login, the only one that may complete it.
    client_id: ClientId,
    /// Client value auth returns unchanged.
    state: String,
    /// Value the ID token must echo.
    nonce: String,
    /// PKCE verifier proving this client started the login.
    verifier: String,
    /// The callback the code is bound to.
    redirect_uri: Url,
    /// `max_age` sent, checked against the ID token's `auth_time`.
    max_age: Option<u32>,
}

impl fmt::Debug for PendingLogin {
    /// Omits the PKCE verifier.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingLogin")
            .field("issuer", &self.issuer)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl PendingLogin {
    /// The `state` sent, which the callback carries back.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Applies the callback checks, in order, before the code goes anywhere: `state`,
    /// then RFC 9207 §2.4 `iss` (error responses included), then `error`, then `code`.
    pub(crate) fn check<'a>(
        &self,
        callback: &'a CallbackParams,
        iss_advertised: bool,
    ) -> Result<&'a str, LoginError> {
        if callback.state.as_deref() != Some(self.state.as_str()) {
            return Err(LoginError::StateMismatch);
        }
        match &callback.iss {
            Some(iss) if *iss != self.issuer => {
                return Err(LoginError::IssuerMismatch {
                    expected: self.issuer.clone(),
                    found: iss.clone(),
                });
            }
            None if iss_advertised => return Err(LoginError::MissingIssuer),
            _ => {}
        }
        if let Some(error) = &callback.error {
            return Err(LoginError::Denied {
                error: error.clone(),
                description: callback.error_description.clone(),
            });
        }
        callback.code.as_deref().ok_or(LoginError::MissingCode)
    }
}

/// The query parameters of an authorization response.
///
/// ```
/// use piquel_auth::CallbackParams;
///
/// let callback = CallbackParams::from_query(
///     "code=pac_v1_abc&state=af0ifjsldkj&iss=https%3A%2F%2Fauth.piquel.fr",
/// )
/// .expect("no parameter repeats");
/// assert_eq!(callback.iss.as_deref(), Some("https://auth.piquel.fr"));
/// // The code is a credential until redeemed, so it is never printed.
/// assert!(!format!("{callback:?}").contains("pac_v1_abc"));
/// assert!(CallbackParams::from_query("state=a&state=b").is_none());
/// ```
#[derive(Clone, Default, Deserialize)]
pub struct CallbackParams {
    /// The authorization code, on success.
    pub code: Option<String>,
    /// The `state` sent.
    pub state: Option<String>,
    /// The issuer that answered (RFC 9207).
    pub iss: Option<String>,
    /// The OAuth error code, on failure.
    pub error: Option<String>,
    /// What went wrong, on failure.
    pub error_description: Option<String>,
}

impl CallbackParams {
    /// Reads the parameters from a callback URL's query string. Returns `None` if a
    /// parameter repeats, which RFC 6749 §3.1 forbids: treat that as a failed login.
    #[must_use]
    pub fn from_query(query: &str) -> Option<Self> {
        let mut callback = Self::default();
        for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let field = match name.as_ref() {
                "code" => &mut callback.code,
                "state" => &mut callback.state,
                "iss" => &mut callback.iss,
                "error" => &mut callback.error,
                "error_description" => &mut callback.error_description,
                _ => continue,
            };
            if field.replace(value.into_owned()).is_some() {
                return None;
            }
        }
        Some(callback)
    }
}

impl fmt::Debug for CallbackParams {
    /// Omits the code, a credential until it is redeemed.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackParams")
            .field("state", &self.state)
            .field("iss", &self.iss)
            .field("error", &self.error)
            .field("error_description", &self.error_description)
            .finish_non_exhaustive()
    }
}

/// The token endpoint's success response.
#[derive(Deserialize)]
struct TokenResponse {
    /// The access token.
    access_token: String,
    /// Must be `Bearer`.
    token_type: String,
    /// Access token lifetime, in seconds.
    expires_in: u32,
    /// Granted scopes.
    scope: Scopes,
    /// ID token, with `openid`.
    id_token: Option<String>,
    /// Refresh token, with `offline_access`.
    refresh_token: Option<String>,
}

/// What the client shares across clones.
struct ClientInner {
    /// The issuer it signs in with.
    issuer: Issuer,
    /// Its registration.
    config: ClientConfig,
}

/// Signs users in with one issuer as one client. Cheap to clone.
///
/// A whole login, from the redirect to the signed-in user:
///
/// ```no_run
/// # async fn run(issuer: piquel_auth::Issuer, callback_query: &str) -> Result<(), Box<dyn std::error::Error>> {
/// use piquel_auth::{AuthorizeRequest, CallbackParams, ClientConfig, ClientId, Credentials, PendingLogin};
///
/// let client = issuer.client(ClientConfig {
///     client_id: ClientId::new("notes-web"),
///     credentials: Credentials::Secret(std::env::var("NOTES_CLIENT_SECRET")?.into()),
///     redirect_uri: "https://notes.piquel.fr/auth/callback".parse()?,
/// });
///
/// // 1. Send the browser to `url`, and keep the pending login server-side under its
/// //    state, never in the browser: it holds the PKCE verifier.
/// let (url, pending) = client.authorize(&AuthorizeRequest {
///     scopes: "profile offline_access".parse()?,
///     ..AuthorizeRequest::default()
/// })?;
/// let saved = (pending.state().to_owned(), serde_json::to_string(&pending)?);
///
/// // 2. On the callback, take the pending login back, once, and complete it.
/// let callback = CallbackParams::from_query(callback_query).ok_or("repeated parameter")?;
/// let pending: PendingLogin = serde_json::from_str(&saved.1)?;
/// let tokens = client.complete(pending, &callback).await?;
/// let id_token = tokens.id_token.as_ref().expect("login always returns one");
/// println!("signed in as {}", id_token.user_id()?);
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct Client(Arc<ClientInner>);

impl fmt::Debug for Client {
    /// Names the issuer and client.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("issuer", &self.0.issuer)
            .field("client_id", &self.0.config.client_id)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// The client `config` describes, signing in with `issuer`.
    pub(crate) fn new(issuer: Issuer, config: ClientConfig) -> Self {
        Self(Arc::new(ClientInner { issuer, config }))
    }

    /// The issuer this client signs in with.
    #[must_use]
    pub fn issuer(&self) -> &Issuer {
        &self.0.issuer
    }

    /// The client's registration.
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.0.config
    }

    /// Builds the authorization URL to redirect the browser to, and the pending login
    /// to store server-side until the callback.
    ///
    /// # Errors
    /// Fails only if the operating system cannot supply random bytes.
    pub fn authorize(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<(Url, PendingLogin), rand::Error> {
        let random = || -> Result<String, rand::Error> {
            let mut bytes = [0; RANDOM_BYTES];
            OsRng.try_fill_bytes(&mut bytes)?;
            Ok(URL_SAFE_NO_PAD.encode(bytes))
        };
        let pending = PendingLogin {
            issuer: self.issuer().issuer().to_owned(),
            client_id: self.config().client_id.clone(),
            state: random()?,
            nonce: random()?,
            verifier: random()?,
            redirect_uri: self.config().redirect_uri.clone(),
            max_age: request.step_up.max_age,
        };
        let scopes: Scopes = request
            .scopes
            .iter()
            .chain([Scope::OpenId.as_str()])
            .map(str::to_owned)
            .collect();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
        let mut url = self.issuer().metadata().authorization_endpoint.clone();
        {
            // `audience` is never sent: auth then picks the client's default resource.
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", ResponseType::Code.as_str())
                .append_pair("client_id", self.config().client_id.as_str())
                .append_pair("redirect_uri", pending.redirect_uri.as_str())
                .append_pair("scope", &scopes.to_string())
                .append_pair("state", &pending.state)
                .append_pair("nonce", &pending.nonce)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", CodeChallengeMethod::S256.as_str());
            if let Some(prompt) = request.prompt {
                query.append_pair("prompt", prompt.as_str());
            }
            for (name, value) in request.step_up.authorize_params() {
                query.append_pair(name, &value);
            }
        }
        Ok((url, pending))
    }

    /// Completes a login from its callback: checks the response, exchanges the code
    /// and validates the ID token against the pending login.
    ///
    /// # Errors
    /// See [`LoginError`]. Callback checks fail before the code is sent anywhere.
    pub async fn complete(
        &self,
        pending: PendingLogin,
        callback: &CallbackParams,
    ) -> Result<Tokens, LoginError> {
        // The code and verifier go only to the client and issuer that started the login.
        if pending.issuer != self.issuer().issuer() || pending.client_id != self.config().client_id
        {
            return Err(LoginError::ForeignLogin);
        }
        let metadata = self.issuer().metadata();
        let code = pending.check(
            callback,
            metadata.authorization_response_iss_parameter_supported,
        )?;
        let response = self
            .token_request(&[
                ("grant_type", GrantType::AuthorizationCode.as_str()),
                ("code", code),
                ("redirect_uri", pending.redirect_uri.as_str()),
                ("code_verifier", &pending.verifier),
            ])
            .await?;
        let tokens = self
            .tokens(response, Some(&pending.nonce), pending.max_age)
            .await?;
        // `openid` was requested, so a response without an ID token names no user.
        if tokens.id_token.is_none() {
            return Err(OAuthError::UnexpectedResponse {
                endpoint: "token",
                status: StatusCode::OK.as_u16(),
                source: None,
            }
            .into());
        }
        Ok(tokens)
    }

    /// Redeems a refresh token. The response carries a new refresh token; the old one
    /// must not be used again. A returned ID token is validated, but has no pending
    /// login to compare with: callers holding the previous ID token must check that
    /// `sub` is unchanged (OIDC Core §12.2), as the axum login routes do.
    ///
    /// # Errors
    /// See [`OAuthError`].
    ///
    /// ```no_run
    /// # async fn run(client: piquel_auth::Client, stored: piquel_auth::RefreshToken) -> Result<(), Box<dyn std::error::Error>> {
    /// let tokens = client.refresh(&stored).await?;
    /// // Store the rotated token in place of the old one, which auth now refuses.
    /// let rotated = tokens.refresh_token.unwrap_or(stored);
    /// # Ok(()) }
    /// ```
    pub async fn refresh(&self, refresh: &RefreshToken) -> Result<Tokens, OAuthError> {
        let response = self
            .token_request(&[
                ("grant_type", GrantType::RefreshToken.as_str()),
                ("refresh_token", refresh.expose()),
            ])
            .await?;
        self.tokens(response, None, None).await
    }

    /// Revokes a refresh token and its whole family (RFC 7009).
    ///
    /// # Errors
    /// See [`OAuthError`].
    ///
    /// ```no_run
    /// # async fn run(client: piquel_auth::Client, refresh: piquel_auth::RefreshToken) -> Result<(), piquel_auth::OAuthError> {
    /// client.revoke(&refresh).await?;
    /// # Ok(()) }
    /// ```
    pub async fn revoke(&self, refresh: &RefreshToken) -> Result<(), OAuthError> {
        let url = &self.issuer().metadata().revocation_endpoint;
        let reply = self.post(url, &[("token", refresh.expose())]).await?;
        Self::read::<serde::de::IgnoredAny>("revocation", &reply).map(|_| ())
    }

    /// Reads the user's claims with an access token.
    ///
    /// # Errors
    /// See [`OAuthError`].
    ///
    /// ```no_run
    /// # async fn run(client: piquel_auth::Client, tokens: piquel_auth::Tokens) -> Result<(), piquel_auth::OAuthError> {
    /// let user = client.userinfo(&tokens.access_token).await?;
    /// println!("{} <{:?}>", user.sub, user.profile.email);
    /// # Ok(()) }
    /// ```
    pub async fn userinfo(&self, access: &BearerToken) -> Result<UserInfo, OAuthError> {
        let url = &self.issuer().metadata().userinfo_endpoint;
        let reply = self
            .issuer()
            .http()
            .get(url, Authorization::Bearer(access.expose()))
            .await?;
        Self::read("userinfo", &reply)
    }

    /// The RP-initiated logout URL: auth ends the browser session, then sends the
    /// browser to `post_logout`, which must be registered for this client.
    ///
    /// ```no_run
    /// # fn run(client: piquel_auth::Client, id_token: piquel_auth::IdToken) -> Result<(), url::ParseError> {
    /// // Redirect the browser here once the app's own session is gone.
    /// let after: url::Url = "https://notes.piquel.fr/".parse()?;
    /// let logout = client.logout_url(&id_token, &after);
    /// # Ok(()) }
    /// ```
    #[must_use]
    pub fn logout_url(&self, id_token: &IdToken, post_logout: &Url) -> Url {
        let mut url = self.issuer().metadata().end_session_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("id_token_hint", id_token.as_str())
            .append_pair("post_logout_redirect_uri", post_logout.as_str())
            .append_pair("client_id", self.config().client_id.as_str());
        url
    }

    /// Posts a grant to the token endpoint.
    async fn token_request(&self, form: &[(&str, &str)]) -> Result<TokenResponse, OAuthError> {
        let url = &self.issuer().metadata().token_endpoint;
        Self::read("token", &self.post(url, form).await?)
    }

    /// Posts a form, authenticating as this client: HTTP Basic for confidential
    /// clients, `client_id` in the form for public ones.
    async fn post(&self, url: &Url, form: &[(&str, &str)]) -> Result<Reply, NetworkError> {
        let config = self.config();
        let http = self.issuer().http();
        match &config.credentials {
            Credentials::None => {
                let mut form = form.to_vec();
                form.push(("client_id", config.client_id.as_str()));
                http.post_form(url, &form, Authorization::None).await
            }
            Credentials::Secret(secret) => {
                let basic = Authorization::Basic(config.client_id.as_str(), secret.expose_secret());
                http.post_form(url, form, basic).await
            }
        }
    }

    /// Parses a success body, or the OAuth error of a failed request.
    fn read<T: DeserializeOwned>(endpoint: &'static str, reply: &Reply) -> Result<T, OAuthError> {
        let status = reply.status.as_u16();
        if reply.status == StatusCode::OK {
            // An empty body, as the revocation endpoint sends, parses as JSON null.
            let body: &[u8] = if reply.body.is_empty() {
                b"null"
            } else {
                &reply.body
            };
            return serde_json::from_slice(body).map_err(|source| OAuthError::UnexpectedResponse {
                endpoint,
                status,
                source: Some(source),
            });
        }
        match serde_json::from_slice(&reply.body) {
            Ok(response) => Err(OAuthError::Rejected {
                endpoint,
                status,
                response,
            }),
            Err(source) => Err(OAuthError::UnexpectedResponse {
                endpoint,
                status,
                source: Some(source),
            }),
        }
    }

    /// Checks a token response and validates its ID token.
    async fn tokens(
        &self,
        response: TokenResponse,
        nonce: Option<&str>,
        max_age: Option<u32>,
    ) -> Result<Tokens, OAuthError> {
        if !response.token_type.eq_ignore_ascii_case("Bearer") {
            return Err(OAuthError::UnexpectedResponse {
                endpoint: "token",
                status: StatusCode::OK.as_u16(),
                source: None,
            });
        }
        let id_token = match &response.id_token {
            Some(token) => Some(
                self.issuer()
                    .id_token(token, &self.config().client_id, nonce, max_age)
                    .await
                    .map_err(OAuthError::IdToken)?,
            ),
            None => None,
        };
        Ok(Tokens {
            access_token: BearerToken::new(response.access_token),
            expires_at: self.issuer().now() + TimeDelta::seconds(response.expires_in.into()),
            scopes: response.scope,
            id_token,
            refresh_token: response.refresh_token.map(RefreshToken::new),
        })
    }
}
