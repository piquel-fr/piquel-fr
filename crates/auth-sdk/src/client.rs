//! Login: the authorization code flow with PKCE, then refresh, revocation, `UserInfo`
//! and logout.

use crate::{
    IdToken, Issuer, LogoutToken, TokenError,
    http::{Authorization, NetworkError, Reply},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use rand::{RngCore, rngs::OsRng};
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sourceorigin_common::{
    ClientId,
    protocol::{
        claims::{IdTokenClaims, LogoutTokenClaims, UserInfo},
        jwt::TokenType,
        oauth::{
            CodeChallengeMethod, ErrorResponse, GrantType, Prompt, ResponseType, Scope, Scopes,
        },
        sdk::{ErrorCategory, ErrorReason, SdkError},
        step_up::StepUpRequirement,
    },
};
use std::{fmt, sync::Arc};
use thiserror::Error;
use url::Url;

/// Random bytes in `state`, `nonce` and the PKCE verifier: 256 bits, which encode to
/// a 43-character verifier, the shortest RFC 7636 allows.
const RANDOM_BYTES: usize = 32;

/// An auth endpoint failed or answered with an OAuth error.
///
/// ```no_run
/// # async fn run(client: sourceorigin_auth::Client, refresh: sourceorigin_auth::RefreshToken, signed_in: sourceorigin_auth::IdToken) {
/// use sourceorigin_auth::{OAuthError, protocol::oauth::ErrorCode};
///
/// match client.refresh(&refresh, signed_in.claims()).await {
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
    /// `UserInfo` names another user than the ID token (OIDC Core §5.3.2), so its
    /// claims must not be used.
    #[error("UserInfo names the user {found:?}, expected {expected:?}")]
    UserInfoSubject {
        /// The ID token's `sub`.
        expected: String,
        /// `UserInfo`'s `sub`.
        found: String,
    },
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
            Self::UserInfoSubject { .. } => {
                SdkError::new(ErrorCategory::InvalidToken, ErrorReason::SubjectMismatch)
            }
        }
    }
}

/// A login could not start, its authorization response failed, or its code could not
/// be exchanged.
///
/// ```
/// use sourceorigin_auth::{
///     LoginError,
///     protocol::sdk::{ErrorCategory, ErrorReason, SdkError},
/// };
///
/// let mixed_up = LoginError::IssuerMismatch {
///     expected: "https://auth.sourceorigin.dev".into(),
///     found: "https://evil.example".into(),
/// };
/// assert_eq!(
///     mixed_up.code(),
///     SdkError::new(ErrorCategory::Callback, ErrorReason::IssuerMismatch)
/// );
/// ```
#[derive(Debug, Error)]
pub enum LoginError {
    /// The operating system could not supply random bytes for `state`, `nonce` and
    /// the PKCE verifier.
    #[error("operating system randomness is unavailable")]
    Randomness(#[source] rand::Error),
    /// The pushed authorization request failed (RFC 9126 §2.3).
    #[error(transparent)]
    Push(OAuthError),
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
            Self::Push(error) | Self::Exchange(error) => return error.code(),
            // No shared category names a local failure; like an HTTP client that
            // cannot be built, it keeps the SDK from reaching auth.
            Self::Randomness(_) => return SdkError::category(ErrorCategory::Network),
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
/// use sourceorigin_auth::Credentials;
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
/// use sourceorigin_auth::{AuthorizeRequest, protocol::challenge::BearerChallenge};
///
/// // An API answered with a step-up challenge: ask auth for what it names, with
/// // profile claims and a refresh token.
/// let challenge: BearerChallenge = r#"Bearer error="insufficient_user_authentication", acr_values="phr", max_age="300""#
///     .parse()?;
/// let request = AuthorizeRequest {
///     scopes: "profile offline_access".parse()?,
///     step_up: challenge.step_up,
///     ..AuthorizeRequest::default()
/// };
/// assert_eq!(request.step_up.max_age, Some(300));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct AuthorizeRequest {
    /// Scopes to request besides `openid`.
    pub scopes: Scopes,
    /// `prompt`, such as [`Prompt::Login`] to force a fresh sign-in.
    pub prompt: Option<Prompt>,
    /// The authentication to ask for, sent as `acr_values` and `max_age`, such as the
    /// one a step-up challenge names. [`Client::complete`] fails unless the ID token
    /// meets it.
    pub step_up: StepUpRequirement,
    /// The signed-in user's ID token, sent as `id_token_hint` so auth signs in that
    /// account only, as a step-up must. [`Client::complete`] fails unless the new ID
    /// token names the same user.
    pub id_token_hint: Option<IdToken>,
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
    /// use sourceorigin_auth::BearerToken;
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
    /// use sourceorigin_auth::RefreshToken;
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
#[derive(Clone, Debug)]
pub struct Tokens {
    /// The access token.
    pub access_token: BearerToken,
    /// When the access token expires, by the token endpoint's `expires_in`.
    pub expires_at: DateTime<Utc>,
    /// Granted scopes.
    pub scopes: Scopes,
    /// The validated ID token, when `openid` was granted.
    pub id_token: Option<IdToken>,
    /// A refresh token, when `offline_access` was granted. A public client's rotates
    /// on every refresh, and auth revokes the whole family if an old one is reused; a
    /// confidential client's is kept.
    pub refresh_token: Option<RefreshToken>,
}

/// A login waiting for its callback. It holds the PKCE verifier, so keep it
/// server-side, keyed by [`Self::state`], or seal it into a cookie as the axum login
/// routes do, and pass it to [`Client::complete`]. Auth redeems a code once, so a
/// callback completes at most once.
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
    /// The authentication asked for, which the ID token must meet.
    step_up: StepUpRequirement,
    /// The user the login's `id_token_hint` names, whom the ID token must name too.
    #[serde(default)]
    subject: Option<String>,
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
/// use sourceorigin_auth::CallbackParams;
///
/// let callback = CallbackParams::from_query(
///     "code=pac_v1_abc&state=af0ifjsldkj&iss=https%3A%2F%2Fauth.sourceorigin.dev",
/// )
/// .expect("no parameter repeats");
/// assert_eq!(callback.iss.as_deref(), Some("https://auth.sourceorigin.dev"));
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

/// The pushed authorization endpoint's success response (RFC 9126 §2.2). Its
/// `expires_in` is not needed: the browser is redirected at once.
#[derive(Deserialize)]
struct PushedAuthorization {
    /// What the browser brings to the authorization endpoint, with `client_id`.
    request_uri: String,
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
/// # async fn run(issuer: sourceorigin_auth::Issuer, callback_query: &str) -> Result<(), Box<dyn std::error::Error>> {
/// use sourceorigin_auth::{AuthorizeRequest, CallbackParams, ClientConfig, Credentials, PendingLogin};
///
/// let client = issuer.client(ClientConfig {
///     client_id: "notes-web".parse()?,
///     credentials: Credentials::Secret(std::env::var("NOTES_CLIENT_SECRET")?.into()),
///     redirect_uri: "https://notes.sourceorigin.dev/auth/callback".parse()?,
/// });
///
/// // 1. Send the browser to `url`, and keep the pending login server-side under its
/// //    state, never in the browser unsealed: it holds the PKCE verifier.
/// let (url, pending) = client
///     .authorize(&AuthorizeRequest {
///         scopes: "profile offline_access".parse()?,
///         ..AuthorizeRequest::default()
///     })
///     .await?;
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

    /// Starts a login: the authorization URL to redirect the browser to, and the
    /// pending login to keep until the callback.
    ///
    /// When discovery advertises a pushed authorization endpoint, the request is
    /// pushed there (RFC 9126), authenticated as at the token endpoint, and the URL
    /// carries only `client_id` and the returned `request_uri`. A client auth
    /// requires to push can then sign in, and the request never crosses the browser.
    /// Otherwise the URL carries the request itself.
    ///
    /// # Errors
    /// [`LoginError::Push`] if the push fails, with the OAuth error auth answered;
    /// [`LoginError::Randomness`] if the operating system cannot supply random bytes.
    pub async fn authorize(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<(Url, PendingLogin), LoginError> {
        let random = || -> Result<String, LoginError> {
            let mut bytes = [0; RANDOM_BYTES];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(LoginError::Randomness)?;
            Ok(URL_SAFE_NO_PAD.encode(bytes))
        };
        let pending = PendingLogin {
            issuer: self.issuer().issuer().to_owned(),
            client_id: self.config().client_id.clone(),
            state: random()?,
            nonce: random()?,
            verifier: random()?,
            redirect_uri: self.config().redirect_uri.clone(),
            step_up: request.step_up,
            subject: request
                .id_token_hint
                .as_ref()
                .map(|hint| hint.claims().sub.clone()),
        };
        let mut scopes = request.scopes.clone();
        scopes.insert(Scope::OpenId);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
        // `audience` is never sent: auth then picks the client's default resource.
        // `client_id` is added where the request goes, as `post` adds it.
        let mut parameters = vec![
            ("response_type", ResponseType::Code.as_str().to_owned()),
            ("redirect_uri", pending.redirect_uri.to_string()),
            ("scope", scopes.to_string()),
            ("state", pending.state.clone()),
            ("nonce", pending.nonce.clone()),
            ("code_challenge", challenge),
            (
                "code_challenge_method",
                CodeChallengeMethod::S256.as_str().to_owned(),
            ),
        ];
        parameters.extend(
            request
                .prompt
                .map(|prompt| ("prompt", prompt.as_str().to_owned())),
        );
        parameters.extend(request.step_up.authorize_params());
        parameters.extend(
            request
                .id_token_hint
                .as_ref()
                .map(|hint| ("id_token_hint", hint.as_str().to_owned())),
        );
        let parameters: Vec<_> = parameters
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let metadata = self.issuer().metadata();
        let client_id = ("client_id", self.config().client_id.as_str());
        let mut url = metadata.authorization_endpoint.clone();
        match &metadata.pushed_authorization_request_endpoint {
            Some(endpoint) => {
                let push = async {
                    let reply = self.post(endpoint, &parameters).await?;
                    let pushed: PushedAuthorization =
                        Self::read("pushed authorization", &reply, StatusCode::CREATED)?;
                    // A request URI is one token (RFC 9126 §2.2): an empty one names nothing.
                    if pushed.request_uri.is_empty()
                        || pushed.request_uri.contains(char::is_whitespace)
                    {
                        return Err(OAuthError::UnexpectedResponse {
                            endpoint: "pushed authorization",
                            status: reply.status.as_u16(),
                            source: None,
                        });
                    }
                    Ok(pushed)
                };
                let pushed = push.await.map_err(LoginError::Push)?;
                url.query_pairs_mut()
                    .extend_pairs([client_id, ("request_uri", pushed.request_uri.as_str())]);
            }
            None => {
                url.query_pairs_mut()
                    .extend_pairs([client_id].into_iter().chain(parameters));
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
            .tokens(response, Some(&pending.nonce), pending.step_up.max_age)
            .await?;
        // `openid` was requested, so a response without an ID token names no user.
        let Some(id_token) = &tokens.id_token else {
            return Err(OAuthError::UnexpectedResponse {
                endpoint: "token",
                status: StatusCode::OK.as_u16(),
                source: None,
            }
            .into());
        };
        // A step-up login that fell short would only be asked for again, and one that
        // signed in another account must not replace the hinted one.
        id_token
            .require_authentication(pending.step_up, self.issuer().now())
            .map_err(OAuthError::IdToken)?;
        if let Some(subject) = &pending.subject
            && let Err(error) = id_token.require_subject(subject)
        {
            // The code is spent: revoke its grant, which would otherwise live on at
            // auth unused. The mismatch is the error either way, so a revocation
            // that fails adds nothing to report.
            if let Some(refresh_token) = &tokens.refresh_token {
                let _revoked = self.revoke(refresh_token).await;
            }
            return Err(OAuthError::IdToken(error).into());
        }
        Ok(tokens)
    }

    /// Redeems a refresh token of the sign-in that `signed_in` describes: the claims
    /// of the sign-in's ID token, or of a session's that passed this check before
    /// with the sign-in's `nonce` kept, as the axum login routes keep them. For a
    /// public client, the response carries a new refresh token and the old one must
    /// not be used again; a confidential client's stays valid, and the response
    /// carries none. A returned ID token is validated, then must carry over the
    /// sign-in (OIDC Core §12.2): the same user, `auth_time` and `acr`, and no `nonce`
    /// but the sign-in's.
    ///
    /// # Errors
    /// See [`OAuthError`]; [`OAuthError::IdToken`] with
    /// [`TokenError::SubjectMismatch`] or [`TokenError::AuthenticationChanged`] when
    /// the new ID token breaks §12.2.
    ///
    /// ```no_run
    /// # async fn run(client: sourceorigin_auth::Client, stored: sourceorigin_auth::RefreshToken, signed_in: sourceorigin_auth::IdToken) -> Result<(), Box<dyn std::error::Error>> {
    /// let tokens = client.refresh(&stored, signed_in.claims()).await?;
    /// // A public client stores the rotated token in place of the old one.
    /// let current = tokens.refresh_token.unwrap_or(stored);
    /// # Ok(()) }
    /// ```
    pub async fn refresh(
        &self,
        refresh: &RefreshToken,
        signed_in: &IdTokenClaims,
    ) -> Result<Tokens, OAuthError> {
        let response = self
            .token_request(&[
                ("grant_type", GrantType::RefreshToken.as_str()),
                ("refresh_token", refresh.expose()),
            ])
            .await?;
        let tokens = self.tokens(response, None, None).await?;
        if let Some(id_token) = &tokens.id_token {
            id_token
                .require_refresh_of(signed_in)
                .map_err(OAuthError::IdToken)?;
        }
        Ok(tokens)
    }

    /// Revokes a refresh token and its whole family (RFC 7009).
    ///
    /// # Errors
    /// See [`OAuthError`].
    ///
    /// ```no_run
    /// # async fn run(client: sourceorigin_auth::Client, refresh: sourceorigin_auth::RefreshToken) -> Result<(), sourceorigin_auth::OAuthError> {
    /// client.revoke(&refresh).await?;
    /// # Ok(()) }
    /// ```
    pub async fn revoke(&self, refresh: &RefreshToken) -> Result<(), OAuthError> {
        let url = &self.issuer().metadata().revocation_endpoint;
        let reply = self.post(url, &[("token", refresh.expose())]).await?;
        // A success's body carries nothing and is ignored (RFC 7009 §2.2).
        if reply.status == StatusCode::OK {
            return Ok(());
        }
        Self::read::<serde::de::IgnoredAny>("revocation", &reply, StatusCode::OK).map(|_| ())
    }

    /// Reads the claims of the user `signed_in` names, the claims of their ID token,
    /// with an access token of the same sign-in. `UserInfo` must name that user (OIDC
    /// Core §5.3.2).
    ///
    /// # Errors
    /// See [`OAuthError`]; [`OAuthError::UserInfoSubject`] when `UserInfo` names
    /// another user.
    ///
    /// ```no_run
    /// # async fn run(client: sourceorigin_auth::Client, tokens: sourceorigin_auth::Tokens, id_token: sourceorigin_auth::IdToken) -> Result<(), sourceorigin_auth::OAuthError> {
    /// let user = client.userinfo(&tokens.access_token, id_token.claims()).await?;
    /// println!("{} <{:?}>", user.sub, user.profile.email);
    /// # Ok(()) }
    /// ```
    pub async fn userinfo(
        &self,
        access: &BearerToken,
        signed_in: &IdTokenClaims,
    ) -> Result<UserInfo, OAuthError> {
        let url = &self.issuer().metadata().userinfo_endpoint;
        let reply = self
            .issuer()
            .http()
            .get(url, Authorization::Bearer(access.expose()))
            .await?;
        let user: UserInfo = Self::read("userinfo", &reply, StatusCode::OK)?;
        let expected = &signed_in.sub;
        if user.sub != *expected {
            return Err(OAuthError::UserInfoSubject {
                expected: expected.clone(),
                found: user.sub,
            });
        }
        Ok(user)
    }

    /// The RP-initiated logout URL: auth ends the browser session, then sends the
    /// browser to `post_logout`, which must be registered for this client. Without
    /// one, auth shows its own page. `id_token_hint` names the sign-in being ended
    /// when the app kept its ID token; auth asks the user to confirm either way.
    ///
    /// ```no_run
    /// # fn run(client: sourceorigin_auth::Client, id_token: sourceorigin_auth::IdToken) -> Result<(), url::ParseError> {
    /// // Redirect the browser here once the app's own session is gone.
    /// let after: url::Url = "https://notes.sourceorigin.dev/".parse()?;
    /// let logout = client.logout_url(Some(&id_token), Some(&after));
    /// # Ok(()) }
    /// ```
    #[must_use]
    pub fn logout_url(&self, id_token_hint: Option<&IdToken>, post_logout: Option<&Url>) -> Url {
        let mut url = self.issuer().metadata().end_session_endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            if let Some(id_token) = id_token_hint {
                query.append_pair("id_token_hint", id_token.as_str());
            }
            query.append_pair("client_id", self.config().client_id.as_str());
            if let Some(post_logout) = post_logout {
                query.append_pair("post_logout_redirect_uri", post_logout.as_str());
            }
        }
        url
    }

    /// Validates a back-channel logout token auth posted to this client (OIDC
    /// Back-Channel Logout 1.0 §2.6). It is checked like an ID token, with `typ`
    /// `logout+jwt` and an `aud` naming only this client, then must be valid for at
    /// most 10 minutes, carry the logout event, have no `nonce`, and name `sub` or
    /// `sid`. Rejecting a `jti` seen before is left to the caller, as the axum login
    /// routes do.
    ///
    /// # Errors
    /// See [`TokenError`]. [`TokenError::Keys`] is the server's failure: answer 503 so
    /// auth retries. Any other error answers 400.
    ///
    /// ```no_run
    /// # async fn run(client: sourceorigin_auth::Client, logout_token: &str) -> Result<(), sourceorigin_auth::TokenError> {
    /// use sourceorigin_auth::LogoutScope;
    ///
    /// // The `logout_token` form field auth posted.
    /// let logout = client.logout_token(logout_token).await?;
    /// match logout.scope() {
    ///     LogoutScope::Session(sid) => println!("end the sessions of auth session {sid}"),
    ///     LogoutScope::Subject(sub) => println!("end every session of {sub}"),
    /// }
    /// # Ok(()) }
    /// ```
    pub async fn logout_token(&self, token: &str) -> Result<LogoutToken, TokenError> {
        let client = self.config().client_id.as_str();
        let claims: LogoutTokenClaims = self
            .issuer()
            .decode(token, TokenType::Logout, client)
            .await?;
        LogoutToken::from_claims(claims)
    }

    /// Posts a grant to the token endpoint.
    async fn token_request(&self, form: &[(&str, &str)]) -> Result<TokenResponse, OAuthError> {
        let url = &self.issuer().metadata().token_endpoint;
        Self::read("token", &self.post(url, form).await?, StatusCode::OK)
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

    /// Parses the body of a `success` answer, which is `201 Created` for the pushed
    /// authorization endpoint and `200 OK` for the others, or the OAuth error of a
    /// failed request.
    fn read<T: DeserializeOwned>(
        endpoint: &'static str,
        reply: &Reply,
        success: StatusCode,
    ) -> Result<T, OAuthError> {
        let status = reply.status.as_u16();
        if reply.status == success {
            return serde_json::from_slice(&reply.body).map_err(|source| {
                OAuthError::UnexpectedResponse {
                    endpoint,
                    status,
                    source: Some(source),
                }
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
