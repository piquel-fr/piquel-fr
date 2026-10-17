//! Validated tokens, the checks they pass, and why a token is rejected.

use crate::{Issuer, KeyError, LEEWAY, keys::Jws, scope::ScopeSet};
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{
    ClientId, SessionId, TokenId, UserId,
    challenge::{BearerChallenge, BearerError},
    claims::{
        AccessTokenClaims, Acr, Actor, Amr, Audience, Confirmation, IdTokenClaims, ProfileClaims,
    },
    jwt::{Algorithm, TokenType},
    oauth::Scopes,
    sdk::{ErrorCategory, ErrorReason, SdkError},
    step_up::StepUpRequirement,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Why a token was rejected. [`Self::code`] gives the shared SDK code, and
/// [`Self::challenge`] the `WWW-Authenticate` value a resource server answers with.
///
/// ```
/// use chrono::Utc;
/// use piquel_auth::{
///     KeyError, TokenError,
///     protocol::sdk::{ErrorCategory, ErrorReason, SdkError},
/// };
///
/// let expired = TokenError::Expired(Utc::now());
/// assert_eq!(
///     expired.code(),
///     SdkError::new(ErrorCategory::InvalidToken, ErrorReason::Expired)
/// );
/// let challenge = expired.challenge().expect("the client's fault");
/// assert_eq!((challenge.status(), challenge.to_string().as_str()), (401, r#"Bearer error="invalid_token""#));
///
/// let missing = TokenError::InsufficientScope { required: "notes:write".parse()? };
/// let challenge = missing.challenge().expect("the client's fault");
/// assert_eq!(challenge.status(), 403);
/// assert_eq!(challenge.to_string(), r#"Bearer error="insufficient_scope", scope="notes:write""#);
///
/// // Keys that cannot be fetched are the server's failure: answer 503, not a challenge.
/// assert!(TokenError::Keys(KeyError::Unavailable).challenge().is_none());
/// # Ok::<(), piquel_auth::protocol::oauth::InvalidScope>(())
/// ```
#[derive(Debug, Error)]
pub enum TokenError {
    /// The token is not a compact JWS.
    #[error("token is malformed: {0}")]
    Malformed(&'static str),
    /// The header lists `crit` extensions, which this SDK does not understand.
    #[error("token requires header extensions this SDK does not understand")]
    UnsupportedCriticalHeader,
    /// The `typ` header is not the one expected.
    #[error("token type is {found:?}, expected {expected}")]
    WrongType {
        /// The type required here.
        expected: TokenType,
        /// The type sent, if any.
        found: Option<String>,
    },
    /// `alg` is not allowed by both the issuer and the SDK.
    #[error("token algorithm {0:?} is not accepted")]
    UnsupportedAlgorithm(String),
    /// No usable key matches `kid`, even after a refetch.
    #[error("no signing key matches key ID {0:?}")]
    UnknownKey(Option<String>),
    /// Keys were needed but could not be fetched.
    #[error("signing keys are unavailable")]
    Keys(#[source] KeyError),
    /// The signature does not verify.
    #[error("token signature is invalid")]
    BadSignature,
    /// Claims are missing or have the wrong type.
    #[error("token claims are invalid")]
    InvalidClaims(#[source] serde_json::Error),
    /// `sub` is neither an account ID nor the client.
    #[error("token subject {0:?} is not an account ID")]
    InvalidSubject(String),
    /// `iss` is not the issuer.
    #[error("token issuer is {found:?}, expected {expected:?}")]
    WrongIssuer {
        /// The configured issuer.
        expected: String,
        /// The token's `iss`.
        found: String,
    },
    /// `aud` does not contain the expected value.
    #[error("token audience {found:?} does not contain {expected:?}")]
    WrongAudience {
        /// The resource or client this token must be for.
        expected: String,
        /// The token's `aud`.
        found: Audience,
    },
    /// `exp` has passed, beyond the leeway.
    #[error("token expired at {0}")]
    Expired(DateTime<Utc>),
    /// `nbf` is in the future, beyond the leeway.
    #[error("token is not valid before {0}")]
    NotYetValid(DateTime<Utc>),
    /// `iat` is in the future, beyond the leeway.
    #[error("token is issued in the future, at {0}")]
    IssuedInFuture(DateTime<Utc>),
    /// The ID token's `nonce` is not the pending login's.
    #[error("ID token nonce does not match this login")]
    NonceMismatch,
    /// The ID token's `azp` names another client.
    #[error("ID token authorized party is {found:?}, expected {expected:?}")]
    WrongAuthorizedParty {
        /// This client.
        expected: ClientId,
        /// The token's `azp`.
        found: ClientId,
    },
    /// `auth_time` is missing or older than the requested `max_age`.
    #[error("authentication at {auth_time:?} is older than {max_age} seconds")]
    AuthenticationTooOld {
        /// When the user authenticated, if the token says.
        auth_time: Option<DateTime<Utc>>,
        /// The longest acceptable age, in seconds.
        max_age: u32,
    },
    /// The user's authentication is too weak or too old for the request (RFC 9470).
    #[error("authentication does not meet {0:?}")]
    InsufficientUserAuthentication(StepUpRequirement),
    /// A valid token lacks scopes the request needs.
    #[error("token lacks the scopes {required}")]
    InsufficientScope {
        /// Every scope the request needs, granted or not.
        required: Scopes,
    },
}

impl TokenError {
    /// The shared SDK error code.
    #[must_use]
    pub const fn code(&self) -> SdkError {
        let reason = match self {
            Self::Keys(error) => return error.code(),
            Self::InsufficientScope { .. } => {
                return SdkError::category(ErrorCategory::InsufficientScope);
            }
            Self::InsufficientUserAuthentication(_) => {
                return SdkError::category(ErrorCategory::InsufficientUserAuthentication);
            }
            Self::Malformed(_) => ErrorReason::Malformed,
            Self::UnsupportedCriticalHeader => ErrorReason::UnsupportedCriticalHeader,
            Self::WrongType { .. } => ErrorReason::WrongType,
            Self::UnsupportedAlgorithm(_) => ErrorReason::UnsupportedAlgorithm,
            Self::UnknownKey(_) => ErrorReason::UnknownKey,
            Self::BadSignature => ErrorReason::BadSignature,
            Self::InvalidClaims(_) | Self::InvalidSubject(_) => ErrorReason::InvalidClaims,
            Self::WrongIssuer { .. } => ErrorReason::IssuerMismatch,
            Self::WrongAudience { .. } => ErrorReason::WrongAudience,
            Self::Expired(_) => ErrorReason::Expired,
            Self::NotYetValid(_) => ErrorReason::NotYetValid,
            Self::IssuedInFuture(_) => ErrorReason::IssuedInFuture,
            Self::NonceMismatch => ErrorReason::NonceMismatch,
            Self::WrongAuthorizedParty { .. } => ErrorReason::WrongAuthorizedParty,
            Self::AuthenticationTooOld { .. } => ErrorReason::AuthenticationTooOld,
        };
        SdkError::new(ErrorCategory::InvalidToken, reason)
    }

    /// The challenge a resource server answers with (RFC 6750 §3), or `None` when keys
    /// could not be fetched: that is the server's failure, not the client's, and
    /// deserves a 503 rather than a challenge the client cannot satisfy.
    #[must_use]
    pub fn challenge(&self) -> Option<BearerChallenge> {
        match self {
            Self::Keys(_) => None,
            Self::InsufficientScope { required } => Some(BearerChallenge {
                scope: Some(required.clone()),
                ..BearerChallenge::error(BearerError::InsufficientScope)
            }),
            Self::InsufficientUserAuthentication(requirement) => {
                Some(BearerChallenge::step_up(*requirement))
            }
            _ => Some(BearerChallenge::error(BearerError::InvalidToken)),
        }
    }

    /// Requires the authentication `acr` and `auth_time` describe to meet
    /// `requirement` at `now`, allowing the leeway on `auth_time`.
    fn require_authentication(
        requirement: StepUpRequirement,
        acr: Option<&Acr>,
        auth_time: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<(), Self> {
        requirement
            .check(acr, auth_time, now - LEEWAY)
            .map_err(Self::InsufficientUserAuthentication)
    }
}

/// What an operation needs from the user's authentication, named as a type so
/// extractors can require it. Declare one per policy:
///
/// ```
/// use chrono::{TimeDelta, Utc};
/// use piquel_auth::{Acr, AuthenticationPolicy, StepUpRequirement, TokenError};
///
/// /// A passkey confirmation within the last five minutes.
/// struct RecentPasskey;
///
/// impl AuthenticationPolicy for RecentPasskey {
///     const REQUIREMENT: StepUpRequirement = StepUpRequirement::passkey_within(300);
/// }
///
/// let error = TokenError::InsufficientUserAuthentication(RecentPasskey::REQUIREMENT);
/// assert_eq!(
///     error.challenge().map(|challenge| challenge.to_string()).as_deref(),
///     Some(r#"Bearer error="insufficient_user_authentication", acr_values="phr", max_age="300""#)
/// );
/// ```
///
/// A token meets the policy as auth would judge the session behind it
/// ([`StepUpRequirement::check`]), with the 30-second leeway on `auth_time`: `phr`
/// meets a social requirement too.
pub trait AuthenticationPolicy: Send + Sync + 'static {
    /// What the operation needs.
    const REQUIREMENT: StepUpRequirement;
}

/// Who an access token acts for.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Subject {
    /// A user's account.
    User(UserId),
    /// The client itself, with no user (client credentials, RFC 9068 §2.2).
    Client(ClientId),
}

/// A validated access token. `S` proves which scopes it holds: [`Scopes`] keeps the
/// granted list, while a [`scopes!`](crate::scopes) marker or tuple proves those
/// scopes are present. `X` holds application claims.
///
/// ```
/// use chrono::{TimeDelta, Utc};
/// use piquel_auth::{AccessToken, ClientId, ProfileClaims, Scopes, Subject};
///
/// piquel_auth::scopes! {
///     /// Scopes of the notes API.
///     pub mod notes {
///         Read = "notes:read",
///         Write = "notes:write",
///     }
/// }
///
/// // Normally returned by `ResourceValidator::validate`.
/// let token: AccessToken = AccessToken {
///     subject: Subject::User("01936f3e-8c00-7000-8000-000000000001".parse()?),
///     client_id: ClientId::new("notes-web"),
///     scopes: "openid notes:read".parse()?,
///     token_id: "01936f3e-8c00-7000-8000-000000000003".parse()?,
///     session_id: None,
///     auth_time: None,
///     amr: Vec::new(),
///     acr: None,
///     actor: None,
///     confirmation: None,
///     profile: ProfileClaims::default(),
///     issued_at: Utc::now(),
///     expires_at: Utc::now() + TimeDelta::minutes(5),
///     extra: (),
/// };
/// let readable = token.require::<notes::Read>()?;
/// assert_eq!(readable.scopes, notes::Read);
/// assert!(token.require::<(notes::Read, notes::Write)>().is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessToken<S = Scopes, X = ()> {
    /// Who the token acts for.
    pub subject: Subject,
    /// Client that requested the token.
    pub client_id: ClientId,
    /// The scopes proven present.
    pub scopes: S,
    /// Unique token ID, for replay detection.
    pub token_id: TokenId,
    /// Browser session behind the token, when a user signed in.
    pub session_id: Option<SessionId>,
    /// When the user authenticated.
    pub auth_time: Option<DateTime<Utc>>,
    /// How the user authenticated (RFC 8176); values this version does not know are
    /// dropped.
    pub amr: Vec<Amr>,
    /// The authentication context class reached; a class this version does not know
    /// reads as none.
    pub acr: Option<Acr>,
    /// Who is acting for the subject, for exchanged tokens.
    pub actor: Option<Actor>,
    /// The key the token is bound to, for sender-constrained tokens.
    pub confirmation: Option<Confirmation>,
    /// Profile and email claims allowed by the granted scopes.
    pub profile: ProfileClaims,
    /// When the token was issued.
    pub issued_at: DateTime<Utc>,
    /// When the token expires.
    pub expires_at: DateTime<Utc>,
    /// Application claims.
    pub extra: X,
}

impl<S, X> AccessToken<S, X> {
    /// Requires the token's authentication to meet `requirement` at `now`; use the
    /// issuer's clock, as [`ResourceValidator::now`](crate::ResourceValidator::now)
    /// gives.
    ///
    /// # Errors
    /// [`TokenError::InsufficientUserAuthentication`], whose challenge asks the
    /// client to sign the user in again (RFC 9470).
    pub fn require_authentication(
        &self,
        requirement: StepUpRequirement,
        now: DateTime<Utc>,
    ) -> Result<(), TokenError> {
        TokenError::require_authentication(requirement, self.acr.as_ref(), self.auth_time, now)
    }
}

impl<X> AccessToken<Scopes, X> {
    /// Converts validated claims. A `sub` equal to `client_id` with no session is the
    /// client itself; any other `sub` must be an account ID.
    pub(crate) fn from_claims(claims: AccessTokenClaims<X>) -> Result<Self, TokenError> {
        let session_id = claims.authentication.sid;
        let subject = if session_id.is_none() && claims.sub == claims.client_id.as_str() {
            Subject::Client(claims.client_id.clone())
        } else {
            Subject::User(
                claims
                    .sub
                    .parse()
                    .map_err(|_| TokenError::InvalidSubject(claims.sub.clone()))?,
            )
        };
        Ok(Self {
            subject,
            client_id: claims.client_id,
            scopes: claims.scope,
            token_id: claims.jti,
            session_id,
            auth_time: claims.authentication.auth_time,
            amr: claims.authentication.amr,
            acr: claims.authentication.acr,
            actor: claims.act,
            confirmation: claims.cnf,
            profile: claims.profile,
            issued_at: claims.iat,
            expires_at: claims.exp,
            extra: claims.extra,
        })
    }

    /// Requires the scopes `S`, returning the token with their proof.
    ///
    /// # Errors
    /// [`TokenError::InsufficientScope`], naming every scope `S` requires.
    pub fn require<S: ScopeSet>(&self) -> Result<AccessToken<S, X>, TokenError>
    where
        X: Clone,
    {
        self.clone().into_scoped()
    }

    /// Like [`Self::require`], consuming the token.
    pub(crate) fn into_scoped<S: ScopeSet>(self) -> Result<AccessToken<S, X>, TokenError> {
        let scopes =
            S::from_granted(&self.scopes).ok_or_else(|| TokenError::InsufficientScope {
                required: S::required(),
            })?;
        Ok(AccessToken {
            subject: self.subject,
            client_id: self.client_id,
            scopes,
            token_id: self.token_id,
            session_id: self.session_id,
            auth_time: self.auth_time,
            amr: self.amr,
            acr: self.acr,
            actor: self.actor,
            confirmation: self.confirmation,
            profile: self.profile,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            extra: self.extra,
        })
    }
}

/// A validated ID token, kept with its compact form for logout's `id_token_hint`.
/// It serializes so a server-side session can store it; deserializing does not
/// validate it again.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdToken {
    /// The validated claims.
    claims: IdTokenClaims,
    /// The token as issued.
    raw: String,
}

impl std::fmt::Debug for IdToken {
    /// Shows the claims, never the token itself, which is a credential.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdToken")
            .field("claims", &self.claims)
            .finish_non_exhaustive()
    }
}

impl IdToken {
    /// The validated claims.
    #[must_use]
    pub const fn claims(&self) -> &IdTokenClaims {
        &self.claims
    }

    /// The token as issued.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Requires the sign-in to meet `requirement` at `now`, with the leeway on
    /// `auth_time`.
    ///
    /// # Errors
    /// [`TokenError::InsufficientUserAuthentication`].
    pub fn require_authentication(
        &self,
        requirement: StepUpRequirement,
        now: DateTime<Utc>,
    ) -> Result<(), TokenError> {
        let authentication = &self.claims.authentication;
        TokenError::require_authentication(
            requirement,
            authentication.acr.as_ref(),
            authentication.auth_time,
            now,
        )
    }

    /// The signed-in account.
    ///
    /// # Errors
    /// [`TokenError::InvalidSubject`] if `sub` is not an account ID.
    pub fn user_id(&self) -> Result<UserId, TokenError> {
        self.claims
            .sub
            .parse()
            .map_err(|_| TokenError::InvalidSubject(self.claims.sub.clone()))
    }
}

/// The registered claims every token type checks the same way.
pub(crate) trait RegisteredClaims: DeserializeOwned {
    /// `iss`.
    fn issuer(&self) -> &str;
    /// `aud`.
    fn audience(&self) -> &Audience;
    /// `exp`.
    fn expires_at(&self) -> DateTime<Utc>;
    /// `nbf`, if any.
    fn not_before(&self) -> Option<DateTime<Utc>>;
    /// `iat`.
    fn issued_at(&self) -> DateTime<Utc>;

    /// Whether `aud` must name the expected audience alone. ID tokens trust no other
    /// audience (OIDC Core §3.1.3.7), so `azp` can only confirm this client; access
    /// tokens may name several.
    const EXCLUSIVE_AUDIENCE: bool;

    /// Checks `iss`, `aud` and the times, in the documented order.
    fn check(&self, issuer: &str, audience: &str, now: DateTime<Utc>) -> Result<(), TokenError> {
        if self.issuer() != issuer {
            return Err(TokenError::WrongIssuer {
                expected: issuer.to_owned(),
                found: self.issuer().to_owned(),
            });
        }
        let others =
            Self::EXCLUSIVE_AUDIENCE && self.audience().iter().any(|value| value != audience);
        if others || !self.audience().contains(audience) {
            return Err(TokenError::WrongAudience {
                expected: audience.to_owned(),
                found: self.audience().clone(),
            });
        }
        // Checked: a far-future `exp` must not overflow, and never expires.
        if self
            .expires_at()
            .checked_add_signed(LEEWAY)
            .is_some_and(|deadline| now >= deadline)
        {
            return Err(TokenError::Expired(self.expires_at()));
        }
        if let Some(not_before) = self.not_before().filter(|nbf| *nbf > now + LEEWAY) {
            return Err(TokenError::NotYetValid(not_before));
        }
        if self.issued_at() > now + LEEWAY {
            return Err(TokenError::IssuedInFuture(self.issued_at()));
        }
        Ok(())
    }
}

impl<X: DeserializeOwned> RegisteredClaims for AccessTokenClaims<X> {
    const EXCLUSIVE_AUDIENCE: bool = false;

    fn issuer(&self) -> &str {
        &self.iss
    }
    fn audience(&self) -> &Audience {
        &self.aud
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.exp
    }
    fn not_before(&self) -> Option<DateTime<Utc>> {
        self.nbf
    }
    fn issued_at(&self) -> DateTime<Utc> {
        self.iat
    }
}

impl RegisteredClaims for IdTokenClaims {
    const EXCLUSIVE_AUDIENCE: bool = true;

    fn issuer(&self) -> &str {
        &self.iss
    }
    fn audience(&self) -> &Audience {
        &self.aud
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.exp
    }
    fn not_before(&self) -> Option<DateTime<Utc>> {
        self.nbf
    }
    fn issued_at(&self) -> DateTime<Utc> {
        self.iat
    }
}

impl Issuer {
    /// Algorithms both this SDK and the issuer accept.
    fn algorithms(&self) -> Vec<Algorithm> {
        Algorithm::ALL
            .into_iter()
            .filter(|algorithm| {
                self.metadata()
                    .id_token_signing_alg_values_supported
                    .contains(algorithm)
            })
            .collect()
    }

    /// Runs the shared checks on a token of type `typ` meant for `audience`, in the
    /// order of the SDK design: framing, type, algorithm, key, signature, claims.
    pub(crate) async fn decode<T: RegisteredClaims>(
        &self,
        token: &str,
        typ: TokenType,
        audience: &str,
    ) -> Result<T, TokenError> {
        let jws = Jws::parse(token)?;
        jws.require_type(typ)?;
        let algorithm = jws.require_algorithm(&self.algorithms())?;
        self.keys().verify(&jws, algorithm).await?;
        let claims: T = serde_json::from_slice(jws.payload()).map_err(TokenError::InvalidClaims)?;
        claims.check(self.issuer(), audience, self.now())?;
        Ok(claims)
    }

    /// Validates an ID token for `client`, against the pending login's `nonce` and
    /// `max_age` when it sent them.
    pub(crate) async fn id_token(
        &self,
        token: &str,
        client: &ClientId,
        nonce: Option<&str>,
        max_age: Option<u32>,
    ) -> Result<IdToken, TokenError> {
        let claims: IdTokenClaims = self.decode(token, TokenType::Id, client.as_str()).await?;
        if nonce.is_some_and(|nonce| claims.nonce.as_deref() != Some(nonce)) {
            return Err(TokenError::NonceMismatch);
        }
        if let Some(azp) = claims.azp.as_ref().filter(|azp| *azp != client) {
            return Err(TokenError::WrongAuthorizedParty {
                expected: client.clone(),
                found: azp.clone(),
            });
        }
        if let Some(max_age) = max_age {
            let requirement = StepUpRequirement {
                acr: None,
                max_age: Some(max_age),
            };
            let auth_time = claims.authentication.auth_time;
            if requirement
                .check(None, auth_time, self.now() - LEEWAY)
                .is_err()
            {
                return Err(TokenError::AuthenticationTooOld {
                    auth_time: claims.authentication.auth_time,
                    max_age,
                });
            }
        }
        Ok(IdToken {
            claims,
            raw: token.to_owned(),
        })
    }
}
