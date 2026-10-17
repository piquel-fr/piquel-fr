//! Validated tokens, the checks they pass, and why a token is rejected.

use crate::{Issuer, KeyError, LEEWAY, keys::Jws, scope::ScopeSet};
use chrono::{DateTime, TimeDelta, Utc};
use piquel_auth_protocol::{
    ClientId, SessionId, TokenId, UserId,
    challenge::{BearerChallenge, BearerError},
    claims::{
        AccessTokenClaims, Acr, Actor, Amr, Audience, BACKCHANNEL_LOGOUT_EVENT, Confirmation,
        IdTokenClaims, LogoutTokenClaims, ProfileClaims,
    },
    jwt::{Algorithm, TokenType},
    oauth::Scopes,
    sdk::{ErrorCategory, ErrorReason, SdkError},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Why a token was rejected. [`Self::code`] gives the shared SDK code, and
/// [`Self::challenge`] the `WWW-Authenticate` value a resource server answers with.
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
        max_age: u64,
    },
    /// A logout token breaks a back-channel logout rule.
    #[error("logout token is invalid: {0}")]
    InvalidLogoutToken(&'static str),
    /// The user's authentication is too weak or too old for the request (RFC 9470).
    #[error("authentication does not meet acr {acr:?} within {max_age:?} seconds")]
    InsufficientUserAuthentication {
        /// The authentication context class required.
        acr: Option<Acr>,
        /// The longest acceptable time since authentication, in seconds.
        max_age: Option<u64>,
    },
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
            Self::InsufficientUserAuthentication { .. } => {
                return SdkError::category(ErrorCategory::InsufficientUserAuthentication);
            }
            Self::Malformed(_) => ErrorReason::Malformed,
            Self::UnsupportedCriticalHeader => ErrorReason::UnsupportedCriticalHeader,
            Self::WrongType { .. } => ErrorReason::WrongType,
            Self::UnsupportedAlgorithm(_) => ErrorReason::UnsupportedAlgorithm,
            Self::UnknownKey(_) => ErrorReason::UnknownKey,
            Self::BadSignature => ErrorReason::BadSignature,
            Self::InvalidClaims(_) | Self::InvalidSubject(_) | Self::InvalidLogoutToken(_) => {
                ErrorReason::InvalidClaims
            }
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
            Self::InsufficientUserAuthentication { acr, max_age } => Some(BearerChallenge {
                acr_values: acr.iter().cloned().collect(),
                max_age: *max_age,
                ..BearerChallenge::error(BearerError::InsufficientUserAuthentication)
            }),
            _ => Some(BearerChallenge::error(BearerError::InvalidToken)),
        }
    }
}

impl TokenError {
    /// Whether `auth_time` is at most `max_age` seconds, plus the leeway, before `now`.
    /// A `max_age` too large to add to `auth_time` cannot be exceeded.
    fn recent(auth_time: Option<DateTime<Utc>>, max_age: u64, now: DateTime<Utc>) -> bool {
        auth_time.is_some_and(|auth_time| {
            i64::try_from(max_age)
                .ok()
                .and_then(TimeDelta::try_seconds)
                .and_then(|age| age.checked_add(&LEEWAY))
                .and_then(|age| auth_time.checked_add_signed(age))
                .is_none_or(|deadline| now <= deadline)
        })
    }

    /// Requires the authentication `acr` and `auth_time` describe to meet `P` at `now`.
    fn require_authentication<P: AuthenticationPolicy>(
        acr: Option<&Acr>,
        auth_time: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<(), Self> {
        let strong = P::ACR.as_ref().is_none_or(|required| acr == Some(required));
        let fresh = P::MAX_AGE.is_none_or(|max_age| Self::recent(auth_time, max_age, now));
        if strong && fresh {
            Ok(())
        } else {
            Err(Self::InsufficientUserAuthentication {
                acr: P::ACR,
                max_age: P::MAX_AGE,
            })
        }
    }
}

/// What an operation needs from the user's authentication (RFC 9470): an
/// authentication context class, a maximum age, or both. Declare one per policy:
///
/// ```
/// use piquel_auth::{Acr, AuthenticationPolicy};
///
/// /// A passkey confirmation within the last five minutes.
/// struct RecentPasskey;
///
/// impl AuthenticationPolicy for RecentPasskey {
///     const ACR: Option<Acr> = Some(Acr::PhishingResistant);
///     const MAX_AGE: Option<u64> = Some(300);
/// }
/// ```
///
/// A token meets the policy when its `acr` equals `ACR` and its `auth_time` is at
/// most `MAX_AGE` seconds old, with the 30-second leeway.
pub trait AuthenticationPolicy: Send + Sync + 'static {
    /// The authentication context class required, if any.
    const ACR: Option<Acr> = None;
    /// The longest acceptable time since the user authenticated, in seconds, if any.
    const MAX_AGE: Option<u64> = None;
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
    /// How the user authenticated (RFC 8176); unknown values are kept as `Other`.
    pub amr: Vec<Amr>,
    /// The authentication context class reached; unknown values are kept as `Other`.
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

    /// Requires the token's authentication to meet `P` at `now`; use the issuer's
    /// clock, as [`ResourceValidator::now`](crate::ResourceValidator::now) gives.
    ///
    /// # Errors
    /// [`TokenError::InsufficientUserAuthentication`], whose challenge asks the
    /// client to sign the user in again (RFC 9470).
    pub fn require_authentication<P: AuthenticationPolicy>(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), TokenError> {
        TokenError::require_authentication::<P>(self.acr.as_ref(), self.auth_time, now)
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

    /// Requires the sign-in to meet `P` at `now`.
    ///
    /// # Errors
    /// [`TokenError::InsufficientUserAuthentication`].
    pub fn require_authentication<P: AuthenticationPolicy>(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), TokenError> {
        let authentication = &self.claims.authentication;
        TokenError::require_authentication::<P>(
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

    /// Whether `aud` must name the expected audience alone. ID and logout tokens trust
    /// no other audience (OIDC Core §3.1.3.7), so `azp` can only confirm this client;
    /// access tokens may name several.
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

impl RegisteredClaims for LogoutTokenClaims {
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
        None
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
        max_age: Option<u64>,
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
        if let Some(max_age) = max_age
            && !TokenError::recent(claims.authentication.auth_time, max_age, self.now())
        {
            return Err(TokenError::AuthenticationTooOld {
                auth_time: claims.authentication.auth_time,
                max_age,
            });
        }
        Ok(IdToken {
            claims,
            raw: token.to_owned(),
        })
    }

    /// Validates a back-channel logout token for `client`: checked like an ID token,
    /// then required to be recent, to carry the logout event and `sub` or `sid`, and
    /// to have no `nonce` (OIDC Back-Channel Logout 1.0 §2.6).
    pub(crate) async fn logout_token(
        &self,
        token: &str,
        client: &ClientId,
    ) -> Result<LogoutTokenClaims, TokenError> {
        let claims: LogoutTokenClaims = self
            .decode(token, TokenType::Logout, client.as_str())
            .await?;
        let invalid = |rule| Err(TokenError::InvalidLogoutToken(rule));
        if claims
            .iat
            .checked_add_signed(MAX_LOGOUT_TOKEN_AGE + LEEWAY)
            .is_some_and(|deadline| deadline < self.now())
        {
            return invalid("iat is more than five minutes ago");
        }
        if !claims.events.contains_key(BACKCHANNEL_LOGOUT_EVENT) {
            return invalid("events lacks the back-channel logout event");
        }
        if claims.nonce.is_some() {
            return invalid("nonce must be absent");
        }
        if claims.sub.is_none() && claims.sid.is_none() {
            return invalid("neither sub nor sid is present");
        }
        Ok(claims)
    }
}

/// Oldest `iat` a logout token may have. Auth signs each delivery attempt afresh, so
/// an older token is a replay.
const MAX_LOGOUT_TOKEN_AGE: TimeDelta = TimeDelta::minutes(5);
