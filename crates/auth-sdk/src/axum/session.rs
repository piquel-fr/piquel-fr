//! What the browser's cookies hold: the signed-in user's session, and each login
//! waiting for its callback. Both are sealed with the app's
//! [`CookieKey`](super::CookieKey); nothing is kept server-side.

use super::ReturnTo;
use crate::{
    BearerToken, IdToken, PendingLogin, RefreshToken, Scopes, SessionId, Tokens,
    protocol::claims::IdTokenClaims,
};
use chrono::{DateTime, Utc, serde::ts_seconds};
use serde::{Deserialize, Serialize};

/// A signed-in user's session, as its sealed cookie holds it: the access token and
/// the refresh token, and the claims of the sign-in's ID token, but not the token
/// itself, so the cookie stays small. Its tokens are reached through methods, and it
/// does not serialize, so the refresh token cannot reach a browser by way of a
/// handler's `Json`.
///
/// ```no_run
/// # async fn run(user: piquel_auth::axum::SignedIn) -> Result<(), reqwest::Error> {
/// // Call an API for the user with their access token, refreshed by the login layer.
/// let notes = reqwest::Client::new()
///     .get("https://notes.piquel.fr/api/notes")
///     .bearer_auth(user.login().access_token().expose())
///     .send()
///     .await?;
/// # Ok(()) }
/// ```
#[derive(Clone, Debug)]
pub struct StoredLogin(pub(super) LoginData);

/// What a [`StoredLogin`] holds, as the session cookie stores it. Every SDK reads and
/// writes this shape, which `tests/sdk-vectors/sessions` pins.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct LoginData {
    /// The validated claims of the sign-in's ID token, or of the latest refresh that
    /// returned one.
    claims: IdTokenClaims,
    /// The latest access token.
    access_token: BearerToken,
    /// When the access token expires.
    #[serde(with = "ts_seconds")]
    expires_at: DateTime<Utc>,
    /// Scopes granted to the access token.
    scopes: Scopes,
    /// The refresh token. A confidential client's does not rotate, so every copy of
    /// the cookie stays usable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<RefreshToken>,
    /// When the session ends, checked as well as the cookie's `Max-Age`, which a
    /// copied cookie escapes.
    #[serde(with = "ts_seconds")]
    ends_at: DateTime<Utc>,
}

impl StoredLogin {
    /// The session `tokens` start, ending at `ends_at`, if they hold the ID token every
    /// sign-in returns. Without a refresh token, the session cannot learn that auth
    /// revoked it, so it ends with its access token.
    pub(super) fn new(tokens: Tokens, ends_at: DateTime<Utc>) -> Option<Self> {
        let ends_at = if tokens.refresh_token.is_some() {
            ends_at
        } else {
            ends_at.min(tokens.expires_at)
        };
        Some(Self(LoginData {
            claims: tokens.id_token.map(IdToken::into_claims)?,
            access_token: tokens.access_token,
            expires_at: tokens.expires_at,
            scopes: tokens.scopes,
            refresh_token: tokens.refresh_token,
            ends_at,
        }))
    }

    /// This session after a refresh returned `tokens`. An absent ID token or refresh
    /// token keeps the current one. `None` if a new ID token names another user or
    /// issuer (OIDC Core §12.2).
    pub(super) fn refreshed(&self, tokens: Tokens) -> Option<Self> {
        let current = &self.0;
        let claims = match tokens.id_token {
            Some(id_token) => {
                let claims = id_token.into_claims();
                (claims.sub == current.claims.sub && claims.iss == current.claims.iss)
                    .then_some(claims)?
            }
            None => current.claims.clone(),
        };
        Some(Self(LoginData {
            claims,
            access_token: tokens.access_token,
            expires_at: tokens.expires_at,
            scopes: tokens.scopes,
            refresh_token: tokens
                .refresh_token
                .or_else(|| current.refresh_token.clone()),
            ends_at: current.ends_at,
        }))
    }

    /// The validated claims of the sign-in's ID token, or of the latest refresh that
    /// returned one.
    #[must_use]
    pub const fn claims(&self) -> &IdTokenClaims {
        &self.0.claims
    }

    /// The latest access token, to call APIs for the user.
    #[must_use]
    pub const fn access_token(&self) -> &BearerToken {
        &self.0.access_token
    }

    /// When the access token expires.
    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.0.expires_at
    }

    /// Scopes granted to the access token.
    #[must_use]
    pub const fn scopes(&self) -> &Scopes {
        &self.0.scopes
    }

    /// When the session ends, whatever happens at auth.
    #[must_use]
    pub const fn ends_at(&self) -> DateTime<Utc> {
        self.0.ends_at
    }

    /// The user's `sub`.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.0.claims.sub
    }

    /// Auth's session ID, if the ID token carries one: what a back-channel logout
    /// names.
    #[must_use]
    pub const fn sid(&self) -> Option<SessionId> {
        self.0.claims.authentication.sid
    }

    /// The refresh token, which only the SDK redeems.
    pub(super) const fn refresh_token(&self) -> Option<&RefreshToken> {
        self.0.refresh_token.as_ref()
    }
}

/// A login waiting for its callback, with where to send the user afterwards. The
/// browser keeps it, sealed, in a cookie named for its `state`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PendingAuthorization {
    /// The PKCE verifier, `state` and `nonce` of the login.
    pub(super) login: PendingLogin,
    /// Where the user goes once signed in.
    pub(super) return_to: ReturnTo,
    /// Whether the login steps up, so the return to `return_to` is its retry.
    pub(super) step_up: bool,
    /// When the login expires, checked as well as the cookie's `Max-Age`, which a
    /// copied cookie escapes.
    pub(super) expires_at: DateTime<Utc>,
}
