//! Session storage. Applications implement [`SessionBackend`], four plain operations
//! on opaque records, wherever they want to keep sessions. The SDK keeps everything
//! else: the record format, its sealing and validation, expiry, the refresh lease
//! that stops two requests from redeeming one refresh token, and the indexes
//! back-channel logout finds sessions with.

/// The storage interface applications implement, and the in-memory backend.
mod backend;
/// The SDK's session logic over a backend.
mod store;
/// `check_backend`, for testing an application's backend.
#[cfg(any(test, feature = "test-util"))]
mod test_util;

pub(crate) use backend::BackendError;
pub use backend::{MemoryBackend, SessionBackend, SessionRecord};
pub(crate) use store::{Lease, LeaseId, Session, Sessions};
#[cfg(any(test, feature = "test-util"))]
pub use test_util::{BackendCheckError, check_backend};

use super::ReturnTo;
use crate::{BearerToken, IdToken, PendingLogin, RefreshToken, Scopes, SessionId, Tokens};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Random bytes in a session key: 256 bits.
const KEY_BYTES: usize = 32;

/// A signed-in user's tokens, kept server-side. Its tokens are reached through
/// methods, and it does not serialize, so the refresh token cannot reach a browser
/// by way of a handler's `Json`.
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
pub struct StoredLogin(LoginData);

/// What a [`StoredLogin`] holds, as the sealed session record stores it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct LoginData {
    /// The issuer the user signed in with.
    issuer: String,
    /// The validated ID token of the sign-in, or of the latest refresh that sent one.
    id_token: IdToken,
    /// The latest access token.
    access_token: BearerToken,
    /// When the access token expires.
    expires_at: DateTime<Utc>,
    /// Scopes granted to the access token.
    scopes: Scopes,
    /// The refresh token, with `offline_access`. Auth rotates it on every refresh.
    refresh_token: Option<RefreshToken>,
}

impl StoredLogin {
    /// The login `tokens` describe, if they hold the ID token every sign-in returns.
    pub(super) fn new(issuer: String, tokens: Tokens) -> Option<Self> {
        Some(Self(LoginData {
            issuer,
            id_token: tokens.id_token?,
            access_token: tokens.access_token,
            expires_at: tokens.expires_at,
            scopes: tokens.scopes,
            refresh_token: tokens.refresh_token,
        }))
    }

    /// This login after a refresh returned `tokens`. An absent ID token or refresh
    /// token keeps the current one. `None` if a new ID token names another user or
    /// issuer (OIDC Core §12.2).
    pub(super) fn refreshed(&self, tokens: Tokens) -> Option<Self> {
        let current = &self.0;
        let same = |id_token: &IdToken| {
            let (new, old) = (id_token.claims(), current.id_token.claims());
            new.sub == old.sub && new.iss == old.iss
        };
        if tokens
            .id_token
            .as_ref()
            .is_some_and(|id_token| !same(id_token))
        {
            return None;
        }
        Some(Self(LoginData {
            issuer: current.issuer.clone(),
            id_token: tokens.id_token.unwrap_or_else(|| current.id_token.clone()),
            access_token: tokens.access_token,
            expires_at: tokens.expires_at,
            scopes: tokens.scopes,
            refresh_token: tokens
                .refresh_token
                .or_else(|| current.refresh_token.clone()),
        }))
    }

    /// The issuer the user signed in with.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.0.issuer
    }

    /// The validated ID token of the sign-in, or of the latest refresh that sent one.
    #[must_use]
    pub const fn id_token(&self) -> &IdToken {
        &self.0.id_token
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

    /// The refresh token, which only the SDK redeems.
    pub(super) const fn refresh_token(&self) -> Option<&RefreshToken> {
        self.0.refresh_token.as_ref()
    }

    /// The user's `sub`.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.0.id_token.claims().sub
    }

    /// Auth's session ID, if the ID token carries one.
    #[must_use]
    pub fn sid(&self) -> Option<SessionId> {
        self.0.id_token.claims().authentication.sid
    }
}

/// A session's random key, held by the browser in a cookie. Backends see only its
/// SHA-256, and the record under it is sealed with a key derived from it, so reading
/// the backend gives neither sessions nor tokens.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct SessionKey(String);

impl fmt::Debug for SessionKey {
    /// Never prints the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionKey(REDACTED)")
    }
}

impl SessionKey {
    /// A fresh random key.
    pub(super) fn generate() -> Result<Self, rand::Error> {
        Ok(Self(random(KEY_BYTES)?))
    }

    /// A key read from a cookie, if it has the shape of one.
    pub(super) fn parse(value: &str) -> Option<Self> {
        URL_SAFE_NO_PAD
            .decode(value)
            .ok()
            .filter(|bytes| bytes.len() == KEY_BYTES)
            .map(|_| Self(value.to_owned()))
    }

    /// The key as sent in the cookie.
    pub(super) fn as_cookie(&self) -> &str {
        &self.0
    }

    /// The key's text, the secret its record's name and sealing key derive from.
    fn secret(&self) -> &str {
        &self.0
    }
}

/// The backend key of the record of `kind` for `parts`: their SHA-256, joined by NUL,
/// never the values themselves, namespaced by `kind` so record kinds never collide.
fn hashed(kind: &str, parts: &[&str]) -> String {
    let digest = Sha256::digest(parts.join("\0"));
    format!("{kind}:{}", URL_SAFE_NO_PAD.encode(digest))
}

/// `bytes` random bytes, base64url-encoded.
fn random(bytes: usize) -> Result<String, rand::Error> {
    let mut buffer = vec![0; bytes];
    OsRng.try_fill_bytes(&mut buffer)?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
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
