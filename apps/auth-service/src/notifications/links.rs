//! The links of notifications' emails that work without signing in: turning
//! announcements' email off, and signing the account out everywhere. Each names
//! an ID and a token derived from it under a key of its own, so nothing is
//! stored. A change of key keeps the links of the accepted key working until it
//! is dropped.

use crate::{config::LinkKeys, routes::page};
use serde::{Deserialize, Serialize};
use sourceorigin_common::{NotificationId, UserId, config::Origin};
use sourceorigin_crypto::{CryptoError, Secret};
use std::{fmt::Display, marker::PhantomData};

/// What a link of a notification's email names, and the page it opens.
pub(crate) trait LinkTarget: Copy + Display {
    /// The page the link opens.
    const PAGE: &'static str;

    /// The bytes its token is derived from.
    fn bytes(self) -> [u8; 16];
}

impl LinkTarget for UserId {
    /// An account's link turns its announcements' email off. It never expires:
    /// whoever holds it can only turn that email off, which the owner sees in
    /// their history and turns back on in their settings.
    const PAGE: &'static str = page::UNSUBSCRIBE;

    fn bytes(self) -> [u8; 16] {
        self.as_uuid().into_bytes()
    }
}

impl LinkTarget for NotificationId {
    /// A security notification's link signs its account out everywhere, once,
    /// within [`super::SIGN_OUT_LINK_LIFETIME`].
    const PAGE: &'static str = page::SIGN_OUT;

    fn bytes(self) -> [u8; 16] {
        self.as_uuid().into_bytes()
    }
}

/// The links naming a `T`, on auth's origin.
pub(crate) struct Links<T> {
    /// Auth's origin, where the link's page is.
    origin: Origin,
    /// Derives and checks the tokens.
    keys: LinkKeys,
    /// What the links name.
    target: PhantomData<fn() -> T>,
}

/// Every [`Links`] can be cloned, whatever it names.
impl<T> Clone for Links<T> {
    fn clone(&self) -> Self {
        Self {
            origin: self.origin.clone(),
            keys: self.keys.clone(),
            target: PhantomData,
        }
    }
}

/// What a link's query names: the `T`, and its token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Link<T> {
    /// What it acts on. Unsubscribe links named it `account` before the two
    /// kinds of links shared their form.
    #[serde(alias = "account")]
    pub(crate) id: T,
    /// Its token, encoded.
    pub(crate) token: String,
}

/// The links that turn an account's announcements' email off, which every email
/// that is not essential carries.
pub(crate) type UnsubscribeLinks = Links<UserId>;
/// The links that sign an account out everywhere, which every security
/// notification's email carries.
pub(crate) type SignOutLinks = Links<NotificationId>;

impl<T: LinkTarget> Links<T> {
    /// Links to `origin`'s page for `T`, with tokens `keys` derive.
    pub(crate) const fn new(origin: Origin, keys: LinkKeys) -> Self {
        Self {
            origin,
            keys,
            target: PhantomData,
        }
    }

    /// The link naming `id`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn link(&self, id: T) -> Result<String, CryptoError> {
        // An ID and an unpadded base64url token need no escaping.
        let token = self.keys.token(&id.bytes())?.encoded();
        Ok(format!(
            "{}?id={id}&token={token}",
            self.origin.join(T::PAGE)
        ))
    }

    /// What `link` names, if a configured key derives its token.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn check(&self, link: &Link<T>) -> Result<Option<T>, CryptoError> {
        let Ok(token) = Secret::parse(&link.token) else {
            return Ok(None);
        };
        Ok(self
            .keys
            .derives(&link.id.bytes(), &token)?
            .then_some(link.id))
    }
}
