//! What a change makes and its page shows once, such as a client's new secret or
//! an invitation's link, without the page answering a `POST`: the dashboard loads
//! no script that could put the page's address back, and reloading a `POST`'s
//! answer would make the change again.
//!
//! The change's answer instead seals what it made into a cookie, for a minute,
//! and redirects to the page that shows it, which a `GET` then shows once:
//! [`answers`](super::answers) deletes the cookie with every `GET`'s answer.
//! Reloading gets the page without it. The value is never in a URL, the
//! history or a cache, since every answer is `no-store`, and the browser only
//! ever holds it sealed under the key-encryption key, which every replica has,
//! bound to the administrator's auth session and to the page that shows it.

use super::AdminApplication;
use crate::{admin::SignedInAdmin, security::BrowserCookie};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use topcoat::{
    Error, Result,
    context::Cx,
    router::{
        Method,
        error::see_other,
        request::{headers, method, uri},
        response::{IntoResponse, Response},
    },
};

/// How long a sealed value waits for its page: the redirect follows at once.
const REVEAL_FOR: Duration = Duration::minutes(1);

/// What the cookie seals: the value, and until when its page shows it.
#[derive(Serialize, Deserialize)]
struct Sealed<T> {
    /// Until when the page shows it.
    until: DateTime<Utc>,
    /// What the change made.
    value: T,
}

impl AdminApplication {
    /// Answers a change that made `value` by sending the browser to `page`, which
    /// shows it once with [`Self::revealed`].
    pub(super) fn reveal<T: Serialize>(
        cx: &Cx,
        admin: &SignedInAdmin,
        page: String,
        value: T,
    ) -> Result<Response> {
        let sealed = Sealed {
            until: Utc::now() + REVEAL_FOR,
            value,
        };
        let plaintext = serde_json::to_vec(&sealed).map_err(Error::from)?;
        let sealed = Self::of(cx)
            .kek
            .seal(&plaintext, &Self::bound_to(admin, &page))
            .map_err(Error::from)?;
        let mut response = see_other(page).into_response(cx)?;
        BrowserCookie::DashboardReveal
            .set_text_on(&mut response, &URL_SAFE_NO_PAD.encode(sealed))
            .map_err(Error::from)?;
        Ok(response)
    }

    /// What a change made for this page to show, when a `GET` follows its
    /// [`Self::reveal`] in time. Anything else, such as a reload, finds nothing:
    /// a cookie for another page, session or key, or a late one, opens to nothing.
    pub(super) fn revealed<T: DeserializeOwned>(cx: &Cx, admin: &SignedInAdmin) -> Option<T> {
        if method(cx) != Method::GET {
            return None;
        }
        let sealed = URL_SAFE_NO_PAD
            .decode(BrowserCookie::DashboardReveal.value(headers(cx))?)
            .ok()?;
        let plaintext = Self::of(cx)
            .kek
            .open(&sealed, &Self::bound_to(admin, uri(cx).path()))
            .ok()?;
        let sealed: Sealed<T> = serde_json::from_slice(&plaintext).ok()?;
        (Utc::now() < sealed.until).then_some(sealed.value)
    }

    /// The associated data binding a sealed value to `admin`'s auth session and
    /// the `page` showing it, apart from every other use of the key.
    fn bound_to(admin: &SignedInAdmin, page: &str) -> Vec<u8> {
        let session = admin
            .operator
            .session()
            .map(|session| session.to_string())
            .unwrap_or_default();
        format!("piquel dashboard reveal\0{session}\0{page}").into_bytes()
    }
}
