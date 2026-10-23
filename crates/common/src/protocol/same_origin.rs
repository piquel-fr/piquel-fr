//! Whether a browser request comes from a site's own pages: the CSRF rule that
//! auth's pages and the SDK's login routes share. `SameSite=Lax` cookies alone would
//! still let a sibling site under the same domain post with them.
//!
//! `Sec-Fetch-Site` decides whenever the browser sends it, as every current browser
//! does. Only without it does `Origin` have to be the site's. A page served with
//! `Referrer-Policy: no-referrer` sends `Origin: null` on a native form `POST`, so
//! `Origin` alone would refuse the site's own forms; `null` never matches.

use url::Origin;

/// The `Sec-Fetch-Site` value of a request from the same origin.
const SAME_ORIGIN: &str = "same-origin";

/// What a browser says about where a request comes from: its `Sec-Fetch-Site` and
/// `Origin` header values. A header that is absent, or not text, is `None`.
///
/// ```
/// use piquel_common::protocol::same_origin::BrowserRequest;
///
/// let site = url::Url::parse("https://notes.piquel.fr/auth/callback")?.origin();
/// let request = |fetch_site, origin| BrowserRequest { fetch_site, origin };
///
/// // A form posted from a page with `Referrer-Policy: no-referrer`.
/// assert!(request(Some("same-origin"), Some("null")).is_same_origin(&site));
/// // `Sec-Fetch-Site` decides, whatever `Origin` says.
/// assert!(!request(Some("same-site"), Some("https://notes.piquel.fr")).is_same_origin(&site));
/// // An older browser: its `Origin` must be the site's.
/// assert!(request(None, Some("https://notes.piquel.fr")).is_same_origin(&site));
/// assert!(!request(None, Some("null")).is_same_origin(&site));
/// assert!(!request(None, None).is_same_origin(&site));
///
/// // An opaque origin, such as a native app's callback, serializes as `null`
/// // but matches nothing.
/// let opaque = url::Url::parse("com.example.notes:/callback")?.origin();
/// assert!(!request(None, Some("null")).is_same_origin(&opaque));
/// # Ok::<(), url::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrowserRequest<'a> {
    /// The `Sec-Fetch-Site` header: how the request's initiator relates to its target.
    pub fetch_site: Option<&'a str>,
    /// The `Origin` header.
    pub origin: Option<&'a str>,
}

impl BrowserRequest<'_> {
    /// Whether the request comes from `site`'s own pages.
    #[must_use]
    pub fn is_same_origin(&self, site: &Origin) -> bool {
        match self.fetch_site {
            Some(fetch_site) => fetch_site == SAME_ORIGIN,
            None => site.is_tuple() && self.origin == Some(site.ascii_serialization().as_str()),
        }
    }
}
