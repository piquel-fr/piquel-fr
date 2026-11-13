//! The Content-Security-Policy of every response a listener sends, pages, JSON,
//! redirects, downloads and errors alike: one policy per listener, which a page
//! may only widen in its `form-action`.

use crate::{AuthConfig, assets::EmbeddedAssets, routes};
use axum::{
    http::{HeaderValue, header, header::InvalidHeaderValue},
    response::Response,
};
use sourceorigin_common::config::Origin;
use std::sync::Arc;
use url::{Host, Url};

/// An origin a page's forms may post or redirect to, as a Content-Security-Policy
/// source names it. Only [`FormTarget::of`] makes one, so it never holds anything
/// but a scheme, a host and a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FormTarget(String);

impl FormTarget {
    /// The source naming `target`'s origin, or `None` when no policy can name it.
    /// Host sources name domains whose labels are letters, digits and hyphens, and
    /// never match an IP address (CSP3 §6.7.2.6), such as a native application's
    /// loopback callback (RFC 8252 §7.3).
    pub(crate) fn of(target: &Url) -> Option<Self> {
        let nameable = match target.host() {
            Some(Host::Domain(domain)) => domain.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }),
            Some(Host::Ipv4(_) | Host::Ipv6(_)) | None => false,
        };
        let origin = target.origin();
        (nameable && origin.is_tuple()).then(|| Self(origin.ascii_serialization()))
    }
}

/// Where a page's forms may also post, or redirect on to, besides the listener's
/// own origin, which a page puts on its response for its policy to allow: browsers
/// apply `form-action` to a form's redirects too.
#[derive(Clone, Debug, Default)]
pub(crate) struct FormTargets(pub(crate) Vec<FormTarget>);

/// A listener's Content-Security-Policy.
#[derive(Clone)]
pub(super) struct ContentPolicy {
    /// The policy of a response that names no [`FormTargets`].
    policy: HeaderValue,
    /// The same, which a page's targets extend, as it ends with `form-action`.
    text: Arc<str>,
}

impl ContentPolicy {
    /// The policy of every directive in `base` and the `form_action` sources.
    /// `form-action` comes last, so a page's targets extend it by appending.
    ///
    /// # Errors
    /// Fails when a configured origin cannot be sent in a header.
    fn new(base: &str, form_action: &str) -> Result<Self, InvalidHeaderValue> {
        let text = format!("{base}; form-action {form_action}");
        Ok(Self {
            policy: HeaderValue::try_from(&text)?,
            text: text.into(),
        })
    }

    /// Auth's: its stylesheet, typefaces and scripts, whose passkey ceremonies
    /// fetch auth's own JSON routes, and its own images, which the profile's
    /// pictures are, with the `blob:` URL the picture script shows a picture being
    /// chosen from, before it is uploaded. A source with a path needs the whole URL:
    /// `'self'` names none.
    ///
    /// # Errors
    /// Fails when auth's origin cannot be sent in a header.
    pub(super) fn auth(config: &AuthConfig) -> Result<Self, InvalidHeaderValue> {
        let origin = &config.oidc.origin;
        let scripts = EmbeddedAssets::SCRIPTS.map(|script| origin.join(&script.path()));
        Self::new(
            &format!(
                "default-src 'none'; style-src {}; script-src {}; font-src 'self'; \
                 connect-src 'self'; img-src 'self' blob:; frame-ancestors 'none'; \
                 base-uri 'none'",
                origin.join(&EmbeddedAssets::STYLESHEET.path()),
                scripts.join(" "),
            ),
            "'self'",
        )
    }

    /// The admin dashboard's, on `dashboard`: its stylesheet, typefaces and
    /// scripts, which fetch only the dashboard's own passkey ceremonies and
    /// search, and auth's images, which serve the profile pictures. A form's answer
    /// may send the browser on to auth's handoff page, to sign in or confirm again.
    ///
    /// # Errors
    /// Fails when the dashboard's or auth's origin cannot be sent in a header.
    pub(super) fn dashboard(
        config: &AuthConfig,
        dashboard: &Origin,
    ) -> Result<Self, InvalidHeaderValue> {
        let auth = &config.passkey.origin;
        let scripts =
            EmbeddedAssets::DASHBOARD_SCRIPTS.map(|script| dashboard.join(&script.path()));
        Self::new(
            &format!(
                "default-src 'none'; script-src {}; style-src {}; font-src 'self'; \
                 img-src {}; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
                scripts.join(" "),
                dashboard.join(&EmbeddedAssets::STYLESHEET.path()),
                auth.serialized(),
            ),
            &format!("'self' {}", auth.join(routes::page::ADMIN)),
        )
    }

    /// Sets the policy on `response`, its `form-action` widened by the
    /// [`FormTargets`] the response names, if any.
    pub(super) fn set_on(&self, response: &mut Response) {
        let widened = match response.extensions().get::<FormTargets>() {
            Some(FormTargets(targets)) if !targets.is_empty() => {
                let mut text = self.text.to_string();
                for FormTarget(target) in targets {
                    text.push(' ');
                    text.push_str(target);
                }
                // A target holds only an origin, which a header always takes; the
                // listener's own policy stays should one ever not.
                HeaderValue::try_from(text).ok()
            }
            Some(_) | None => None,
        };
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            widened.unwrap_or_else(|| self.policy.clone()),
        );
    }
}
