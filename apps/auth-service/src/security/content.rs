//! The Content-Security-Policy of every response a listener sends, pages, JSON,
//! redirects, downloads and errors alike: one policy per listener, which a page
//! may only widen in its `form-action`.

use crate::{AuthConfig, assets::EmbeddedAssets, routes};
use axum::{
    http::{HeaderValue, header},
    response::Response,
};
use sourceorigin_common::config::Origin;

/// Where a page's forms may also post, or redirect on to, besides the listener's
/// own origin: sources a page adds to its response for its policy to allow, since
/// browsers apply `form-action` to a form's redirects too.
#[derive(Clone, Debug, Default)]
pub(crate) struct FormTargets(pub(crate) Vec<String>);

/// A listener's Content-Security-Policy.
#[derive(Clone)]
pub(super) struct ContentPolicy {
    /// Every directive but `form-action`.
    base: String,
    /// The `form-action` sources of every response.
    form_action: String,
}

impl ContentPolicy {
    /// Auth's: its stylesheet, typefaces and scripts, whose passkey ceremonies
    /// fetch auth's own JSON routes, and its own images, which the profile's
    /// pictures are, with the `blob:` URL the picture script shows a picture being
    /// chosen from, before it is uploaded. A source with a path needs the whole URL:
    /// `'self'` names none.
    pub(super) fn auth(config: &AuthConfig) -> Self {
        let origin = &config.oidc.origin;
        let scripts = EmbeddedAssets::SCRIPTS.map(|script| origin.join(&script.path()));
        Self {
            base: format!(
                "default-src 'none'; style-src {}; script-src {}; font-src 'self'; \
                 connect-src 'self'; img-src 'self' blob:; frame-ancestors 'none'; \
                 base-uri 'none'",
                origin.join(&EmbeddedAssets::STYLESHEET.path()),
                scripts.join(" "),
            ),
            form_action: "'self'".to_owned(),
        }
    }

    /// The admin dashboard's, on `dashboard`: its stylesheet, typefaces and
    /// scripts, which fetch only the dashboard's own passkey ceremonies and
    /// search, and auth's images, which serve the profile pictures. A form's answer
    /// may send the browser on to auth's handoff page, to sign in or confirm again.
    pub(super) fn dashboard(config: &AuthConfig, dashboard: &Origin) -> Self {
        let auth = &config.passkey.origin;
        let scripts =
            EmbeddedAssets::DASHBOARD_SCRIPTS.map(|script| dashboard.join(&script.path()));
        Self {
            base: format!(
                "default-src 'none'; script-src {}; style-src {}; font-src 'self'; \
                 img-src {}; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
                scripts.join(" "),
                dashboard.join(&EmbeddedAssets::STYLESHEET.path()),
                auth.serialized(),
            ),
            form_action: format!("'self' {}", auth.join(routes::page::ADMIN)),
        }
    }

    /// Whether `target` is a source naming an origin and nothing else: no
    /// keyword, wildcard, space or `;` could widen the policy past its
    /// `form-action`.
    fn names_an_origin(target: &str) -> bool {
        target.contains("://")
            && target
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b":/.-".contains(&byte))
    }

    /// Sets the policy on `response`, its `form-action` widened by the
    /// [`FormTargets`] the response names, if any. A target that names no origin is
    /// left out, so its form's redirect is refused rather than the policy widened.
    pub(super) fn set_on(&self, response: &mut Response) {
        let mut form_action = self.form_action.clone();
        if let Some(FormTargets(targets)) = response.extensions().get::<FormTargets>() {
            for target in targets
                .iter()
                .filter(|target| Self::names_an_origin(target))
            {
                form_action.push(' ');
                form_action.push_str(target);
            }
        }
        let policy = format!("{}; form-action {form_action}", self.base);
        // Its sources are origins and paths, and each target names an origin.
        if let Ok(value) = HeaderValue::try_from(policy) {
            response
                .headers_mut()
                .insert(header::CONTENT_SECURITY_POLICY, value);
        }
    }
}
