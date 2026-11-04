//! Host-only browser cookies: the secrets binding server-side state, the notice
//! of a change just made, and the preferences each origin keeps.

use super::SESSION_LIFETIME_DAYS;
use axum::http::{
    HeaderMap, HeaderValue,
    header::{self, InvalidHeaderValue},
};
use piquel_crypto::Secret;
use piquel_ui::{PreferenceChange, Preferences};

/// Browser flow cookies slightly outlive their server-side ceremonies.
const FLOW_COOKIE_MAX_AGE: u32 = 600;

piquel_common::str_enum! {
    /// Host-only cookies: browser secrets binding server-side state, and the notice
    /// of an account page's change just made.
    pub(crate) enum BrowserCookie {
        /// Central sign-in session.
        Session = "__Host-piquel_session",
        /// In-progress WebAuthn ceremony.
        Ceremony = "__Host-piquel_ceremony",
        /// Provider redirect awaiting its callback.
        Federation = "__Host-piquel_federation",
        /// Verified identity awaiting signup or linking.
        FederationPending = "__Host-piquel_federation_pending",
        /// Offer to restore an account scheduled for deletion, from a passkey sign-in.
        Restore = "__Host-piquel_restore",
        /// What an account page's change just did, which the page it goes to says once.
        Notice = "__Host-piquel_notice",
        /// The admin dashboard's session, on the dashboard's own origin.
        Dashboard = "__Host-piquel_dashboard",
        /// A sign-in to the admin dashboard awaiting auth's handoff, on the
        /// dashboard's origin.
        DashboardState = "__Host-piquel_dashboard_state",
        /// What a dashboard change made and its page shows once, such as a client
        /// secret, sealed, across the redirect that follows the change's form.
        DashboardReveal = "__Host-piquel_dashboard_reveal",
        /// The theme the browser chose, on each origin.
        Theme = "__Host-piquel_theme",
        /// The sidebar's width the browser chose, on each origin.
        Sidebar = "__Host-piquel_sidebar",
    }
}

/// How long a preference is kept: a year.
const PREFERENCE_MAX_AGE: u32 = 365 * 24 * 60 * 60;

impl BrowserCookie {
    /// Lifetime in seconds. Flow cookies outlive their server-side state slightly; a
    /// notice is shown on the page its change goes to, at once.
    const fn max_age(self) -> u32 {
        match self {
            Self::Session | Self::Dashboard => SESSION_LIFETIME_DAYS * 24 * 60 * 60,
            Self::Ceremony
            | Self::Federation
            | Self::FederationPending
            | Self::DashboardState
            | Self::Restore => FLOW_COOKIE_MAX_AGE,
            Self::Notice | Self::DashboardReveal => 60,
            Self::Theme | Self::Sidebar => PREFERENCE_MAX_AGE,
        }
    }

    /// The theme and sidebar preferences the browser's cookies carry. A value
    /// that is none counts as unset.
    pub(crate) fn read_preferences(headers: &HeaderMap) -> Preferences {
        Preferences {
            theme: Self::Theme
                .value(headers)
                .and_then(|value| value.parse().ok()),
            sidebar: Self::Sidebar
                .value(headers)
                .and_then(|value| value.parse().ok()),
        }
    }

    /// Adds the `Set-Cookie` headers keeping what `change` chose, to the answer of
    /// the preference page.
    pub(crate) fn set_preferences_on<B>(
        response: &mut axum::http::Response<B>,
        change: &PreferenceChange,
    ) -> Result<(), InvalidHeaderValue> {
        if let Some(theme) = change.theme {
            Self::Theme.append(response, theme.as_str(), Self::Theme.max_age())?;
        }
        if let Some(sidebar) = change.sidebar {
            Self::Sidebar.append(response, sidebar.as_str(), Self::Sidebar.max_age())?;
        }
        Ok(())
    }

    /// Reads this cookie's value. A duplicated cookie counts as absent, so an
    /// injected value can never shadow the browser's own.
    pub(crate) fn value(self, headers: &HeaderMap) -> Option<&str> {
        let mut values = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|header| header.split(';'))
            .filter_map(|part| part.trim().strip_prefix(self.as_str())?.strip_prefix('='));
        let value = values.next()?;
        values.next().is_none().then_some(value)
    }

    /// Reads this cookie's secret, as [`Self::value`] reads it. A malformed one
    /// counts as absent too.
    pub(crate) fn read(self, headers: &HeaderMap) -> Option<Secret> {
        Secret::parse(self.value(headers)?).ok()
    }

    /// Adds a `Set-Cookie` header storing `secret` to an axum response or a page's,
    /// keeping any other cookies being set.
    pub(crate) fn set_on<B>(
        self,
        response: &mut axum::http::Response<B>,
        secret: &Secret,
    ) -> Result<(), InvalidHeaderValue> {
        self.append(response, &secret.encoded(), self.max_age())
    }

    /// Adds a `Set-Cookie` header storing `value`, text a cookie may hold such as
    /// base64url, to an axum response or a page's.
    pub(crate) fn set_text_on<B>(
        self,
        response: &mut axum::http::Response<B>,
        value: &str,
    ) -> Result<(), InvalidHeaderValue> {
        self.append(response, value, self.max_age())
    }

    /// The notice [`Self::Notice`] carries, of the change just made. An unknown or
    /// duplicated one counts as absent.
    pub(crate) fn read_notice(headers: &HeaderMap) -> Option<piquel_ui::Notice> {
        Self::Notice.value(headers)?.parse().ok()
    }

    /// Adds a `Set-Cookie` header storing `notice` in [`Self::Notice`], to the
    /// answer of the change it says was made.
    pub(crate) fn set_notice_on<B>(
        response: &mut axum::http::Response<B>,
        notice: piquel_ui::Notice,
    ) -> Result<(), InvalidHeaderValue> {
        Self::Notice.append(response, notice.as_str(), Self::Notice.max_age())
    }

    /// Adds a `Set-Cookie` header deleting this cookie, to an axum response or a page's.
    pub(crate) fn clear_on<B>(
        self,
        response: &mut axum::http::Response<B>,
    ) -> Result<(), InvalidHeaderValue> {
        self.append(response, "", 0)
    }

    /// Appends a host-only, `Secure`, `HttpOnly`, `SameSite=Lax` cookie header.
    fn append<B>(
        self,
        response: &mut axum::http::Response<B>,
        value: &str,
        max_age: u32,
    ) -> Result<(), InvalidHeaderValue> {
        let cookie = format!(
            "{}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            self.as_str()
        );
        response
            .headers_mut()
            .append(header::SET_COOKIE, HeaderValue::from_str(&cookie)?);
        Ok(())
    }
}
