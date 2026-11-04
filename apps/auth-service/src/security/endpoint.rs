//! How the HTTP boundary classifies a route, which its origin, CSRF and rate
//! policies all read, and the independent request budgets of each class.

use crate::routes::{ACCOUNT_PREFIX, audit, oidc, page, passkey, pictures, service};
use axum::extract::{MatchedPath, Request};

/// How the HTTP boundary treats a route. Origin, CSRF and rate policy all read this one
/// classification, so it must list every route that differs from `Other`.
#[derive(Clone, Copy)]
pub(super) enum Endpoint {
    /// Token, revocation and pushed authorization requests, authenticated by client
    /// credentials.
    OAuthBackChannel,
    /// Bearer-authenticated `UserInfo`.
    UserInfo,
    /// Public metadata, signing keys and related origins, readable from any origin.
    Discovery,
    /// Public audit checkpoints, read from the database and readable from any origin.
    Checkpoints,
    /// Profile pictures, which any origin may load, cookie-less, like any image.
    Picture,
    /// Liveness and readiness probes polled by the orchestrator.
    Health,
    /// Authorization requests, including cross-site form navigation.
    Authorize,
    /// RP-initiated logout, validated by its own hint, which only sends the browser to
    /// confirm on the logout page.
    Logout,
    /// The account's JSON APIs, which browsers may call only from auth's own pages.
    Account,
    /// Auth's server-rendered pages, sign-in included, which anyone may navigate to,
    /// and the forms they post.
    Page,
    /// The admin dashboard's pages, the admin listener's only routes, and the forms
    /// they post.
    Dashboard,
    /// Passkey sign-in on the pages of approved related origins, without cookies.
    RelatedLogin,
    /// Passkey ceremonies, the providers' callbacks and the other auth-origin
    /// routes.
    Other,
}

impl Endpoint {
    /// Classifies `request` by the template of the route it matched, so that a page
    /// whose path names an app is a page, or by its path when no route matched.
    pub(super) fn of(request: &Request) -> Self {
        Self::classify(
            request
                .extensions()
                .get::<MatchedPath>()
                .map_or(request.uri().path(), MatchedPath::as_str),
        )
    }

    /// Classifies a route's template, or an unmatched path: exact protocol and page
    /// routes, and the account route family.
    pub(super) fn classify(path: &str) -> Self {
        match path {
            oidc::TOKEN | oidc::REVOKE | oidc::PAR => Self::OAuthBackChannel,
            oidc::USERINFO => Self::UserInfo,
            oidc::DISCOVERY | oidc::OAUTH_METADATA | oidc::JWKS | passkey::RELATED_ORIGINS => {
                Self::Discovery
            }
            passkey::RELATED_START | passkey::RELATED_FINISH => Self::RelatedLogin,
            audit::LATEST_CHECKPOINT | audit::CHECKPOINTS => Self::Checkpoints,
            pictures::IMAGE => Self::Picture,
            service::LIVE | service::READY => Self::Health,
            oidc::AUTHORIZE => Self::Authorize,
            oidc::LOGOUT => Self::Logout,
            // The root and a page's path ending in a slash redirect to a page.
            page::ROOT => Self::Page,
            _ if page::ALL.contains(&path.strip_suffix('/').unwrap_or(path)) => Self::Page,
            _ if path.starts_with(ACCOUNT_PREFIX) => Self::Account,
            _ => Self::Other,
        }
    }

    /// Protocol handlers enforce their own credentials and navigation checks.
    pub(super) const fn is_protocol(self) -> bool {
        match self {
            Self::OAuthBackChannel | Self::UserInfo | Self::Authorize | Self::Logout => true,
            Self::Discovery
            | Self::Checkpoints
            | Self::Picture
            | Self::Health
            | Self::Account
            | Self::Page
            | Self::Dashboard
            | Self::RelatedLogin
            | Self::Other => false,
        }
    }

    /// Selects the budget of a matched route, reads included: they verify token
    /// signatures or hold a connection from the small database pool. Only routes that
    /// do neither are free. Discovery is cacheable, and served from memory but for
    /// the related origins' one small query. A throttled health probe would take the
    /// service out of rotation; readiness costs one `SELECT 1`, no more than the
    /// budget's own upsert would.
    pub(super) const fn rate_category(self) -> Option<RateCategory> {
        match self {
            Self::OAuthBackChannel => Some(RateCategory::Token),
            Self::UserInfo => Some(RateCategory::UserInfo),
            Self::Account => Some(RateCategory::Account),
            Self::Authorize | Self::Logout | Self::RelatedLogin | Self::Other => {
                Some(RateCategory::Login)
            }
            Self::Page => Some(RateCategory::Page),
            Self::Dashboard => Some(RateCategory::Dashboard),
            Self::Checkpoints => Some(RateCategory::Audit),
            Self::Picture => Some(RateCategory::Picture),
            Self::Discovery | Self::Health => None,
        }
    }
}

piquel_common::str_enum! {
    /// Independent request budgets persisted under stable category names, so one kind of
    /// traffic from a client cannot exhaust another: a relying party's `UserInfo` calls
    /// never block its code exchanges, and browsing auth's pages never blocks a passkey
    /// ceremony or an authorization.
    pub(super) enum RateCategory {
        /// OAuth credential exchanges and revocation.
        Token = "token",
        /// Bearer-token claim lookups by relying parties.
        UserInfo = "userinfo",
        /// The account JSON APIs' reads and mutations.
        Account = "account",
        /// Passkey ceremonies, providers' callbacks, authorization, logout and the
        /// other auth-origin routes.
        Login = "login",
        /// Auth's server-rendered pages, sign-in included, and the forms they post.
        Page = "page",
        /// The admin dashboard's pages and forms.
        Dashboard = "dashboard",
        /// Reads of the public audit checkpoints.
        Audit = "audit",
        /// Profile pictures, which a page listing accounts loads many of at once.
        Picture = "picture",
    }
}
