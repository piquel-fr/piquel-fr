//! How the HTTP boundary classifies a route, which its origin, CSRF and rate
//! policies all read, and the independent request budgets of each class.

use crate::routes::{ACCOUNT_PREFIX, audit, dashboard, oidc, page, passkey, pictures, service};
use axum::{
    extract::{MatchedPath, Request},
    http::Method,
};

/// The header the search script sends with a live search's refresh, which spends
/// the search budget rather than the pages'. A client gains nothing by sending it
/// with other requests: each budget is as small as the other.
pub(super) const LIVE_HEADER: &str = "x-sourceorigin-live";

/// How the HTTP boundary treats a route. Origin, CSRF and rate policy, and whether a
/// failure is shown as a page, all read this one classification, so it must list
/// every route that differs from `Other`.
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
    /// The admin dashboard's pages, the admin listener's routes, and the forms
    /// they post.
    Dashboard,
    /// What the dashboard's searches find as the administrator types, the top
    /// bar's and the live ones', on a budget of its own, so typing never costs
    /// the pages theirs.
    DashboardSearch,
    /// Passkey sign-in on the pages of approved related origins, without cookies.
    RelatedLogin,
    /// The unsubscribe page of announcements' emails, which mail clients post to
    /// from anywhere in one click (RFC 8058): its link's token is its credential,
    /// and it only turns that email off.
    Unsubscribe,
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

    /// Classifies a request to the admin listener: the top bar's search, a live
    /// search refreshing its page's results, which the search script marks with
    /// [`LIVE_HEADER`], or a page.
    pub(super) fn dashboard(request: &Request) -> Self {
        if request.uri().path() == dashboard::SEARCH || request.headers().contains_key(LIVE_HEADER)
        {
            Self::DashboardSearch
        } else {
            Self::Dashboard
        }
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
            page::UNSUBSCRIBE => Self::Unsubscribe,
            // The root and a page's path ending in a slash redirect to a page.
            page::ROOT => Self::Page,
            _ if page::ALL.contains(&path.strip_suffix('/').unwrap_or(path)) => Self::Page,
            _ if path.starts_with(ACCOUNT_PREFIX) => Self::Account,
            _ => Self::Other,
        }
    }

    /// Protocol handlers, and the unsubscribe page, enforce their own credentials
    /// and navigation checks.
    pub(super) const fn is_protocol(self) -> bool {
        match self {
            Self::OAuthBackChannel
            | Self::UserInfo
            | Self::Authorize
            | Self::Logout
            | Self::Unsubscribe => true,
            Self::Discovery
            | Self::Checkpoints
            | Self::Picture
            | Self::Health
            | Self::Account
            | Self::Page
            | Self::Dashboard
            | Self::DashboardSearch
            | Self::RelatedLogin
            | Self::Other => false,
        }
    }

    /// Whether a browser navigates to it with `method`, so that a failure a
    /// browser without fetch metadata gets is shown as a page when it accepts
    /// HTML. A client calling a protocol or JSON route keeps its JSON, whatever it
    /// accepts: among the other routes, browsers only `GET` or `HEAD` the
    /// providers' callbacks, an authorization's resumption, the assets and unknown
    /// paths, while scripts post the ceremonies' JSON.
    pub(super) fn browsed(self, method: &Method) -> bool {
        match self {
            Self::Authorize | Self::Logout | Self::Page | Self::Dashboard | Self::Unsubscribe => {
                true
            }
            Self::Other => matches!(*method, Method::GET | Method::HEAD),
            Self::OAuthBackChannel
            | Self::UserInfo
            | Self::Discovery
            | Self::Checkpoints
            | Self::Picture
            | Self::Health
            | Self::Account
            | Self::DashboardSearch
            | Self::RelatedLogin => false,
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
            Self::Page | Self::Unsubscribe => Some(RateCategory::Page),
            Self::Dashboard => Some(RateCategory::Dashboard),
            Self::DashboardSearch => Some(RateCategory::Search),
            Self::Checkpoints => Some(RateCategory::Audit),
            Self::Picture => Some(RateCategory::Picture),
            Self::Discovery | Self::Health => None,
        }
    }
}

sourceorigin_common::str_enum! {
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
        /// What the dashboard's searches find, asked for as the administrator types.
        Search = "search",
        /// Reads of the public audit checkpoints.
        Audit = "audit",
        /// Profile pictures, which a page listing accounts loads many of at once.
        Picture = "picture",
    }
}
