//! Every HTTP path the service serves. Routers, discovery metadata and the security
//! layer's endpoint classification all read these, so they cannot drift apart.

/// Health and public browser configuration.
pub(crate) mod service {
    /// Liveness probe; answers whenever the process serves HTTP.
    pub(crate) const LIVE: &str = "/health/live";
    /// Readiness probe; also checks the database.
    pub(crate) const READY: &str = "/health/ready";
    /// Public configuration read by the browser frontends.
    pub(crate) const CONFIG: &str = "/config";
}

/// Passkey ceremonies, passkey management and the browser session.
pub(crate) mod passkey {
    /// Starts account registration with a new passkey.
    pub(crate) const REGISTER_START: &str = "/webauthn/register/start";
    /// Finishes account registration.
    pub(crate) const REGISTER_FINISH: &str = "/webauthn/register/finish";
    /// Starts passkey sign-in.
    pub(crate) const AUTHENTICATE_START: &str = "/webauthn/authenticate/start";
    /// Finishes passkey sign-in.
    pub(crate) const AUTHENTICATE_FINISH: &str = "/webauthn/authenticate/finish";
    /// Starts the passkey check that confirms the current session.
    pub(crate) const CONFIRM_START: &str = "/account/passkeys/confirm/start";
    /// Finishes the passkey check that confirms the current session.
    pub(crate) const CONFIRM_FINISH: &str = "/account/passkeys/confirm/finish";
    /// Starts adding another passkey.
    pub(crate) const ENROLL_START: &str = "/account/passkeys/enroll/start";
    /// Finishes adding another passkey.
    pub(crate) const ENROLL_FINISH: &str = "/account/passkeys/enroll/finish";
    /// Lists the account's passkeys.
    pub(crate) const LIST: &str = "/account/passkeys";
    /// Renames or removes one passkey.
    pub(crate) const ITEM: &str = "/account/passkeys/{id}";
    /// Describes the current browser session.
    pub(crate) const SESSION: &str = "/session";
    /// Ends the current browser session.
    pub(crate) const SESSION_LOGOUT: &str = "/session/logout";
}

/// Social sign-in and linked identities.
pub(crate) mod federation {
    /// Lists the configured providers.
    pub(crate) const PROVIDERS: &str = "/login/providers";
    /// Redirects to a provider.
    pub(crate) const START: &str = "/login/{provider}/start";
    /// Receives the provider's redirect back.
    pub(crate) const CALLBACK: &str = "/login/{provider}/callback";
    /// Describes this browser's pending signup or link.
    pub(crate) const PENDING: &str = "/login/social/pending";
    /// Confirms a pending link with a passkey session.
    pub(crate) const LINK: &str = "/login/social/link";
    /// Abandons a pending signup or link.
    pub(crate) const CANCEL: &str = "/login/social/cancel";
    /// Lists the account's linked identities.
    pub(crate) const IDENTITIES: &str = "/account/social-identities";
    /// Unlinks one provider.
    pub(crate) const IDENTITY: &str = "/account/social-identities/{provider}";
}

/// OAuth 2.0 and `OpenID` Connect endpoints.
pub(crate) mod oidc {
    use piquel_common::protocol::metadata;

    /// `OpenID` Provider metadata.
    pub(crate) const DISCOVERY: &str = metadata::OPENID_CONFIGURATION_PATH;
    /// OAuth authorization server metadata (RFC 8414), the same document as [`DISCOVERY`].
    pub(crate) const OAUTH_METADATA: &str = metadata::OAUTH_AUTHORIZATION_SERVER_PATH;
    /// Public signing keys.
    pub(crate) const JWKS: &str = "/.well-known/jwks.json";
    /// Authorization requests, by GET or form POST.
    pub(crate) const AUTHORIZE: &str = "/oauth/authorize";
    /// Continues an authorization after sign-in.
    pub(crate) const AUTHORIZE_RESUME: &str = "/oauth/authorize/resume";
    /// Describes a pending authorization to the consent page.
    pub(crate) const AUTHORIZE_TRANSACTION: &str = "/oauth/authorize/transaction/{transaction}";
    /// Records the consent page's decision.
    pub(crate) const AUTHORIZE_DECISION: &str = "/oauth/authorize/decision";
    /// Exchanges codes and refresh tokens.
    pub(crate) const TOKEN: &str = "/oauth/token";
    /// Revokes refresh tokens.
    pub(crate) const REVOKE: &str = "/oauth/revoke";
    /// Returns claims for a bearer access token.
    pub(crate) const USERINFO: &str = "/oidc/userinfo";
    /// RP-initiated logout.
    pub(crate) const LOGOUT: &str = "/oidc/logout";
}

/// The admin API, served only on the private admin listener. The paths are shared
/// with the dashboard through `piquel-admin-api`.
pub(crate) mod admin {
    pub(crate) use piquel_admin_api::paths::*;
}

/// Pages of the embedded auth frontend that the service redirects browsers to.
pub(crate) mod page {
    /// Sign-in, social signup and link confirmation.
    pub(crate) const LOGIN: &str = "/login";
    /// OAuth consent.
    pub(crate) const CONSENT: &str = "/authorize";
    /// RP-initiated logout confirmation.
    pub(crate) const LOGOUT: &str = "/logout";
}

/// Prefix shared by the settings APIs, which the settings site may call.
pub(crate) const ACCOUNT_PREFIX: &str = "/account/";
/// Prefix shared by social sign-in, which the settings site may also start.
pub(crate) const LOGIN_PREFIX: &str = "/login/";
