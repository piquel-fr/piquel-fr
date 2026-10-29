//! Every HTTP path the service serves. Routers, discovery metadata and the security
//! layer's endpoint classification all read these, so they cannot drift apart.

/// Health probes.
pub(crate) mod service {
    /// Liveness probe; answers whenever the process serves HTTP.
    pub(crate) const LIVE: &str = "/health/live";
    /// Readiness probe; also checks the database.
    pub(crate) const READY: &str = "/health/ready";
}

/// Passkey ceremonies and passkey management.
pub(crate) mod passkey {
    /// Starts account registration with a new passkey.
    pub(crate) const REGISTER_START: &str = "/webauthn/register/start";
    /// Finishes account registration.
    pub(crate) const REGISTER_FINISH: &str = "/webauthn/register/finish";
    /// Starts passkey sign-in.
    pub(crate) const AUTHENTICATE_START: &str = "/webauthn/authenticate/start";
    /// Finishes passkey sign-in.
    pub(crate) const AUTHENTICATE_FINISH: &str = "/webauthn/authenticate/finish";
    /// Lists the origins whose pages may use auth's passkeys (`WebAuthn` related origins).
    pub(crate) const RELATED_ORIGINS: &str = "/.well-known/webauthn";
    /// Starts a passkey sign-in on an approved origin's page.
    pub(crate) const RELATED_START: &str = "/webauthn/related/start";
    /// Finishes a passkey sign-in on an approved origin's page.
    pub(crate) const RELATED_FINISH: &str = "/webauthn/related/finish";
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
    /// The passkey proof the admin dashboard's handoff page posts, which counts
    /// for that handoff only: the passkey script starts it at
    /// [`ADMIN_PROOF_START`].
    pub(crate) const ADMIN_PROOF: &str = "/admin/proof";
    /// Starts the passkey proof of a handoff to the admin dashboard.
    pub(crate) const ADMIN_PROOF_START: &str = "/admin/proof/start";
}

/// Social sign-in and linked identities.
pub(crate) mod federation {
    /// Receives the provider's redirect back.
    pub(crate) const CALLBACK: &str = "/login/{provider}/callback";
    /// Lists the account's linked identities.
    pub(crate) const IDENTITIES: &str = "/account/social-identities";
    /// Unlinks one provider.
    pub(crate) const IDENTITY: &str = "/account/social-identities/{provider}";
}

/// The account's email addresses.
pub(crate) mod emails {
    /// Lists the account's addresses, or adds one.
    pub(crate) const LIST: &str = "/account/emails";
    /// Verifies an address with the token of its verification link.
    pub(crate) const VERIFY: &str = "/account/emails/verify";
    /// Makes a verified address the primary one.
    pub(crate) const PRIMARY: &str = "/account/emails/{id}/primary";
    /// Removes an address.
    pub(crate) const ITEM: &str = "/account/emails/{id}";
}

/// Account recoveries: their link's page, and undoing one.
pub(crate) mod recovery {
    /// Starts enrolling a passkey with a recovery link.
    pub(crate) const START: &str = "/recovery/start";
    /// Finishes enrolling it, which uses the link and signs the browser in.
    pub(crate) const FINISH: &str = "/recovery/finish";
    /// Describes the account's recovery that can still be undone.
    pub(crate) const STATUS: &str = "/account/recovery";
    /// Starts undoing it with any passkey but its own; needs no session.
    pub(crate) const UNDO_START: &str = "/account/recovery/undo/start";
    /// Finishes the undo, and signs the browser in with that passkey unless the
    /// account is disabled.
    pub(crate) const UNDO_FINISH: &str = "/account/recovery/undo/finish";
}

/// The account's security history.
pub(crate) mod history {
    /// Pages through the account's history, newest first.
    pub(crate) const LIST: &str = "/account/history";
    /// Reports one entry as not the user's, ending their other sessions.
    pub(crate) const REPORT: &str = "/account/history/{event_id}/report";
}

/// The account's sessions, one per signed-in browser.
pub(crate) mod sessions {
    /// Lists the account's active sessions, most recently active first.
    pub(crate) const LIST: &str = "/account/sessions";
    /// Signs one other session out.
    pub(crate) const ITEM: &str = "/account/sessions/{id}";
    /// Signs every other session out.
    pub(crate) const REVOKE_OTHERS: &str = "/account/sessions/revoke-others";
}

/// The audit chain's signed checkpoints, public so anyone can keep copies.
pub(crate) mod audit {
    /// The newest checkpoint, as a signed note.
    pub(crate) const LATEST_CHECKPOINT: &str = "/audit/checkpoints/latest";
    /// Checkpoints after a position, oldest first.
    pub(crate) const CHECKPOINTS: &str = "/audit/checkpoints";
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
    /// Pushed authorization requests (RFC 9126), from the client's back channel.
    pub(crate) const PAR: &str = "/oauth/par";
    /// Continues an authorization after sign-in.
    pub(crate) const AUTHORIZE_RESUME: &str = "/oauth/authorize/resume";
    /// Exchanges codes and refresh tokens.
    pub(crate) const TOKEN: &str = "/oauth/token";
    /// Revokes refresh tokens.
    pub(crate) const REVOKE: &str = "/oauth/revoke";
    /// Returns claims for a bearer access token.
    pub(crate) const USERINFO: &str = "/oidc/userinfo";
    /// RP-initiated logout, confirmed on [`page::LOGOUT`](super::page::LOGOUT).
    pub(crate) const LOGOUT: &str = "/oidc/logout";
}

/// The admin dashboard, on its own origin, which the admin listener serves. Its
/// pages declare their own paths, under these prefixes.
pub(crate) mod dashboard {
    /// Redeems auth's handoff code, signing the browser in to the dashboard.
    pub(crate) const SIGN_IN: &str = "/sign-in";
    /// Every path the dashboard serves is one of these, or under one: the admin
    /// listener mounts the pages on them, and nowhere else.
    pub(crate) const PREFIXES: [&str; 10] = [
        "/",
        SIGN_IN,
        "/sign-out",
        "/assets",
        "/users",
        "/administrators",
        "/invitations",
        "/clients",
        "/events",
        "/audit",
    ];
}

/// Pages browsers visit. Each server-rendered page answers `GET` with the page and
/// `POST` with its form's result, and is listed in [`ALL`](page::ALL).
pub(crate) mod page {
    /// Auth's root, which redirects to the account's settings, so that piquel.fr's
    /// root, which redirects here, still lands on them.
    pub(crate) const ROOT: &str = "/";
    /// Sign-in, social signup and link confirmation.
    pub(crate) const LOGIN: &str = "/login";
    /// Creating an account, which invitations link.
    pub(crate) const REGISTER: &str = "/register";
    /// OAuth consent.
    pub(crate) const CONSENT: &str = "/authorize";
    /// RP-initiated logout confirmation.
    pub(crate) const LOGOUT: &str = "/logout";
    /// Enrolls a passkey with a recovery link, whose token is in the fragment.
    pub(crate) const RECOVER: &str = "/recover";
    /// Undoes a recovery, whose ID is in the fragment; the notices link to it.
    pub(crate) const RECOVER_UNDO: &str = "/recover/undo";
    /// Hands an administrator's passkey session off to the admin dashboard.
    pub(crate) const ADMIN: &str = "/admin";

    /// The account's settings, at the paths piquel.fr served them on, so its redirect
    /// keeps old links and sent emails working.
    pub(crate) mod settings {
        /// Sign-in methods: passkeys and social sign-in.
        pub(crate) const HOME: &str = "/settings";
        /// Email addresses.
        pub(crate) const EMAILS: &str = "/settings/emails";
        /// Confirming an address, from its verification link.
        pub(crate) const VERIFY: &str = "/settings/emails/verify";
        /// Signed-in devices.
        pub(crate) const SESSIONS: &str = "/settings/sessions";
        /// Apps that keep access to the account.
        pub(crate) const APPS: &str = "/settings/apps";
        /// Security history.
        pub(crate) const HISTORY: &str = "/settings/history";
        /// Downloading the account's data, and deleting the account.
        pub(crate) const DATA: &str = "/settings/data";
    }

    /// The developer console: the account's apps, and each app's pages, whose
    /// `{id}` is its client ID.
    pub(crate) mod developers {
        use piquel_common::ClientId;

        /// The account's apps.
        pub(crate) const HOME: &str = "/developers";
        /// Registering an app.
        pub(crate) const NEW: &str = "/developers/new";
        /// An app's overview: what its `OpenID` Connect library needs.
        pub(crate) const APP: &str = "/developers/clients/{id}";
        /// An app's settings, disabling and deleting it.
        pub(crate) const APP_SETTINGS: &str = "/developers/clients/{id}/settings";
        /// A confidential app's secrets.
        pub(crate) const APP_SECRETS: &str = "/developers/clients/{id}/secrets";

        /// The page `template` of the app `id`. Client IDs need no escaping in a
        /// path segment.
        pub(crate) fn of(template: &str, id: &ClientId) -> String {
            template.replace("{id}", id.as_str())
        }
    }

    /// Every server-rendered page's route, which the security layer classifies as
    /// pages.
    pub(crate) const ALL: [&str; 19] = [
        LOGIN,
        REGISTER,
        CONSENT,
        LOGOUT,
        ADMIN,
        settings::HOME,
        settings::EMAILS,
        settings::VERIFY,
        settings::SESSIONS,
        settings::APPS,
        settings::HISTORY,
        settings::DATA,
        developers::HOME,
        developers::NEW,
        developers::APP,
        developers::APP_SETTINGS,
        developers::APP_SECRETS,
        RECOVER,
        RECOVER_UNDO,
    ];
}

/// Prefix shared by the account JSON APIs.
pub(crate) const ACCOUNT_PREFIX: &str = "/account/";
