//! Every HTTP path the service serves. Routers, discovery metadata and the security
//! layer's endpoint classification all read these, so they cannot drift apart.

/// Health probes.
pub(crate) mod service {
    /// Liveness probe; answers whenever the process serves HTTP.
    pub(crate) const LIVE: &str = "/health/live";
    /// Readiness probe; also checks the database and the signing keys' freshness.
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
    /// Starts the passkey proof of a handoff to the admin dashboard, which the
    /// handoff page posts and verifies itself: it counts for that handoff only.
    pub(crate) const ADMIN_PROOF_START: &str = "/admin/proof/start";

    /// The ceremonies auth's pages run, which their router keeps in every page's
    /// context.
    pub(crate) const CEREMONIES: piquel_ui::PasskeyRoutes = {
        use piquel_ui::CeremonyRoutes as Routes;
        piquel_ui::PasskeyRoutes {
            sign_in: Routes {
                start: AUTHENTICATE_START,
                finish: AUTHENTICATE_FINISH,
            },
            register: Routes {
                start: REGISTER_START,
                finish: REGISTER_FINISH,
            },
            enroll: Routes {
                start: ENROLL_START,
                finish: ENROLL_FINISH,
            },
            confirm: Routes {
                start: CONFIRM_START,
                finish: CONFIRM_FINISH,
            },
            recover: Routes {
                start: super::recovery::START,
                finish: super::recovery::FINISH,
            },
            undo: Routes {
                start: super::recovery::UNDO_START,
                finish: super::recovery::UNDO_FINISH,
            },
        }
    };
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

/// Profile pictures.
pub(crate) mod pictures {
    use piquel_common::{PictureId, config::Origin};

    /// A picture, by the ID of its upload. No file extension, so the edge, which
    /// caches static files by extension, keeps no copy past its removal.
    pub(crate) const IMAGE: &str = "/pictures/{id}";
    /// The account's own picture: viewing, setting and removing it.
    pub(crate) const OWN: &str = "/account/picture";

    /// The path of the picture `id`. IDs need no escaping in a path segment.
    pub(crate) fn of(id: PictureId) -> String {
        IMAGE.replace("{id}", &id.to_string())
    }

    /// The picture `id`'s URL on `origin`: its `picture` claim.
    pub(crate) fn url(origin: &Origin, id: PictureId) -> String {
        origin.join(&of(id))
    }
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

/// The apps that keep access to the account.
pub(crate) mod apps {
    /// Lists the apps that keep access to the account.
    pub(crate) const LIST: &str = "/account/apps";
    /// Removes one app's access.
    pub(crate) const ITEM: &str = "/account/apps/{client_id}";
}

/// The account's profile, which relying parties receive.
pub(crate) mod profile {
    /// Changes the display name.
    pub(crate) const ITEM: &str = "/account/profile";
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
    /// The passkey ceremony the dashboard's dialog runs, under `/start` and
    /// `/finish`, to confirm the dashboard on its own page.
    pub(crate) const CONFIRM: &str = "/confirm";
    /// Keeps the theme and sidebar preferences a page's forms post, in cookies.
    pub(crate) const PREFERENCES: &str = "/preferences";
    /// Every path the dashboard serves is one of these, or under one: the admin
    /// listener mounts the pages on them, and nowhere else.
    pub(crate) const PREFIXES: [&str; 15] = [
        "/",
        SIGN_IN,
        CONFIRM,
        "/sign-out",
        PREFERENCES,
        "/assets",
        "/users",
        "/administrators",
        "/invitations",
        "/handles",
        "/clients",
        "/events",
        "/deliveries",
        "/keys",
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
    /// Keeps the theme and sidebar preferences a page's forms post, in cookies.
    pub(crate) const PREFERENCES: &str = "/preferences";

    /// The account's settings, at the paths piquel.fr served them on, so its redirect
    /// keeps old links and sent emails working.
    pub(crate) mod settings {
        /// The account at a glance.
        pub(crate) const HOME: &str = "/settings";
        /// Sign-in methods: passkeys and social sign-in.
        pub(crate) const SIGN_IN: &str = "/settings/sign-in";
        /// The profile: its handle, display name and picture.
        pub(crate) const PROFILE: &str = "/settings/profile";
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
    pub(crate) const ALL: [&str; 22] = [
        LOGIN,
        REGISTER,
        CONSENT,
        LOGOUT,
        ADMIN,
        PREFERENCES,
        settings::HOME,
        settings::SIGN_IN,
        settings::PROFILE,
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
