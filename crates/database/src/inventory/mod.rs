//! What every table holds about the people behind accounts: the one inventory
//! the data export and the purge are checked against. Its tests fail while a
//! migration adds a table it does not name, or a table referencing an account
//! that it says holds nothing; auth's export test fails while the export of an
//! account with a row in every table holds nothing at a path it names, and the
//! purge test while a purge leaves a row referencing the account. How long each kind of record is kept is documented beside the
//! cleanup statements (`MaintenanceRepository::purge_expired_auth_state`) and in
//! `docs/dev/architecture/account-deletion.md`.

piquel_common::str_enum! {
    /// Every table of the schema, by name.
    pub enum Table {
        /// Accounts scheduled for deletion, and their restore tokens.
        AccountDeletions = "account_deletions",
        /// Recoveries support started for accounts.
        AccountRecoveries = "account_recoveries",
        /// Which account holds each verified address.
        ActiveVerifiedEmailOwnership = "active_verified_email_ownership",
        /// Administrator rights.
        Administrators = "administrators",
        /// What administrators post on an alert while they handle it.
        AlertUpdates = "alert_updates",
        /// Conditions administrators are shown.
        Alerts = "alerts",
        /// The accounts an announcement goes to.
        AnnouncementRecipients = "announcement_recipients",
        /// Announcements administrators write.
        Announcements = "announcements",
        /// Where the audit chain starts.
        AuditAnchor = "audit_anchor",
        /// Signed checkpoints of the audit chain.
        AuditCheckpoints = "audit_checkpoints",
        /// Authorization codes.
        AuthorizationCodes = "authorization_codes",
        /// Authorization requests in progress.
        AuthorizationRequests = "authorization_requests",
        /// Digests of session cookies.
        BrowserSessionSecrets = "browser_session_secrets",
        /// Clients' related origins.
        ClientWebauthnOrigins = "client_webauthn_origins",
        /// Sign-ins to the admin dashboard in progress.
        DashboardHandoffs = "dashboard_handoffs",
        /// Administrators' sign-ins to the admin dashboard.
        DashboardSessions = "dashboard_sessions",
        /// The outbound delivery queue.
        Deliveries = "deliveries",
        /// The next position of each ordered delivery key.
        DeliveryOrderings = "delivery_orderings",
        /// Domain events, the audit chain's content.
        DomainEvents = "domain_events",
        /// Digests of address verification links.
        EmailVerificationSecrets = "email_verification_secrets",
        /// Event consumers' cursors.
        EventConsumers = "event_consumers",
        /// The personal data of each event.
        EventPersonalData = "event_personal_data",
        /// Linked GitHub and Google identities.
        ExternalLoginIdentities = "external_login_identities",
        /// Sign-ins at GitHub or Google in progress.
        FederationTransactions = "federation_transactions",
        /// Handles accounts hold or held.
        Handles = "handles",
        /// Signup invitations.
        Invitations = "invitations",
        /// Which categories of notifications each account has emailed.
        NotificationPreferences = "notification_preferences",
        /// Accounts' inboxes.
        Notifications = "notifications",
        /// Digests of client secrets.
        OidcClientSecrets = "oidc_client_secrets",
        /// OIDC clients.
        OidcClients = "oidc_clients",
        /// The scopes accounts approved for clients.
        OidcConsents = "oidc_consents",
        /// Clients' redirect URIs.
        OidcRedirectUris = "oidc_redirect_uris",
        /// The clients each session signed in to.
        OidcSessionClients = "oidc_session_clients",
        /// Passkeys.
        PasskeyCredentials = "passkey_credentials",
        /// GitHub and Google sign-ups in progress.
        PendingFederation = "pending_federation",
        /// Profile pictures.
        ProfilePictures = "profile_pictures",
        /// Refresh grants.
        RefreshTokenFamilies = "refresh_token_families",
        /// Digests of refresh tokens.
        RefreshTokens = "refresh_tokens",
        /// Rate limit counters.
        RequestLimits = "request_limits",
        /// Handles administrators reserved.
        ReservedHandles = "reserved_handles",
        /// Browser sessions.
        Sessions = "sessions",
        /// Token signing keys.
        SigningKeys = "signing_keys",
        /// Email addresses.
        UserEmails = "user_emails",
        /// Accounts.
        Users = "users",
        /// Passkey ceremonies in progress.
        WebauthnCeremonies = "webauthn_ceremonies",
    }
}

/// What a table holds about the person behind an account, and whether the
/// account's data export includes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holds {
    /// Nothing that identifies a person: keys, cursors, the audit chain's own
    /// records, or invitations, which name nobody.
    Nothing,
    /// The account's records, which its export includes at this path: a
    /// top-level section, then, through `/`, `*` for any item of an array and
    /// the field holding them, e.g. `clients/*/related_origins`.
    Exported(&'static str),
    /// Personal data the export leaves out, for this reason: a secret, state
    /// that lasts minutes, or a copy of what another section holds.
    Withheld(&'static str),
}

impl Table {
    /// What this table holds about the person behind an account. Naming every
    /// table, so a new one needs a decision before it compiles.
    #[must_use]
    pub const fn holds(self) -> Holds {
        match self {
            Self::Users => Holds::Exported("profile"),
            Self::ProfilePictures => Holds::Exported("picture"),
            Self::Handles => Holds::Exported("handles"),
            Self::Administrators => Holds::Exported("administrator"),
            Self::DashboardSessions => Holds::Exported("dashboard_sessions"),
            Self::UserEmails => Holds::Exported("emails"),
            // A copy of the verified addresses.
            Self::ActiveVerifiedEmailOwnership => Holds::Exported("emails/*/verified"),
            Self::PasskeyCredentials => Holds::Exported("passkeys"),
            Self::ExternalLoginIdentities => Holds::Exported("identities"),
            Self::Sessions => Holds::Exported("sessions"),
            Self::OidcSessionClients => Holds::Exported("sessions/*/clients"),
            Self::OidcConsents => Holds::Exported("consents"),
            Self::RefreshTokenFamilies => Holds::Exported("grants"),
            Self::OidcClients => Holds::Exported("clients"),
            Self::OidcRedirectUris => Holds::Exported("clients/*/redirect_uris"),
            Self::ClientWebauthnOrigins => Holds::Exported("clients/*/related_origins"),
            Self::AccountRecoveries => Holds::Exported("recoveries"),
            Self::DomainEvents => Holds::Exported("events"),
            Self::EventPersonalData => Holds::Exported("events/*/ip"),
            Self::Notifications => Holds::Exported("notifications"),
            Self::NotificationPreferences => Holds::Exported("notification_preferences"),
            // Sent ones; a draft is the administrators' until it is sent.
            Self::Announcements | Self::AnnouncementRecipients => Holds::Exported("announcements"),
            Self::AccountDeletions => Holds::Withheld(
                "it exists only while the account is scheduled for deletion, \
                when nobody can sign in to export it",
            ),
            Self::Deliveries => Holds::Withheld(
                "outbound messages, copies of notifications and logout tokens, \
                deleted 7 to 30 days after they finish",
            ),
            Self::BrowserSessionSecrets
            | Self::EmailVerificationSecrets
            | Self::RefreshTokens
            | Self::OidcClientSecrets => Holds::Withheld("digests of secrets"),
            Self::AuthorizationRequests
            | Self::AuthorizationCodes
            | Self::WebauthnCeremonies
            | Self::FederationTransactions
            | Self::PendingFederation
            | Self::DashboardHandoffs => {
                Holds::Withheld("sign-ins and ceremonies in progress, deleted within a day")
            }
            Self::AlertUpdates => Holds::Withheld(
                "administrators' handling of alerts, naming its author as an event's \
                actor does; its note is its event's personal data",
            ),
            Self::RequestLimits => Holds::Withheld(
                "keyed digests of IP addresses, accounts and email addresses, \
                deleted within an hour",
            ),
            Self::ReservedHandles => Holds::Withheld(
                "handles administrators reserved, maybe for a person, tied to no account",
            ),
            Self::Alerts
            | Self::AuditAnchor
            | Self::AuditCheckpoints
            | Self::DeliveryOrderings
            | Self::EventConsumers
            | Self::Invitations
            | Self::SigningKeys => Holds::Nothing,
        }
    }
}

/// The inventory against the migrated schema.
#[cfg(test)]
mod tests;
