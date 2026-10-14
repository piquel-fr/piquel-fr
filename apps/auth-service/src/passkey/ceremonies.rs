//! Typed, single-use `WebAuthn` state bound to the browser that started it.

use super::{
    BrowserCookie, PasskeyApplication, PasskeyError,
    types::{CeremonyResponse, DisplayName, Username},
};
use axum::{
    Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use piquel_crypto::Secret;
use piquel_repository::{CeremonyKind, InsertCeremony};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration,
};

/// Browser proofs expire after five minutes regardless of cookie lifetime.
const CEREMONY_LIFETIME: Duration = Duration::minutes(5);

/// Initial account registration and the identity data to commit with its passkey.
#[derive(Serialize, Deserialize)]
pub(super) struct RegistrationCeremony {
    /// New account identifier included in the authenticator's user handle.
    pub(super) user_id: UserId,
    /// Validated account username.
    pub(super) username: Username,
    /// Validated account display name.
    pub(super) display_name: DisplayName,
    /// Digest redeemed atomically with account creation when admission is gated.
    pub(super) invitation: Option<Vec<u8>>,
    /// Explicit social signup to attach inside account creation, if any.
    pub(super) pending: Option<TokenId>,
    /// Library state containing the challenge; never returned or logged.
    pub(super) state: PasskeyRegistration,
}

/// Authentication against an already identified account's credentials.
#[derive(Serialize, Deserialize)]
pub(super) struct LoginCeremony {
    /// Account named when authentication started.
    pub(super) user_id: UserId,
    /// Server-side challenge and credential snapshot.
    pub(super) state: PasskeyAuthentication,
}

/// Account-picker authentication whose account is learned from the signed response.
#[derive(Serialize, Deserialize)]
pub(super) struct DiscoverCeremony {
    /// Server-side account-picker challenge.
    pub(super) state: DiscoverableAuthentication,
}

/// Passkey proof that unlocks settings only for the initiating session.
#[derive(Serialize, Deserialize)]
pub(super) struct ManagementCeremony {
    /// Account that must still own the current session.
    pub(super) user_id: UserId,
    /// Initiating session; another login cannot reuse this management proof.
    pub(super) session_id: SessionId,
    /// Server-side authentication challenge and credential snapshot.
    pub(super) state: PasskeyAuthentication,
}

/// Additional credential registration bound to an authorized settings session.
#[derive(Serialize, Deserialize)]
pub(super) struct EnrollmentCeremony {
    /// Account receiving the new credential.
    pub(super) user_id: UserId,
    /// Session that started the enrollment and must still be authorized.
    pub(super) session_id: SessionId,
    /// Server-side registration challenge.
    pub(super) state: PasskeyRegistration,
}

/// Persisted ceremony payload; its variant determines kind and account/session binding.
/// Stored as externally tagged JSON, such as `{"Discover": {...}}`.
#[derive(Serialize, Deserialize)]
pub(super) enum Ceremony {
    /// Initial account and first passkey creation.
    Register(RegistrationCeremony),
    /// Username-based authentication.
    Login(LoginCeremony),
    /// Username-based authentication for a username without an active account or
    /// passkey. It holds no `WebAuthn` state, so its finish can never succeed.
    Decoy,
    /// Discoverable account-picker authentication.
    Discover(DiscoverCeremony),
    /// Settings authorization for the initiating session.
    Manage(ManagementCeremony),
    /// Additional passkey creation.
    Enroll(EnrollmentCeremony),
}

impl Ceremony {
    /// Derives the database purpose so callers cannot store a mismatched kind.
    pub(super) const fn kind(&self) -> CeremonyKind {
        match self {
            Self::Register(_) => CeremonyKind::Registration,
            Self::Login(_) | Self::Decoy | Self::Discover(_) => CeremonyKind::Authentication,
            Self::Manage(_) => CeremonyKind::PurposeAuthentication,
            Self::Enroll(_) => CeremonyKind::Enrollment,
        }
    }

    /// Derives the existing-account binding; signup has no account row yet.
    const fn user_id(&self) -> Option<UserId> {
        match self {
            Self::Register(_) | Self::Decoy | Self::Discover(_) => None,
            Self::Login(state) => Some(state.user_id),
            Self::Manage(state) => Some(state.user_id),
            Self::Enroll(state) => Some(state.user_id),
        }
    }

    /// Derives the initiating-session binding for settings operations.
    const fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::Register(_) | Self::Login(_) | Self::Decoy | Self::Discover(_) => None,
            Self::Manage(state) => Some(state.session_id),
            Self::Enroll(state) => Some(state.session_id),
        }
    }
}

/// Stored browser binding; the challenge state never travels in cookies.
#[derive(Serialize, Deserialize)]
struct BoundCeremony {
    /// Digest of the ceremony cookie secret.
    browser_digest: Vec<u8>,
    /// Typed server-side ceremony payload.
    ceremony: Ceremony,
}

/// Expected payload and purpose for a typed ceremony consumer.
pub(super) trait CeremonyState: Sized {
    /// Database purpose to consume exactly once.
    const KIND: CeremonyKind;
    /// Extracts the expected payload without exposing variants to HTTP handlers.
    fn extract(ceremony: Ceremony) -> Option<Self>;
}

/// Implements `CeremonyState` for a payload stored in exactly one `Ceremony` variant.
macro_rules! ceremony_state {
    ($state:ident, $variant:ident, $kind:ident) => {
        impl CeremonyState for $state {
            const KIND: CeremonyKind = CeremonyKind::$kind;
            /// Returns the payload if the ceremony is this variant.
            fn extract(ceremony: Ceremony) -> Option<Self> {
                if let Ceremony::$variant(state) = ceremony {
                    Some(state)
                } else {
                    None
                }
            }
        }
    };
}
ceremony_state!(RegistrationCeremony, Register, Registration);
ceremony_state!(ManagementCeremony, Manage, PurposeAuthentication);
ceremony_state!(EnrollmentCeremony, Enroll, Enrollment);

/// Either supported account sign-in payload, sharing one database purpose.
pub(super) enum AuthenticationCeremony {
    /// Account identified by username before the challenge.
    Login(LoginCeremony),
    /// Username without an active account or passkey; always rejected.
    Decoy,
    /// Account identified by the authenticator's response.
    Discover(DiscoverCeremony),
}

impl CeremonyState for AuthenticationCeremony {
    const KIND: CeremonyKind = CeremonyKind::Authentication;
    /// Accepts both login forms and rejects all registration or settings payloads.
    fn extract(ceremony: Ceremony) -> Option<Self> {
        match ceremony {
            Ceremony::Login(state) => Some(Self::Login(state)),
            Ceremony::Decoy => Some(Self::Decoy),
            Ceremony::Discover(state) => Some(Self::Discover(state)),
            Ceremony::Register(_) | Ceremony::Manage(_) | Ceremony::Enroll(_) => None,
        }
    }
}

impl PasskeyApplication {
    /// Persists a ceremony whose kind and account/session bindings come from its payload.
    pub(super) async fn start(
        &self,
        headers: &HeaderMap,
        ceremony: Ceremony,
        challenge: impl Serialize,
    ) -> Result<Response, PasskeyError> {
        // Reuse the browser's existing binding so overlapping ceremonies stay valid.
        let browser = match BrowserCookie::Ceremony.read(headers) {
            Some(browser) => browser,
            None => Secret::generate()?,
        };
        let id = TokenId::new();
        let browser_digest = browser.digest().as_bytes().to_vec();
        self.database
            .passkeys()
            .insert_ceremony(&InsertCeremony {
                id,
                user_id: ceremony.user_id(),
                session_id: ceremony.session_id(),
                kind: ceremony.kind(),
                challenge_digest: browser_digest.clone(),
                state: serde_json::to_value(BoundCeremony {
                    browser_digest,
                    ceremony,
                })
                .map_err(PasskeyError::Serialization)?,
                expires_at: Utc::now() + CEREMONY_LIFETIME,
            })
            .await?;
        let mut response = Json(CeremonyResponse {
            ceremony_id: id,
            // Preserve the existing nested JSON map ordering from the library's challenge.
            public_key: serde_json::to_value(challenge).map_err(PasskeyError::Serialization)?,
        })
        .into_response();
        BrowserCookie::Ceremony.set_on(&mut response, &browser)?;
        Ok(response)
    }

    /// Consumes the expected payload once, checking its browser binding before extraction.
    pub(super) async fn consume<T: CeremonyState>(
        &self,
        headers: &HeaderMap,
        id: TokenId,
    ) -> Result<T, PasskeyError> {
        let browser = BrowserCookie::Ceremony
            .read(headers)
            .ok_or(PasskeyError::CeremonyBrowserMissing)?;
        // Once taken, an invalid response cannot reuse the challenge in another attempt.
        // A missing, expired or already consumed ceremony surfaces as `DatabaseError::NotFound`.
        let record = self
            .database
            .passkeys()
            .consume_ceremony(id, T::KIND)
            .await?;
        let bound: BoundCeremony =
            serde_json::from_value(record.state).map_err(PasskeyError::StoredCeremony)?;
        if bound.browser_digest != browser.digest().as_bytes() {
            return Err(PasskeyError::BrowserMismatch);
        }
        T::extract(bound.ceremony).ok_or(PasskeyError::WrongCeremony)
    }
}
