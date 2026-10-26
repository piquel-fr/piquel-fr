//! Typed, single-use `WebAuthn` state bound to the browser that started it, or for
//! a related origin's page, to that origin and the request it completes.

use super::{
    BrowserCookie, PasskeyApplication, PasskeyError,
    types::{CeremonyResponse, DisplayName},
};
use crate::oidc::InlineClaim;
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use piquel_common::{
    ClientId, Handle, RecoveryId, SessionId, TokenId, UserId, clients::RelatedOrigin,
};
use piquel_crypto::{Digest, Secret};
use piquel_repository::{CeremonyKind, DatabaseTransaction, InsertCeremony};
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
    /// Validated, unreserved account handle, free when the ceremony started. The
    /// release before handles stored it as `username`.
    #[serde(alias = "username")]
    pub(super) handle: Handle,
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

/// Passkey proof that confirms only the initiating session.
#[derive(Serialize, Deserialize)]
pub(super) struct ConfirmationCeremony {
    /// Account that must still own the current session.
    pub(super) user_id: UserId,
    /// Initiating session; another login cannot reuse this confirmation.
    pub(super) session_id: SessionId,
    /// Server-side authentication challenge and credential snapshot.
    pub(super) state: PasskeyAuthentication,
}

/// Passkey proof that an administrator's handoff to the admin dashboard posts. It
/// confirms that handoff only, never the session, so a confirmation done for
/// auth's own pages never counts for the dashboard, nor this one for them.
#[derive(Serialize, Deserialize)]
pub(super) struct AdminProofCeremony {
    /// Account that must still own the current session.
    pub(super) user_id: UserId,
    /// Initiating session, which must be the one handing off.
    pub(super) session_id: SessionId,
    /// Server-side authentication challenge and credential snapshot.
    pub(super) state: PasskeyAuthentication,
}

/// Passkey proof that undoes a recovery. It needs no session, so ending the
/// owner's sessions cannot stop it, and works on a disabled account; the
/// assertion itself is the proof.
#[derive(Serialize, Deserialize)]
pub(super) struct UndoCeremony {
    /// The recovery to undo, which must still be the account's undoable one.
    pub(super) recovery_id: RecoveryId,
    /// Its account.
    pub(super) user_id: UserId,
    /// Server-side authentication challenge, offering every active passkey of
    /// the account but the recovery's own.
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

/// Registration of a passkey through a recovery's link, authorized by the link
/// alone. Its finish signs the browser in with a new session, whatever session
/// it had.
#[derive(Serialize, Deserialize)]
pub(super) struct RecoveryCeremony {
    /// The recovery whose link started it, which must still work at its finish.
    pub(super) recovery_id: RecoveryId,
    /// Account receiving the new credential.
    pub(super) user_id: UserId,
    /// Server-side registration challenge.
    pub(super) state: PasskeyRegistration,
}

/// Persisted ceremony payload; its variant determines kind and account/session binding.
/// Stored as externally tagged JSON, such as `{"Discover": {...}}`.
#[derive(Serialize, Deserialize)]
pub(super) enum Ceremony {
    /// Initial account and first passkey creation.
    Register(RegistrationCeremony),
    /// Handle-based authentication.
    Login(LoginCeremony),
    /// Handle-based authentication for a handle without an active account or
    /// passkey. It holds no `WebAuthn` state, so its finish can never succeed.
    Decoy,
    /// Discoverable account-picker authentication.
    Discover(DiscoverCeremony),
    /// Settings authorization for the initiating session.
    Confirm(ConfirmationCeremony),
    /// Additional passkey creation.
    Enroll(EnrollmentCeremony),
    /// Passkey creation through a recovery's link.
    Recover(RecoveryCeremony),
    /// Passkey proof that undoes a recovery.
    Undo(UndoCeremony),
    /// Passkey proof of a handoff to the admin dashboard.
    AdminProof(AdminProofCeremony),
}

impl Ceremony {
    /// Derives the database purpose so callers cannot store a mismatched kind.
    pub(super) const fn kind(&self) -> CeremonyKind {
        match self {
            Self::Register(_) => CeremonyKind::Registration,
            Self::Login(_) | Self::Decoy | Self::Discover(_) => CeremonyKind::Authentication,
            Self::Confirm(_) | Self::Undo(_) | Self::AdminProof(_) => {
                CeremonyKind::PurposeAuthentication
            }
            Self::Enroll(_) | Self::Recover(_) => CeremonyKind::Enrollment,
        }
    }

    /// Derives the existing-account binding; signup has no account row yet.
    const fn user_id(&self) -> Option<UserId> {
        match self {
            Self::Register(_) | Self::Decoy | Self::Discover(_) => None,
            Self::Login(state) => Some(state.user_id),
            Self::Confirm(state) => Some(state.user_id),
            Self::Enroll(state) => Some(state.user_id),
            Self::Recover(state) => Some(state.user_id),
            Self::Undo(state) => Some(state.user_id),
            Self::AdminProof(state) => Some(state.user_id),
        }
    }

    /// Derives the initiating-session binding for settings operations.
    const fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::Register(_)
            | Self::Login(_)
            | Self::Decoy
            | Self::Discover(_)
            | Self::Recover(_)
            | Self::Undo(_) => None,
            Self::Confirm(state) => Some(state.session_id),
            Self::Enroll(state) => Some(state.session_id),
            Self::AdminProof(state) => Some(state.session_id),
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
ceremony_state!(ConfirmationCeremony, Confirm, PurposeAuthentication);
ceremony_state!(EnrollmentCeremony, Enroll, Enrollment);
ceremony_state!(RecoveryCeremony, Recover, Enrollment);
ceremony_state!(UndoCeremony, Undo, PurposeAuthentication);
ceremony_state!(AdminProofCeremony, AdminProof, PurposeAuthentication);

/// Either supported account sign-in payload, sharing one database purpose.
#[derive(Serialize, Deserialize)]
pub(super) enum AuthenticationCeremony {
    /// Account identified by handle before the challenge.
    Login(LoginCeremony),
    /// Handle without an active account or passkey; always rejected.
    Decoy,
    /// Account identified by the authenticator's response.
    Discover(DiscoverCeremony),
}

/// Sign-in on the page of an approved related origin. That page cannot send the
/// ceremony cookie, so the ceremony is bound to its origin and to the pushed
/// request it completes instead. It is stored as is, under its own purpose.
#[derive(Serialize, Deserialize)]
pub(super) struct RelatedCeremony {
    /// The page's origin, which must finish the ceremony and sign the assertion.
    pub(super) origin: RelatedOrigin,
    /// The client the origin was approved for.
    pub(super) client_id: ClientId,
    /// The client's pushed request, claimed when the ceremony started.
    pub(super) claim: InlineClaim,
    /// The hinted account's sign-in, or else an account picker; never a decoy.
    pub(super) sign_in: AuthenticationCeremony,
}

impl CeremonyState for AuthenticationCeremony {
    const KIND: CeremonyKind = CeremonyKind::Authentication;
    /// Accepts both login forms and rejects all registration or settings payloads.
    fn extract(ceremony: Ceremony) -> Option<Self> {
        match ceremony {
            Ceremony::Login(state) => Some(Self::Login(state)),
            Ceremony::Decoy => Some(Self::Decoy),
            Ceremony::Discover(state) => Some(Self::Discover(state)),
            Ceremony::Register(_)
            | Ceremony::Confirm(_)
            | Ceremony::Enroll(_)
            | Ceremony::Recover(_)
            | Ceremony::Undo(_)
            | Ceremony::AdminProof(_) => None,
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
        let mut response = CeremonyResponse::new(id, challenge)?.into_response();
        BrowserCookie::Ceremony.set_on(&mut response, &browser)?;
        Ok(response)
    }

    /// Persists a related origin's ceremony inside `tx`, which also holds the claim
    /// of its request, so both commit together or not at all.
    pub(super) async fn start_related(
        tx: &mut DatabaseTransaction<'_>,
        ceremony: RelatedCeremony,
        challenge: impl Serialize,
    ) -> Result<Response, PasskeyError> {
        let id = TokenId::new();
        tx.passkeys()
            .insert_ceremony(&InsertCeremony {
                id,
                user_id: match &ceremony.sign_in {
                    AuthenticationCeremony::Login(state) => Some(state.user_id),
                    AuthenticationCeremony::Decoy | AuthenticationCeremony::Discover(_) => None,
                },
                session_id: None,
                kind: CeremonyKind::RelatedAuthentication,
                // Unread: the stored origin and claim bind the ceremony; this fills
                // the column every ceremony has.
                challenge_digest: Digest::sha256(ceremony.origin.as_str().as_bytes())
                    .as_bytes()
                    .to_vec(),
                state: serde_json::to_value(ceremony).map_err(PasskeyError::Serialization)?,
                expires_at: Utc::now() + CEREMONY_LIFETIME,
            })
            .await?;
        Ok(CeremonyResponse::new(id, challenge)?.into_response())
    }

    /// Consumes a related origin's ceremony once. The caller checks its origin.
    pub(super) async fn consume_related(
        &self,
        id: TokenId,
    ) -> Result<RelatedCeremony, PasskeyError> {
        let record = self
            .database
            .passkeys()
            .consume_ceremony(id, CeremonyKind::RelatedAuthentication)
            .await?;
        serde_json::from_value(record.state).map_err(PasskeyError::StoredCeremony)
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
