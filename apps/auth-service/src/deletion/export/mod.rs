//! The account's data, as its owner downloads it (GDPR Art. 20): one versioned
//! JSON document, read from one snapshot. It holds no secret, digest or key
//! material: passkeys show their label, dates and backup state only.

use crate::admin::DashboardSignIn;
use crate::{
    clients::OwnedClientView, emails::EmailView, history::HistoryItem,
    notifications::NotificationItem, sessions::SessionItem,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use piquel_common::admin::Consent;
use piquel_common::{
    AccountStatus, Handle, PasskeyId, PictureId, Provider, RecoveryId, SessionId, UserId,
};
use piquel_repository::{
    DatabaseError, DatabaseTransaction, RecentRecovery, RecoveryState, StoredExternalIdentity,
    StoredGrant, StoredHandle, StoredPasskey, StoredPicture, StoredUser,
};
use serde::Serialize;
use serde_json::Value;

/// The `format` of every export.
const FORMAT: &str = "piquel.account-export";
/// The export's version; a change to its shape gets a new one.
const VERSION: u32 = 3;
/// Where the serialized credential holds whether the passkey may be synced.
const BACKUP_ELIGIBLE_POINTER: &str = "/cred/backup_eligible";
/// Where the serialized credential holds whether the passkey is synced.
const BACKED_UP_POINTER: &str = "/cred/backup_state";

/// Everything auth stores about an account, in one document:
/// `{"format": "piquel.account-export", "version": 3, …}`. Version 2 added the
/// profile picture; version 3 moved dashboard sessions under the sessions they
/// rest on, with when each was last used and ends.
#[derive(Serialize)]
pub(crate) struct AccountExport {
    /// Always [`FORMAT`].
    format: &'static str,
    /// Always [`VERSION`].
    version: u32,
    /// When the export was read.
    exported_at: DateTime<Utc>,
    /// The account itself.
    profile: Profile,
    /// The profile picture, if the account has one.
    picture: Option<Picture>,
    /// The handles the account holds or held, the current one first.
    handles: Vec<HandleHeld>,
    /// Whether the account is an administrator.
    administrator: bool,
    /// Email addresses, verified or not, primary first.
    emails: Vec<EmailView>,
    /// Active passkeys.
    passkeys: Vec<Passkey>,
    /// Linked social identities.
    identities: Vec<Identity>,
    /// Active browser sessions, most recently active first, with their devices,
    /// IP addresses and an administrator's dashboard sessions. The one that
    /// downloaded the export is `current`.
    sessions: Vec<SessionItem>,
    /// The scopes approved for each application.
    consents: Vec<Consent>,
    /// Applications' refresh grants, revoked ones included until cleanup deletes them.
    grants: Vec<StoredGrant>,
    /// The OIDC clients the account manages, as its developer console shows them.
    clients: Vec<OwnedClientView>,
    /// The recoveries support started for the account, newest first.
    recoveries: Vec<Recovery>,
    /// The security history, newest first, as the account's history page shows it.
    history: Vec<HistoryItem>,
    /// The inbox, newest first, with when each notification was read.
    notifications: Vec<NotificationItem>,
}

/// The account's profile.
#[derive(Debug, Serialize)]
struct Profile {
    /// Account ID, the `sub` applications know it by.
    id: UserId,
    /// Handle, also the login name.
    handle: Handle,
    /// Name shown to the user and to applications.
    display_name: String,
    /// Whether the account can sign in.
    status: AccountStatus,
    /// When the account was created.
    created_at: DateTime<Utc>,
    /// When the profile last changed.
    updated_at: DateTime<Utc>,
}

/// The profile picture: the JPEG auth stores and serves.
#[derive(Debug, Serialize)]
struct Picture {
    /// Picture ID, in its URL.
    id: PictureId,
    /// When it was uploaded.
    created_at: DateTime<Utc>,
    /// Always `image/jpeg`.
    content_type: &'static str,
    /// The image, in standard base64.
    data: String,
}

impl Picture {
    /// `picture`, whose bytes are `image`.
    fn new(picture: StoredPicture, image: &[u8]) -> Self {
        Self {
            id: picture.id,
            created_at: picture.created_at,
            content_type: "image/jpeg",
            data: base64::engine::general_purpose::STANDARD.encode(image),
        }
    }
}

/// A passkey, without its credential.
#[derive(Debug, Serialize)]
struct Passkey {
    /// Passkey ID.
    id: PasskeyId,
    /// The label its owner chose.
    friendly_name: String,
    /// When it was added.
    created_at: DateTime<Utc>,
    /// When it last signed in, if it has.
    last_used_at: Option<DateTime<Utc>>,
    /// Whether its authenticator lets it sync to other devices, if recorded.
    backup_eligible: Option<bool>,
    /// Whether it is synced, as of its last use, if recorded.
    backed_up: Option<bool>,
}

/// A linked social identity.
#[derive(Debug, Serialize)]
struct Identity {
    /// The provider.
    provider: Provider,
    /// The provider's identifier of the person.
    subject: String,
    /// The email the provider reported when it was linked, if any.
    linked_email: Option<String>,
}

/// A handle the account holds or held.
#[derive(Debug, Serialize)]
struct HandleHeld {
    /// The handle.
    handle: Handle,
    /// When the account claimed it.
    claimed_at: DateTime<Utc>,
    /// When it stopped being the account's handle; `None` for the current one.
    released_at: Option<DateTime<Utc>>,
}

impl From<StoredHandle> for HandleHeld {
    /// Keeps the handle and its dates.
    fn from(handle: StoredHandle) -> Self {
        Self {
            handle: handle.handle,
            claimed_at: handle.claimed_at,
            released_at: handle.released_at,
        }
    }
}

/// A recovery support started for the account, without its link.
#[derive(Debug, Serialize)]
struct Recovery {
    /// Recovery ID.
    id: RecoveryId,
    /// When support started it.
    started_at: DateTime<Utc>,
    /// When its link stopped, or stops, working if unused.
    expires_at: DateTime<Utc>,
    /// When its link enrolled a passkey, if it did.
    completed_at: Option<DateTime<Utc>>,
    /// The passkey its link enrolled, if it did.
    passkey_id: Option<PasskeyId>,
    /// When it was cancelled before its link was used.
    cancelled_at: Option<DateTime<Utc>>,
    /// When it was undone.
    undone_at: Option<DateTime<Utc>>,
    /// Where it stands: `open`, `probation`, `settled` or `ended`.
    state: &'static str,
    /// When its probation ends, while it lasts.
    settles_at: Option<DateTime<Utc>>,
}

impl From<RecentRecovery> for Recovery {
    /// Keeps its dates, state and passkey.
    fn from(recovery: RecentRecovery) -> Self {
        let (state, settles_at) = match recovery.state {
            RecoveryState::Open => ("open", None),
            RecoveryState::Probation { settles_at } => ("probation", Some(settles_at)),
            RecoveryState::Settled => ("settled", None),
            RecoveryState::Ended => ("ended", None),
        };
        Self {
            id: recovery.id,
            started_at: recovery.started_at,
            expires_at: recovery.expires_at,
            completed_at: recovery.completed_at,
            passkey_id: recovery.passkey.map(|passkey| passkey.id),
            cancelled_at: recovery.cancelled_at,
            undone_at: recovery.undone_at,
            state,
            settles_at,
        }
    }
}

impl From<StoredUser> for Profile {
    /// Keeps every column.
    fn from(user: StoredUser) -> Self {
        Self {
            id: user.id,
            handle: user.handle,
            display_name: user.display_name,
            status: user.status,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl From<StoredPasskey> for Passkey {
    /// Reads the backup flags out of the credential, and leaves the rest of it.
    fn from(passkey: StoredPasskey) -> Self {
        let flag = |pointer| passkey.credential.pointer(pointer).and_then(Value::as_bool);
        Self {
            backup_eligible: flag(BACKUP_ELIGIBLE_POINTER),
            backed_up: flag(BACKED_UP_POINTER),
            id: passkey.id,
            friendly_name: passkey.friendly_name,
            created_at: passkey.created_at,
            last_used_at: passkey.last_used_at,
        }
    }
}

impl From<StoredExternalIdentity> for Identity {
    /// Keeps the provider, its subject and the linked email.
    fn from(identity: StoredExternalIdentity) -> Self {
        Self {
            provider: identity.provider,
            subject: identity.subject,
            linked_email: identity.linked_email,
        }
    }
}

impl AccountExport {
    /// Reads the account `user_id` for its session `current` in `tx`, one
    /// snapshot, so every part is consistent with the others.
    pub(super) async fn read(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        current: SessionId,
    ) -> Result<Self, DatabaseError> {
        let user = tx
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        let picture = match tx.pictures().find(user_id).await? {
            Some(picture) => {
                let image = tx.pictures().image_of(user_id).await?;
                image.map(|image| Picture::new(picture, &image))
            }
            None => None,
        };
        Ok(Self {
            format: FORMAT,
            version: VERSION,
            exported_at: Utc::now(),
            picture,
            handles: (tx.handles().of_user(user_id).await?)
                .into_iter()
                .map(HandleHeld::from)
                .collect(),
            administrator: tx.administrators().contains(user_id).await?,
            emails: (tx.emails().list(user_id).await?)
                .into_iter()
                .map(EmailView::from)
                .collect(),
            passkeys: (tx.passkeys().list_active(user_id).await?)
                .into_iter()
                .map(Passkey::from)
                .collect(),
            identities: (tx.federation().list_active(user_id).await?)
                .into_iter()
                .map(Identity::from)
                .collect(),
            sessions: SessionItem::all(
                tx.sessions().list_active_for_user(user_id).await?,
                &(tx.dashboard())
                    .of_user(user_id, DashboardSignIn::idle_since())
                    .await?,
                Some(current),
            ),
            consents: tx.oidc().list_consents(user_id).await?,
            grants: tx.tokens().list_for_user(user_id).await?,
            recoveries: (tx
                .recoveries()
                .recent(user_id, DateTime::UNIX_EPOCH)
                .await?)
                .into_iter()
                .map(Recovery::from)
                .collect(),
            clients: (tx.oidc().list_owned_clients(user_id).await?)
                .into_iter()
                .map(OwnedClientView::from)
                .collect(),
            history: HistoryItem::all(tx, user_id).await?,
            notifications: NotificationItem::all(tx, user_id).await?,
            profile: user.into(),
        })
    }

    /// The download's file name, `piquel-account-<handle>-<date>.json`.
    /// Handles are lowercase ASCII letters, digits and `-`, so it needs no quoting
    /// in a header.
    pub(crate) fn file_name(&self) -> String {
        format!(
            "piquel-account-{}-{}.json",
            self.profile.handle,
            self.exported_at.format("%Y-%m-%d")
        )
    }
}

#[cfg(test)]
mod tests;
