//! The account's data, as its owner downloads it (GDPR Art. 15 and 20): one
//! versioned JSON document, read from one snapshot. It holds every record
//! `sourceorigin_repository::Table` names as exported, and no secret, digest or key
//! material: passkeys show their label, dates and backup state only.
//!
//! Its events are unbounded, so the document streams: the request reads every
//! other section, then a task writes them and the events, a batch at a time,
//! while the browser downloads. The task holds the snapshot, and its database
//! connection, until the download ends or [`DEADLINE`] passes, so a replica
//! streams at most [`STREAMS`] exports at once.

use crate::{clients::OwnedClientView, emails::EmailView, history::HistoryItem};
use axum::body::Bytes;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sourceorigin_common::admin::{ApprovedOrigin, Consent, DashboardSession};
use sourceorigin_common::{
    AccountStatus, ClientId, ErrorChain, Handle, PasskeyId, PictureId, RecoveryId, SessionId,
    UserId, notifications::NotificationPreference,
};
use sourceorigin_repository::{
    AnnouncementRecord, DatabaseError, DatabaseTransaction, EventFilter, IdentityRecord,
    NotificationRecord, RecentRecovery, RecordedEvent, RecoveryState, SessionRecord, StoredGrant,
    StoredHandle, StoredOidcClient, StoredPasskey, StoredPicture, StoredUser,
};
use std::{collections::BTreeMap, time::Duration};
use tokio::sync::{
    Semaphore, SemaphorePermit,
    mpsc::{self, Sender},
};
use tokio_stream::wrappers::ReceiverStream;
use tracing::Instrument;

/// The `format` of every export.
const FORMAT: &str = "sourceorigin.account-export";
/// The export's version; a change to its shape gets a new one.
const VERSION: u32 = 4;
/// Where the serialized credential holds whether the passkey may be synced.
const BACKUP_ELIGIBLE_POINTER: &str = "/cred/backup_eligible";
/// Where the serialized credential holds whether the passkey is synced.
const BACKED_UP_POINTER: &str = "/cred/backup_state";
/// Events read, and sent to the browser, at a time.
const EVENT_BATCH: u16 = 500;
/// Chunks written ahead of the browser's download, at most: a slow download
/// holds the writer back rather than filling memory.
const CHUNKS_AHEAD: usize = 4;
/// How long an export may take to download, once its other sections are read.
const DEADLINE: Duration = Duration::from_mins(5);
/// How many exports a replica streams at once, each holding a database
/// connection: more would let one account, which may start several, starve
/// every other request of connections.
const STREAMS: usize = 2;
/// The replica's export streams; [`AccountExport::permit`] takes one.
static STREAMING: Semaphore = Semaphore::const_new(STREAMS);
/// The kind of the events left out: an administrator's views of the account,
/// which its history hides too, since a read may be a confidential inquiry.
const VIEWS: &str = "account_viewed";

/// Everything auth stores about an account, read from one snapshot and streamed
/// as one document: `{"format": "sourceorigin.account-export", "version": 4, …,
/// "events": […]}`. Version 2 added the profile picture; version 3 moved
/// dashboard sessions under the sessions they rest on. Version 4 added what
/// ended and is still stored (revoked passkeys, unlinked identities, ended
/// sessions), each session's apps, the owned apps' related origins, and every
/// event about the account as stored, which replaced its history, deleted apps,
/// notifications of kinds a newer release wrote, and received announcements.
pub(crate) struct AccountExport {
    /// Every section but the events, read when the export starts.
    records: Records,
    /// The snapshot the events are read from as the document streams.
    snapshot: DatabaseTransaction<'static>,
    /// Registered clients' names, by ID, which events name apps by.
    clients: BTreeMap<ClientId, String>,
    /// The replica's export stream this export holds until it ends.
    permit: SemaphorePermit<'static>,
}

/// Every section of the document but its events, which follow them.
#[derive(Serialize)]
struct Records {
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
    /// The account's administrator rights, if it has them.
    administrator: Option<Administrator>,
    /// Email addresses, verified or not, primary first.
    emails: Vec<EmailView>,
    /// Passkeys, revoked ones included until cleanup deletes them, oldest first.
    passkeys: Vec<Passkey>,
    /// Linked social identities, unlinked ones included until cleanup deletes
    /// them, oldest first.
    identities: Vec<IdentityRecord>,
    /// Browser sessions, ended ones included until cleanup deletes them, most
    /// recently active first, with their devices, IP addresses and apps. The one
    /// that downloaded the export is `current`.
    sessions: Vec<Session>,
    /// The scopes approved for each application.
    consents: Vec<Consent>,
    /// Applications' refresh grants, revoked ones included until cleanup deletes them.
    grants: Vec<StoredGrant>,
    /// The OIDC clients the account manages or managed, as its developer
    /// console shows them, with their related origins: a deleted one keeps only
    /// its ID, settings and dates.
    clients: Vec<Client>,
    /// The recoveries support started for the account, newest first.
    recoveries: Vec<Recovery>,
    /// The inbox, newest first, with when each notification was read.
    notifications: Vec<Notification>,
    /// Whether each category of notifications is emailed.
    notification_preferences: Vec<NotificationPreference>,
    /// The announcements the account received, newest first.
    announcements: Vec<AnnouncementRecord>,
}

/// The account's profile.
#[derive(Debug, Serialize)]
struct Profile {
    /// Account ID, the `sub` applications know it by.
    id: UserId,
    /// Handle, also the login name.
    handle: Handle,
    /// When the handle last changed.
    handle_changed_at: DateTime<Utc>,
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

/// The account's administrator rights.
#[derive(Debug, Serialize)]
struct Administrator {
    /// When they were granted.
    granted_at: DateTime<Utc>,
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
    /// When it was removed; `None` while it signs in.
    revoked_at: Option<DateTime<Utc>>,
    /// Whether its authenticator lets it sync to other devices, if recorded.
    backup_eligible: Option<bool>,
    /// Whether it is synced, as of its last use, if recorded.
    backed_up: Option<bool>,
}

/// A browser session.
#[derive(Debug, Serialize)]
struct Session {
    /// The session as stored.
    #[serde(flatten)]
    record: SessionRecord,
    /// Whether it downloaded the export.
    current: bool,
    /// An administrator's admin dashboard sessions resting on it, newest first.
    dashboard: Vec<DashboardSession>,
}

/// A client the account manages, or managed until it was deleted.
#[derive(Debug, Serialize)]
struct Client {
    /// The client, as the developer console shows it.
    #[serde(flatten)]
    view: OwnedClientView,
    /// When it was registered.
    created_at: DateTime<Utc>,
    /// When it was deleted; `None` while it exists.
    deleted_at: Option<DateTime<Utc>>,
    /// The origins approved for its pages to sign in with passkeys.
    related_origins: Vec<ApprovedOrigin>,
}

impl Client {
    /// `client`, with those of `origins` approved for it.
    fn new(client: StoredOidcClient, origins: &[ApprovedOrigin]) -> Self {
        Self {
            related_origins: (origins.iter())
                .filter(|origin| origin.client_id == client.id)
                .cloned()
                .collect(),
            created_at: client.created_at,
            deleted_at: client.deleted_at,
            view: OwnedClientView::from(client),
        }
    }
}

/// A notification of the inbox: as stored, with what it says when this release
/// knows its kind.
#[derive(Debug, Serialize)]
struct Notification {
    /// The notification as stored.
    #[serde(flatten)]
    record: NotificationRecord,
    /// Its subject; `None` for a kind a newer release wrote.
    subject: Option<String>,
    /// What it says; `None` for a kind a newer release wrote.
    body: Option<String>,
}

impl From<NotificationRecord> for Notification {
    /// Reads what it says from its payload, when this release knows its kind.
    fn from(record: NotificationRecord) -> Self {
        let known = serde_json::from_value::<sourceorigin_common::notifications::Notification>(
            record.payload.clone(),
        )
        .ok();
        Self {
            subject: (known.as_ref()).map(|known| known.subject().to_owned()),
            body: known.map(|known| known.body()),
            record,
        }
    }
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

impl Records {
    /// [`AccountExport::file_name`]. Handles are lowercase ASCII letters, digits
    /// and `-`, so it needs no quoting in a header.
    fn file_name(&self) -> String {
        format!(
            "sourceorigin-account-{}-{}.json",
            self.profile.handle,
            self.exported_at.format("%Y-%m-%d")
        )
    }
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
            handle_changed_at: user.handle_changed_at,
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
            revoked_at: passkey.revoked_at,
        }
    }
}

/// Why an export stopped streaming. The browser's download then fails, rather
/// than saving a truncated document.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExportError {
    /// Reading the events failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// A section could not be serialized.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The download outlasted [`DEADLINE`].
    #[error("the export did not finish downloading within {} seconds", DEADLINE.as_secs())]
    Deadline,
    /// The browser stopped downloading.
    #[error("the browser stopped downloading the export")]
    Closed,
}

impl AccountExport {
    /// One of the replica's export streams, or `None` while every one is in use.
    pub(super) fn permit() -> Option<SemaphorePermit<'static>> {
        STREAMING.try_acquire().ok()
    }

    /// Reads every section but the events of the account `user_id`, for its
    /// session `current`, from `snapshot`, which then streams the events, so
    /// every part is consistent with the others. Takes `permit` until the
    /// stream ends.
    pub(super) async fn read(
        mut snapshot: DatabaseTransaction<'static>,
        user_id: UserId,
        current: SessionId,
        permit: SemaphorePermit<'static>,
    ) -> Result<Self, DatabaseError> {
        // The snapshot waits on the browser's download between batches.
        snapshot.allow_idle(DEADLINE).await?;
        let tx = &mut snapshot;
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
        // Events name every app, so every client is read once for both. A
        // deleted client keeps its owner, so the account's tombstones are in it.
        let every = tx.oidc().list_clients().await?;
        let names = HistoryItem::names(&every);
        let origins = tx.oidc().related_origins().await?;
        let clients = (every.into_iter())
            .filter(|client| client.owner_id == Some(user_id))
            .map(|client| Client::new(client, &origins))
            .collect();
        // Every dashboard session still stored, idle ones included.
        let dashboard = (tx.dashboard())
            .of_user(user_id, DateTime::UNIX_EPOCH)
            .await?;
        let records = Records {
            format: FORMAT,
            version: VERSION,
            exported_at: Utc::now(),
            picture,
            handles: (tx.handles().of_user(user_id).await?)
                .into_iter()
                .map(HandleHeld::from)
                .collect(),
            administrator: (tx.exports().administrator_since(user_id).await?)
                .map(|granted_at| Administrator { granted_at }),
            emails: (tx.emails().list(user_id).await?)
                .into_iter()
                .map(EmailView::from)
                .collect(),
            passkeys: (tx.exports().passkeys(user_id).await?)
                .into_iter()
                .map(Passkey::from)
                .collect(),
            identities: tx.exports().identities(user_id).await?,
            sessions: (tx.exports().sessions(user_id).await?)
                .into_iter()
                .map(|record| Session {
                    current: record.id == current,
                    dashboard: DashboardSession::on(&dashboard, record.id),
                    record,
                })
                .collect(),
            consents: tx.oidc().list_consents(user_id).await?,
            grants: tx.tokens().list_for_user(user_id).await?,
            recoveries: (tx
                .recoveries()
                .recent(user_id, DateTime::UNIX_EPOCH)
                .await?)
                .into_iter()
                .map(Recovery::from)
                .collect(),
            clients,
            notifications: (tx.exports().notifications(user_id).await?)
                .into_iter()
                .map(Notification::from)
                .collect(),
            notification_preferences: tx.notifications().preferences(user_id).await?,
            announcements: tx.exports().announcements(user_id).await?,
            profile: user.into(),
        };
        Ok(Self {
            records,
            snapshot,
            clients: names,
            permit,
        })
    }

    /// The download's file name, `sourceorigin-account-<handle>-<date>.json`.
    pub(crate) fn file_name(&self) -> String {
        self.records.file_name()
    }

    /// The document, in chunks a task writes while they are downloaded, for at
    /// most [`DEADLINE`]. A failure is logged here, since no response reports
    /// it, and ends the stream with an error.
    pub(crate) fn stream(self) -> ReceiverStream<Result<Bytes, ExportError>> {
        let (sender, receiver) = mpsc::channel(CHUNKS_AHEAD);
        tokio::spawn(
            async move {
                let written = tokio::time::timeout(DEADLINE, self.write(&sender)).await;
                let error = match written {
                    Ok(Ok(()) | Err(ExportError::Closed)) => return,
                    Ok(Err(error)) => error,
                    Err(_) => ExportError::Deadline,
                };
                tracing::error!(error = %ErrorChain(&error), "account export failed");
                // The browser may already be gone.
                let _ = sender.send(Err(error)).await;
            }
            .in_current_span(),
        );
        ReceiverStream::new(receiver)
    }

    /// Writes the document to `sender`: the other sections, pretty-printed,
    /// then every event about the account but views, newest first, one per
    /// line. Ends the snapshot, and frees the stream, once written.
    async fn write(self, sender: &Sender<Result<Bytes, ExportError>>) -> Result<(), ExportError> {
        let Self {
            records,
            mut snapshot,
            clients,
            permit,
        } = self;
        let send = async |chunk: Vec<u8>| {
            (sender.send(Ok(chunk.into())).await).map_err(|_| ExportError::Closed)
        };
        let mut head = serde_json::to_vec_pretty(&records)?;
        // A struct with fields pretty-prints as `{…\n}`: reopen it for the events.
        head.truncate(head.len() - b"\n}".len());
        head.extend_from_slice(b",\n  \"events\": [");
        send(head).await?;
        let mut filter = EventFilter {
            subject: Some(records.profile.id),
            except_kind: Some(VIEWS.to_owned()),
            ..EventFilter::default()
        };
        let mut separator: &[u8] = b"\n    ";
        loop {
            let batch = (snapshot.events())
                .list(&filter, u32::from(EVENT_BATCH))
                .await?;
            let mut chunk = Vec::new();
            for stored in &batch {
                chunk.extend_from_slice(separator);
                separator = b",\n    ";
                let event: HistoryItem<&RecordedEvent> =
                    HistoryItem::with(stored, &clients, &stored.event);
                serde_json::to_writer(&mut chunk, &event)?;
            }
            send(chunk).await?;
            filter.before = batch.last().map(|stored| stored.id);
            if batch.len() < usize::from(EVENT_BATCH) {
                break;
            }
        }
        send(b"\n  ]\n}\n".to_vec()).await?;
        drop((snapshot, permit));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
