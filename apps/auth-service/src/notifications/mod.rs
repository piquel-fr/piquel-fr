//! The account's inbox: the notifications its events gave it, newest first, read
//! or unread. Any administrator may also read them, which [`AccountService`]
//! serves, and reading never marks one read: only the owner does, by opening it
//! in their settings or through [`NotificationApplication`]'s routes.

use crate::{
    account::{AccountError, AccountService, Owner, Viewer},
    history::HistoryItem,
    routes,
    security::ApiError,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use chrono::{DateTime, Utc};
use piquel_common::{
    EventId, NotificationId, UserId,
    notifications::{Notification, NotificationPreference},
};
use piquel_repository::{Database, DatabaseError, DatabaseTransaction, StoredNotification};
use serde::{Deserialize, Serialize};

/// Notification failures and their response mapping.
mod error;
/// Email preferences and unsubscribe links.
mod preferences;
pub(crate) use error::NotificationError;
pub(crate) use preferences::{Unsubscribe, UnsubscribeLinks};

/// Notifications per page.
const PAGE_SIZE: u16 = 50;

/// The owner's routes that change their inbox's read state and email
/// preferences, and count what is unread.
#[derive(Clone)]
pub(crate) struct NotificationApplication {
    /// The operations behind the routes.
    service: AccountService,
}

/// The query of [`routes::notifications::LIST`].
#[derive(Deserialize)]
pub(crate) struct NotificationQuery {
    /// The previous page's [`NotificationPage::next`], to continue with older ones.
    pub(crate) before: Option<NotificationId>,
}

/// One page of the inbox, newest first.
#[derive(Serialize)]
pub(crate) struct NotificationPage {
    /// The notifications.
    pub(crate) notifications: Vec<NotificationItem>,
    /// The cursor of the next, older page, when there may be one.
    pub(crate) next: Option<NotificationId>,
}

/// One notification, with what it says.
#[derive(Serialize)]
pub(crate) struct NotificationItem {
    /// Notification ID.
    pub(crate) id: NotificationId,
    /// When it was written.
    pub(crate) created_at: DateTime<Utc>,
    /// When the owner read it, unless they marked it unread since.
    pub(crate) read_at: Option<DateTime<Utc>>,
    /// The event it comes from, which the security history shows while kept.
    pub(crate) event_id: Option<EventId>,
    /// Its `kind` and facts.
    #[serde(flatten)]
    pub(crate) notification: Notification,
    /// Its subject.
    pub(crate) subject: String,
    /// What it says.
    pub(crate) body: String,
}

/// One notification, as its own page shows it.
#[derive(Serialize)]
pub(crate) struct NotificationView {
    /// The notification.
    #[serde(flatten)]
    pub(crate) item: NotificationItem,
    /// Its event's entry in the security history, while the history keeps it.
    pub(crate) history: Option<HistoryItem>,
}

/// What an inbox page shows: a page of notifications, how many are unread, and
/// which categories are emailed.
pub(crate) struct Inbox {
    /// The page.
    pub(crate) page: NotificationPage,
    /// How many notifications are unread.
    pub(crate) unread: u64,
    /// Whether each category's notifications are emailed.
    pub(crate) preferences: Vec<NotificationPreference>,
}

/// How many notifications are unread.
#[derive(Serialize)]
pub(crate) struct Unread {
    /// The count.
    pub(crate) unread: u64,
}

impl NotificationItem {
    /// The notification `stored` holds, or `None` for a kind a newer release
    /// wrote.
    fn new(stored: StoredNotification) -> Option<Self> {
        let notification = stored.notification?;
        Some(Self {
            id: stored.id,
            created_at: stored.created_at,
            read_at: stored.read_at,
            event_id: stored.event_id,
            subject: notification.subject().to_owned(),
            body: notification.body(),
            notification,
        })
    }

    /// Whether the owner has read it.
    pub(crate) const fn read(&self) -> bool {
        self.read_at.is_some()
    }

    /// Every notification of `user`'s, newest first, read in `tx`, for their
    /// data export.
    pub(crate) async fn all(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
    ) -> Result<Vec<Self>, DatabaseError> {
        let mut items = Vec::new();
        let mut before = None;
        loop {
            let batch = tx
                .notifications()
                .list(user, before, u32::from(PAGE_SIZE))
                .await?;
            let exhausted = batch.len() < usize::from(PAGE_SIZE);
            before = batch.last().map(|stored| stored.id);
            items.extend(batch.into_iter().filter_map(Self::new));
            if exhausted {
                return Ok(items);
            }
        }
    }
}

/// The inbox any administrator may also read.
impl AccountService {
    /// A page of the account's notifications, newest first, older than `before`.
    pub(crate) async fn notifications(
        &self,
        viewer: &Viewer,
        before: Option<NotificationId>,
    ) -> Result<NotificationPage, AccountError> {
        viewer.authorize(&self.database).await?;
        let batch = self
            .database
            .notifications()
            .list(viewer.user(), before, u32::from(PAGE_SIZE))
            .await?;
        Ok(Self::page(batch))
    }

    /// The page a `batch` of at most [`PAGE_SIZE`] notifications makes.
    fn page(batch: Vec<StoredNotification>) -> NotificationPage {
        let next = (batch.len() == usize::from(PAGE_SIZE))
            .then(|| batch.last().map(|stored| stored.id))
            .flatten();
        NotificationPage {
            notifications: batch
                .into_iter()
                .filter_map(NotificationItem::new)
                .collect(),
            next,
        }
    }

    /// The account's notification `id`, with its event's history entry. Reading
    /// it marks nothing read.
    pub(crate) async fn notification(
        &self,
        viewer: &Viewer,
        id: NotificationId,
    ) -> Result<NotificationView, AccountError> {
        viewer.authorize(&self.database).await?;
        let item = self
            .database
            .notifications()
            .find(viewer.user(), id)
            .await?
            .and_then(NotificationItem::new)
            .ok_or(NotificationError::NotFound)?;
        let history = match item.event_id {
            Some(event_id) => HistoryItem::find(&self.database, viewer.user(), event_id).await?,
            None => None,
        };
        Ok(NotificationView { item, history })
    }

    /// The inbox's page of notifications older than `before`, with how many are
    /// unread and the email preferences, as its pages show them, authorized once.
    pub(crate) async fn inbox(
        &self,
        viewer: &Viewer,
        before: Option<NotificationId>,
    ) -> Result<Inbox, AccountError> {
        viewer.authorize(&self.database).await?;
        let mut notifications = self.database.notifications();
        Ok(Inbox {
            page: Self::page(
                notifications
                    .list(viewer.user(), before, u32::from(PAGE_SIZE))
                    .await?,
            ),
            unread: notifications.unread(viewer.user()).await?,
            preferences: notifications.preferences(viewer.user()).await?,
        })
    }

    /// How many of the account's notifications are unread.
    pub(crate) async fn unread_notifications(&self, viewer: &Viewer) -> Result<u64, AccountError> {
        viewer.authorize(&self.database).await?;
        Ok(self.database.notifications().unread(viewer.user()).await?)
    }
}

/// Marking notifications read or unread, which only the owner does: the read
/// state says what they have seen. Their session is enough.
impl AccountService {
    /// Marks the owner's notification `id` read, or unread.
    pub(crate) async fn mark_notification(
        &self,
        owner: &Owner,
        id: NotificationId,
        read: bool,
    ) -> Result<(), AccountError> {
        if self
            .database
            .notifications()
            .mark(owner.user(), id, read)
            .await?
        {
            Ok(())
        } else {
            Err(NotificationError::NotFound.into())
        }
    }

    /// Marks every notification of the owner's read.
    pub(crate) async fn read_all_notifications(&self, owner: &Owner) -> Result<(), AccountError> {
        Ok(self
            .database
            .notifications()
            .mark_all_read(owner.user())
            .await?)
    }
}

impl NotificationApplication {
    /// Serves the signed-in owner's inbox from `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self {
            service: AccountService::new(database),
        }
    }

    /// Returns the owner's inbox routes, with this application as state.
    pub(crate) fn routes(self) -> Router {
        use routes::notifications::{MARK_UNREAD, PREFERENCES, READ, READ_ALL, UNREAD};
        Router::new()
            .route(UNREAD, get(Self::unread))
            .route(PREFERENCES, put(Self::prefer))
            .route(READ, post(Self::read))
            .route(MARK_UNREAD, post(Self::mark_unread))
            .route(READ_ALL, post(Self::read_all))
            .with_state(self)
    }

    /// Says how many notifications are unread.
    async fn unread(State(app): State<Self>, owner: Owner) -> Result<Json<Unread>, ApiError> {
        let viewer = Viewer::from(&owner);
        let unread = app.service.unread_notifications(&viewer).await?;
        Ok(Json(Unread { unread }))
    }

    /// Marks one notification read.
    async fn read(
        State(app): State<Self>,
        owner: Owner,
        Path(id): Path<NotificationId>,
    ) -> Result<StatusCode, ApiError> {
        app.service.mark_notification(&owner, id, true).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Marks one notification unread.
    async fn mark_unread(
        State(app): State<Self>,
        owner: Owner,
        Path(id): Path<NotificationId>,
    ) -> Result<StatusCode, ApiError> {
        app.service.mark_notification(&owner, id, false).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Marks every notification read.
    async fn read_all(State(app): State<Self>, owner: Owner) -> Result<StatusCode, ApiError> {
        app.service.read_all_notifications(&owner).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Sets whether one category's notifications are emailed.
    async fn prefer(
        State(app): State<Self>,
        owner: Owner,
        Json(preference): Json<NotificationPreference>,
    ) -> Result<StatusCode, ApiError> {
        app.service
            .set_notification_preference(&owner, preference)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }
}

/// Supplies the shared database boundary to browser-session extractors.
impl axum::extract::FromRef<NotificationApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &NotificationApplication) -> Self {
        application.service.database.clone()
    }
}

/// Database-backed inbox scenarios.
#[cfg(test)]
mod tests;
