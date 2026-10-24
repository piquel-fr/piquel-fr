//! The account's security history, and the owner's reports of entries that were
//! not theirs. Any administrator may also read the history, which
//! [`AccountService`] serves; only the owner can report an entry.
use crate::account::{AccountError, AccountService, Owner, Viewer};
use crate::routes;
use crate::security::ApiError;
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::{DateTime, Utc};
use piquel_common::{
    ClientId, EventId, Personal, UserId,
    events::{
        Actor, DomainEvent, FollowUp, HistoryActor, HistoryEntry, RequestOrigin, RevocationReason,
        UserAgentFamily,
    },
};
use piquel_repository::{Database, EventFilter, EventRepository, SessionScope, StoredEvent};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

/// History failures and their browser response mapping.
mod error;
pub(crate) use error::HistoryError;

/// Entries per page.
const PAGE_SIZE: u16 = 50;
/// Batches of [`PAGE_SIZE`] events one page reads at most, visible or not, so a
/// long run of hidden events cannot hold a request.
const MAX_BATCHES: usize = 10;

/// The account's security history and its reports.
#[derive(Clone)]
pub(crate) struct HistoryApplication {
    /// Events, sessions, refresh families and client names.
    database: Database,
}

/// The query of [`routes::history::LIST`].
#[derive(Deserialize)]
pub(crate) struct HistoryQuery {
    /// The previous page's [`HistoryPage::next`], to continue with older entries.
    pub(crate) before: Option<EventId>,
}

/// One page of the account's history, newest first.
#[derive(Serialize)]
pub(crate) struct HistoryPage {
    /// The entries.
    pub(crate) entries: Vec<HistoryItem>,
    /// The cursor of the next, older page, when there may be one. A page can be
    /// short, even empty, and still have one.
    pub(crate) next: Option<EventId>,
}

/// One entry of the account's history. Entries whose actor is `account` can be
/// reported.
#[derive(Serialize)]
pub(crate) struct HistoryItem {
    /// Event ID, to report the entry.
    pub(crate) id: EventId,
    /// When it happened.
    pub(crate) occurred_at: DateTime<Utc>,
    /// What happened: its `kind` and details.
    #[serde(flatten)]
    pub(crate) entry: HistoryEntry,
    /// Who did it.
    pub(crate) actor: HistoryActor,
    /// Why, as the administrator or operator who did it wrote it, while kept.
    pub(crate) reason: Option<String>,
    /// The application involved, if any.
    pub(crate) client: Option<ClientView>,
    /// The request's IP address, while kept.
    pub(crate) ip: Option<IpAddr>,
    /// The request's browser and platform, while kept. Entries recorded before
    /// platforms were have `other` for theirs.
    pub(crate) device: Option<UserAgentFamily>,
    /// Whether retention or a purge deleted the IP address and device.
    pub(crate) erased: bool,
}

/// An application named by a history entry.
#[derive(Serialize)]
pub(crate) struct ClientView {
    /// Client ID.
    pub(crate) id: ClientId,
    /// The name its consent screen shows; `None` if it is not registered.
    pub(crate) name: Option<String>,
}

/// The answer to a report.
#[derive(Serialize)]
struct Report {
    /// What the user should still do to undo the entry. It needs a passkey confirmation.
    follow_up: Option<FollowUp>,
}

impl HistoryItem {
    /// The entry `stored` shows its subject, or `None` if it shows none, as for an
    /// event a newer release wrote. `clients` maps client IDs to their names.
    fn new(stored: &StoredEvent, clients: &BTreeMap<ClientId, String>) -> Option<Self> {
        let event = stored.event.known()?;
        let entry = event.history_entry()?;
        let client = event
            .client_id()
            .or(stored.actor.client_id())
            .map(|id| ClientView {
                name: clients.get(id).cloned(),
                id: id.clone(),
            });
        let (origin, erased) = match &stored.origin {
            Personal::Value(origin) => (*origin, false),
            Personal::Erased => (RequestOrigin::default(), true),
        };
        Some(Self {
            id: stored.id,
            occurred_at: stored.occurred_at,
            entry,
            actor: HistoryActor::from(&stored.actor),
            reason: stored.reason.clone(),
            client,
            ip: origin.client_ip,
            device: origin.user_agent_family,
            erased,
        })
    }
}

impl HistoryApplication {
    /// Serves the history from `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Returns the report endpoint with this application as state. Only the owner
    /// can say an entry was not theirs.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::history::REPORT, post(Self::report))
            .with_state(self)
    }

    /// Reports an entry the owner's account caused as not theirs, and returns the
    /// action that undoes it, if any.
    async fn report(
        State(app): State<Self>,
        owner: Owner,
        Path(event_id): Path<EventId>,
    ) -> Result<Json<Report>, ApiError> {
        let follow_up = AccountService::new(app.database.clone())
            .report(&owner, event_id)
            .await?;
        Ok(Json(Report { follow_up }))
    }
}

/// The history any administrator may also read, and the reports only its owner
/// makes.
impl AccountService {
    /// Reports an entry the account caused as not the owner's. In one
    /// transaction, records the report, ends every other session of the account
    /// and revokes every refresh family, this session's included. Returns the
    /// action that undoes the entry, if any.
    ///
    /// The owner's session is enough: the worst a stolen cookie can do here is
    /// sign the owner out of their other devices. Undoing the entry needs a
    /// passkey confirmation.
    pub(crate) async fn report(
        &self,
        owner: &Owner,
        event_id: EventId,
    ) -> Result<Option<FollowUp>, AccountError> {
        let mut tx = self.database.begin().await?;
        owner.lock(&mut tx).await?;
        let (stored, entry) = Self::entry(tx.events(), owner.user(), event_id).await?;
        if !matches!(stored.actor, Actor::User { user_id, .. } if user_id == owner.user()) {
            return Err(HistoryError::NotReportable.into());
        }
        let context = owner.context();
        tx.record(
            &context,
            Some(owner.user()),
            DomainEvent::CompromiseReported { event_id },
        )
        .await?;
        tx.revoke_sessions(
            &context,
            owner.user(),
            SessionScope::AllExcept(owner.session().id),
            &RevocationReason::CompromiseReported,
        )
        .await?;
        tx.tokens().revoke_all_for_user(owner.user()).await?;
        tx.commit().await?;
        Ok(entry.follow_up())
    }

    /// What undoes the entry `event_id`, if anything, once the account reported it:
    /// `None` when it has no report of that entry among its [`PAGE_SIZE`] newest.
    /// The report's page shows it, and nobody can make it claim a report that was
    /// never made.
    pub(crate) async fn reported(
        &self,
        viewer: &Viewer,
        event_id: EventId,
    ) -> Result<Option<Option<FollowUp>>, AccountError> {
        viewer.authorize(&self.database).await?;
        let report = DomainEvent::CompromiseReported { event_id };
        let filter = EventFilter {
            subject: Some(viewer.user()),
            kind: Some(report.kind().to_owned()),
            ..EventFilter::default()
        };
        let reports = self
            .database
            .events()
            .list(&filter, u32::from(PAGE_SIZE))
            .await?;
        if !reports
            .iter()
            .any(|stored| stored.event.known() == Some(&report))
        {
            return Ok(None);
        }
        let (_, entry) = Self::entry(self.database.events(), viewer.user(), event_id).await?;
        Ok(Some(entry.follow_up()))
    }

    /// The account `user`'s entry `event_id`, as recorded and as its history shows
    /// it.
    async fn entry(
        mut events: EventRepository<'_>,
        user: UserId,
        event_id: EventId,
    ) -> Result<(StoredEvent, HistoryEntry), AccountError> {
        let filter = EventFilter {
            subject: Some(user),
            id: Some(event_id),
            ..EventFilter::default()
        };
        let stored = events
            .list(&filter, 1)
            .await?
            .pop()
            .ok_or(HistoryError::EntryNotFound)?;
        let entry = stored
            .event
            .known()
            .and_then(DomainEvent::history_entry)
            .ok_or(HistoryError::EntryNotFound)?;
        Ok((stored, entry))
    }

    /// Returns a page of the account's entries, newest first, older than
    /// `before`. Events the owner does not see are skipped, and reading continues
    /// until the page is full, the history ends or [`MAX_BATCHES`] were read. Only
    /// the account's own events are read: the repository query filters on its ID.
    pub(crate) async fn history(
        &self,
        viewer: &Viewer,
        before: Option<EventId>,
    ) -> Result<HistoryPage, AccountError> {
        viewer.authorize(&self.database).await?;
        let clients: BTreeMap<_, _> = self
            .database
            .oidc()
            .list_clients()
            .await?
            .into_iter()
            .map(|client| (client.id, client.display_name))
            .collect();
        let mut filter = EventFilter {
            subject: Some(viewer.user()),
            before,
            ..EventFilter::default()
        };
        let mut entries = Vec::new();
        for _ in 0..MAX_BATCHES {
            let batch = self
                .database
                .events()
                .list(&filter, u32::from(PAGE_SIZE))
                .await?;
            let exhausted = batch.len() < usize::from(PAGE_SIZE);
            for stored in batch {
                filter.before = Some(stored.id);
                entries.extend(HistoryItem::new(&stored, &clients));
                if entries.len() == usize::from(PAGE_SIZE) {
                    return Ok(HistoryPage {
                        entries,
                        next: filter.before,
                    });
                }
            }
            if exhausted {
                return Ok(HistoryPage {
                    entries,
                    next: None,
                });
            }
        }
        Ok(HistoryPage {
            entries,
            next: filter.before,
        })
    }
}

/// Supplies the shared database boundary to browser-session extractors.
impl axum::extract::FromRef<HistoryApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &HistoryApplication) -> Self {
        application.database.clone()
    }
}

/// Database-backed history and report scenarios.
#[cfg(test)]
mod tests;
