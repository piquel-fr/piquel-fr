//! Publishes signed checkpoints, so anyone can keep copies the server cannot
//! change and later check that the history still extends them.

use super::{Chain, ChainPoint};
use crate::{
    routes::audit,
    security::{ApiError, CacheClass, Cached},
};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use piquel_repository::{ChainLink, Checkpoint, Database};
use serde::{Deserialize, Serialize};

/// Public, cacheable checkpoint routes. Checkpoints hold only positions and
/// hashes, so serving them reveals nothing but how many events were recorded.
#[derive(Clone)]
pub(crate) struct AuditApplication {
    /// Where checkpoints are stored.
    database: Database,
}

/// The query of [`audit::CHECKPOINTS`].
#[derive(Deserialize)]
struct CheckpointQuery {
    /// Only checkpoints after this position; all of them when absent.
    #[serde(default)]
    after: u64,
}

/// A checkpoint as [`audit::CHECKPOINTS`] lists it.
#[derive(Serialize)]
struct PublishedCheckpoint {
    /// The head it signs.
    #[serde(flatten)]
    head: ChainPoint,
    /// When it was signed.
    time: DateTime<Utc>,
    /// The signed note, which holds the same values.
    note: String,
}

impl From<Checkpoint> for PublishedCheckpoint {
    /// Keeps the stored values; the note is what readers verify.
    fn from(checkpoint: Checkpoint) -> Self {
        Self {
            head: ChainLink {
                position: checkpoint.position,
                hash: checkpoint.head,
            }
            .point(),
            time: checkpoint.created_at,
            note: checkpoint.note,
        }
    }
}

impl AuditApplication {
    /// Checkpoints per page of [`audit::CHECKPOINTS`].
    const PAGE: u32 = 100;
    /// Caches may reuse an answer for a minute: a new checkpoint is signed at most
    /// every five.
    const CACHE: CacheClass = CacheClass::Public {
        max_age: std::time::Duration::from_secs(60),
    };

    /// Builds the routes over `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Returns the checkpoint routes with this application as state.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(audit::LATEST_CHECKPOINT, get(Self::latest))
            .route(audit::CHECKPOINTS, get(Self::list))
            .with_state(self)
    }

    /// The newest checkpoint's signed note, as `text/plain`.
    async fn latest(State(app): State<Self>) -> Result<Response, ApiError> {
        let checkpoint = app
            .database
            .audit()
            .latest_checkpoint()
            .await?
            .ok_or_else(|| ApiError::not_found("no checkpoint has been signed yet"))?;
        Ok(Cached(
            Self::CACHE,
            (
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                checkpoint.note,
            ),
        )
        .into_response())
    }

    /// Up to 100 checkpoints after `after`, oldest first. An empty page is the end.
    async fn list(
        State(app): State<Self>,
        Query(query): Query<CheckpointQuery>,
    ) -> Result<Response, ApiError> {
        let checkpoints: Vec<PublishedCheckpoint> = app
            .database
            .audit()
            .checkpoints(query.after, Self::PAGE)
            .await?
            .into_iter()
            .map(PublishedCheckpoint::from)
            .collect();
        Ok(Cached(Self::CACHE, Json(checkpoints)).into_response())
    }
}
