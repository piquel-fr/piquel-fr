//! Publishes signed checkpoints, so anyone can keep copies the server cannot
//! change and later check that the history still extends them.

use super::{AuditKeys, Chain, ChainPoint};
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
use std::sync::Arc;

/// Public, cacheable checkpoint routes. Checkpoints hold only positions and
/// hashes, so serving them reveals nothing but how many events were recorded.
#[derive(Clone)]
pub(crate) struct AuditApplication {
    /// Where checkpoints are stored.
    database: Database,
    /// Verifies the latest checkpoint before it is served.
    keys: Arc<AuditKeys>,
}

/// The query of [`audit::CHECKPOINTS`].
#[derive(Deserialize)]
struct CheckpointQuery {
    /// Only checkpoints after this position; all of them when absent. Positions
    /// fit in a signed 64-bit integer.
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

    /// Builds the routes over `database`, serving only a latest checkpoint `keys`
    /// verify.
    pub(crate) const fn new(database: Database, keys: Arc<AuditKeys>) -> Self {
        Self { database, keys }
    }

    /// Returns the checkpoint routes with this application as state.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(audit::LATEST_CHECKPOINT, get(Self::latest))
            .route(audit::CHECKPOINTS, get(Self::list))
            .with_state(self)
    }

    /// The signed note of the newest checkpoint that verifies, as `text/plain`.
    /// Newer ones that do not are never served; `audit verify` reports them.
    async fn latest(State(app): State<Self>) -> Result<Response, ApiError> {
        let checkpoint = app
            .keys
            .newest_trusted(&mut app.database.audit())
            .await
            .map_err(ApiError::internal)?
            .trusted
            .ok_or_else(|| {
                ApiError::not_found("no checkpoint that verifies has been signed yet")
            })?;
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
        if i64::try_from(query.after).is_err() {
            return Err(ApiError::bad_request(
                "after must be at most 9223372036854775807",
            ));
        }
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
