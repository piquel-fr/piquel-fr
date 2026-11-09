//! The claims on the changes the dashboard's forms post, which
//! [`AdminApplication::change`](super::AdminApplication) runs every one through:
//!
//! - a claim on each change, by the digest of its administrator, page, query and
//!   form, so the same form posted to the same page again, such as by a double
//!   click or a reload, changes nothing twice. A repeat of a change that was made
//!   within [`SUBMISSION_WINDOW`] is skipped; one of a change still being made
//!   gets its form back, saying so; a refused change gives up its claim, so
//!   posting it again tries again. No transaction is held while a change is made:
//!   the claim is written, then marked made or deleted.

use chrono::{Duration, Utc};
use serde::Serialize;
use sourceorigin_common::UserId;
use sourceorigin_crypto::Digest;
use sourceorigin_repository::{Database, DatabaseError, Submission, SubmissionToken};

/// How long a change blocks the same form posted again: a double click, or a
/// slow first answer, but rarely a real repeat.
const SUBMISSION_WINDOW: Duration = Duration::seconds(10);
/// Why the dashboard could not claim a change.
#[derive(Debug, thiserror::Error)]
pub(super) enum SubmissionsError {
    /// The database failed.
    #[error("a dashboard change's claim could not be stored")]
    Database(#[from] DatabaseError),
    /// The form could not be written as JSON.
    #[error("a dashboard change's form could not be written as JSON")]
    Json(#[from] serde_json::Error),
}

/// The dashboard's claims on changes, over the database.
#[derive(Clone)]
pub(super) struct Submissions {
    /// The claims.
    database: Database,
}

/// What [`Submissions::claim`] found of a change just posted.
pub(super) enum Claimed<'a> {
    /// It is claimed now, to be made.
    New(Claim<'a>),
    /// The same change was made moments ago: this is a repeat, which changes
    /// nothing.
    Made,
    /// The same change is being made still, by another request.
    Pending,
}

/// A change [`Submissions::claim`] claimed, while it is made.
pub(super) struct Claim<'a> {
    /// Where its claim is kept.
    submissions: &'a Submissions,
    /// Its claim's own token, which only this request holds.
    token: SubmissionToken,
}

impl Claim<'_> {
    /// Keeps the claim for [`SUBMISSION_WINDOW`]: the change was made.
    pub(super) async fn keep(self) -> Result<(), SubmissionsError> {
        let expires_at = Utc::now() + SUBMISSION_WINDOW;
        (self.submissions.database.dashboard())
            .made_submission(self.token, expires_at)
            .await?;
        Ok(())
    }

    /// Gives up the claim: the change made nothing, so posting it again tries
    /// again.
    pub(super) async fn release(self) -> Result<(), SubmissionsError> {
        (self.submissions.database.dashboard())
            .release_submission(self.token)
            .await?;
        Ok(())
    }
}

impl Submissions {
    /// Keeps the dashboard's forms in `database`.
    pub(super) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Claims the change `form`, which `user_id` posted to `page`, its path and
    /// query, unless the same form was posted there moments ago.
    pub(super) async fn claim(
        &self,
        user_id: UserId,
        page: &str,
        form: &impl Serialize,
    ) -> Result<Claimed<'_>, SubmissionsError> {
        let mut posted = user_id.as_uuid().as_bytes().to_vec();
        posted.extend_from_slice(page.as_bytes());
        // A page cannot hold a NUL, so the form cannot shift into it.
        posted.push(0);
        posted.extend_from_slice(&serde_json::to_vec(form)?);
        let digest = Digest::sha256(&posted);
        // A change still being made after the window, such as one that failed
        // without releasing its claim, no longer holds back its repeat.
        let expires_at = Utc::now() + SUBMISSION_WINDOW;
        let found = (self.database.dashboard())
            .claim_submission(digest.as_bytes(), user_id, expires_at)
            .await?;
        Ok(match found {
            Submission::Claimed(token) => Claimed::New(Claim {
                submissions: self,
                token,
            }),
            Submission::Made => Claimed::Made,
            Submission::Pending => Claimed::Pending,
        })
    }
}
