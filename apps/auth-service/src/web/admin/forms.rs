//! What the dashboard keeps of the changes its forms post, which
//! [`AdminApplication::change`](super::AdminApplication) runs every one through:
//!
//! - a claim on each change, by the digest of its administrator, page, query and
//!   form, so the same form posted to the same page again, such as by a double
//!   click or a reload, changes nothing twice. The claim is written in a
//!   transaction held open while the change is made: a repeat posted meanwhile
//!   waits for it, then is skipped if the change was made, and made itself,
//!   meeting the same refusal, if not. A made change keeps its claim for
//!   [`SUBMISSION_WINDOW`];
//! - a draft of a change that needed a newer passkey confirmation, or a new
//!   sign-in, which sends the browser through auth's handoff page: the page shows
//!   the form again once, the next time it opens, so what was typed is not lost,
//!   even where the dashboard's script could not confirm on the page.

use chrono::{Duration, Utc};
use piquel_common::UserId;
use piquel_crypto::Digest;
use piquel_repository::{Database, DatabaseError, DatabaseTransaction};
use serde::{Serialize, de::DeserializeOwned};

/// How long a change blocks the same form posted again: a double click, or a
/// slow first answer, but rarely a real repeat.
const SUBMISSION_WINDOW: Duration = Duration::seconds(10);
/// How long a draft waits for the administrator to come back from auth's handoff
/// page, signing in there first if they must. It holds what they typed, which
/// may name people.
const DRAFT_LIFETIME: Duration = Duration::minutes(10);

/// Why the dashboard could not keep or read a form.
#[derive(Debug, thiserror::Error)]
pub(super) enum FormsError {
    /// The database failed.
    #[error("the dashboard's forms could not be stored")]
    Database(#[from] DatabaseError),
    /// The form could not be written as JSON.
    #[error("a dashboard form could not be kept")]
    Json(#[from] serde_json::Error),
}

/// The dashboard's claims on changes and its drafts, over the database.
#[derive(Clone)]
pub(super) struct DashboardForms {
    /// The claims and drafts.
    database: Database,
}

/// A change `DashboardForms::claim` claimed, while it is being made: its claim
/// is written in this transaction, which a repeat of it waits for.
pub(super) struct Claim<'a>(DatabaseTransaction<'a>);

impl Claim<'_> {
    /// Keeps the claim for [`SUBMISSION_WINDOW`]: the change was made.
    pub(super) async fn keep(self) -> Result<(), FormsError> {
        Ok(self.0.commit().await?)
    }

    /// Gives up the claim: the change made nothing, so a repeat, waiting or
    /// posted later, is made itself.
    pub(super) async fn release(self) -> Result<(), FormsError> {
        Ok(self.0.rollback().await?)
    }
}

impl DashboardForms {
    /// Keeps the dashboard's forms in `database`.
    pub(super) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Claims the change `form`, which `user_id` posted to `page`, its path and
    /// query: `None` when the same form was posted there within
    /// [`SUBMISSION_WINDOW`] and made, or is still being made after the lock
    /// wait's few seconds.
    pub(super) async fn claim(
        &self,
        user_id: UserId,
        page: &str,
        form: &impl Serialize,
    ) -> Result<Option<Claim<'_>>, FormsError> {
        let mut posted = user_id.as_uuid().as_bytes().to_vec();
        posted.extend_from_slice(page.as_bytes());
        // A page cannot hold a NUL, so the form cannot shift into it.
        posted.push(0);
        posted.extend_from_slice(&serde_json::to_vec(form)?);
        let digest = Digest::sha256(&posted);
        let expires_at = Utc::now() + SUBMISSION_WINDOW;
        let mut tx = self.database.begin().await?;
        match tx
            .dashboard()
            .claim_submission(digest.as_bytes(), expires_at)
            .await
        {
            Ok(true) => Ok(Some(Claim(tx))),
            Ok(false) | Err(DatabaseError::LockUnavailable(_)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Keeps `form`, which `user_id` posted to the page `path`, as that page's
    /// draft for [`DRAFT_LIFETIME`].
    pub(super) async fn keep(
        &self,
        user_id: UserId,
        path: &str,
        form: &impl Serialize,
    ) -> Result<(), FormsError> {
        let form = serde_json::to_string(form)?;
        let expires_at = Utc::now() + DRAFT_LIFETIME;
        (self.database.dashboard())
            .keep_draft(user_id, path, &form, expires_at)
            .await?;
        Ok(())
    }

    /// Takes the draft `user_id` posted to the page `path`, if it has not
    /// expired: its form, shown once. One that no longer decodes as `I`, such as
    /// after a release changed the form, is dropped.
    pub(super) async fn take<I: DeserializeOwned>(
        &self,
        user_id: UserId,
        path: &str,
    ) -> Result<Option<I>, FormsError> {
        let draft = (self.database.dashboard())
            .take_draft(user_id, path)
            .await?;
        Ok(draft.and_then(|form| serde_json::from_str(&form).ok()))
    }
}
