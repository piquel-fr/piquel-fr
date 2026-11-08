//! What the dashboard keeps of the changes its forms post, which
//! [`AdminApplication::change`](super::AdminApplication) runs every one through:
//!
//! - a claim on each change, by the digest of its administrator, page and form,
//!   for [`SUBMISSION_WINDOW`], so the same form posted again meanwhile, such as
//!   by a double click or a reload, changes nothing twice;
//! - a draft of a change that needed a newer passkey confirmation, or a new
//!   sign-in, which sends the browser through auth's handoff page: the page shows
//!   the form again once, the next time it opens, so what was typed is not lost,
//!   even where the dashboard's script could not confirm on the page.

use chrono::{Duration, Utc};
use piquel_common::UserId;
use piquel_crypto::Digest;
use piquel_repository::{Database, DatabaseError};
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

/// A change `DashboardForms::claim` claimed, which `DashboardForms::release`
/// gives up when it changed nothing.
pub(super) struct Claim(Digest);

impl DashboardForms {
    /// Keeps the dashboard's forms in `database`.
    pub(super) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Claims the change `form`, which `user_id` posted to the page `path`, for
    /// [`SUBMISSION_WINDOW`]: `None` when the same form was posted there within
    /// it, and is made or being made.
    pub(super) async fn claim(
        &self,
        user_id: UserId,
        path: &str,
        form: &impl Serialize,
    ) -> Result<Option<Claim>, FormsError> {
        let mut posted = user_id.as_uuid().as_bytes().to_vec();
        posted.extend_from_slice(path.as_bytes());
        // The path cannot hold a NUL, so the form cannot shift into it.
        posted.push(0);
        posted.extend_from_slice(&serde_json::to_vec(form)?);
        let digest = Digest::sha256(&posted);
        let expires_at = Utc::now() + SUBMISSION_WINDOW;
        let claimed = (self.database.dashboard())
            .claim_submission(digest.as_bytes(), expires_at)
            .await?;
        Ok(claimed.then_some(Claim(digest)))
    }

    /// Gives up `claim`, whose change changed nothing, so posting it again tries
    /// again.
    pub(super) async fn release(&self, claim: Claim) -> Result<(), FormsError> {
        let Claim(digest) = claim;
        (self.database.dashboard())
            .release_submission(digest.as_bytes())
            .await?;
        Ok(())
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
