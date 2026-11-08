//! What the dashboard keeps of the changes its forms post, which
//! [`AdminApplication::change`](super::AdminApplication) runs every one through:
//!
//! - a claim on each change, by the digest of its administrator, page, query and
//!   form, so the same form posted to the same page again, such as by a double
//!   click or a reload, changes nothing twice. A repeat of a change that was made
//!   within [`SUBMISSION_WINDOW`] is skipped; one of a change still being made
//!   gets its form back, saying so; a refused change gives up its claim, so
//!   posting it again tries again. No transaction is held while a change is made:
//!   the claim is written, then marked made or deleted;
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

/// What [`DashboardForms::claim`] found of a change just posted.
pub(super) enum Claimed<'a> {
    /// It is claimed now, to be made.
    New(Claim<'a>),
    /// The same change was made moments ago: this is a repeat, which changes
    /// nothing.
    Made,
    /// The same change is being made still, by another request.
    Pending,
}

/// A change [`DashboardForms::claim`] claimed, while it is made.
pub(super) struct Claim<'a> {
    /// Where its claim is kept.
    forms: &'a DashboardForms,
    /// The digest of its administrator, page, query and form.
    digest: Digest,
}

impl Claim<'_> {
    /// Keeps the claim for [`SUBMISSION_WINDOW`]: the change was made.
    pub(super) async fn keep(self) -> Result<(), FormsError> {
        let expires_at = Utc::now() + SUBMISSION_WINDOW;
        (self.forms.database.dashboard())
            .made_submission(self.digest.as_bytes(), expires_at)
            .await?;
        Ok(())
    }

    /// Gives up the claim: the change made nothing, so posting it again tries
    /// again.
    pub(super) async fn release(self) -> Result<(), FormsError> {
        (self.forms.database.dashboard())
            .release_submission(self.digest.as_bytes())
            .await?;
        Ok(())
    }
}

impl DashboardForms {
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
    ) -> Result<Claimed<'_>, FormsError> {
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
            .claim_submission(digest.as_bytes(), expires_at)
            .await?;
        Ok(match found {
            None => Claimed::New(Claim {
                forms: self,
                digest,
            }),
            Some(true) => Claimed::Made,
            Some(false) => Claimed::Pending,
        })
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
