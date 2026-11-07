//! Drafting, editing and sending announcements.

use super::*;
use piquel_common::{AnnouncementId, EmailId};
use piquel_repository::{EventFilter, InsertVerifiedEmail};

/// An announcement's draft to `recipients`.
pub(super) fn announcement(recipients: AnnouncementRecipients) -> AnnouncementDraft {
    AnnouncementDraft::new("Incident", "What happened.", recipients).expect("draft")
}

/// A draft needs no recent confirmation, and changes until it is sent, which
/// needs one, and then never again. Sending records who sent it, and queues its
/// email to each recipient with a primary verified address. An account the
/// draft names that does not exist is named in the refusal.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "One announcement's life, from its draft to what sending it recorded."
)]
async fn announcements_change_until_a_confirmed_administrator_sends_them() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = harness.admin().await;
    let (mailed, unmailed) = (
        harness.account().await.user_id,
        harness.account().await.user_id,
    );
    harness
        .database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: EmailId::new(),
            user_id: mailed,
            normalized_email: format!("{mailed}@example.com"),
            is_primary: true,
            verified_at: Utc::now(),
        })
        .await
        .expect("address");
    let stale = operator(admin, Utc::now() - Duration::hours(1));
    let chosen = |users: &[UserId]| {
        announcement(AnnouncementRecipients::Accounts(
            users.iter().copied().map(UserRef::Id).collect(),
        ))
    };
    let missing = UserRef::Handle("nobody-has-this".into());
    let refused = service
        .draft_announcement(
            &stale,
            &announcement(AnnouncementRecipients::Accounts(vec![missing])),
        )
        .await
        .expect_err("unknown account");
    assert!(
        matches!(&refused, AdminError::UnknownRecipient(UserRef::Handle(handle)) if handle == "nobody-has-this"),
        "{refused:?}"
    );
    let id = service
        .draft_announcement(&stale, &chosen(&[mailed]))
        .await
        .expect("draft");
    service
        .edit_announcement(&stale, id, &chosen(&[mailed, unmailed, mailed]))
        .await
        .expect("edit");
    let draft = service.view_announcement(&stale, id).await.expect("view");
    assert_eq!(
        (
            draft.announcement.recipients,
            draft.mailed,
            draft.accounts.len()
        ),
        (2, 1, 2)
    );

    let revision = draft.announcement.revision;
    let refused = service
        .send_announcement(&stale, id, revision)
        .await
        .expect_err("stale");
    assert!(
        matches!(refused, AdminError::StepUpRequired(_)),
        "{refused:?}"
    );
    let administrator = operator(admin, Utc::now());
    assert_refused(
        &service
            .send_announcement(&administrator, id, revision - 1)
            .await
            .expect_err("changed"),
        &AdminError::AnnouncementChanged,
        "changed",
    );
    assert_eq!(
        service
            .send_announcement(&administrator, id, revision)
            .await
            .expect("send"),
        2
    );
    for refused in [
        service
            .send_announcement(&administrator, id, revision)
            .await
            .map(drop),
        service
            .edit_announcement(&stale, id, &chosen(&[mailed]))
            .await
            .map(drop),
        service.discard_announcement(&stale, id).await,
    ] {
        assert_refused(
            &refused.expect_err("sent"),
            &AdminError::AnnouncementSent,
            "sent",
        );
    }
    let sent = service.view_announcement(&stale, id).await.expect("view");
    assert!(sent.announcement.sent_at.is_some());
    assert_eq!(sent.emails.pending, 1);
    let filter = EventFilter {
        kind: Some("announcement_sent".into()),
        ..EventFilter::default()
    };
    let events = harness
        .database
        .events()
        .list(&filter, 100)
        .await
        .expect("events");
    let recorded = events
        .iter()
        .find(|stored| {
            stored.event.known()
                == Some(&DomainEvent::AnnouncementSent {
                    announcement_id: id,
                    recipients: 2,
                })
        })
        .expect("recorded");
    assert_eq!(recorded.actor, administrator.context().actor);
    assert_refused(
        &service
            .view_announcement(&stale, AnnouncementId::new())
            .await
            .expect_err("unknown"),
        &AdminError::AnnouncementNotFound,
        "unknown",
    );
}
