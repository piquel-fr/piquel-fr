//! Messages to one account.

use super::*;
use crate::security::CONFIRMATION_MAX_AGE;
use sourceorigin_common::{
    EmailId,
    notifications::{EmailCategory, Notification, NotificationPreference},
};
use sourceorigin_repository::{EventFilter, InsertVerifiedEmail};

/// The message every scenario sends.
fn letter() -> Letter {
    Letter::new(
        "About your account",
        "Support needs a word with you.\n\nWrite to support@example.com.",
    )
    .expect("letter")
}

impl Harness {
    /// The notifications in `user_id`'s inbox, newest first.
    async fn inbox(&self, user_id: UserId) -> Vec<Option<Notification>> {
        let stored = self.database.notifications().list(user_id, None, 10).await;
        let stored = stored.expect("inbox");
        stored
            .into_iter()
            .map(|stored| stored.notification)
            .collect()
    }
}

/// A message lands in its account's inbox, and is emailed to its primary
/// verified address alone, even with announcements' email turned off. Its
/// event records who sent it, not what it says, so purging the account deletes
/// the message, and its email with it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn messages_reach_the_inbox_and_the_primary_address_until_purged() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = operator(harness.admin().await, Utc::now());
    let user = harness.account().await.user_id;
    let (primary, other) = (EmailId::new(), EmailId::new());
    for (id, is_primary) in [(primary, true), (other, false)] {
        let address = InsertVerifiedEmail {
            id,
            user_id: user,
            normalized_email: format!("{id}@example.com"),
            is_primary,
            verified_at: Utc::now(),
        };
        let inserted = harness.database.emails().insert_verified(&address).await;
        inserted.expect("address");
    }
    let off = NotificationPreference {
        category: EmailCategory::Announcements,
        email: false,
    };
    harness
        .database
        .notifications()
        .set_preference(user, off)
        .await
        .expect("preference");

    service
        .message_user(&admin, user, letter())
        .await
        .expect("send");
    let message = Notification::Message {
        title: "About your account".into(),
        text: "Support needs a word with you.\n\nWrite to support@example.com.".into(),
    };
    assert_eq!(harness.inbox(user).await, [Some(message.clone())]);
    let emailed = async |email_id: EmailId| {
        let destination = format!("account {user}, address {email_id}");
        let payloads = harness.database.deliveries().payloads(&destination).await;
        payloads.expect("payloads")
    };
    let mailed = emailed(primary).await;
    assert_eq!(mailed.len(), 1);
    assert_eq!(
        mailed[0]["notification"],
        serde_json::to_value(&message).expect("JSON")
    );
    assert_eq!(emailed(other).await.len(), 0);
    let filter = EventFilter {
        kind: Some("message_sent".into()),
        subject: Some(user),
        ..EventFilter::default()
    };
    let events = harness.database.events().list(&filter, 10).await;
    let [sent] = events.expect("events").try_into().expect("one event");
    assert_eq!(sent.event.known(), Some(&DomainEvent::MessageSent {}));
    assert_eq!(sent.actor, admin.reading().actor);
    // Nobody writes a reason for it: its text says why.
    assert_eq!(sent.reason.as_deref(), Some("See message contents"));

    service
        .purge_user(&cli(), user, reason("Asked by email"))
        .await
        .expect("purge");
    assert_eq!(harness.inbox(user).await, []);
    assert_eq!(emailed(primary).await.len(), 0);
}

/// The dashboard needs a recent passkey confirmation to send a message, and
/// sends nothing without one. A message changes nothing about an account, so
/// the dashboard and the CLI both message an administrator's.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_are_messaged_after_a_recent_confirmation() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = harness.admin().await;
    let administrator = harness.admin().await.user_id;
    let step_up = StepUpRequirement::passkey_within(CONFIRMATION_MAX_AGE);
    let stale = Utc::now() - Duration::minutes(10);
    let refused = service
        .message_user(&operator(admin, stale), administrator, letter())
        .await;
    let refusal = AdminError::StepUpRequired(step_up);
    assert_refused(&refused.expect_err("refused"), &refusal, "message");
    assert_eq!(harness.inbox(administrator).await, []);
    service
        .message_user(&operator(admin, Utc::now()), administrator, letter())
        .await
        .expect("the dashboard messages an administrator");
    service
        .message_user(&cli(), administrator, letter())
        .await
        .expect("the CLI messages an administrator");
    assert_eq!(harness.inbox(administrator).await.len(), 2);
}
