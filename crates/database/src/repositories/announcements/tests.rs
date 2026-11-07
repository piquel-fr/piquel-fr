//! Drafts, sending, the notification each recipient gets, and the emails a
//! sending queues.

use super::*;
use crate::{
    Database, DatabaseTransaction, EmailRepository, InsertUser, InsertVerifiedEmail,
    NotificationRepository, UserRepository,
};
use chrono::Utc;
use piquel_common::{
    EmailId,
    events::{Actor, DomainEvent, EventContext, RequestOrigin},
};
use sqlx::PgPool;

/// The announcements in `user`'s inbox, newest first.
async fn inbox(pool: &PgPool, user: UserId) -> Vec<AnnouncementId> {
    NotificationRepository::from_pool(pool)
        .list(user, None, 1000)
        .await
        .expect("inbox")
        .into_iter()
        .filter_map(|stored| match stored.notification {
            Some(Notification::Announcement {
                announcement_id, ..
            }) => Some(announcement_id),
            _ => None,
        })
        .collect()
}

/// Creates an account, with `address` as its primary verified one if given.
async fn account(pool: &PgPool, address: Option<&str>) -> UserId {
    let user = UserRepository::from_pool(pool)
        .insert(&InsertUser::named("announce"))
        .await
        .expect("user")
        .id;
    if let Some(address) = address {
        EmailRepository::from_pool(pool)
            .insert_verified(&InsertVerifiedEmail {
                id: EmailId::new(),
                user_id: user,
                normalized_email: format!("{user}@{address}"),
                is_primary: true,
                verified_at: Utc::now(),
            })
            .await
            .expect("address");
    }
    user
}

/// Sends the draft `id` at `revision` in one transaction, recording its event as
/// the CLI would, and returns how many accounts it went to.
async fn send(pool: &PgPool, id: AnnouncementId, revision: u64) -> Option<u64> {
    let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    let recipients = tx.announcements().send(id, revision).await.expect("send")?;
    let context = EventContext {
        actor: Actor::Anonymous,
        origin: RequestOrigin::default(),
        reason: None,
    };
    let sent = DomainEvent::AnnouncementSent {
        announcement_id: id,
        recipients,
    };
    tx.record(&context, None, sent).await.expect("record");
    tx.commit().await.expect("commit");
    Some(recipients)
}

/// A draft to chosen accounts changes until it is sent, and then never again.
/// Sending it emails only the recipients with a primary verified address, and
/// only then do they see it.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn drafts_change_until_sent_and_reach_only_their_recipients() {
    let pool = Database::test_pool().await;
    let mailed = account(&pool, Some("example.com")).await;
    let unmailed = account(&pool, None).await;
    let bystander = account(&pool, Some("example.com")).await;
    let mut announcements = AnnouncementRepository::from_pool(&pool);
    let id = AnnouncementId::new();
    let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    tx.announcements()
        .insert_draft(&DraftedAnnouncement {
            id,
            subject: "Draft",
            body: "Text",
            recipients: Recipients::Accounts(&[bystander]),
        })
        .await
        .expect("draft");
    let edited = DraftedAnnouncement {
        id,
        subject: "Incident",
        body: "What happened",
        recipients: Recipients::Accounts(&[mailed, unmailed, mailed]),
    };
    assert_eq!(
        tx.announcements()
            .update_draft(&edited)
            .await
            .expect("edit"),
        Some(2)
    );
    tx.commit().await.expect("commit");
    let draft = announcements.find(id).await.expect("find").expect("draft");
    assert_eq!(
        (draft.subject.as_str(), draft.recipients, draft.sent_at),
        ("Incident", 2, None)
    );
    assert_eq!(announcements.mailed(id).await.expect("mailed"), 1);
    let received = inbox(&pool, mailed).await;
    assert!(!received.contains(&id), "a draft");

    assert_eq!(draft.revision, 2, "edited once");
    assert_eq!(send(&pool, id, 1).await, None, "a revision since changed");
    assert_eq!(send(&pool, id, 2).await, Some(2));
    assert_eq!(send(&pool, id, 2).await, None, "sent once");
    assert_eq!(
        announcements.update_draft(&edited).await.expect("edit"),
        None
    );
    assert!(!announcements.discard(id).await.expect("discard"));
    // Other tests' announcements to everyone reach these accounts too.
    for (user, received) in [(mailed, true), (unmailed, true), (bystander, false)] {
        let announcements = inbox(&pool, user).await;
        assert_eq!(announcements.contains(&id), received);
    }
    // Its page counts the recipients who read it in their inbox.
    assert_eq!(announcements.read(id).await.expect("read"), 0);
    let mut notifications = NotificationRepository::from_pool(&pool);
    let opened = notifications.list(mailed, None, 1000).await.expect("inbox");
    let opened = opened
        .iter()
        .find(|stored| {
            matches!(&stored.notification,
                Some(Notification::Announcement { announcement_id, .. }) if *announcement_id == id)
        })
        .expect("its notification");
    assert!(
        notifications
            .mark(mailed, opened.id, true)
            .await
            .expect("mark")
    );
    assert_eq!(announcements.read(id).await.expect("read"), 1);
    assert_eq!(
        announcements.emails(id).await.expect("emails"),
        AnnouncementEmails {
            pending: 1,
            ..AnnouncementEmails::default()
        }
    );
    let mut emails = EmailRepository::from_pool(&pool);
    let email = emails.announcement(mailed, id).await.expect("email");
    assert_eq!(
        email.map(|email| (email.address, email.subject)),
        Some((format!("{mailed}@example.com"), "Incident".to_owned()))
    );
    assert_eq!(
        emails.announcement(unmailed, id).await.expect("email"),
        None
    );
}

/// A draft to everyone has no recipients until it is sent, when every account
/// becomes one. A discarded draft is gone.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn an_announcement_to_everyone_goes_to_every_account_once_sent() {
    let pool = Database::test_pool().await;
    let (first, second) = (account(&pool, None).await, account(&pool, None).await);
    let mut announcements = AnnouncementRepository::from_pool(&pool);
    let (id, discarded) = (AnnouncementId::new(), AnnouncementId::new());
    for id in [id, discarded] {
        let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
        tx.announcements()
            .insert_draft(&DraftedAnnouncement {
                id,
                subject: "Privacy policy",
                body: "It changed.",
                recipients: Recipients::Everyone,
            })
            .await
            .expect("draft");
        tx.commit().await.expect("commit");
    }
    assert!(announcements.discard(discarded).await.expect("discard"));
    assert_eq!(announcements.find(discarded).await.expect("find"), None);
    let received = inbox(&pool, first).await;
    assert!(!received.contains(&id), "a draft");

    let recipients = send(&pool, id, 1).await.expect("a draft");
    let sent = announcements.find(id).await.expect("find").expect("sent");
    assert_eq!(sent.recipients, recipients);
    assert!(sent.sent_at.is_some());
    for user in [first, second] {
        let received = inbox(&pool, user).await;
        assert!(received.contains(&id));
    }
}

/// Purges `user` in `tx` as auth's callers do: the administrator list locked,
/// then the account, before the purge.
async fn purge_as_callers_do(tx: &mut DatabaseTransaction<'_>, user: UserId) {
    tx.administrators().lock().await.expect("administrators");
    let locked = tx.users().find_by_id_for_update(user).await.expect("lock");
    assert!(locked.is_some(), "the account");
    assert!(tx.deletions().purge(user).await.expect("purge"));
}

/// Waits until a transaction waits for one of `holder`'s locks.
async fn until_blocked(holder: &mut DatabaseTransaction<'_>) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while holder.blocked_transactions().await.expect("lock waits") < 1 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the other transaction waits for the holder's lock");
}

/// The announcement deliveries queued to `user`.
async fn deliveries_to(pool: &PgPool, user: UserId, id: AnnouncementId) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM deliveries
        WHERE channel = 'announcement' AND recipient = to_jsonb($1::text)
        AND payload = to_jsonb($2::text)",
    )
    .bind(user.to_string())
    .bind(id.to_string())
    .fetch_one(pool)
    .await
    .expect("deliveries")
}

/// An account's purge and an announcement's sending wait for each other rather
/// than fail or leave an email behind: a sending to everyone leaves out the
/// account a purge deleted first, and a purge that waited for a sending deletes
/// the email it queued to the account.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn sending_and_purging_wait_for_each_other() {
    let pool = Database::test_pool().await;
    let draft = async |recipients: Recipients<'_>| {
        let id = AnnouncementId::new();
        let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
        tx.announcements()
            .insert_draft(&DraftedAnnouncement {
                id,
                subject: "Incident",
                body: "What happened.",
                recipients,
            })
            .await
            .expect("draft");
        tx.commit().await.expect("commit");
        id
    };

    // The purge goes first: the sending waits for it, then leaves the account out.
    let purged = account(&pool, Some("example.com")).await;
    let everyone = draft(Recipients::Everyone).await;
    let mut purge = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    purge_as_callers_do(&mut purge, purged).await;
    let (sent, ()) = tokio::join!(send(&pool, everyone, 1), async {
        until_blocked(&mut purge).await;
        purge.commit().await.expect("commit");
    });
    assert!(sent.is_some(), "sent without the purged account");
    assert_eq!(deliveries_to(&pool, purged, everyone).await, 0);

    // The sending goes first: the purge waits for it, then deletes its email.
    let (purged, kept) = (
        account(&pool, Some("example.com")).await,
        account(&pool, Some("example.com")).await,
    );
    let chosen = draft(Recipients::Accounts(&[purged, kept])).await;
    let mut sending = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    let recipients = sending.announcements().send(chosen, 1).await.expect("send");
    let context = EventContext {
        actor: Actor::Anonymous,
        origin: RequestOrigin::default(),
        reason: None,
    };
    let event = DomainEvent::AnnouncementSent {
        announcement_id: chosen,
        recipients: recipients.expect("a draft"),
    };
    sending.record(&context, None, event).await.expect("record");
    let purge = async {
        let mut purge = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
        purge_as_callers_do(&mut purge, purged).await;
        purge.commit().await.expect("commit");
    };
    tokio::join!(purge, async {
        until_blocked(&mut sending).await;
        sending.commit().await.expect("commit");
    });
    assert_eq!(deliveries_to(&pool, purged, chosen).await, 0);
    assert_eq!(deliveries_to(&pool, kept, chosen).await, 1);
    // Other tests' announcements to everyone may reach these accounts too.
    assert!(inbox(&pool, kept).await.contains(&chosen));
    assert!(
        !inbox(&pool, purged).await.contains(&chosen),
        "gone with the account"
    );
}

/// Purging a targeted announcement's last two recipients at once still deletes
/// its text, which may concern them: the second purge waits for the first, then
/// finds itself the last.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn purging_the_last_recipients_at_once_deletes_the_text() {
    let pool = Database::test_pool().await;
    let (first, second) = (account(&pool, None).await, account(&pool, None).await);
    let id = AnnouncementId::new();
    let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    tx.announcements()
        .insert_draft(&DraftedAnnouncement {
            id,
            subject: "About you two",
            body: "Names them.",
            recipients: Recipients::Accounts(&[first, second]),
        })
        .await
        .expect("draft");
    tx.commit().await.expect("commit");
    assert!(send(&pool, id, 1).await.is_some());

    let mut purge = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    // Bare purges: auth's callers also serialize on the administrators table
    // lock, which would hide the repository's own turn-taking.
    assert!(purge.deletions().purge(first).await.expect("purge"));
    let other = async {
        let mut other = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
        assert!(other.deletions().purge(second).await.expect("purge"));
        other.commit().await.expect("commit");
    };
    tokio::join!(other, async {
        until_blocked(&mut purge).await;
        purge.commit().await.expect("commit");
    });
    let announcements = AnnouncementRepository::from_pool(&pool).find(id).await;
    assert_eq!(announcements.expect("find"), None);
}

/// A draft to chosen accounts saved naming an account while that account is
/// purged goes with it too: the purge's cleanup misses the uncommitted draft, but
/// deleting the account waits for it, then finds it without recipients.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn a_draft_saved_during_a_purge_goes_with_the_account() {
    let pool = Database::test_pool().await;
    let named = account(&pool, None).await;
    let id = AnnouncementId::new();
    let mut drafting = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    drafting
        .announcements()
        .insert_draft(&DraftedAnnouncement {
            id,
            subject: "About you",
            body: "Names you.",
            recipients: Recipients::Accounts(&[named]),
        })
        .await
        .expect("draft");
    let purge = async {
        let mut purge = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
        purge_as_callers_do(&mut purge, named).await;
        purge.commit().await.expect("commit");
    };
    tokio::join!(purge, async {
        until_blocked(&mut drafting).await;
        drafting.commit().await.expect("commit");
    });
    let left = AnnouncementRepository::from_pool(&pool).find(id).await;
    assert_eq!(left.expect("find"), None);
}
