//! Retries, address resolution and rendering, with a fake relay.

use super::*;
use crate::{
    account::AccountService,
    config::{LinkKeys, TokenDigestKey, TokenDigestKeys},
    recovery::{LINK_LIFETIME, PROBATION, RecoveryLinks},
    security::RequestContext,
    tests::{AUTH_ORIGIN, Browser, Replicas, verified_address},
};
use sourceorigin_common::{
    AccountStatus, EmailId, Handle, NotificationId, PasskeyId, RecoveryId,
    config::Origin,
    events::{Actor, DomainEvent, EventContext, RequestOrigin},
    notifications::Notification,
};
use sourceorigin_crypto::Secret;
use sourceorigin_repository::{
    DraftedAnnouncement, InsertRecovery, InsertUnverifiedEmail, InsertUser, Recipients,
};
use std::{
    net::{IpAddr, Ipv6Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// A relay that keeps every message. The first send can be ambiguous: the relay
/// keeps the message, but the connection breaks before its reply arrives.
#[derive(Default)]
struct Outbox {
    /// Every message received, in order.
    sent: Mutex<Vec<Message>>,
    /// Whether the next send is ambiguous.
    ambiguous: AtomicBool,
}

impl Mailer for Arc<Outbox> {
    /// Keeps the message, then fails the first send as a broken connection.
    fn send(&self, message: Message) -> impl Future<Output = Result<(), DeliveryError>> + Send {
        self.sent.lock().expect("outbox").push(message);
        std::future::ready(if self.ambiguous.swap(false, Ordering::SeqCst) {
            Err(DeliveryError::Retryable {
                failure: Failure::Connection,
                retry_after: None,
            })
        } else {
            Ok(())
        })
    }
}

/// Creates an account on `database`, named after its ID.
async fn account(database: &Database) -> UserId {
    let user_id = UserId::new();
    database
        .users()
        .insert(&InsertUser {
            id: user_id,
            handle: Handle::parse(&format!("mail-{}", &user_id.to_string()[24..])).expect("handle"),
            display_name: "Mail test".into(),
        })
        .await
        .expect("user");
    user_id
}

/// Starts recovering `user_id` with a token from `links`, and returns the
/// recovery and its token.
async fn recover(
    database: &Database,
    user_id: UserId,
    links: &RecoveryLinks,
) -> (RecoveryId, Secret) {
    let id = RecoveryId::new();
    let token = links.token(id).expect("token");
    database
        .recoveries()
        .insert(&InsertRecovery {
            id,
            user_id,
            secret_digest: token.digest().as_bytes(),
            expires_at: chrono::Utc::now() + LINK_LIFETIME,
        })
        .await
        .expect("recovery");
    (id, token)
}

impl<M: Mailer> EmailSender<M> {
    /// Asserts that `message` to `user_id` has a recipient, and a plain-text and
    /// an HTML body.
    async fn assert_renders(&self, user_id: UserId, message: &EmailMessage) {
        let content = self.content(user_id, message).await.expect("content");
        let formatted = self
            .compose(DeliveryId::new(), &content.expect("a recipient"))
            .await
            .expect("message")
            .formatted();
        let formatted = String::from_utf8_lossy(&formatted);
        assert!(
            formatted.contains("Content-Type: text/plain"),
            "{formatted}"
        );
        assert!(formatted.contains("Content-Type: text/html"), "{formatted}");
    }
}

impl Outbox {
    /// The `Message-ID` and `To` of every message received.
    fn headers(&self) -> Vec<(String, String)> {
        self.sent
            .lock()
            .expect("outbox")
            .iter()
            .map(|message| {
                let header = |name| message.headers().get_raw(name).expect(name).to_owned();
                (header("Message-ID"), header("To"))
            })
            .collect()
    }

    /// The token of the verification link in the last message received, read
    /// from its body, which may be quoted-printable.
    fn verification_token(&self) -> String {
        let sent = self.sent.lock().expect("outbox");
        let formatted = sent.last().expect("a message").formatted();
        let body = String::from_utf8_lossy(&formatted)
            .replace("=\r\n", "")
            .replace("=3D", "=");
        let (_, token) = body
            .split_once("/settings/emails/verify#token=")
            .expect("a verification link");
        token
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            .collect()
    }
}

/// A retry after an ambiguous send sends the same message again, with the same
/// `Message-ID`: a duplicate the mail client can recognize. Once the address is
/// removed, its verification link is not sent, but notices still are; nothing is
/// while email is disabled. The verification email has a plain-text and an HTML
/// body, and its link names the account. The notifications' rendering is checked
/// with the recovery notices.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn retries_resend_the_same_message_to_the_current_address() {
    let database = Replicas::database().await;
    let config = EmailConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"), true);
    let user_id = account(&database).await;
    let email_id = EmailId::new();
    let token = config.verification_keys.token(email_id).expect("token");
    database
        .emails()
        .insert_unverified(&InsertUnverifiedEmail {
            id: email_id,
            user_id,
            normalized_email: "ada@example.com",
            secret_digest: token.digest().as_bytes(),
            expires_at: chrono::Utc::now() + VERIFICATION_LIFETIME,
        })
        .await
        .expect("address");
    let outbox = Arc::new(Outbox::default());
    outbox.ambiguous.store(true, Ordering::SeqCst);
    let sender = EmailSender::with_mailer(database.clone(), Some(Arc::clone(&outbox)), &config);
    let id = DeliveryId::new();
    let verify = EmailMessage::VerifyAddress { email_id };

    assert!(matches!(
        sender.deliver(id, user_id, &verify).await,
        Err(DeliveryError::Retryable { .. })
    ));
    assert_eq!(sender.deliver(id, user_id, &verify).await, Ok(()));
    let expected = (
        format!("<{id}@sourceorigin.dev>"),
        "ada@example.com".to_owned(),
    );
    assert_eq!(outbox.headers(), [expected.clone(), expected]);

    sender.assert_renders(user_id, &verify).await;
    let removed = EmailMessage::Notification {
        address: "ada@example.com".into(),
        notification_id: NotificationId::new(),
        notification: Notification::EmailRemoved,
        recovery_id: None,
    };
    let Some(Content {
        said: EmailContent::VerifyAddress { link, handle, .. },
        ..
    }) = sender.content(user_id, &verify).await.expect("content")
    else {
        panic!("a verification message has a link");
    };
    assert_eq!(
        handle.as_str(),
        format!("mail-{}", &user_id.to_string()[24..])
    );
    assert_eq!(
        link,
        format!(
            "https://auth.sourceorigin.dev/settings/emails/verify#token={}",
            token.encoded()
        )
    );

    // A removed address gets no verification link, but still gets its notices.
    database
        .emails()
        .remove(user_id, email_id)
        .await
        .expect("remove");
    assert_eq!(sender.deliver(id, user_id, &verify).await, Ok(()));
    assert_eq!(outbox.headers().len(), 2, "no link to a removed address");
    assert_eq!(sender.deliver(id, user_id, &removed).await, Ok(()));
    assert_eq!(outbox.headers().len(), 3, "the notice is sent");
    let disabled = EmailSender::<Arc<Outbox>>::with_mailer(database, None, &config);
    assert_eq!(disabled.deliver(id, user_id, &removed).await, Ok(()));
    assert_eq!(outbox.headers().len(), 3, "nothing is sent while disabled");
}

/// A verification email queued on one side of a change of token digest key and
/// sent from the other, as a rolling deploy or a rollback can, carries a link
/// that verifies its address. Once the key it was queued under is removed, its
/// delivery fails, and a disabled account's link is not sent.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_verification_link_survives_a_change_of_key() {
    let database = Replicas::database().await;
    let accounts = AccountService::new(database.clone());
    let (old, new) = (
        Secret::generate().expect("key"),
        Secret::generate().expect("key"),
    );
    // Email settings under `current`, accepting `accepted` too.
    let settings = |current: &Secret, accepted: Option<&Secret>| {
        let derive = |key: &Secret| TokenDigestKey::derive(key.as_bytes()).expect("digest key");
        let mut config = EmailConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"), true);
        config.verification_keys =
            TokenDigestKeys::new(derive(current), accepted.map(derive)).verification_keys();
        config
    };
    // The change's first deploy accepts the new key, and its second makes it
    // current.
    let (before, after) = (settings(&old, Some(&new)), settings(&new, Some(&old)));
    // Adds an address to a new account under `config`, from a client IP of its
    // own so no other test shares its limit, and returns the account and the
    // message its delivery queued.
    let queue = async |config: &EmailConfig| {
        let browser = Browser::new_account(&database).await;
        let ip = IpAddr::V6(Ipv6Addr::from(browser.user_id.as_uuid().as_u128()));
        let owner = accounts
            .owner(RequestContext::from_ip(ip), &browser.headers())
            .await
            .expect("session lookup")
            .expect("signed in");
        let address = format!("{}@example.com", browser.user_id);
        let added = accounts
            .add_email(&owner, config, &address)
            .await
            .expect("added");
        let destination = format!("account {}, address {}", browser.user_id, added.id);
        let payloads = database.deliveries().payloads(&destination).await;
        let [payload] = <[_; 1]>::try_from(payloads.expect("payloads")).expect("one delivery");
        let message: EmailMessage = serde_json::from_value(payload).expect("message");
        (browser.user_id, message)
    };
    // Sends `message` to `user_id` under `config`, and returns the outcome and
    // the relay.
    let send = async |config: &EmailConfig, user_id, message: &EmailMessage| {
        let outbox = Arc::new(Outbox::default());
        let sender = EmailSender::with_mailer(database.clone(), Some(Arc::clone(&outbox)), config);
        let outcome = sender.deliver(DeliveryId::new(), user_id, message).await;
        (outcome, outbox)
    };

    for (queued, sent) in [(&before, &after), (&after, &before)] {
        let (user_id, message) = queue(queued).await;
        let (outcome, outbox) = send(sent, user_id, &message).await;
        assert_eq!(outcome, Ok(()));
        accounts
            .verify_email(&outbox.verification_token(), None, RequestContext::TEST)
            .await
            .expect("the link verifies");
    }

    let (user_id, message) = queue(&before).await;
    let (outcome, _) = send(&settings(&new, None), user_id, &message).await;
    assert_eq!(
        outcome,
        Err(DeliveryError::Permanent(Failure::Message)),
        "no link under a key no longer configured"
    );
    let disabled = database
        .users()
        .set_status(user_id, AccountStatus::Disabled)
        .await;
    assert!(disabled.expect("status"));
    let (outcome, outbox) = send(&after, user_id, &message).await;
    assert_eq!(outcome, Ok(()));
    assert!(outbox.headers().is_empty(), "no link to a disabled account");
}

/// A recovery's link goes to its address, naming the account, only while the
/// link works and the account is active, under the key its recovery started
/// with, even once a change of token digest key made it the accepted one. With
/// that key gone, the delivery fails.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_recovery_link_is_sent_while_it_works() {
    let database = Replicas::database().await;
    let mut config = EmailConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"), true);
    let user_id = account(&database).await;
    let address = format!("{user_id}@example.com");
    let email_id = verified_address(&database, user_id, &address, true).await;
    // Started under a key that a change of token digest key made the accepted
    // one before the link was sent.
    let origin: Origin = "https://auth.sourceorigin.dev".parse().expect("origin");
    let started = Secret::generate().expect("recovery key");
    let current = Secret::generate().expect("recovery key");
    let before = RecoveryLinks::new(origin.clone(), LinkKeys::new(started.clone(), None));
    let keys = LinkKeys::new(current.clone(), Some(started));
    config.recovery_links = RecoveryLinks::new(origin.clone(), keys);
    let (recovery_id, token) = recover(&database, user_id, &before).await;
    let outbox = Arc::new(Outbox::default());
    let sender = EmailSender::with_mailer(database.clone(), Some(Arc::clone(&outbox)), &config);
    let link = EmailMessage::RecoveryLink {
        recovery_id,
        email_id,
    };

    let content = sender.content(user_id, &link).await.expect("content");
    let Some(Content {
        address: to,
        said: EmailContent::RecoveryLink {
            handle, link: url, ..
        },
    }) = content
    else {
        panic!("a recovery's link has a recipient");
    };
    assert_eq!(to, address);
    assert_eq!(
        handle.as_str(),
        format!("mail-{}", &user_id.to_string()[24..])
    );
    assert_eq!(
        url,
        before.url(&token).as_str(),
        "under the key it started with"
    );
    sender.assert_renders(user_id, &link).await;

    config.recovery_links = RecoveryLinks::new(origin, LinkKeys::new(current, None));
    let unkeyed = EmailSender::with_mailer(database.clone(), Some(Arc::clone(&outbox)), &config);
    let content = unkeyed.content(user_id, &link).await;
    assert!(
        matches!(content, Err(DeliveryError::Permanent(Failure::Message))),
        "no link under a key no longer configured"
    );

    // A disabled account's link is not sent, nor a replaced recovery's.
    let disable = async |status| {
        let changed = database.users().set_status(user_id, status).await;
        assert!(changed.expect("status"));
    };
    disable(AccountStatus::Disabled).await;
    assert!(
        sender
            .content(user_id, &link)
            .await
            .expect("content")
            .is_none()
    );
    disable(AccountStatus::Active).await;
    database
        .recoveries()
        .cancel_open(user_id)
        .await
        .expect("cancel");
    assert_eq!(
        sender.deliver(DeliveryId::new(), user_id, &link).await,
        Ok(())
    );
    assert!(outbox.headers().is_empty(), "no link that stopped working");

    // A recovery started under the current key is sent under it.
    let (current_id, token) = recover(&database, user_id, &config.recovery_links).await;
    let link = EmailMessage::RecoveryLink {
        recovery_id: current_id,
        email_id,
    };
    let content = unkeyed.content(user_id, &link).await.expect("content");
    let Some(Content {
        said: EmailContent::RecoveryLink { link: url, .. },
        ..
    }) = content
    else {
        panic!("a recovery's link has a recipient");
    };
    assert_eq!(url, config.recovery_links.url(&token).as_str());

    // A used link is not sent.
    let mut recoveries = database.recoveries();
    let used = recoveries
        .complete(user_id, current_id, PasskeyId::new(), PROBATION)
        .await;
    assert!(used.expect("complete"));
    let content = unkeyed.content(user_id, &link).await.expect("content");
    assert!(content.is_none(), "no link once used");
}

/// The link email and the notification that a recovery enrolled a passkey link
/// to its undo page, where a passkey from before it undoes it; the notification
/// of a `--revoke` start does only while a kept passkey can. Each notification's
/// email links its page in the inbox.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn recovery_notices_link_to_the_undo_page() {
    let database = Replicas::database().await;
    let config = EmailConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"), true);
    let user_id = account(&database).await;
    let address = format!("{user_id}@example.com");
    let email_id = verified_address(&database, user_id, &address, true).await;
    let (recovery_id, _) = recover(&database, user_id, &config.recovery_links).await;
    let sender = EmailSender::with_mailer(database.clone(), None::<Arc<Outbox>>, &config);
    let link = EmailMessage::RecoveryLink {
        recovery_id,
        email_id,
    };
    let recovered = EmailMessage::Notification {
        address: address.clone(),
        notification_id: NotificationId::new(),
        notification: Notification::Recovered,
        recovery_id: Some(recovery_id),
    };
    // The channel names the recovery only while a kept passkey can undo it.
    let revoked = |kept: bool| EmailMessage::Notification {
        address: address.clone(),
        notification_id: NotificationId::new(),
        notification: Notification::AccountSecured { kept },
        recovery_id: kept.then_some(recovery_id),
    };
    let undo_page = format!("https://auth.sourceorigin.dev/recover/undo#recovery={recovery_id}");

    let content = sender.content(user_id, &link).await.expect("content");
    assert!(
        matches!(content, Some(Content { said: EmailContent::RecoveryLink { undo, .. }, .. }) if undo == undo_page)
    );
    for (message, expected) in [
        (&recovered, Some(undo_page.clone())),
        (&revoked(true), Some(undo_page.clone())),
        (&revoked(false), None),
    ] {
        let content = sender.content(user_id, message).await.expect("content");
        assert!(
            matches!(&content, Some(Content { said: EmailContent::Notification { undo, page, .. }, .. })
                if *undo == expected && page.starts_with("https://auth.sourceorigin.dev/settings/notifications/")),
            "{message:?}"
        );
    }
    for message in [&recovered, &revoked(true), &revoked(false)] {
        sender.assert_renders(user_id, message).await;
    }
}

/// A notification is emailed to the addresses its kind names, each once, with
/// what the notification says: support's change to the primary verified
/// address only, a removal to the removed address, and a completed recovery to
/// every verified address, with its undo page. An account without a verified
/// address gets the notification and no email.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn notifications_are_emailed_to_the_addresses_their_kind_names() {
    let database = Replicas::database().await;
    let user_id = account(&database).await;
    let primary =
        verified_address(&database, user_id, &format!("{user_id}@example.com"), true).await;
    let other = verified_address(
        &database,
        user_id,
        &format!("other-{user_id}@example.com"),
        false,
    )
    .await;
    let record = async |user: UserId, event: DomainEvent| {
        let context = EventContext {
            actor: Actor::Cli {
                os_user: "operator".into(),
                host: "host".into(),
            },
            origin: RequestOrigin::default(),
            reason: None,
        };
        let mut tx = database.begin().await.expect("transaction");
        tx.record(&context, Some(user), event)
            .await
            .expect("record");
        tx.commit().await.expect("commit");
    };
    // The kinds of the notifications emailed to `email`, oldest first.
    let emailed = async |email: EmailId| -> Vec<(String, bool)> {
        let destination = format!("account {user_id}, address {email}");
        let payloads = database.deliveries().payloads(&destination).await;
        payloads
            .expect("payloads")
            .iter()
            .filter(|payload| payload["type"] == "notification")
            .map(|payload| {
                let kind = payload["notification"]["kind"].as_str().expect("kind");
                (kind.to_owned(), payload.get("recovery_id").is_some())
            })
            .collect()
    };

    record(user_id, DomainEvent::AccountEnabled {}).await;
    record(user_id, DomainEvent::EmailRemoved { email_id: other }).await;
    record(
        user_id,
        DomainEvent::RecoveryCompleted {
            recovery_id: RecoveryId::new(),
            passkey_id: PasskeyId::new(),
        },
    )
    .await;
    record(
        user_id,
        DomainEvent::RecoveryStarted {
            recovery_id: RecoveryId::new(),
            expires_at: chrono::Utc::now(),
            revoke: None,
        },
    )
    .await;
    let enabled = ("account_enabled".to_owned(), false);
    let removed = ("email_removed".to_owned(), false);
    let recovered = ("recovered".to_owned(), true);
    let started = ("recovery_started".to_owned(), true);
    assert_eq!(
        emailed(primary).await,
        [enabled, recovered.clone(), started.clone()]
    );
    assert_eq!(emailed(other).await, [removed, recovered, started]);

    let unaddressed = account(&database).await;
    record(unaddressed, DomainEvent::AccountEnabled {}).await;
    let unread = database.notifications().unread(unaddressed).await;
    assert_eq!(unread.expect("unread"), 1, "the inbox has it");
    let queued = database.deliveries().list(None, Some("email"), 1000).await;
    let to = format!("account {unaddressed},");
    assert!(
        !queued
            .expect("deliveries")
            .iter()
            .any(|delivery| delivery.destination.starts_with(&to)),
        "no email without a verified address"
    );
}

/// A raised alert notifies every active administrator, in their inbox and at
/// their primary verified address only, and nobody else: not a disabled
/// administrator, nor an account that administers nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_raised_alert_notifies_active_administrators() {
    use sourceorigin_common::{
        AlertId,
        admin::{ChainBreak, ChainProblem},
        alerts::Alert,
        events::JobName,
    };
    let database = Replicas::database().await;
    let addressed = async || {
        let user_id = account(&database).await;
        let primary =
            verified_address(&database, user_id, &format!("{user_id}@example.com"), true).await;
        let other = format!("other-{user_id}@example.com");
        let other = verified_address(&database, user_id, &other, false).await;
        (user_id, primary, other)
    };
    let (admin, primary, other) = addressed().await;
    let (disabled, disabled_primary, _) = addressed().await;
    let (member, member_primary, _) = addressed().await;
    for user_id in [admin, disabled] {
        database
            .administrators()
            .grant(user_id)
            .await
            .expect("grant");
    }
    database
        .users()
        .set_status(disabled, AccountStatus::Disabled)
        .await
        .expect("disable");
    let alert = Alert::AuditChainBroken(ChainBreak {
        position: 5,
        problem: ChainProblem::EventChanged,
    });
    let alert_id = AlertId::new();
    let context = EventContext::system(JobName::AuditVerification);
    let raised = DomainEvent::AlertRaised {
        alert_id,
        alert: alert.clone(),
    };
    let mut tx = database.begin().await.expect("transaction");
    tx.record(&context, None, raised).await.expect("record");
    tx.commit().await.expect("commit");

    let notified = async |user_id: UserId| {
        let inbox = database.notifications().list(user_id, None, 10).await;
        inbox
            .expect("inbox")
            .into_iter()
            .filter_map(|stored| stored.notification)
            .collect::<Vec<_>>()
    };
    let expected = Notification::AlertRaised {
        alert_id,
        title: format!("Alert: {}", alert.subject()),
        text: alert.body(),
    };
    assert_eq!(notified(admin).await, [expected]);
    assert_eq!(notified(disabled).await, []);
    assert_eq!(notified(member).await, []);
    let emailed = async |user_id: UserId, email_id: EmailId| {
        let destination = format!("account {user_id}, address {email_id}");
        let payloads = database.deliveries().payloads(&destination).await;
        payloads.expect("payloads").len()
    };
    assert_eq!(emailed(admin, primary).await, 1);
    assert_eq!(emailed(admin, other).await, 0);
    assert_eq!(emailed(disabled, disabled_primary).await, 0);
    assert_eq!(emailed(member, member_primary).await, 0);
}

/// An alert's email links the dashboard's Alerts tab, and only when auth serves
/// a dashboard.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_alerts_email_links_the_dashboard() {
    let database = Replicas::database().await;
    let user_id = account(&database).await;
    let config = EmailConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"), true);
    let message = EmailMessage::Notification {
        address: format!("{user_id}@example.com"),
        notification_id: NotificationId::new(),
        notification: Notification::AlertRaised {
            alert_id: sourceorigin_common::AlertId::new(),
            title: "The audit chain is broken".into(),
            text: "A verification found the chain broken.".into(),
        },
        recovery_id: None,
    };
    let dashboard: Origin = "https://admin.sourceorigin.dev".parse().expect("origin");
    for (linked, expected) in [
        (
            Some(&dashboard),
            Some("https://admin.sourceorigin.dev/alerts"),
        ),
        (None, None),
    ] {
        let sender = EmailSender::with_mailer(database.clone(), None::<Arc<Outbox>>, &config)
            .linking(linked);
        let content = sender.content(user_id, &message).await.expect("content");
        assert!(
            matches!(&content, Some(Content { said: EmailContent::Notification { alerts, .. }, .. }) if alerts.as_deref() == expected),
            "{linked:?}"
        );
        sender.assert_renders(user_id, &message).await;
    }
}

/// A security notification's email carries the link that signs its account out
/// everywhere, which names the notification and is one auth checks; an alert
/// to administrators, about the service, carries none.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn security_emails_carry_the_sign_out_link() {
    let database = Replicas::database().await;
    let user_id = account(&database).await;
    let config = EmailConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"), true);
    let sender = EmailSender::with_mailer(database.clone(), None::<Arc<Outbox>>, &config);
    let notification_id = NotificationId::new();
    let message = |notification| EmailMessage::Notification {
        address: format!("{user_id}@example.com"),
        notification_id,
        notification,
        recovery_id: None,
    };
    let alert = message(Notification::NewDeviceSignIn);
    let Some(Content {
        said:
            EmailContent::Notification {
                sign_out: Some(link),
                ..
            },
        ..
    }) = sender.content(user_id, &alert).await.expect("content")
    else {
        panic!("a security notification's email carries the link");
    };
    let link = url::Url::parse(&link).expect("URL");
    assert_eq!(link.path(), routes::page::SIGN_OUT);
    let query: std::collections::HashMap<_, _> = link.query_pairs().into_owned().collect();
    let checked = config.sign_out_links.check(&crate::notifications::Link {
        id: query["id"].parse().expect("notification"),
        token: query["token"].clone(),
    });
    assert_eq!(checked.expect("check"), Some(notification_id));
    sender.assert_renders(user_id, &alert).await;
    let service = message(Notification::AlertRaised {
        alert_id: sourceorigin_common::AlertId::new(),
        title: "Alert".into(),
        text: "Text".into(),
    });
    assert!(matches!(
        sender.content(user_id, &service).await.expect("content"),
        Some(Content {
            said: EmailContent::Notification { sign_out: None, .. },
            ..
        })
    ));
}

/// An announcement's email offers a one-click unsubscribe (RFC 8058) whose
/// link turns only its recipient's announcements' email off, in its headers and
/// its body; an essential one, which its recipient cannot turn off, offers none.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn announcement_emails_offer_unsubscribing_unless_essential() {
    let database = Replicas::database().await;
    let user_id = account(&database).await;
    verified_address(&database, user_id, &format!("{user_id}@example.com"), true).await;
    let sent = async |essential| {
        let id = AnnouncementId::new();
        let mut tx = database.begin().await.expect("transaction");
        tx.announcements()
            .insert_draft(&DraftedAnnouncement {
                id,
                subject: "News",
                body: "Something changed.",
                recipients: Recipients::Accounts(&[user_id]),
                essential,
            })
            .await
            .expect("draft");
        tx.announcements().send(id, 1).await.expect("send");
        tx.commit().await.expect("commit");
        id
    };
    let origin: Origin = AUTH_ORIGIN.parse().expect("origin");
    let config = EmailConfig::test(&origin, true);
    let outbox = Arc::new(Outbox::default());
    let sender = EmailSender::with_mailer(database.clone(), Some(outbox.clone()), &config);
    for id in [sent(false).await, sent(true).await] {
        sender
            .announce(DeliveryId::new(), user_id, id)
            .await
            .expect("sent");
    }
    let sent = outbox.sent.lock().expect("outbox");
    let [news, essential] = sent.as_slice() else {
        panic!("two messages");
    };
    let header = |message: &Message, name| message.headers().get_raw(name).map(str::to_owned);
    let link = header(news, "List-Unsubscribe").expect("an unsubscribe link");
    let link = link
        .strip_prefix('<')
        .and_then(|link| link.strip_suffix('>'))
        .expect("in angle brackets");
    assert_eq!(
        header(news, "List-Unsubscribe-Post").as_deref(),
        Some("List-Unsubscribe=One-Click")
    );
    let url = url::Url::parse(link).expect("URL");
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let unsubscribe = crate::notifications::Link {
        id: query["id"].parse().expect("account"),
        token: query["token"].clone(),
    };
    assert_eq!(
        config.unsubscribe_links.check(&unsubscribe).expect("check"),
        Some(user_id)
    );
    let body = String::from_utf8_lossy(&news.formatted())
        .replace("=\r\n", "")
        .replace("=3D", "=")
        .replace("&amp;", "&");
    assert!(body.contains(link), "{body}");
    assert_eq!(header(essential, "List-Unsubscribe"), None);
    assert!(
        !String::from_utf8_lossy(&essential.formatted()).contains("/unsubscribe"),
        "no link in its body"
    );
}

/// A message's email says what administrators wrote, in its paragraphs, exactly
/// as the dashboard previewed it, and offers no unsubscribing: it is about the
/// account itself.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_messages_email_is_its_preview() {
    let database = Replicas::database().await;
    let user_id = account(&database).await;
    let origin: Origin = AUTH_ORIGIN.parse().expect("origin");
    let config = EmailConfig::test(&origin, true);
    let letter = Letter::new(
        "About your account",
        "First line.\nSecond line.\n\nWrite to support@example.com.",
    )
    .expect("letter");
    let message = EmailMessage::Notification {
        address: format!("{user_id}@example.com"),
        notification_id: NotificationId::new(),
        notification: Notification::Message {
            title: letter.subject.clone(),
            text: letter.body.clone(),
        },
        recovery_id: None,
    };
    let outbox = Arc::new(Outbox::default());
    let sender = EmailSender::with_mailer(database.clone(), Some(outbox.clone()), &config);
    let content = sender.content(user_id, &message).await.expect("content");
    let mail = content.expect("an email").said.mail();
    assert_eq!(mail.text(), EmailSender::preview(&letter, &origin));
    let html = mail.html().await.expect("HTML");
    assert!(
        html.contains("<p>First line.<br>Second line.</p>"),
        "{html}"
    );
    sender
        .deliver(DeliveryId::new(), user_id, &message)
        .await
        .expect("sent");
    let sent = outbox.sent.lock().expect("outbox");
    let [email] = sent.as_slice() else {
        panic!("one message");
    };
    assert_eq!(email.headers().get_raw("List-Unsubscribe"), None);
}

/// Every kind of email, as its recipient reads it: its subject, then its
/// plain-text and HTML bodies, a tag a line. A change to what any of them says
/// shows in its snapshot under `snapshots/`.
#[tokio::test]
async fn every_email_reads_as_its_snapshot() {
    let link = |path: &str| format!("https://auth.sourceorigin.dev{path}");
    let origin: Origin = AUTH_ORIGIN.parse().expect("origin");
    let handle = Handle::parse("ada").expect("handle");
    let address = || "ada@example.com".to_owned();
    let written = "First line.\nSecond line.\n\nWrite to <support@example.com>.";
    let announced = |subject: &str, everyone, unsubscribe| {
        Content::announcement(
            address(),
            Announced {
                subject: subject.into(),
                body: written.into(),
                everyone,
                unsubscribe,
            },
            &origin,
        )
        .said
    };
    let contents = [
        (
            "verify_address",
            EmailContent::VerifyAddress {
                address: address(),
                handle: handle.clone(),
                link: link("/settings/emails/verify#token=TOKEN"),
                hours: 24,
            },
        ),
        (
            "recovery_link",
            EmailContent::RecoveryLink {
                handle,
                link: link("/recover#token=TOKEN"),
                hours: 72,
                undo: link("/recover/undo#recovery=RECOVERY"),
            },
        ),
        (
            "notification_recovered",
            EmailContent::Notification {
                subject: Notification::Recovered.subject().to_owned(),
                body: Notification::Recovered.body(),
                page: link("/settings/notifications/NOTIFICATION"),
                undo: Some(link("/recover/undo#recovery=RECOVERY")),
                alerts: None,
                sign_out: Some(link("/sign-out#token=TOKEN")),
            },
        ),
        (
            "notification_alert",
            EmailContent::Notification {
                subject: "Alert: The audit chain is broken".into(),
                body: "A verification found the chain broken.".into(),
                page: link("/settings/notifications/NOTIFICATION"),
                undo: None,
                alerts: Some("https://admin.sourceorigin.dev/alerts".into()),
                sign_out: None,
            },
        ),
        (
            "message",
            Content::message(
                address(),
                "About your account".into(),
                written.into(),
                &origin,
            )
            .said,
        ),
        (
            "announcement",
            announced(
                "News",
                true,
                Some(link("/unsubscribe?account=ACCOUNT&token=TOKEN")),
            ),
        ),
        (
            "announcement_essential",
            announced("Our terms changed", false, None),
        ),
    ];
    for (name, content) in contents {
        let mail = content.mail();
        let html = mail.html().await.expect("HTML").replace("><", ">\n<");
        let read = format!(
            "Subject: {}\n\n--- text/plain ---\n{}\n\n--- text/html ---\n{html}\n",
            mail.subject,
            mail.text()
        );
        insta::assert_snapshot!(name, read);
    }
}
