//! Retries, address resolution and rendering, with a fake relay.

use super::*;
use crate::{
    account::AccountService,
    config::{LinkKeys, TokenDigestKey, TokenDigestKeys},
    recovery::{LINK_LIFETIME, PROBATION, RecoveryLinks},
    security::RequestContext,
    tests::{AUTH_ORIGIN, Replicas, verified_address},
};
use piquel_common::{AccountStatus, EmailId, Handle, PasskeyId, RecoveryId, config::Origin};
use piquel_crypto::Secret;
use piquel_repository::{InsertRecovery, InsertUnverifiedEmail, InsertUser};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
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
}

/// A retry after an ambiguous send sends the same message again, with the same
/// `Message-ID`: a duplicate the mail client can recognize. Once the address is
/// removed, its verification link is not sent, but notices still are; nothing is
/// while email is disabled. Every message has a plain-text and an HTML body, and
/// a verification link names the account.
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
    let expected = (format!("<{id}@piquel.fr>"), "ada@example.com".to_owned());
    assert_eq!(outbox.headers(), [expected.clone(), expected]);

    let notice = EmailMessage::PrimaryAddressChanged {
        address: "ada@example.com".into(),
    };
    let removed = EmailMessage::AddressRemoved {
        address: "ada@example.com".into(),
    };
    for message in [&verify, &notice, &removed] {
        sender.assert_renders(user_id, message).await;
    }
    let Some(Content::VerifyAddress { link, handle, .. }) =
        sender.content(user_id, &verify).await.expect("content")
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
            "https://auth.piquel.fr/settings/emails/verify#token={}",
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

/// A verification link added before a change of token digest key, and still
/// queued when the change made its key the accepted one, is sent under that key,
/// and verifies its address. A disabled account's link is not sent.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_verification_link_survives_a_change_of_key() {
    let database = Replicas::database().await;
    let mut config = EmailConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"), true);
    let user_id = account(&database).await;
    let (old, new) = (
        Secret::generate().expect("key"),
        Secret::generate().expect("key"),
    );
    let keys = |current: &Secret, accepted: &Secret| {
        let derive = |key: &Secret| TokenDigestKey::derive(key.as_bytes()).expect("digest key");
        TokenDigestKeys::new(derive(current), Some(derive(accepted))).verification_keys()
    };
    // Added after the first deploy of the change, which accepts the new key.
    config.verification_keys = keys(&old, &new);
    let email_id = EmailId::new();
    let address = format!("{user_id}@example.com");
    let added = config.verification_keys.token(email_id).expect("token");
    database
        .emails()
        .insert_unverified(&InsertUnverifiedEmail {
            id: email_id,
            user_id,
            normalized_email: &address,
            secret_digest: added.digest().as_bytes(),
            expires_at: chrono::Utc::now() + VERIFICATION_LIFETIME,
        })
        .await
        .expect("address");
    // Sent after the second, which makes the new key current.
    config.verification_keys = keys(&new, &old);
    let sender = EmailSender::with_mailer(database.clone(), None::<Arc<Outbox>>, &config);
    let verify = EmailMessage::VerifyAddress { email_id };

    let set_status = async |status| {
        let changed = database.users().set_status(user_id, status).await;
        assert!(changed.expect("status"));
    };
    set_status(AccountStatus::Disabled).await;
    let content = sender.content(user_id, &verify).await.expect("content");
    assert!(content.is_none(), "no link to a disabled account");
    set_status(AccountStatus::Active).await;

    let content = sender.content(user_id, &verify).await.expect("content");
    let Some(Content::VerifyAddress { link, .. }) = content else {
        panic!("a verification message has a link");
    };
    let (_, token) = link.split_once("#token=").expect("token");
    let verified = AccountService::new(database)
        .verify_email(token, None, RequestContext::TEST)
        .await
        .expect("the link verifies");
    assert_eq!(verified.address, address);
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
    let origin: Origin = "https://auth.piquel.fr".parse().expect("origin");
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
    let Some(Content::RecoveryLink {
        address: to,
        handle,
        link: url,
        ..
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
    let Some(Content::RecoveryLink { link: url, .. }) = content else {
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

/// The link email and the notice that a recovery enrolled a passkey link to its
/// undo page, where a passkey from before it undoes it; the notice of a
/// `--revoke` start does only while a kept passkey can, and otherwise points to
/// support.
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
    let recovered = EmailMessage::Recovered {
        address: address.clone(),
        recovery_id,
    };
    let revoked = |kept| EmailMessage::RecoveryRevoked {
        address: address.clone(),
        recovery_id,
        kept,
    };
    let undo_page = format!("https://auth.piquel.fr/recover/undo#recovery={recovery_id}");

    let content = sender.content(user_id, &link).await.expect("content");
    assert!(matches!(content, Some(Content::RecoveryLink { undo, .. }) if undo == undo_page));
    let content = sender.content(user_id, &recovered).await.expect("content");
    assert!(matches!(
        content,
        Some(Content::Recovered { undo, days, .. })
            if undo == undo_page && days == PROBATION.num_days()
    ));
    for (kept, expected) in [(true, Some(undo_page.clone())), (false, None)] {
        let content = sender
            .content(user_id, &revoked(kept))
            .await
            .expect("content");
        assert!(
            matches!(content, Some(Content::RecoveryRevoked { undo, .. }) if undo == expected),
            "kept: {kept}"
        );
    }
    for message in [&recovered, &revoked(true), &revoked(false)] {
        sender.assert_renders(user_id, message).await;
    }
}
