//! Retries, address resolution and rendering, with a fake relay.

use super::*;
use crate::{
    recovery::LINK_LIFETIME,
    tests::{Replicas, verified_address},
};
use piquel_common::{AccountStatus, EmailId, Handle, RecoveryId};
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
    let settings = "https://piquel.fr/settings".parse().expect("settings URL");
    let config = EmailConfig::test(&settings, true);
    let user_id = account(&database).await;
    let email_id = EmailId::new();
    let token = config.verification_key.token(email_id).expect("token");
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
    let Some(Content::VerifyAddress { link, username, .. }) =
        sender.content(user_id, &verify).await.expect("content")
    else {
        panic!("a verification message has a link");
    };
    assert_eq!(username, format!("mail-{}", &user_id.to_string()[24..]));
    assert_eq!(
        link,
        format!(
            "https://piquel.fr/settings/emails/verify#token={}",
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

/// A recovery's link goes to its address, naming the account, only while the
/// link works and the account is active. The notice that a recovery enrolled a passkey links to settings,
/// where an older passkey undoes it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_recovery_link_is_sent_while_it_works() {
    let database = Replicas::database().await;
    let settings = "https://piquel.fr/settings".parse().expect("settings URL");
    let config = EmailConfig::test(&settings, true);
    let user_id = account(&database).await;
    let address = format!("{user_id}@example.com");
    let email_id = verified_address(&database, user_id, &address, true).await;
    let recovery_id = RecoveryId::new();
    let token = config.recovery_links.token(recovery_id).expect("token");
    database
        .recoveries()
        .insert(&InsertRecovery {
            id: recovery_id,
            user_id,
            secret_digest: token.digest().as_bytes(),
            primary_email_id: Some(email_id),
            expires_at: chrono::Utc::now() + LINK_LIFETIME,
        })
        .await
        .expect("recovery");
    let outbox = Arc::new(Outbox::default());
    let sender = EmailSender::with_mailer(database.clone(), Some(Arc::clone(&outbox)), &config);
    let link = EmailMessage::RecoveryLink {
        recovery_id,
        email_id,
    };
    let recovered = EmailMessage::Recovered {
        address: address.clone(),
    };

    let content = sender.content(user_id, &link).await.expect("content");
    let Some(Content::RecoveryLink {
        address: to,
        username,
        link: url,
        ..
    }) = content
    else {
        panic!("a recovery's link has a recipient");
    };
    assert_eq!(to, address);
    assert_eq!(username, format!("mail-{}", &user_id.to_string()[24..]));
    let expected = config.recovery_links.link(recovery_id).expect("link");
    assert_eq!(url, expected.as_str());
    let content = sender.content(user_id, &recovered).await.expect("content");
    assert!(matches!(
        content,
        Some(Content::Recovered { settings, .. }) if settings == "https://piquel.fr/settings"
    ));
    for message in [&link, &recovered] {
        sender.assert_renders(user_id, message).await;
    }

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
}
