//! Creating, mailing and revoking invitations.

use super::*;
use crate::tests::invitation_links;
use sourceorigin_common::{admin::InvitationSent, email::NormalizedEmail};
use sourceorigin_repository::{Channel, Invitation, InvitationKey};

/// A mailed invitation needs email, and an address the sender can send to:
/// otherwise, the service refuses before anything is created, and a link to pass
/// on still works. With both, the address is kept and the link is queued for it,
/// never shown; a resend queues it again, and only a mailed invitation can be
/// resent.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn mailed_invitations_need_email_and_queue_their_link() {
    let harness = Harness::new().await;
    let links = invitation_links();
    // Unique, since other scenarios share the database.
    let jane = format!("jane-{}@example.com", TokenId::new());
    let address = || Some(NormalizedEmail::parse(&jane).expect("address"));
    let listed = async |service: &AdminService| {
        let listed = service.list_invitations(&cli()).await.expect("list");
        listed
            .into_iter()
            .filter(|listed| listed.email.as_deref() == Some(jane.as_str()))
            .map(|listed| listed.id)
            .collect::<Vec<_>>()
    };
    let unmailed = AdminService::new(harness.database.clone(), false);
    let refused = unmailed
        .create_invitation(
            &cli(),
            &links,
            InviteExpiry::default(),
            address(),
            reason("Jane"),
        )
        .await;
    assert!(
        matches!(refused, Err(AdminError::InvitationNeedsEmail)),
        "{refused:?}"
    );
    assert!(listed(&unmailed).await.is_empty(), "nothing created");
    let link = unmailed
        .create_invitation(
            &cli(),
            &links,
            InviteExpiry::default(),
            None,
            reason("Jane"),
        )
        .await
        .expect("link");
    assert!(matches!(link.sent, InvitationSent::Link(_)), "{link:?}");

    let service = harness.service();
    // A valid address the sender can't send to would never get its link.
    let unsendable = NormalizedEmail::parse("a:b@example.com").expect("valid address");
    let refused = service
        .create_invitation(
            &cli(),
            &links,
            InviteExpiry::default(),
            Some(unsendable),
            reason("Jane"),
        )
        .await;
    assert!(
        matches!(refused, Err(AdminError::InvitationUnsendable(_))),
        "{refused:?}"
    );
    let mailed = service
        .create_invitation(
            &cli(),
            &links,
            InviteExpiry::default(),
            address(),
            reason("Jane"),
        )
        .await
        .expect("mailed");
    assert_eq!(mailed.sent, InvitationSent::Mailed(jane.clone()));
    assert_eq!(listed(&service).await, [mailed.id]);
    service
        .resend_invitation(&cli(), mailed.id, reason("Jane lost it"))
        .await
        .expect("resend");
    let queued = harness
        .database
        .deliveries()
        .list(None, Some(Invitation::NAME), 1000)
        .await
        .expect("deliveries");
    let destination = format!("invitation {}", mailed.id);
    assert_eq!(
        queued
            .iter()
            .filter(|delivery| delivery.destination == destination)
            .count(),
        2
    );
    let again = service
        .resend_invitation(&cli(), link.id, reason("Jane lost it"))
        .await;
    assert!(
        matches!(again, Err(AdminError::InvitationNotMailed)),
        "{again:?}"
    );
}

/// An invitation link works until an administrator revokes it, which also ends
/// its expiry, for the previous release; revoking it again finds nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn revoked_invitations_cannot_be_redeemed() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = operator(harness.admin().await, Utc::now());
    let links = invitation_links();
    let created = service
        .create_invitation(
            &admin,
            &links,
            "24h".parse().expect("expiry"),
            None,
            reason("Asked by email"),
        )
        .await
        .expect("invitation");
    let InvitationSent::Link(url) = &created.sent else {
        panic!("a link to pass on: {created:?}");
    };
    assert_eq!(url.path(), crate::routes::page::REGISTER);
    let digest = links.token(created.id).digest();
    let open = || async {
        harness
            .database
            .security()
            .open_invitation(InvitationKey::Digest(digest.as_bytes()))
            .await
            .expect("lookup")
            .is_some()
    };
    assert!(open().await);
    service
        .revoke_invitation(&admin, created.id, reason("Asked by email"))
        .await
        .expect("revoke");
    assert!(!open().await);
    let listed = service.list_invitations(&admin).await.expect("list");
    let revoked = listed
        .iter()
        .find(|listed| listed.id == created.id)
        .expect("revoked invitation");
    assert!(Some(revoked.expires_at) <= revoked.revoked_at);
    let again = service
        .revoke_invitation(&admin, created.id, reason("Asked by email"))
        .await;
    assert!(
        matches!(again, Err(AdminError::InvitationNotFound)),
        "{again:?}"
    );
}

/// Revoking an invitation that a signup is redeeming waits for the signup, which
/// may end the administrator's session as it signs the new account in on the
/// same browser.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn invitation_revocation_waits_for_signup() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let service = harness.service();
    let links = invitation_links();
    let invitation = service
        .create_invitation(
            &cli(),
            &links,
            InviteExpiry::default(),
            None,
            reason("Asked by email"),
        )
        .await
        .expect("invitation");
    let digest = links.token(invitation.id).digest();
    let mut signup = harness.database.begin().await.expect("transaction");
    assert!(
        signup
            .security()
            .redeem_invitation(digest.as_bytes())
            .await
            .expect("redeem")
            .is_some()
    );
    let operator = operator(admin, Utc::now());
    let (result, ()) = tokio::join!(
        service.revoke_invitation(&operator, invitation.id, reason("Asked by email")),
        async {
            until_blocked(&mut signup, 1).await;
            // The signup revokes the browser's session without a deadlock.
            admin.sign_out(&mut signup).await;
            signup.commit().await.expect("signup");
        }
    );
    assert!(
        matches!(result, Err(AdminError::InvitationNotFound)),
        "{result:?}"
    );
}
