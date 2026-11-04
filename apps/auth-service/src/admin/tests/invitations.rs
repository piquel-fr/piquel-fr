//! Creating and revoking invitations.

use super::*;
use piquel_crypto::Secret;

/// An invitation link works until an administrator revokes it, which also ends
/// its expiry, for the previous release; revoking it again finds nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn revoked_invitations_cannot_be_redeemed() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = operator(harness.admin().await, Utc::now());
    let created = service
        .create_invitation(&admin, &origin(), "24h".parse().expect("expiry"))
        .await
        .expect("invitation");
    assert_eq!(created.url.path(), crate::routes::page::REGISTER);
    let (_, encoded) = created
        .url
        .query_pairs()
        .find(|(name, _)| name == "invitation")
        .expect("invitation secret");
    let digest = Secret::parse(&encoded).expect("secret").digest();
    let active = || harness.database.security();
    assert!(
        active()
            .invitation_active(digest.as_bytes())
            .await
            .expect("lookup")
    );
    service
        .revoke_invitation(&admin, created.id)
        .await
        .expect("revoke");
    assert!(
        !active()
            .invitation_active(digest.as_bytes())
            .await
            .expect("lookup")
    );
    let listed = service.list_invitations(&admin).await.expect("list");
    let revoked = listed
        .iter()
        .find(|listed| listed.id == created.id)
        .expect("revoked invitation");
    assert!(Some(revoked.expires_at) <= revoked.revoked_at);
    let again = service.revoke_invitation(&admin, created.id).await;
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
    let invitation = service
        .create_invitation(&cli(), &origin(), InviteExpiry::default())
        .await
        .expect("invitation");
    let (_, encoded) = invitation
        .url
        .query_pairs()
        .find(|(name, _)| name == "invitation")
        .expect("invitation secret");
    let digest = piquel_crypto::Secret::parse(&encoded)
        .expect("secret")
        .digest();
    let mut signup = harness.database.begin().await.expect("transaction");
    assert!(
        signup
            .security()
            .redeem_invitation(digest.as_bytes())
            .await
            .expect("redeem")
    );
    let operator = operator(admin, Utc::now());
    let (result, ()) = tokio::join!(service.revoke_invitation(&operator, invitation.id), async {
        until_blocked(&mut signup, 1).await;
        // The signup revokes the browser's session without a deadlock.
        admin.sign_out(&mut signup).await;
        signup.commit().await.expect("signup");
    });
    assert!(
        matches!(result, Err(AdminError::InvitationNotFound)),
        "{result:?}"
    );
}
