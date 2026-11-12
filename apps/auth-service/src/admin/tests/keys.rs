//! Changing signing keys.

use super::*;
use crate::security::CONFIRMATION_MAX_AGE;

/// Rotating the signing key checks its administrator as every change does, after
/// its last write and before committing: one whose rights were revoked, or whose
/// confirmation is stale, gets the refusal any change gets, and publishes nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_key_changes_check_their_administrator() {
    let harness = Harness::new().await;
    let service = harness.service();
    let keys = crate::KeyStore::new(
        harness.database.clone(),
        crate::tests::key_encryption_keys(),
    );
    let admin = harness.admin().await;
    let revoked = harness.admin().await;
    service
        .revoke_administrator(&cli(), revoked.user_id, reason("Asked by email"))
        .await
        .expect("revoke");
    let stale = Utc::now() - Duration::minutes(10);
    let step_up = StepUpRequirement::passkey_within(CONFIRMATION_MAX_AGE);
    for (operator, refusal) in [
        (operator(revoked, Utc::now()), AdminError::NotAdministrator),
        (operator(admin, stale), AdminError::StepUpRequired(step_up)),
    ] {
        let refused = service
            .rotate_signing_key(&operator, &keys, true, reason("Asked by email"))
            .await
            .expect_err("rotate");
        assert_refused(&refused, &refusal, "rotate");
    }
}
