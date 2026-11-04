//! Prompt, `max_age` and consent decision parsing.

use super::*;
use crate::oidc::Interaction;
use chrono::{Duration, Utc};
use piquel_common::{AuthenticationMethod, SessionId, UserId};
use piquel_repository::StoredSession;

/// Duplicates are allowed, unknown values are rejected, and `none` stands alone.
#[test]
fn prompts_enforce_interaction_policy() {
    let interaction = |prompt: &str| {
        let mut parameters = AuthorizationParameters::default();
        parameters.prompt = Some(prompt.into());
        parameters.interaction()
    };
    let interactive = interaction("login consent select_account login");
    assert_eq!(interactive.ok(), Some(Interaction::LoginAndConsent));
    assert_eq!(interaction("").ok(), Some(Interaction::AsNeeded));
    assert!(interaction("none login").is_err());
    assert!(interaction("unrecognized").is_err());
}

/// `max_age` holds up to its boundary at authorize too. `0` needs a sign-in after
/// the request, a negative age is never met, and one past `u32` limits nothing.
#[test]
fn max_age_bounds_the_session_authentication() {
    let now = Utc::now();
    let session = StoredSession {
        id: SessionId::new(),
        user_id: UserId::new(),
        authentication_methods: vec![AuthenticationMethod::Passkey],
        authenticated_at: now - Duration::days(1),
        expires_at: now + Duration::days(1),
        last_seen_at: now,
        revoked_at: None,
        passkey_confirmed_at: Some(now - Duration::seconds(300)),
        user_agent_family: None,
        last_seen_ip: None,
    };
    let satisfies = |max_age, started_at| {
        OidcApplication::session_satisfies(&session, false, Some(max_age), None, None, started_at)
    };
    assert!(satisfies(310, None));
    assert!(!satisfies(290, None));
    assert!(satisfies(i64::MAX, None));
    assert!(!satisfies(-1, None));
    assert!(!satisfies(0, None));
    assert!(!satisfies(0, Some(now - Duration::seconds(200))));
    assert!(satisfies(0, Some(now - Duration::seconds(400))));
}

/// Known decisions parse; unknown ones become `Unsupported` instead of failing.
#[test]
fn consent_decisions_are_closed() {
    for (wire, expected) in [
        ("approve", ConsentDecision::Approve),
        ("deny", ConsentDecision::Deny),
    ] {
        let input = serde_json::json!({"transaction":"pending", "decision":wire});
        let parsed: AuthorizationDecision = serde_json::from_value(input).expect("decision");
        assert_eq!(parsed.decision, expected);
    }
    let unsupported: AuthorizationDecision = serde_json::from_value(
        serde_json::json!({"transaction":"pending", "decision":"arbitrary"}),
    )
    .expect("unknown choice preserves handler rejection");
    assert_eq!(unsupported.decision, ConsentDecision::Unsupported);
}
