//! The overview's arithmetic.
use super::*;
use sourceorigin_common::{
    AuthenticationMethod, SessionId,
    events::{DomainEvent, SignInFailure},
};

/// The kinds counted are the tags the events are stored under.
#[test]
fn the_counted_kinds_are_the_stored_tags() {
    let failed = DomainEvent::SignInFailed {
        method: AuthenticationMethod::Passkey,
        reason: SignInFailure::InvalidCredential,
    };
    assert_eq!(failed.kind(), Kinds::FAILED);
    let signed_in = DomainEvent::SignedIn {
        session_id: SessionId::new(),
        method: AuthenticationMethod::Passkey,
        inline: None,
    };
    assert_eq!(signed_in.kind(), Kinds::SIGNED_IN);
    let grant = DomainEvent::GrantIssued {
        client_id: "notes".parse().expect("client ID"),
        family_id: None,
        scopes: Vec::new(),
    };
    assert_eq!(grant.kind(), Kinds::GRANT);
}

/// A spike needs both a floor and a multiple of usual: a quiet week's first
/// failures are no alarm, and a busy service's usual failures are none either.
#[test]
fn a_spike_is_at_least_ten_and_over_three_times_usual() {
    assert!(!Rate::new(9, 0).spikes());
    assert!(Rate::new(10, 0).spikes());
    assert!(!Rate::new(30, HOURS_PER_WEEK * 10).spikes());
    assert!(Rate::new(31, HOURS_PER_WEEK * 10).spikes());
    assert_eq!(Rate::new(0, 1).usual, 1, "a week's one failure rounds up");
}
