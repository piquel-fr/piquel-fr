//! Focused tests for exported vocabulary expansion and identifier syntax.
use super::*;

str_enum! {
    /// Test vocabulary proving downstream macro expansion.
    enum Example {
        /// First value.
        First = "first",
        /// Second value.
        Second = "second",
    }
}

/// Closed vocabularies round-trip every spelling and reject unknown values.
#[test]
fn vocabulary_round_trips() {
    assert_eq!(Example::ALL.len(), 2);
    for value in Example::ALL {
        assert_eq!(value.as_str().parse::<Example>(), Ok(value));
        assert_eq!(value.to_string(), value.as_str());
        let json = serde_json::to_string(&value).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Example>(&json).expect("deserialize"),
            value
        );
    }
    assert_eq!(
        "unknown"
            .parse::<Example>()
            .expect_err("unknown")
            .vocabulary,
        "Example"
    );
    assert!(serde_json::from_str::<Example>("\"unknown\"").is_err());
}

open_str_enum! {
    /// Test vocabulary proving open-vocabulary expansion.
    enum OpenExample {
        /// Known value.
        Known = "known",
    }
}

/// Open vocabularies parse known spellings to variants and keep others verbatim.
#[test]
fn open_vocabulary_keeps_unknown_values() {
    assert_eq!(OpenExample::from("known"), OpenExample::Known);
    let other: OpenExample = serde_json::from_str("\"later\"").expect("deserialize");
    assert_eq!(other, OpenExample::Other("later".into()));
    assert_eq!(
        serde_json::to_string(&other).expect("serialize"),
        "\"later\""
    );
    assert_eq!(OpenExample::KNOWN.len(), 1);
}

/// IDs accept only canonical `UUIDv7`, preserving syntax diagnostics on malformed text.
#[test]
fn ids_are_canonical_uuid_v7() {
    let id = UserId::new();
    assert_eq!(id.to_string().parse::<UserId>(), Ok(id));
    assert!(
        "00000000-0000-4000-8000-000000000000"
            .parse::<UserId>()
            .is_err()
    );
    assert!(id.to_string().to_uppercase().parse::<UserId>().is_err());
    let error = "not-a-uuid".parse::<UserId>().expect_err("UUID syntax");
    assert!(std::error::Error::source(&error).is_some());
}

/// Trace IDs read and write exactly 32 lower-case hex digits, never all zero.
#[test]
fn trace_ids_are_lower_case_hex() {
    let text = "4bf92f3577b34da6a3ce929d0e0e4736";
    let id: TraceId = text.parse().expect("trace ID");
    assert_eq!(id.to_string(), text);
    assert_eq!(TraceId::from_bytes([0; 16]), None);
    for invalid in [
        "00000000000000000000000000000000",
        "4BF92F3577B34DA6A3CE929D0E0E4736",
        "4bf92f3577b34da6a3ce929d0e0e473",
        "4bf92f3577b34da6a3ce929d0e0e473g",
    ] {
        assert!(invalid.parse::<TraceId>().is_err(), "{invalid}");
    }
}

/// `DomainEvent::kind` is the serde tag each variant is stored under.
#[cfg(feature = "events")]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one literal per event kind, so it grows with `DomainEvent`"
)]
fn event_kinds_match_their_serde_tags() {
    use events::{DomainEvent, GrantRevocation, RevocationReason, SignInFailure};
    use serde_json::json;

    let session_id = SessionId::new();
    let passkey_id = PasskeyId::new();
    let client_id: ClientId = "client".parse().expect("client ID");
    let imported = serde_json::from_value(json!({
        "action": "passkey.login", "outcome": "success", "metadata": {}
    }))
    .expect("imported audit row");
    let events = [
        DomainEvent::AccountCreated {
            method: AuthenticationMethod::Passkey,
            invited: false,
        },
        DomainEvent::SignedIn {
            session_id,
            method: AuthenticationMethod::Federation,
        },
        DomainEvent::SignInFailed {
            method: AuthenticationMethod::Passkey,
            reason: SignInFailure::UnknownAccount,
        },
        DomainEvent::SessionRevoked {
            session_id,
            reason: RevocationReason::Logout,
        },
        DomainEvent::PasskeyConfirmed { session_id },
        DomainEvent::PasskeyAdded { passkey_id },
        DomainEvent::PasskeyRenamed { passkey_id },
        DomainEvent::PasskeyRemoved { passkey_id },
        DomainEvent::IdentityLinked {
            provider: Provider::GitHub,
            subject: Personal::Value("1".into()),
        },
        DomainEvent::IdentityUnlinked {
            provider: Provider::Google,
        },
        DomainEvent::ConsentGranted {
            client_id: client_id.clone(),
            scopes: vec![],
        },
        DomainEvent::GrantIssued {
            client_id: client_id.clone(),
            family_id: None,
            scopes: vec![],
        },
        DomainEvent::GrantRevoked {
            client_id: client_id.clone(),
            family_id: TokenId::new(),
            reason: GrantRevocation::RefreshReplay,
        },
        DomainEvent::CodeReplayed {
            client_id: client_id.clone(),
        },
        DomainEvent::InvitationCreated {
            expires_at: chrono::Utc::now(),
        },
        DomainEvent::InvitationRevoked {
            invitation_id: TokenId::new(),
        },
        DomainEvent::AccountDisabled {
            reason: Personal::Erased,
        },
        DomainEvent::AccountEnabled {},
        DomainEvent::AccountViewed {},
        DomainEvent::AdministratorGranted {},
        DomainEvent::AdministratorRevoked {},
        DomainEvent::HandleChanged {
            old: Personal::Value("a_b".into()),
            new: Personal::Value(Handle::parse("a-b").expect("handle")),
        },
        DomainEvent::HandleReleased {
            handle: Personal::Value(Handle::parse("a-b").expect("handle")),
        },
        DomainEvent::ClientRegistered {
            client_id: client_id.clone(),
            kind: clients::ClientKind::Public,
        },
        DomainEvent::ClientUpdated {
            client_id: client_id.clone(),
            changed: vec![clients::ClientField::DisplayName],
        },
        DomainEvent::ClientEnabled {
            client_id: client_id.clone(),
        },
        DomainEvent::ClientDisabled {
            client_id: client_id.clone(),
        },
        DomainEvent::ClientSuspended {
            client_id: client_id.clone(),
        },
        DomainEvent::ClientSuspensionLifted {
            client_id: client_id.clone(),
        },
        DomainEvent::ClientDeleted {
            client_id: client_id.clone(),
        },
        DomainEvent::ClientSecretRotated {
            client_id,
            previous_expire_at: chrono::Utc::now(),
        },
        DomainEvent::CompromiseReported {
            event_id: EventId::new(),
        },
        DomainEvent::Imported(imported),
    ];
    for event in events {
        let tagged = serde_json::to_value(&event).expect("serialize");
        assert_eq!(tagged["kind"], event.kind(), "{event:?}");
    }
}
