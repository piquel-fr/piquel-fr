//! Name validation, typed ceremony payloads and the account states a passkey
//! is accepted for.

use super::*;

/// Names count Unicode characters, preserve spacing and reject blank/control input.
#[test]
fn display_and_passkey_names_share_unicode_validation() {
    for valid in [" Alice ".to_owned(), "é".repeat(80)] {
        assert_eq!(
            DisplayName::parse(valid.clone())
                .expect("display name")
                .as_str(),
            valid
        );
        assert_eq!(
            PasskeyName::parse(valid.clone())
                .expect("passkey name")
                .as_str(),
            valid
        );
    }
    for invalid in [String::new(), " \t ".into(), "a\0b".into(), "é".repeat(81)] {
        assert!(matches!(
            DisplayName::parse(invalid.clone()),
            Err(PasskeyError::InvalidDisplayName)
        ));
        assert!(matches!(
            PasskeyName::parse(invalid),
            Err(PasskeyError::InvalidPasskeyName)
        ));
    }
}

/// Typed payloads retain the stored ceremony representation and reject wrong consumers.
#[test]
fn typed_ceremonies_preserve_persistence_and_check_the_expected_payload() {
    use ceremonies::CeremonyState;

    let user_id = UserId::new();
    let session_id = piquel_common::SessionId::new();
    let origin = Url::parse("https://auth.piquel.fr").expect("origin");
    let webauthn = WebauthnBuilder::new("auth.piquel.fr", &origin)
        .expect("builder")
        .build()
        .expect("WebAuthn");
    let (_, state) = webauthn
        .start_discoverable_authentication()
        .expect("challenge");
    let encoded_state = serde_json::to_value(&state).expect("state");
    let ceremony = Ceremony::Discover(DiscoverCeremony { state });
    assert_eq!(
        ceremony.kind(),
        piquel_repository::CeremonyKind::Authentication
    );
    let encoded = serde_json::to_value(ceremony).expect("ceremony");
    assert_eq!(encoded, json!({"Discover":{"state":encoded_state}}));
    let stored = || serde_json::from_value(encoded.clone()).expect("stored ceremony");
    assert!(AuthenticationCeremony::extract(stored()).is_some());
    assert!(RegistrationCeremony::extract(stored()).is_none());
    assert!(EnrollmentCeremony::extract(stored()).is_none());
    assert!(ConfirmationCeremony::extract(stored()).is_none());

    let (_, state) = webauthn
        .start_passkey_registration(user_id.as_uuid(), "alice", "Alice", None)
        .expect("registration");
    let enrollment = Ceremony::Enroll(EnrollmentCeremony {
        user_id,
        session_id,
        state,
    });
    assert_eq!(enrollment.kind(), EnrollmentCeremony::KIND);
    assert!(EnrollmentCeremony::extract(enrollment).is_some());
}

/// Sign-in and confirmation accept only an active account's passkey; the
/// owner's undo of a recovery accepts a disabled account's too, without a
/// credential to sign in with. An account being deleted has nothing to accept.
#[test]
fn only_an_undo_accepts_a_disabled_accounts_passkey() {
    let passkey = PasskeyId::new();
    let credential = Credential::Passkey(passkey);
    let signs_in = |status| <Credential as Acceptance>::accept(status, passkey, credential);
    assert_eq!(signs_in(AccountStatus::Active).ok(), Some(credential));
    for status in [AccountStatus::Disabled, AccountStatus::Deleting] {
        assert!(matches!(
            signs_in(status),
            Err(PasskeyError::AccountInactive)
        ));
    }
    let undoes = |status| <Accepted as Acceptance>::accept(status, passkey, credential);
    assert!(matches!(undoes(AccountStatus::Active), Ok(Accepted::Active(id)) if id == passkey));
    assert!(matches!(undoes(AccountStatus::Disabled), Ok(Accepted::Disabled(id)) if id == passkey));
    assert!(matches!(
        undoes(AccountStatus::Deleting),
        Err(PasskeyError::AccountInactive)
    ));
}
