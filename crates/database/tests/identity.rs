#![allow(missing_docs)]

use chrono::{Duration as ChronoDuration, Utc};
use piquel_auth_protocol::{AccountStatus, AuthenticationMethod, SessionId, TokenId, UserId};
use piquel_repository::{
    AppendInternalEvent, BootstrapOidcClient, Database, DatabaseConfig, DatabaseError,
    InsertAuthorizationRequest, InsertCeremony, InsertExternalIdentity,
    InsertFederationTransaction, InsertPasskey, InsertRefreshFamily, InsertRefreshToken,
    InsertSession, InsertUser, InsertVerifiedEmail, RefreshRotationError, UpdateUserProfile,
};
use std::{env, time::Duration};

async fn database() -> Database {
    let url = env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
    let config = DatabaseConfig::new_development(&url, 10, Duration::from_secs(5))
        .expect("test database configuration");
    let database = Database::connect(config)
        .await
        .expect("connect test database");
    database.run_migrations().await.expect("run migrations");
    database
}

async fn insert_user(database: &Database, prefix: &str) -> UserId {
    let id = UserId::new();
    let username = format!("{prefix}_{}", &id.to_string()[..8]);
    database
        .users()
        .insert(&InsertUser {
            id,
            username: username.clone(),
            display_name: username,
        })
        .await
        .expect("insert user");
    id
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn identity_transactions_and_concurrency_hold() {
    let database = database().await;

    let rolled_back = UserId::new();
    let mut transaction = database.begin().await.expect("begin");
    transaction
        .users()
        .insert(&InsertUser {
            id: rolled_back,
            username: format!("rollback_{}", &rolled_back.to_string()[..8]),
            display_name: "Rolled Back".into(),
        })
        .await
        .expect("insert");
    transaction
        .internal_events()
        .append(&AppendInternalEvent {
            id: TokenId::new(),
            aggregate_type: "user".into(),
            aggregate_id: rolled_back,
            event_type: "account.created".into(),
            schema_version: 1,
            payload: serde_json::json!({}),
        })
        .await
        .expect("event");
    transaction.rollback().await.expect("rollback");
    assert!(
        database
            .users()
            .find_by_id(rolled_back)
            .await
            .expect("lookup")
            .is_none()
    );

    let invalid_primary = UserId::new();
    let mut transaction = database.begin().await.expect("begin invalid account");
    transaction
        .users()
        .insert(&InsertUser {
            id: invalid_primary,
            username: format!("invalid_{}", &invalid_primary.to_string()[..8]),
            display_name: "Invalid Primary".into(),
        })
        .await
        .expect("insert account");
    transaction
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: invalid_primary,
            normalized_email: format!("invalid-{invalid_primary}@example.com"),
            is_primary: false,
            verified_at: Utc::now(),
        })
        .await
        .expect("insert until deferred check");
    assert!(transaction.commit().await.is_err());
    assert!(
        database
            .users()
            .find_by_id(invalid_primary)
            .await
            .expect("lookup invalid account")
            .is_none()
    );

    let first = insert_user(&database, "first").await;
    let second = insert_user(&database, "second").await;

    let ceremony_id = TokenId::new();
    database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: ceremony_id,
            user_id: Some(first),
            session_id: None,
            kind: "authentication".into(),
            challenge_digest: vec![1; 32],
            state: serde_json::json!({"test":true}),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        })
        .await
        .expect("ceremony");
    let one = database.clone();
    let two = database.clone();
    let (left, right) = tokio::join!(
        async move {
            one.passkeys()
                .consume_ceremony(ceremony_id, "authentication")
                .await
        },
        async move {
            two.passkeys()
                .consume_ceremony(ceremony_id, "authentication")
                .await
        }
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);

    let enrollment_id = TokenId::new();
    database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: enrollment_id,
            user_id: Some(first),
            session_id: None,
            kind: "enrollment".into(),
            challenge_digest: vec![2; 32],
            state: serde_json::json!({"enrollment":true}),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        })
        .await
        .expect("enrollment ceremony");
    database
        .passkeys()
        .consume_ceremony(enrollment_id, "enrollment")
        .await
        .expect("consume enrollment ceremony");

    let refresh_session = SessionId::new();
    database
        .sessions()
        .insert(&InsertSession {
            id: refresh_session,
            user_id: first,
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: Utc::now(),
            expires_at: Utc::now() + ChronoDuration::hours(1),
            user_agent_family: None,
        })
        .await
        .expect("refresh session");
    let mut setup = database.begin().await.expect("OIDC setup");
    setup
        .oidc()
        .bootstrap_client(&BootstrapOidcClient {
            id: "test-client".into(),
            display_name: "Test".into(),
            redirect_uris: vec!["https://client.example/callback".into()],
            post_logout_uris: vec!["https://client.example/logout".into()],
            allowed_scopes: vec!["openid".into(), "offline_access".into()],
            allowed_audiences: vec!["test-api".into()],
            allow_refresh: true,
        })
        .await
        .expect("client");
    let family_id = TokenId::new();
    let refresh_id = TokenId::new();
    let digest = vec![9_u8; 32];
    setup
        .tokens()
        .insert_family(
            &InsertRefreshFamily {
                id: family_id,
                user_id: first,
                client_id: "test-client".into(),
                session_id: refresh_session,
                audience: "test-api".into(),
                scopes: vec!["openid".into()],
            },
            &InsertRefreshToken {
                id: refresh_id,
                family_id,
                secret_digest: digest.clone(),
                expires_at: Utc::now() + ChronoDuration::days(1),
            },
        )
        .await
        .expect("refresh family");
    setup.commit().await.expect("OIDC setup commit");
    let authorization_id = TokenId::new();
    let authorization_digest = vec![31_u8; 32];
    database
        .oidc()
        .insert_authorization_request(&InsertAuthorizationRequest {
            id: authorization_id,
            secret_digest: authorization_digest.clone(),
            client_id: "test-client".into(),
            redirect_uri: "https://client.example/callback".into(),
            client_state: "client-state".into(),
            nonce: Some("nonce".into()),
            pkce_challenge: "challenge".into(),
            scopes: vec!["openid".into()],
            audience: "test-api".into(),
            force_login: false,
            max_age: None,
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        })
        .await
        .expect("authorization request");
    let one = database.clone();
    let two = database.clone();
    let (left, right) = tokio::join!(
        async move {
            one.oidc()
                .consume_authorization_request(authorization_id, &authorization_digest)
                .await
        },
        async move {
            two.oidc()
                .consume_authorization_request(authorization_id, &[31_u8; 32])
                .await
        }
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let rotate = |database: Database, replacement: TokenId, digest: Vec<u8>| async move {
        let mut tx = database.begin().await.expect("rotation transaction");
        match tx.tokens().consume_for_rotation(refresh_id, &digest).await {
            Ok(token) => {
                tx.tokens()
                    .insert_token(&InsertRefreshToken {
                        id: replacement,
                        family_id: token.family_id,
                        secret_digest: vec![replacement.as_uuid().as_bytes()[0]; 32],
                        expires_at: Utc::now() + ChronoDuration::days(1),
                    })
                    .await
                    .expect("replacement");
                tx.commit().await.expect("rotation commit");
                Ok(replacement)
            }
            Err(error @ RefreshRotationError::Replay { .. }) => {
                tx.commit().await.expect("persist replay revocation");
                Err(error)
            }
            Err(error) => Err(error),
        }
    };
    let replacement_one = TokenId::new();
    let replacement_two = TokenId::new();
    let (left, right) = tokio::join!(
        rotate(database.clone(), replacement_one, digest.clone()),
        rotate(database.clone(), replacement_two, digest),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(RefreshRotationError::Replay { .. }))
            || matches!(right, Err(RefreshRotationError::Replay { .. }))
    );

    let last_factor_user = insert_user(&database, "factors").await;
    let factor_one = TokenId::new();
    let factor_two = TokenId::new();
    for (id, credential) in [(factor_one, 41_u8), (factor_two, 42_u8)] {
        database
            .passkeys()
            .insert(&InsertPasskey {
                id,
                credential_id: vec![credential; 32],
                user_id: last_factor_user,
                credential: serde_json::json!({"fixture":credential}),
                friendly_name: "Factor".into(),
            })
            .await
            .expect("factor");
    }
    let remove = |database: Database, id: TokenId| async move {
        let mut tx = database.begin().await.expect("factor transaction");
        let removed = tx
            .passkeys()
            .revoke_if_not_last(id, last_factor_user)
            .await
            .expect("factor removal");
        tx.commit().await.expect("factor commit");
        removed
    };
    let (left, right) = tokio::join!(
        remove(database.clone(), factor_one),
        remove(database.clone(), factor_two)
    );
    assert_eq!(usize::from(left) + usize::from(right), 1);
    assert_eq!(
        database
            .passkeys()
            .list_active(last_factor_user, 20)
            .await
            .expect("remaining factors")
            .len(),
        1
    );
    let federation_state = vec![11_u8; 32];
    let browser = vec![12_u8; 32];
    database
        .federation()
        .insert_transaction(&InsertFederationTransaction {
            id: TokenId::new(),
            provider: "github".into(),
            state_digest: federation_state.clone(),
            browser_digest: browser.clone(),
            nonce: "nonce".into(),
            pkce_verifier: "v".repeat(43),
            return_to: "/".into(),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        })
        .await
        .expect("federation transaction");
    let one = database.clone();
    let two = database.clone();
    let (left, right) = tokio::join!(
        async move {
            one.federation()
                .consume_transaction("github", &federation_state, &browser)
                .await
        },
        async move {
            two.federation()
                .consume_transaction("github", &[11_u8; 32], &[12_u8; 32])
                .await
        },
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);

    let disable_race_user = insert_user(&database, "disable_race").await;
    let disable_race_session = SessionId::new();
    let insert_database = database.clone();
    let disable_database = database.clone();
    let (inserted, disabled) = tokio::join!(
        async move {
            insert_database
                .sessions()
                .insert(&InsertSession {
                    id: disable_race_session,
                    user_id: disable_race_user,
                    authentication_methods: vec![AuthenticationMethod::Passkey],
                    authenticated_at: Utc::now(),
                    expires_at: Utc::now() + ChronoDuration::hours(1),
                    user_agent_family: None,
                })
                .await
        },
        async move {
            disable_database
                .users()
                .set_status(disable_race_user, AccountStatus::Disabled)
                .await
        }
    );
    assert!(disabled.expect("disable race status"));
    assert!(inserted.is_ok() || matches!(inserted, Err(DatabaseError::NotFound)));
    assert!(
        database
            .sessions()
            .find_active_by_id(disable_race_session)
            .await
            .expect("active session lookup")
            .is_none()
    );

    let policy_user = insert_user(&database, "policy").await;
    let policy_session = SessionId::new();
    database
        .sessions()
        .insert(&InsertSession {
            id: policy_session,
            user_id: policy_user,
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: Utc::now(),
            expires_at: Utc::now() + ChronoDuration::hours(1),
            user_agent_family: None,
        })
        .await
        .expect("policy session");
    database
        .oidc()
        .bootstrap_client(&BootstrapOidcClient {
            id: "policy-client".into(),
            display_name: "Policy client".into(),
            redirect_uris: vec!["https://policy.example/callback".into()],
            post_logout_uris: vec!["https://policy.example/logout".into()],
            allowed_scopes: vec!["openid".into()],
            allowed_audiences: vec!["policy-api".into()],
            allow_refresh: true,
        })
        .await
        .expect("policy client");
    let policy_family = TokenId::new();
    let policy_token = TokenId::new();
    let policy_digest = vec![51_u8; 32];
    database
        .tokens()
        .insert_family(
            &InsertRefreshFamily {
                id: policy_family,
                user_id: policy_user,
                client_id: "policy-client".into(),
                session_id: policy_session,
                audience: "policy-api".into(),
                scopes: vec!["openid".into()],
            },
            &InsertRefreshToken {
                id: policy_token,
                family_id: policy_family,
                secret_digest: policy_digest.clone(),
                expires_at: Utc::now() + ChronoDuration::days(1),
            },
        )
        .await
        .expect("policy family");
    database
        .oidc()
        .bootstrap_client(&BootstrapOidcClient {
            id: "policy-client".into(),
            display_name: "Policy client".into(),
            redirect_uris: vec!["https://policy.example/callback".into()],
            post_logout_uris: vec!["https://policy.example/logout".into()],
            allowed_scopes: vec!["openid".into()],
            allowed_audiences: vec!["policy-api".into()],
            allow_refresh: false,
        })
        .await
        .expect("reduce policy");
    let mut tx = database.begin().await.expect("policy transaction");
    assert!(matches!(
        tx.tokens()
            .consume_for_rotation(policy_token, &policy_digest)
            .await,
        Err(RefreshRotationError::Policy { user_id }) if user_id == policy_user
    ));
    tx.commit().await.expect("persist policy revocation");
    assert!(matches!(
        database
            .tokens()
            .consume_for_rotation(policy_token, &policy_digest)
            .await,
        Err(RefreshRotationError::Invalid)
    ));

    let issuer = "https://github.com";
    let subject = format!("subject-{first}");
    database
        .federation()
        .insert_identity(&InsertExternalIdentity {
            id: TokenId::new(),
            user_id: first,
            provider: "github".into(),
            issuer: issuer.into(),
            subject: subject.clone(),
            linked_email: "first@example.com".into(),
        })
        .await
        .expect("first identity");
    assert!(matches!(
        database
            .federation()
            .insert_identity(&InsertExternalIdentity {
                id: TokenId::new(),
                user_id: second,
                provider: "github".into(),
                issuer: issuer.into(),
                subject,
                linked_email: "second@example.com".into(),
            })
            .await,
        Err(DatabaseError::Conflict)
    ));

    let credential_id = vec![7_u8; 32];
    database
        .passkeys()
        .insert(&InsertPasskey {
            id: TokenId::new(),
            credential_id: credential_id.clone(),
            user_id: first,
            credential: serde_json::json!({"fixture":true}),
            friendly_name: "First".into(),
        })
        .await
        .expect("passkey");
    assert!(matches!(
        database
            .passkeys()
            .insert(&InsertPasskey {
                id: TokenId::new(),
                credential_id,
                user_id: second,
                credential: serde_json::json!({"fixture":true}),
                friendly_name: "Duplicate".into()
            })
            .await,
        Err(DatabaseError::Conflict)
    ));

    let normalized = format!("race-{}@example.com", UserId::new());
    let one = database.clone();
    let two = database.clone();
    let first_claim = InsertVerifiedEmail {
        id: TokenId::new(),
        user_id: first,
        normalized_email: normalized.clone(),
        is_primary: true,
        verified_at: Utc::now(),
    };
    let second_claim = InsertVerifiedEmail {
        id: TokenId::new(),
        user_id: second,
        normalized_email: normalized,
        is_primary: true,
        verified_at: Utc::now(),
    };
    let (left, right) = tokio::join!(
        async move {
            let mut tx = one.begin().await?;
            tx.emails().insert_verified(&first_claim).await?;
            tx.commit().await
        },
        async move {
            let mut tx = two.begin().await?;
            tx.emails().insert_verified(&second_claim).await?;
            tx.commit().await
        }
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);

    let profile = database
        .users()
        .find_by_id(first)
        .await
        .expect("lookup")
        .expect("user");
    database
        .users()
        .update_profile(&UpdateUserProfile {
            id: first,
            expected_version: profile.profile_version,
            username: profile.username.clone(),
            display_name: "Updated".into(),
        })
        .await
        .expect("first update");
    assert!(matches!(
        database
            .users()
            .update_profile(&UpdateUserProfile {
                id: first,
                expected_version: profile.profile_version,
                username: profile.username,
                display_name: "Stale".into()
            })
            .await,
        Err(DatabaseError::Conflict)
    ));

    let session_id = SessionId::new();
    database
        .sessions()
        .insert(&InsertSession {
            id: session_id,
            user_id: first,
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: Utc::now(),
            expires_at: Utc::now() + ChronoDuration::hours(1),
            user_agent_family: None,
        })
        .await
        .expect("session");
    assert!(
        database
            .sessions()
            .revoke(session_id)
            .await
            .expect("revoke")
    );
    assert!(
        !database
            .sessions()
            .revoke(session_id)
            .await
            .expect("idempotent revoke")
    );

    let event = |kind: &str| AppendInternalEvent {
        id: TokenId::new(),
        aggregate_type: "user".into(),
        aggregate_id: first,
        event_type: kind.into(),
        schema_version: 1,
        payload: serde_json::json!({}),
    };
    let sequence_one = database
        .internal_events()
        .append(&event("profile.updated"))
        .await
        .expect("event one");
    let sequence_two = database
        .internal_events()
        .append(&event("profile.updated"))
        .await
        .expect("event two");
    assert_eq!((sequence_one, sequence_two), (1, 2));

    let disabled_one = insert_user(&database, "disabled_a").await;
    let disabled_two = insert_user(&database, "disabled_b").await;
    database
        .users()
        .set_status(disabled_one, AccountStatus::Disabled)
        .await
        .expect("disable");
    database
        .users()
        .set_status(disabled_two, AccountStatus::Disabled)
        .await
        .expect("disable");
    let shared = format!("disabled-{}@example.com", UserId::new());
    database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: disabled_one,
            normalized_email: shared.clone(),
            is_primary: true,
            verified_at: Utc::now(),
        })
        .await
        .expect("email one");
    database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: disabled_two,
            normalized_email: shared,
            is_primary: true,
            verified_at: Utc::now(),
        })
        .await
        .expect("email two");
    let one = database.clone();
    let two = database.clone();
    let (left, right) = tokio::join!(
        async move {
            one.users()
                .set_status(disabled_one, AccountStatus::Active)
                .await
        },
        async move {
            two.users()
                .set_status(disabled_two, AccountStatus::Active)
                .await
        }
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
}
