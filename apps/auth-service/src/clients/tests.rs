//! Client changes reach running replicas on their next request, and each records
//! its event as made by the operator.
use super::*;
use crate::tests::{Browser, Replicas, change, operator, register, registration, replace};
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use base64::Engine;
use piquel_common::{
    UserId,
    clients::{AllowedScopes, RedirectUris},
};
use piquel_crypto::Secret;
use tower::ServiceExt;

/// Sends `method` to `path` on `replica` from a browser page on `origin`, with an
/// optional form body and HTTP Basic credentials.
async fn send(
    replica: &Router,
    method: Method,
    path: &str,
    origin: &str,
    form: &str,
    basic: Option<(&ClientId, &str)>,
) -> Response {
    let mut request = Request::builder()
        .method(method.clone())
        .uri(path)
        .header(header::ORIGIN, origin)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if method == Method::OPTIONS {
        request = request.header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST");
    }
    if let Some((id, secret)) = basic {
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
        request = request.header(header::AUTHORIZATION, format!("Basic {credentials}"));
    }
    replica
        .clone()
        .oneshot(request.body(Body::from(form.to_owned())).expect("request"))
        .await
        .expect("response")
}

/// Whether a token-endpoint preflight from `origin` gets its CORS grant.
async fn cors(replica: &Router, origin: &str) -> bool {
    let response = send(replica, Method::OPTIONS, "/oauth/token", origin, "", None).await;
    response.status() == StatusCode::NO_CONTENT
        && response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN] == origin
}

/// Whether the token endpoint authenticates the public client `id`: an unusable
/// code then fails as a bad grant rather than a bad client.
async fn authenticates(replica: &Router, id: &ClientId, origin: &str) -> bool {
    let form = format!("grant_type=authorization_code&code=unusable&client_id={id}");
    let response = send(replica, Method::POST, "/oauth/token", origin, &form, None).await;
    response.status() != StatusCode::UNAUTHORIZED
}

/// Creating, updating, disabling and enabling a public client changes CORS and
/// client authentication on the next request to either replica, with no restart.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn changes_apply_to_the_next_request_on_every_replica() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let [first, second] = [(); 2].map(|()| format!("https://{}.example", UserId::new()));
    let mut client = registration(ClientKind::Public, &first);
    assert!(!cors(&replicas.a, &first).await, "not registered yet");

    let secret = register(&database, &client).await.expect("create");
    assert!(secret.is_none(), "public clients have no secret");
    assert!(cors(&replicas.b, &first).await);
    assert!(authenticates(&replicas.a, &client.id, &first).await);

    client.redirect_uris =
        RedirectUris::new([format!("{second}/callback").parse().expect("callback")])
            .expect("one callback");
    replace(&database, &client).await.expect("update");
    assert!(
        !cors(&replicas.a, &first).await,
        "the old origin is dropped"
    );
    assert!(cors(&replicas.b, &second).await);

    change(&database, async |registry| {
        registry.set_enabled(&client.id, false).await
    })
    .await
    .expect("disable");
    assert!(!cors(&replicas.a, &second).await);
    assert!(!authenticates(&replicas.b, &client.id, &second).await);
    change(&database, async |registry| {
        registry.set_enabled(&client.id, true).await
    })
    .await
    .expect("enable");
    assert!(authenticates(&replicas.a, &client.id, &second).await);

    let history = database
        .events()
        .history_for_client(&client.id, 10)
        .await
        .expect("history");
    assert!(
        history
            .iter()
            .all(|event| event.actor == operator().context().actor)
    );
    let client_id = client.id.clone();
    assert_eq!(
        history
            .into_iter()
            .map(|stored| stored.event.known().cloned().expect("a known event"))
            .collect::<Vec<_>>(),
        [
            DomainEvent::ClientEnabled {
                client_id: client_id.clone()
            },
            DomainEvent::ClientDisabled {
                client_id: client_id.clone()
            },
            DomainEvent::ClientUpdated {
                client_id: client_id.clone(),
                changed: vec![ClientField::RedirectUris],
            },
            DomainEvent::ClientRegistered {
                client_id,
                kind: ClientKind::Public
            },
        ]
    );
}

/// During a rotation's grace period both secrets authenticate; once it ends, only
/// the newest does. A public client cannot be given a secret.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn rotated_secrets_overlap_until_their_grace_period_ends() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let client = registration(ClientKind::Confidential, "https://api.example");
    // Revocation answers 200 for any token once the client authenticates.
    let revokes = async |secret: &ClientSecret| {
        send(
            &replicas.a,
            Method::POST,
            "/oauth/revoke",
            "https://api.example",
            "token=unknown",
            Some((&client.id, secret.expose())),
        )
        .await
        .status()
            == StatusCode::OK
    };
    let first = register(&database, &client)
        .await
        .expect("create")
        .expect("confidential clients get a secret");
    assert!(revokes(&first).await);

    let rotate = async |id: &ClientId, grace: &str| {
        let grace = grace.parse().expect("grace");
        change(&database, async |registry| {
            registry.rotate_secret(id, grace).await
        })
        .await
    };
    let second = rotate(&client.id, "1h").await.expect("rotate");
    assert!(revokes(&first).await, "still in its grace period");
    assert!(revokes(&second).await);

    let third = rotate(&client.id, "0").await.expect("rotate and revoke");
    assert!(!revokes(&first).await);
    assert!(!revokes(&second).await);
    assert!(revokes(&third).await);

    let public = registration(ClientKind::Public, "https://web.example");
    register(&database, &public).await.expect("public client");
    assert!(matches!(
        rotate(&public.id, "0").await,
        Err(ClientRegistryError::Public(_))
    ));
    assert!(matches!(
        register(&database, &public).await,
        Err(ClientRegistryError::Exists { .. })
    ));
    assert!(matches!(
        change(&database, async |registry| {
            registry
                .update(&public.id, |_| {
                    Ok(ClientRegistration {
                        kind: ClientKind::Confidential,
                        ..public.clone()
                    })
                })
                .await
        })
        .await,
        Err(ClientRegistryError::Immutable(_))
    ));
    let unknown = "unknown-client".parse().expect("ID");
    assert!(matches!(
        change(&database, async |registry| {
            registry.set_enabled(&unknown, false).await
        })
        .await,
        Err(ClientRegistryError::Unknown(_))
    ));
}

/// Applying a deployment's client registers it, then writes only what differs, so
/// each deploy can apply it again. A new secret overlaps with the previous ones for
/// the grace period, a previous secret applied again lasts, and a zero grace
/// revokes the others.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn apply_changes_only_what_differs() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let origin = format!("https://{}.example", UserId::new());
    let mut client = registration(ClientKind::Confidential, &origin);
    let [first, second] = [(); 2].map(|()| Secret::generate().expect("secret").encoded());
    let apply = async |client: &ClientRegistration, secret: Option<&str>, grace: &str| {
        let secret = secret.map(|secret| ClientSecret::parse(secret).expect("secret"));
        let grace = grace.parse().expect("grace");
        change(&database, async |registry| {
            registry.apply(client, secret, grace).await
        })
        .await
    };
    let revokes = async |secret: &str| {
        send(
            &replicas.a,
            Method::POST,
            "/oauth/revoke",
            &origin,
            "token=unknown",
            Some((&client.id, secret)),
        )
        .await
        .status()
            == StatusCode::OK
    };

    assert_eq!(
        apply(&client, Some(&first), "1h").await.expect("register"),
        Applied::Registered
    );
    assert!(revokes(&first).await);
    let mut reordered = client.clone();
    reordered.allowed_scopes =
        AllowedScopes::new(client.allowed_scopes.iter().rev().cloned()).expect("scopes");
    assert_eq!(
        apply(&reordered, Some(&first), "1h").await.expect("again"),
        Applied::Unchanged
    );

    client.display_name = "Renamed app".parse().expect("display name");
    assert_eq!(
        apply(&client, Some(&first), "1h").await.expect("rename"),
        Applied::Updated
    );
    assert_eq!(
        apply(&client, Some(&second), "1h")
            .await
            .expect("new secret"),
        Applied::Updated
    );
    assert!(
        revokes(&first).await,
        "the previous secret is in its grace period"
    );
    assert!(revokes(&second).await);

    assert_eq!(
        apply(&client, Some(&first), "1h").await.expect("back"),
        Applied::Updated,
        "a secret in its grace period is made lasting again"
    );
    assert_eq!(
        apply(&client, Some(&first), "0").await.expect("revoke"),
        Applied::Updated
    );
    assert!(revokes(&first).await);
    assert!(!revokes(&second).await);
    assert_eq!(
        apply(&client, Some(&first), "0").await.expect("again"),
        Applied::Unchanged
    );

    let history = database
        .events()
        .history_for_client(&client.id, 10)
        .await
        .expect("history");
    assert!(matches!(
        history
            .iter()
            .map(|stored| stored.event.known().expect("a known event"))
            .collect::<Vec<_>>()[..],
        [
            DomainEvent::ClientSecretRotated { .. },
            DomainEvent::ClientSecretRotated { .. },
            DomainEvent::ClientSecretRotated { .. },
            DomainEvent::ClientUpdated { .. },
            DomainEvent::ClientRegistered { .. },
        ]
    ));
}

/// Applying refuses a confidential client without its secret, a public one with a
/// secret, and a change of kind.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn apply_refuses_mismatched_secrets_and_kinds() {
    let database = Replicas::database().await;
    let client = registration(ClientKind::Confidential, "https://api.example");
    let first = Secret::generate().expect("secret").encoded();
    let apply = async |client: &ClientRegistration, secret: Option<&str>| {
        let secret = secret.map(|secret| ClientSecret::parse(secret).expect("secret"));
        let grace = "1h".parse().expect("grace");
        change(&database, async |registry| {
            registry.apply(client, secret, grace).await
        })
        .await
    };
    apply(&client, Some(&first)).await.expect("register");
    assert!(matches!(
        apply(&client, None).await,
        Err(ClientRegistryError::MissingSecret(_))
    ));
    let public = ClientRegistration {
        kind: ClientKind::Public,
        ..client.clone()
    };
    assert!(matches!(
        apply(&public, Some(&first)).await,
        Err(ClientRegistryError::Public(_))
    ));
    assert!(matches!(
        apply(&public, None).await,
        Err(ClientRegistryError::Immutable(_))
    ));
}

/// Concurrent registrations by one account count one another: exactly
/// [`MAX_OWNED_CLIENTS`] succeed. Deleting one frees a place, until the account
/// registered [`MAX_DAILY_REGISTRATIONS`] clients that day.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_quota_holds_under_concurrent_registrations() {
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await.user_id;
    let attempts = MAX_OWNED_CLIENTS + 4;
    let mut registrations = tokio::task::JoinSet::new();
    for _ in 0..attempts {
        let database = database.clone();
        registrations.spawn(async move {
            let client = registration(ClientKind::Public, "https://quota.example");
            change(&database, async |registry| {
                registry
                    .create(ClientOwner::Account(owner), &client, None)
                    .await
            })
            .await
            .map(|_| client.id)
        });
    }
    let (mut registered, mut refused) = (Vec::new(), 0);
    while let Some(result) = registrations.join_next().await {
        match result.expect("task") {
            Ok(id) => registered.push(id),
            Err(ClientRegistryError::QuotaExceeded) => refused += 1,
            Err(error) => panic!("unexpected failure: {error}"),
        }
    }
    assert_eq!(registered.len(), MAX_OWNED_CLIENTS as usize);
    assert_eq!(refused, attempts - MAX_OWNED_CLIENTS);
    assert_eq!(
        database
            .oidc()
            .count_owned_clients(owner, chrono::Duration::days(1))
            .await
            .expect("count")
            .live,
        u64::from(MAX_OWNED_CLIENTS)
    );

    // Deleting frees a place, but deleted clients still count against the
    // daily limit, so an account cannot pile up tombstones.
    for registration_number in MAX_OWNED_CLIENTS..=MAX_DAILY_REGISTRATIONS {
        let freed = registered.pop().expect("a client to delete");
        change(&database, async |registry| registry.delete(&freed).await)
            .await
            .expect("delete");
        let client = registration(ClientKind::Public, "https://quota.example");
        let created = change(&database, async |registry| {
            registry
                .create(ClientOwner::Account(owner), &client, None)
                .await
        })
        .await;
        if registration_number < MAX_DAILY_REGISTRATIONS {
            created.expect("a deletion frees a place");
            registered.push(client.id);
        } else {
            assert!(matches!(
                created,
                Err(ClientRegistryError::DailyLimitExceeded)
            ));
        }
    }
}
