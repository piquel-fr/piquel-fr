//! Client changes reach running replicas on their next request, and each records
//! its event as made by whoever made it. Owners find and change only their own
//! clients, confirming what needs it, and a deletion leaves a tombstone without
//! deadlocking the token grants it revokes.
use super::*;
use crate::{
    account::{AccountError, AccountService, Owner},
    security::{Session, SessionError},
    tests::{
        Browser, Replicas, change, operator, refresh_grant, register, registration, replace,
        sign_out, until_blocked,
    },
};
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use base64::Engine;
use piquel_common::{
    AuthenticationMethod, TokenId, UserId,
    clients::{AllowedScopes, RedirectUris},
    events::Actor,
};
use piquel_crypto::Secret;
use piquel_repository::{Database, RefreshRotationError};
use tokio::task::JoinHandle;
use tower::ServiceExt;

/// An account, and the owner's operations on its clients, over the test database.
struct Account {
    /// The scenario database.
    database: Database,
    /// The owner's operations.
    service: AccountService,
    /// A browser signed in to the account with a passkey, so confirmed.
    browser: Browser,
}

impl Account {
    /// Creates an account over a migrated test database.
    async fn new() -> Self {
        let database = Replicas::database().await;
        Self {
            service: AccountService::new(database.clone()),
            browser: Browser::new_account(&database).await,
            database,
        }
    }

    /// The owner, as the browser signed in with a passkey shows them.
    async fn owner(&self) -> Owner {
        self.browser.owner(&self.database).await
    }

    /// Signs another browser in to the account socially, which never confirms
    /// with a passkey.
    async fn social(&self) -> Browser {
        let federation = AuthenticationMethod::Federation;
        Browser::sign_in_with(&self.database, self.browser.user_id, federation).await
    }

    /// Registers a client of `kind` calling back to `https://notes.example` as the
    /// confirmed owner, and returns its ID.
    async fn create(&self, kind: ClientKind) -> ClientId {
        let origin = "https://notes.example";
        self.browser
            .register_app(&self.database, kind, origin)
            .await
    }

    /// The owner's client `id`, as `owner` finds it.
    async fn find(&self, owner: Owner, id: &ClientId) -> OwnedClient {
        let found = self.service.owned_client(owner, id.as_str()).await;
        found.expect("the owner's client")
    }

    /// Makes `change` to client `id` as the owner, from a social session that a
    /// passkey confirms while the change waits for the account lock, and returns
    /// its result.
    async fn confirmed_while_waiting(
        &self,
        id: &ClientId,
        change: impl AsyncFnOnce(&OwnedClient) -> Result<(), AccountError>,
    ) -> Result<(), AccountError> {
        let stale = self.social().await;
        let client = self.find(stale.owner(&self.database).await, id).await;
        let mut holder = self.database.begin().await.expect("transaction");
        holder
            .users()
            .find_active_by_id_for_update(stale.user_id)
            .await
            .expect("lock")
            .expect("account");
        let (result, ()) = tokio::join!(change(&client), async {
            until_blocked(&mut holder, 1).await;
            let session = holder.sessions().find_by_id(stale.session_id).await;
            let session = session.expect("lookup").expect("session");
            let passkey = AuthenticationMethod::Passkey.into();
            Session::reauthenticate(&mut holder, &session, passkey)
                .await
                .expect("confirm");
            holder.commit().await.expect("commit");
        });
        result
    }
}

/// A public client and an account holding refresh grants to it, which the
/// deletion scenarios race a deletion against.
struct Granting {
    /// The scenario database.
    database: Database,
    /// The client, which an operator manages.
    client: ClientId,
    /// The account, signed in.
    user: Browser,
}

impl Granting {
    /// Registers the client over a migrated test database, and signs the account
    /// in.
    async fn new() -> Self {
        let database = Replicas::database().await;
        let client = registration(ClientKind::Public, "https://notes.example");
        register(&database, &client).await.expect("client");
        Self {
            user: Browser::new_account(&database).await,
            client: client.id,
            database,
        }
    }

    /// Issues the refresh grant `family` to the client from the account's session,
    /// and returns its first refresh token's ID and digest.
    async fn grant(&self, family: TokenId) -> (TokenId, Vec<u8>) {
        let user = &self.user;
        refresh_grant(
            &self.database,
            user.user_id,
            user.session_id,
            &self.client,
            family,
        )
        .await
    }

    /// Deletes the client as an operator, in a task of its own.
    fn delete(&self) -> JoinHandle<Result<(), ClientRegistryError>> {
        let (database, id) = (self.database.clone(), self.client.clone());
        tokio::spawn(
            async move { change(&database, async |registry| registry.delete(&id).await).await },
        )
    }
}

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

/// An account lists and finds only its own live clients: another account's, an
/// operator's, an unknown ID and a malformed one are not found. Every operation
/// on one client takes what [`AccountService::owned_client`] found, so none
/// reaches them either.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owners_find_only_their_own_clients() {
    let account = Account::new().await;
    let (alice, service) = (account.owner().await, &account.service);
    let bob = Browser::new_account(&account.database).await;
    let bob = bob.owner(&account.database).await;
    let operated = registration(ClientKind::Public, "https://operated.example");
    register(&account.database, &operated)
        .await
        .expect("operator client");

    let id = account.create(ClientKind::Confidential).await;
    assert!(id.as_str().starts_with("c_"), "{id}");
    let listed = service.clients(&alice).await.expect("list");
    assert_eq!(
        listed.iter().map(|client| &client.id).collect::<Vec<_>>(),
        [&id]
    );
    let app = account.find(alice.clone(), &id).await;
    let secrets = service.client_secrets(&app).await.expect("secrets");
    assert_eq!(secrets.len(), 1);

    assert_eq!(service.clients(&bob).await.expect("list"), []);
    for (owner, id) in [
        (&bob, id.as_str()),
        (&alice, operated.id.as_str()),
        (&alice, "c_unknown"),
        (&alice, "%FF"),
    ] {
        let found = service.owned_client(owner.clone(), id).await;
        assert!(
            matches!(found, Err(AccountError::Client(OwnedClientError::NotFound))),
            "{id}"
        );
    }
}

/// Every change to a client needs a recent passkey confirmation: changing any
/// setting, pausing or resuming it. A refused change leaves the client as it was.
/// A confirmed owner rotates its secret and changes its settings.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_change_needs_a_confirmation() {
    let account = Account::new().await;
    let service = &account.service;
    let id = account.create(ClientKind::Confidential).await;
    let social = account.social().await.owner(&account.database).await;
    let client = account.find(social, &id).await;
    let logout = ClientPatch {
        post_logout_uris: Some(vec!["https://attacker.example/".into()]),
        ..ClientPatch::default()
    };
    let rename = || ClientPatch {
        display_name: Some("Renamed".into()),
        ..ClientPatch::default()
    };
    for refused in [
        service.update_client(&client, logout).await.map(drop),
        service.update_client(&client, rename()).await.map(drop),
        service.set_client_enabled(&client, false).await,
        service.set_client_enabled(&client, true).await,
    ] {
        assert!(
            matches!(
                refused,
                Err(AccountError::Owner(SessionError::StepUpRequired { .. }))
            ),
            "{refused:?}"
        );
    }
    let kept = account.database.oidc().find_client(id.as_str()).await;
    let kept = kept.expect("lookup").expect("client");
    assert_eq!(
        kept.display_name, "Notes",
        "the refused changes were rolled back"
    );
    assert_eq!(kept.post_logout_uris, Vec::<String>::new());
    assert!(kept.enabled);

    let client = account.find(account.owner().await, &id).await;
    let grace = "0".parse().expect("grace period");
    let secret = service.rotate_client_secret(&client, grace).await;
    assert!(secret.expect("rotate").expose().starts_with("pqcs_"));
    let patch = ClientPatch {
        redirect_uris: Some(vec!["https://notes.example/auth".into()]),
        ..rename()
    };
    let changed = service.update_client(&client, patch).await.expect("change");
    assert_eq!(changed.display_name, "Renamed");
    assert_eq!(changed.redirect_uris, ["https://notes.example/auth"]);
    service
        .set_client_enabled(&client, false)
        .await
        .expect("disable");
}

/// An owner found from a cookie their session had before a passkey confirmation
/// never gains that confirmation, even when it commits while the change waits
/// for the account lock: the confirmation replaced the cookie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn confirmations_never_reach_owners_found_before_them() {
    let account = Account::new().await;
    let service = &account.service;
    let id = account.create(ClientKind::Confidential).await;
    let redirect = ClientPatch {
        redirect_uris: Some(vec!["https://attacker.example/callback".into()]),
        ..ClientPatch::default()
    };
    for result in [
        account
            .confirmed_while_waiting(&id, async |client| {
                service.update_client(client, redirect).await.map(drop)
            })
            .await,
        account
            .confirmed_while_waiting(&id, async |client| {
                let grace = GracePeriod::default();
                service.rotate_client_secret(client, grace).await.map(drop)
            })
            .await,
        account
            .confirmed_while_waiting(&id, async |client| {
                service.set_client_enabled(client, false).await
            })
            .await,
        account
            .confirmed_while_waiting(&id, async |client| service.delete_client(client).await)
            .await,
    ] {
        assert!(
            matches!(
                result,
                Err(AccountError::Owner(SessionError::StepUpRequired { .. }))
            ),
            "{result:?}"
        );
    }
    let client = account.database.oidc().find_client(id.as_str()).await;
    let client = client.expect("lookup").expect("client");
    assert_eq!(client.redirect_uris, ["https://notes.example/callback"]);
    assert!(client.enabled && client.deleted_at.is_none());
    let secrets = account.database.oidc().client_secrets(&id).await;
    assert_eq!(secrets.expect("secrets").len(), 1, "no secret was added");
}

/// An invalid setting names its field apart from what is wrong with it, so a
/// form can show the message beside it: owners grant only the standard scopes
/// and send browsers only to URIs auth accepts. Settings are checked before
/// anything else, so an unconfirmed owner's invalid registration is refused for
/// its settings rather than for the confirmation.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn invalid_settings_name_their_field_first() {
    let account = Account::new().await;
    let id = account.create(ClientKind::Public).await;
    let client = account.find(account.owner().await, &id).await;
    let social = account.social().await.owner(&account.database).await;
    let blank = NewClient {
        kind: ClientKind::Public,
        settings: ClientSettings {
            display_name: " ".into(),
            ..ClientSettings::test("https://notes.example")
        },
    };
    let invalid = |result: Result<(), AccountError>, field: ClientField| match result {
        Err(AccountError::Client(OwnedClientError::InvalidSetting(error))) => {
            assert_eq!(error.field(), &field);
            assert_eq!(error.to_string(), format!("{field}: {}", error.reason()));
        }
        result => panic!("{field}: {result:?}"),
    };
    let registered = account.service.create_client(&social, blank).await;
    invalid(registered.map(drop), ClientField::DisplayName);
    for (patch, field) in [
        (
            ClientPatch {
                allowed_scopes: Some(vec!["openid".into(), "notes:read".into()]),
                ..ClientPatch::default()
            },
            ClientField::AllowedScopes,
        ),
        (
            ClientPatch {
                redirect_uris: Some(vec!["http://notes.example/callback".into()]),
                ..ClientPatch::default()
            },
            ClientField::RedirectUris,
        ),
        (
            ClientPatch {
                redirect_uris: Some(Vec::new()),
                ..ClientPatch::default()
            },
            ClientField::RedirectUris,
        ),
        (
            ClientPatch {
                display_name: Some(" ".into()),
                ..ClientPatch::default()
            },
            ClientField::DisplayName,
        ),
    ] {
        let changed = account.service.update_client(&client, patch).await;
        invalid(changed.map(drop), field);
    }
}

/// Deleting a client revokes its refresh tokens, removes its secrets and leaves a
/// disabled tombstone, recorded as the owner's. Its ID can never be registered,
/// applied, enabled, changed or deleted again, by the account or an operator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deleted_clients_stay_deleted() {
    let account = Account::new().await;
    let (database, alice) = (&account.database, &account.browser);
    let owner = account.owner().await;
    let client_id = account.create(ClientKind::Confidential).await;
    let (token, digest) = refresh_grant(
        database,
        alice.user_id,
        alice.session_id,
        &client_id,
        TokenId::new(),
    )
    .await;

    let client = account.find(owner.clone(), &client_id).await;
    account
        .service
        .delete_client(&client)
        .await
        .expect("delete");
    let found = account
        .service
        .owned_client(owner.clone(), client_id.as_str());
    assert!(matches!(
        found.await,
        Err(AccountError::Client(OwnedClientError::NotFound))
    ));
    assert_eq!(account.service.clients(&owner).await.expect("list"), []);

    let mut tx = database.begin().await.expect("transaction");
    assert!(matches!(
        tx.tokens()
            .consume_for_rotation(token, std::slice::from_ref(&digest), client_id.as_str())
            .await,
        Err(RefreshRotationError::Invalid)
    ));
    drop(tx);
    let oidc = &mut database.oidc();
    let tombstone = oidc.find_client(client_id.as_str()).await;
    let tombstone = tombstone.expect("lookup").expect("row");
    assert!(tombstone.deleted_at.is_some() && !tombstone.enabled);
    assert_eq!(oidc.client_secrets(&client_id).await.expect("secrets"), []);
    let history = database
        .events()
        .history_for_client(&client_id, 1)
        .await
        .expect("history");
    assert_eq!(
        (history[0].event.known(), &history[0].actor),
        (
            Some(&DomainEvent::ClientDeleted {
                client_id: client_id.clone()
            }),
            &Actor::User {
                user_id: alice.user_id,
                session_id: Some(alice.session_id),
            }
        )
    );

    let reused = ClientRegistration {
        id: client_id.clone(),
        ..registration(ClientKind::Confidential, "https://notes.example")
    };
    assert!(matches!(
        register(database, &reused).await,
        Err(ClientRegistryError::Exists { .. })
    ));
    let secret = Some(ClientSecret::generate().expect("secret"));
    assert!(matches!(
        change(database, async |registry| {
            registry
                .apply(&reused, secret, GracePeriod::default())
                .await
        })
        .await,
        Err(ClientRegistryError::Deleted(_))
    ));
    assert!(matches!(
        change(database, async |registry| {
            registry.set_enabled(&client_id, true).await
        })
        .await,
        Err(ClientRegistryError::Deleted(_))
    ));
    assert!(matches!(
        change(database, async |registry| {
            registry.delete(&client_id).await
        })
        .await,
        Err(ClientRegistryError::Deleted(_))
    ));
}

/// A deletion and a refresh rotation lock a family and the client in the same
/// order, so they never deadlock. Here a transaction holds one family of the
/// client while the deletion waits for it, then rotates another family, which
/// locks the client: the deletion must not be holding it yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletion_and_refresh_rotation_never_deadlock() {
    let granting = Granting::new().await;
    let (held, held_digest) = granting.grant(TokenId::new()).await;
    let (rotated, rotated_digest) = granting.grant(TokenId::new()).await;

    let mut holder = granting.database.begin().await.expect("transaction");
    holder
        .tokens()
        .revoke_family_for_token(held, std::slice::from_ref(&held_digest))
        .await
        .expect("hold the first family");
    let deletion = granting.delete();
    until_blocked(&mut holder, 1).await;
    holder
        .tokens()
        .consume_for_rotation(
            rotated,
            std::slice::from_ref(&rotated_digest),
            granting.client.as_str(),
        )
        .await
        .expect("the rotation locks the client while the deletion waits");
    holder.commit().await.expect("commit");
    deletion
        .await
        .expect("task")
        .expect("the deletion follows the rotation");

    let mut tx = granting.database.begin().await.expect("transaction");
    assert!(matches!(
        tx.tokens()
            .consume_for_rotation(
                rotated,
                std::slice::from_ref(&rotated_digest),
                granting.client.as_str()
            )
            .await,
        Err(RefreshRotationError::Invalid | RefreshRotationError::Replay { .. })
    ));
}

/// A family granted after a deletion locked the client's families is locked by
/// no one else but a rotation that will find the client deleted, so the deletion
/// skips it instead of waiting, which could deadlock with that rotation. Here the
/// deletion queues behind a held family while the grant commits, then a second
/// transaction holds the new family.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletion_skips_families_granted_while_it_waits() {
    let granting = Granting::new().await;
    let (held, fresh) = (TokenId::new(), TokenId::new());
    granting.grant(held).await;
    let mut holder = granting.database.begin().await.expect("transaction");
    holder
        .tokens()
        .lock_family(held)
        .await
        .expect("hold the family");
    let deletion = granting.delete();
    until_blocked(&mut holder, 1).await;
    let (token, digest) = granting.grant(fresh).await;
    let mut rotation = granting.database.begin().await.expect("transaction");
    rotation
        .tokens()
        .lock_family(fresh)
        .await
        .expect("hold the fresh family");
    holder.commit().await.expect("commit");
    tokio::time::timeout(std::time::Duration::from_secs(10), deletion)
        .await
        .expect("the deletion does not wait for the fresh family")
        .expect("task")
        .expect("deletion");
    let id = granting.client.as_str();
    assert!(matches!(
        rotation
            .tokens()
            .consume_for_rotation(token, std::slice::from_ref(&digest), id)
            .await,
        Err(RefreshRotationError::Invalid)
    ));
}

/// A deletion and a logout that share families lock them in the same order, so
/// they never deadlock. The families are inserted highest ID first, so a scan
/// meets them out of ID order; a transaction holds the lowest while the deletion,
/// then the logout, queue for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletion_and_logout_never_deadlock() {
    let granting = Granting::new().await;
    let (low, high) = (TokenId::new(), TokenId::new());
    for family in [high, low] {
        granting.grant(family).await;
    }

    let mut holder = granting.database.begin().await.expect("transaction");
    holder
        .tokens()
        .lock_family(low)
        .await
        .expect("hold the lowest family");
    let deletion = granting.delete();
    until_blocked(&mut holder, 1).await;
    let logout = tokio::spawn({
        let database = granting.database.clone();
        let (user, session) = (granting.user.user_id, granting.user.session_id);
        async move {
            let mut tx = database.begin().await?;
            sign_out(&mut tx, user, session).await?;
            tx.commit().await
        }
    });
    until_blocked(&mut holder, 2).await;
    holder.commit().await.expect("commit");
    deletion.await.expect("task").expect("deletion");
    logout.await.expect("task").expect("logout");
}

/// An operator's suspension disables a client, and its owner cannot enable it,
/// though they can still see and disable it. Lifting the suspension leaves it
/// disabled, for the owner to enable.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owners_cannot_enable_a_suspended_client() {
    let account = Account::new().await;
    let (service, owner) = (&account.service, account.owner().await);
    let id = account.create(ClientKind::Public).await;
    let client = account.find(owner.clone(), &id).await;
    let suspend = async |suspended: bool| {
        change(&account.database, async |registry| {
            registry.set_suspended(&id, suspended).await
        })
        .await
        .expect("suspension");
    };
    let shown = async || account.find(owner.clone(), &id).await;
    suspend(true).await;
    let suspended = shown().await;
    let suspended = suspended.client();
    assert!(suspended.suspended_at.is_some() && !suspended.enabled);
    let enabled = service.set_client_enabled(&client, true).await;
    assert!(
        matches!(
            enabled,
            Err(AccountError::Client(OwnedClientError::Registry(
                ClientRegistryError::Suspended(_)
            )))
        ),
        "{enabled:?}"
    );
    assert!(matches!(
        change(&account.database, async |registry| {
            registry.set_enabled(&id, true).await
        })
        .await,
        Err(ClientRegistryError::Suspended(_)),
    ));
    service
        .set_client_enabled(&client, false)
        .await
        .expect("disable");

    suspend(false).await;
    let lifted = shown().await;
    let lifted = lifted.client();
    assert!(lifted.suspended_at.is_none() && !lifted.enabled);
    service
        .set_client_enabled(&client, true)
        .await
        .expect("enable");
}

/// Browsers count a related origin by its registrable domain's first label, so
/// `example.co.uk` is `example`, also within auth's own domain. An origin without
/// a registrable domain counts none within auth's domain, and is refused elsewhere.
#[test]
fn related_origins_count_registrable_domain_labels() {
    let domain = |origin: &str| {
        ClientRegistry::domain(&origin.parse().expect("origin"), "auth.piquel.fr")
            .expect("countable origin")
    };
    assert_eq!(
        domain("https://app.example.co.uk").as_deref(),
        Some("example")
    );
    assert_eq!(
        domain("https://notes.alice.github.io").as_deref(),
        Some("alice")
    );
    assert_eq!(domain("https://piquel.fr").as_deref(), Some("piquel"));
    assert_eq!(
        domain("https://notes.auth.piquel.fr").as_deref(),
        Some("piquel")
    );
    let localhost = "https://localhost:4443".parse().expect("origin");
    assert_eq!(
        ClientRegistry::domain(&localhost, "localhost").expect("countable origin"),
        None
    );
    for public in ["https://github.io", "https://localhost"] {
        assert!(matches!(
            ClientRegistry::domain(&public.parse().expect("origin"), "auth.piquel.fr"),
            Err(ClientRegistryError::PublicSuffix(_))
        ));
    }
}

/// Only a trusted client's redirect origins are approved, each once, and approved
/// origins never span more domains than every browser honours. Deleting the client
/// removes its origins.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn origin_approval_needs_trust_a_redirect_origin_and_few_domains() {
    let database = Replicas::database().await;
    let unique = UserId::new();
    // Six registrable domains, then a second origin on the first one.
    let mut origins: Vec<RelatedOrigin> = (0..6)
        .map(|domain| format!("https://d{domain}-{unique}.example"))
        .chain([format!("https://www.d0-{unique}.example")])
        .map(|origin| origin.parse().expect("origin"))
        .collect();
    let inside: RelatedOrigin = format!("https://{unique}.auth.piquel.fr")
        .parse()
        .expect("origin");
    origins.push(inside.clone());
    let client = ClientRegistration {
        redirect_uris: RedirectUris::new(
            origins
                .iter()
                .map(|origin| format!("{origin}/callback").parse().expect("callback")),
        )
        .expect("callbacks"),
        ..registration(ClientKind::Public, inside.as_str())
    };
    register(&database, &client).await.expect("client");
    let approve = async |origin: &RelatedOrigin| {
        change(&database, async |registry| {
            registry
                .approve_origin(&client.id, origin, "auth.piquel.fr")
                .await
        })
        .await
    };
    let remove = async |origin: &RelatedOrigin| {
        change(&database, async |registry| {
            registry.remove_origin(&client.id, origin).await
        })
        .await
    };
    assert!(matches!(
        approve(&inside).await,
        Err(ClientRegistryError::Untrusted(_))
    ));
    replace(
        &database,
        &ClientRegistration {
            trusted: true,
            ..client.clone()
        },
    )
    .await
    .expect("trusted");
    let elsewhere = format!("https://elsewhere-{unique}.auth.piquel.fr")
        .parse()
        .expect("origin");
    assert!(matches!(
        approve(&elsewhere).await,
        Err(ClientRegistryError::NotRedirectOrigin { .. })
    ));
    approve(&inside)
        .await
        .expect("an origin within auth's domain");
    assert!(matches!(
        approve(&inside).await,
        Err(ClientRegistryError::OriginApproved { .. })
    ));
    let mut approved = Vec::new();
    let error = loop {
        match approve(&origins[approved.len()]).await {
            Ok(()) => approved.push(origins[approved.len()].clone()),
            Err(error) => break error,
        }
    };
    let ClientRegistryError::TooManyDomains(domains) = error else {
        panic!("a sixth domain is refused, not {error}");
    };
    assert_eq!(domains.len(), MAX_RELATED_ORIGIN_DOMAINS + 1);
    // Other tests' origins within auth's domain count as `piquel`, and a database
    // other runs left full refuses the first domain. Otherwise another origin on an
    // approved domain still fits.
    if !approved.is_empty() {
        approve(&origins[6])
            .await
            .expect("an already counted domain");
        approved.push(origins[6].clone());
    }
    approved.push(inside.clone());
    for origin in &approved {
        remove(origin).await.expect("removed");
    }
    assert!(matches!(
        remove(&approved[0]).await,
        Err(ClientRegistryError::OriginNotApproved { .. })
    ));

    // Clients are tombstoned, so a trigger, not the query, removes the origins of a
    // deleted one, whichever release deleted it.
    approve(&inside).await.expect("approved again");
    change(&database, async |registry| {
        registry.delete(&client.id).await
    })
    .await
    .expect("deleted");
    let approved = database.oidc().related_origins().await.expect("origins");
    assert!(approved.iter().all(|origin| origin.client_id != client.id));
}
