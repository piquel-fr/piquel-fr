//! Client registrations against a real database: the migration from the clients
//! file's rows, secret rotation, the origins public clients may call from, and
//! when pushed authorization requests can be claimed.
use crate::repositories::OidcRepository;
use crate::{Database, InsertAuthorizationRequest};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    ClientId, TokenId, UserId,
    clients::{
        AllowedScopes, ClientKind, ClientOwner, ClientRegistration, PostLogoutUris, RedirectUris,
        ScopeName,
    },
    protocol::oauth::Scope,
};
use sqlx::{Connection, PgConnection, PgPool};

/// A registration of `kind` named after a fresh ID, redirecting to `origin`.
fn registration(kind: ClientKind, origin: &str) -> ClientRegistration {
    ClientRegistration {
        id: format!("clients_{}", UserId::new())
            .parse()
            .expect("client ID"),
        display_name: "Client test".parse().expect("name"),
        kind,
        redirect_uris: RedirectUris::new([format!("{origin}/callback")
            .parse()
            .expect("redirect URI")])
        .expect("one redirect"),
        post_logout_uris: PostLogoutUris::new([]).expect("no logout pages"),
        allowed_scopes: AllowedScopes::new([ScopeName::from(Scope::OpenId)]).expect("scopes"),
        allow_refresh: false,
        trusted: false,
        require_pushed_authorization_requests: false,
        backchannel_logout_uri: None,
    }
}

/// A unique origin, so no other test's client allows it.
fn origin() -> String {
    format!("https://{}.example", UserId::new())
}

/// The digests of `id`'s secrets that still work, sorted.
async fn active(pool: &PgPool, id: &ClientId) -> Vec<Vec<u8>> {
    let mut digests = OidcRepository::from_pool(pool)
        .active_secret_digests(id.as_str())
        .await
        .expect("active secrets");
    digests.sort();
    digests
}

/// Rotating keeps earlier secrets working until their grace period ends, never
/// lengthens an earlier, shorter one and never revives an expired secret.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn rotation_caps_earlier_secrets_without_reviving_or_extending_them() {
    let pool = Database::test_pool().await;
    let mut oidc = OidcRepository::from_pool(&pool);
    let client = registration(ClientKind::Confidential, &origin());
    oidc.create_client(&client, ClientOwner::Operator)
        .await
        .expect("create");
    let [one, two, three, four, five] = [1, 2, 3, 4, 5].map(|byte| [byte; 32]);
    let rotate = async |digest: [u8; 32], grace: Duration| {
        let mut oidc = OidcRepository::from_pool(&pool);
        let (cap, _) = oidc
            .cap_client_secrets(&client.id, grace, None)
            .await
            .expect("cap");
        oidc.insert_client_secret(&client.id, &digest)
            .await
            .expect("insert");
        cap
    };
    oidc.insert_client_secret(&client.id, &one)
        .await
        .expect("first secret");
    let hour = rotate(two, Duration::hours(1)).await;
    assert_eq!(
        active(&pool, &client.id).await,
        [one.to_vec(), two.to_vec()]
    );
    rotate(three, Duration::hours(24)).await;
    let expiries = |secrets: Vec<crate::StoredClientSecret>| {
        secrets
            .into_iter()
            .map(|secret| secret.expires_at)
            .collect::<Vec<_>>()
    };
    let secrets = oidc.client_secrets(&client.id).await.expect("secrets");
    assert_eq!(expiries(secrets)[0], Some(hour), "the shorter grace stays");
    rotate(four, Duration::zero()).await;
    assert_eq!(active(&pool, &client.id).await, [four.to_vec()]);
    rotate(five, Duration::hours(24)).await;
    assert_eq!(
        active(&pool, &client.id).await,
        [four.to_vec(), five.to_vec()]
    );
    let secrets = oidc.client_secrets(&client.id).await.expect("secrets");
    assert!(
        expiries(secrets)[..3]
            .iter()
            .all(|expiry| expiry.is_some_and(|at| at <= Utc::now())),
        "revoked secrets stay revoked"
    );
}

/// A pushed request can be claimed only before it expires.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn pushed_requests_are_claimed_only_before_they_expire() {
    let pool = Database::test_pool().await;
    let origin = origin();
    let client = registration(ClientKind::Public, &origin);
    OidcRepository::from_pool(&pool)
        .create_client(&client, ClientOwner::Operator)
        .await
        .expect("create");
    let claim = async |expires_at: DateTime<Utc>| {
        let id = TokenId::new();
        let digest = id.as_uuid().as_bytes().to_vec();
        let mut oidc = OidcRepository::from_pool(&pool);
        oidc.insert_authorization_request(&InsertAuthorizationRequest {
            id,
            secret_digest: digest.clone(),
            pushed: true,
            client_id: client.id.clone(),
            redirect_uri: format!("{origin}/callback"),
            client_state: "state".into(),
            nonce: None,
            pkce_challenge: "challenge".into(),
            scopes: vec![Scope::OpenId.as_str().into()],
            audience: client.id.to_string(),
            force_login: false,
            force_consent: false,
            prompt_none: false,
            max_age: None,
            hinted_user_id: None,
            target_acr: None,
            expires_at,
        })
        .await
        .expect("push");
        oidc.claim_pushed_authorization_request(
            id,
            &digest,
            client.id.as_str(),
            TokenId::new().as_uuid().as_bytes(),
            Utc::now() + Duration::minutes(10),
        )
        .await
        .expect("claim")
    };
    assert!(claim(Utc::now() - Duration::seconds(1)).await.is_none());
    assert!(claim(Utc::now() + Duration::minutes(1)).await.is_some());
}

/// Only enabled public clients' authorization redirect origins are allowed, and
/// changes apply to the next lookup.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn public_client_origins_follow_registrations() {
    let pool = Database::test_pool().await;
    let mut oidc = OidcRepository::from_pool(&pool);
    let (first, second, confidential) = (origin(), origin(), origin());
    let mut client = registration(ClientKind::Public, &first);
    oidc.create_client(&client, ClientOwner::Operator)
        .await
        .expect("public client");
    oidc.create_client(
        &registration(ClientKind::Confidential, &confidential),
        ClientOwner::Operator,
    )
    .await
    .expect("confidential client");
    assert!(oidc.public_client_origin(&first).await.expect("lookup"));
    assert!(
        !oidc
            .public_client_origin(&confidential)
            .await
            .expect("lookup")
    );
    assert!(
        oidc.create_client(&client, ClientOwner::Operator)
            .await
            .is_err(),
        "client IDs are unique"
    );

    client.redirect_uris =
        RedirectUris::new([format!("{second}/callback").parse().expect("redirect URI")])
            .expect("one redirect");
    oidc.update_client(&client).await.expect("update");
    assert!(!oidc.public_client_origin(&first).await.expect("lookup"));
    assert!(oidc.public_client_origin(&second).await.expect("lookup"));
    let stored = oidc
        .find_client(client.id.as_str())
        .await
        .expect("find")
        .expect("registered");
    assert_eq!(stored.redirect_uris, [format!("{second}/callback")]);
    assert_eq!(stored.allowed_audiences, [client.id.to_string()]);

    assert!(
        oidc.set_client_enabled(&client.id, false)
            .await
            .expect("disable")
    );
    assert!(
        !oidc
            .set_client_enabled(&client.id, false)
            .await
            .expect("disable again"),
        "nothing changed"
    );
    assert!(!oidc.public_client_origin(&second).await.expect("lookup"));
}

/// Purging an account keeps its deleted clients' tombstones, without their
/// owner, and is refused while it owns a live client, which would otherwise
/// become a client no account manages.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn purging_an_owner_needs_its_live_clients_deleted() {
    let pool = Database::test_pool().await;
    let owner = UserId::new();
    sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Owner test')")
        .bind(owner.as_uuid())
        .bind(format!("owner_{owner}"))
        .execute(&pool)
        .await
        .expect("user");
    let client = registration(ClientKind::Public, &origin());
    let mut oidc = OidcRepository::from_pool(&pool);
    oidc.create_client(&client, ClientOwner::Account(owner))
        .await
        .expect("create");
    let purge = async || {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(owner.as_uuid())
            .execute(&pool)
            .await
    };
    assert!(purge().await.is_err(), "a live client keeps its owner");
    oidc.delete_client(&client.id).await.expect("delete");
    purge()
        .await
        .expect("tombstones never block purging their owner");
    let tombstone = oidc
        .find_client(client.id.as_str())
        .await
        .expect("find")
        .expect("the tombstone stays");
    assert_eq!(tombstone.owner_id, None);
}

/// Clients the startup file registered keep working after the migration: a
/// confidential client keeps its secret, redirect origins are filled in as URL
/// parsing serializes them, and the previous release's writes are mirrored, even
/// of a secret that had expired.
/// It runs in a scratch schema, since the test database is migrated.
#[expect(
    clippy::too_many_lines,
    reason = "Keep the migration, the previous release's writes and the checks in one scenario."
)]
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn migration_keeps_file_clients_and_their_secrets() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let mut connection = PgConnection::connect(&url).await.expect("connect");
    let schema = format!("clients_{}", UserId::new().as_uuid().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .execute(&mut connection)
    .await
    .expect("schema");
    for migration in [
        include_str!("../../../migrations/0001_initial.sql"),
        include_str!("../../../migrations/0002_refresh_family_authorization_code.sql"),
        include_str!("../../../migrations/0003_session_passkey_confirmation.sql"),
        include_str!("../../../migrations/0004_authentication_claims.sql"),
        include_str!("../../../migrations/0005_domain_events.sql"),
        include_str!("../../../migrations/0006_deliveries.sql"),
        include_str!("../../../migrations/0007_administrators.sql"),
    ] {
        sqlx::raw_sql(migration)
            .execute(&mut connection)
            .await
            .expect("earlier migration");
    }
    // A public client, and a confidential one whose secret digest is `digest`.
    let digest = [9; 32];
    sqlx::raw_sql(
        "INSERT INTO oidc_clients (id, display_name, allowed_scopes, allowed_audiences)
        VALUES ('web', 'Web', '[\"openid\"]', '[\"web\"]');
        INSERT INTO oidc_redirect_uris (client_id, uri, kind)
        VALUES
            ('web', 'https://Web.Example:0443/callback', 'authorization'),
            ('web', 'https://bücher.example/callback', 'authorization');
        INSERT INTO oidc_clients (
            id, display_name, allowed_scopes, allowed_audiences, client_secret_hash
        ) VALUES ('api', 'API', '[\"openid\"]', '[\"api\"]', decode(repeat('09', 32), 'hex'));",
    )
    .execute(&mut connection)
    .await
    .expect("file clients");
    // This migration, then the later ones the current release reads with.
    sqlx::raw_sql(concat!(
        include_str!("../../../migrations/0008_oidc_client_registry.sql"),
        include_str!("../../../migrations/0009_pushed_authorization_requests.sql"),
        include_str!("../../../migrations/0012_client_owners.sql"),
        include_str!("../../../migrations/0013_backchannel_logout.sql"),
    ))
    .execute(&mut connection)
    .await
    .expect("migration");

    // The previous release, still running, registers a confidential client.
    let legacy = [8_u8; 32];
    sqlx::query(
        "INSERT INTO oidc_clients (
            id, display_name, allowed_scopes, allowed_audiences, client_secret_hash
        ) VALUES ('legacy', 'Legacy', '[\"openid\"]', '[\"legacy\"]', $1)",
    )
    .bind(legacy.as_slice())
    .execute(&mut connection)
    .await
    .expect("legacy confidential client");
    // It then restarts with a new secret in its file, which replaces the old one,
    // and a rollback restores its earlier file, whose secret had expired.
    let replaced = [7_u8; 32];
    for digest in [replaced, legacy] {
        sqlx::query("UPDATE oidc_clients SET client_secret_hash = $1 WHERE id = 'legacy'")
            .bind(digest.as_slice())
            .execute(&mut connection)
            .await
            .expect("legacy secret change");
        assert_eq!(
            OidcRepository::from_connection(&mut connection)
                .active_secret_digests("legacy")
                .await
                .expect("secrets"),
            [digest.to_vec()]
        );
    }

    let mut oidc = OidcRepository::from_connection(&mut connection);
    oidc.fill_redirect_origins().await.expect("origins");
    for (id, kind) in [
        ("web", ClientKind::Public),
        ("api", ClientKind::Confidential),
        ("legacy", ClientKind::Confidential),
    ] {
        let client = oidc.find_client(id).await.expect("find").expect("migrated");
        assert_eq!((client.kind, client.owner_id), (kind, None), "{id}");
    }
    assert_eq!(
        oidc.active_secret_digests("api").await.expect("secrets"),
        [digest.to_vec()]
    );
    for origin in ["https://web.example", "https://xn--bcher-kva.example"] {
        assert!(
            oidc.public_client_origin(origin).await.expect("origin"),
            "{origin}"
        );
    }
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut connection)
        .await
        .expect("drop schema");
}
