//! Client registrations against a real database: secret rotation, the origins
//! public clients may call from, when pushed authorization requests can be claimed,
//! and which clients of live sessions the back-channel logout migration finds.
use crate::repositories::{OidcRepository, UserRepository};
use crate::{Database, InsertAuthorizationRequest, InsertUser, connection::MIGRATOR};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    ClientId, SessionId, TokenId, UserId,
    clients::{
        AllowedScopes, ClientKind, ClientOwner, ClientRegistration, PostLogoutUris, RedirectUris,
        ScopeName,
    },
    protocol::oauth::Scope,
};
use sqlx::{Connection, PgConnection, PgPool};
use std::ops::RangeBounds;

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
            digest_key: "test".into(),
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
            std::slice::from_ref(&digest),
            client.id.as_str(),
            TokenId::new().as_uuid().as_bytes(),
            "test",
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
    let account = InsertUser::named("owner");
    UserRepository::from_pool(&pool)
        .insert(&account)
        .await
        .expect("user");
    let owner = account.id;
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

/// A connection to a new scratch schema with the migrations in `versions` applied,
/// and the schema's name, for tests of a migration: the test database is already
/// migrated.
async fn scratch_schema(versions: impl RangeBounds<i64>) -> (PgConnection, String) {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let mut connection = PgConnection::connect(&url).await.expect("connect");
    let schema = format!("migration_{}", UserId::new().as_uuid().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .execute(&mut connection)
    .await
    .expect("schema");
    for migration in MIGRATOR.iter().filter(|m| versions.contains(&m.version)) {
        sqlx::raw_sql(&migration.sql)
            .execute(&mut connection)
            .await
            .expect("earlier migration");
    }
    (connection, schema)
}

/// The back-channel logout migration finds the clients of live sessions in what is
/// left of their exchanges: redeemed codes and refresh families. Unredeemed codes
/// and sessions that ended are left out.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn migration_finds_the_clients_of_live_sessions() {
    let (mut connection, schema) = scratch_schema(..13).await;
    let user = UserId::new();
    let (live, revoked, expired) = (SessionId::new(), SessionId::new(), SessionId::new());
    sqlx::raw_sql(&format!(
        "INSERT INTO users (id, username, display_name) VALUES ('{user}', 'backfill', 'Backfill');
        INSERT INTO oidc_clients (id, display_name, allowed_scopes, allowed_audiences)
        SELECT id, id, '[]'::jsonb, '[]'::jsonb
        FROM unnest(array['coded', 'refreshed', 'unredeemed']) id;
        INSERT INTO sessions (
            id, user_id, authentication_methods, authenticated_at, expires_at,
            last_seen_at, revoked_at
        ) VALUES
            ('{live}', '{user}', '[]', now(), now() + interval '1 day', now(), NULL),
            ('{revoked}', '{user}', '[]', now(), now() + interval '1 day', now(), now()),
            ('{expired}', '{user}', '[]', now() - interval '2 days', now() - interval '1 day',
                now(), NULL);
        INSERT INTO authorization_codes (
            id, secret_digest, client_id, user_id, session_id, redirect_uri,
            pkce_challenge, scopes, audience, expires_at, authentication, consumed_at
        )
        SELECT gen_random_uuid(), uuid_send(gen_random_uuid()), client, '{user}', session,
            'https://app.example/callback', 'challenge', '[]'::jsonb, client, now(),
            '{{}}'::jsonb, consumed
        FROM (VALUES
            ('coded', '{live}'::uuid, now()),
            ('unredeemed', '{live}', NULL),
            ('coded', '{revoked}', now())
        ) code(client, session, consumed);
        INSERT INTO refresh_token_families (
            id, user_id, client_id, session_id, audience, scopes, authentication
        )
        SELECT gen_random_uuid(), '{user}', 'refreshed', session, 'refreshed', '[]'::jsonb,
            '{{}}'::jsonb
        FROM unnest(array['{live}', '{expired}']::uuid[]) session;"
    ))
    .execute(&mut connection)
    .await
    .expect("sessions and their exchanges");

    sqlx::raw_sql(include_str!(
        "../../../migrations/0013_backchannel_logout.sql"
    ))
    .execute(&mut connection)
    .await
    .expect("migration");
    let found: Vec<(uuid::Uuid, String)> =
        sqlx::query_as("SELECT session_id, client_id FROM oidc_session_clients ORDER BY client_id")
            .fetch_all(&mut connection)
            .await
            .expect("session clients");
    assert_eq!(
        found,
        [
            (live.as_uuid(), "coded".to_owned()),
            (live.as_uuid(), "refreshed".to_owned()),
        ]
    );
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut connection)
        .await
        .expect("drop schema");
}
