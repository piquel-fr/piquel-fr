//! Database-backed admin API access, protection and operation scenarios.

use super::*;
use crate::security::{BrowserCookie, HttpSecurity};
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, header},
    middleware,
    response::Response,
};
use chrono::{Duration, Utc};
use piquel_auth_protocol::{AccountStatus, AuthenticationMethod};
use piquel_crypto::Secret;
use piquel_repository::{
    AuditAction, BootstrapOidcClient, DatabaseConfig, InsertSession, InsertUser,
    InsertVerifiedEmail,
};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tower::ServiceExt;

/// The only origin the admin API accepts.
const ADMIN_ORIGIN: &str = "https://admin.piquel.fr";
/// The auth origin, which the admin API rejects like any other.
const AUTH_ORIGIN: &str = "https://auth.piquel.fr";
/// Bound on JSON responses read by the scenarios.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// A seeded account with one browser session.
struct Account {
    /// The account.
    user_id: UserId,
    /// Its unique login name.
    username: String,
    /// Its session.
    session_id: SessionId,
    /// `Cookie` header carrying the session.
    cookie: String,
}

/// How a seeded session signed in, and what it may do.
#[derive(Clone, Copy)]
struct Seed {
    /// Whether the account is an administrator.
    administrator: bool,
    /// How the session authenticated.
    method: AuthenticationMethod,
    /// How long ago the session signed in.
    age: Duration,
    /// Whether the session holds a passkey confirmation.
    confirmed: bool,
}

impl Seed {
    /// A non-administrator signed in with a passkey just now.
    const USER: Self = Self {
        administrator: false,
        method: AuthenticationMethod::Passkey,
        age: Duration::zero(),
        confirmed: true,
    };
    /// An administrator with a fresh passkey sign-in and confirmation.
    const CONFIRMED_ADMIN: Self = Self {
        administrator: true,
        ..Self::USER
    };
    /// An administrator with a fresh passkey sign-in but no confirmation.
    const ADMIN: Self = Self {
        confirmed: false,
        ..Self::CONFIRMED_ADMIN
    };
}

/// The admin API behind the production HTTP policy, with its database.
struct Fixture {
    /// Admin routes under [`HttpSecurity::protect`].
    router: Router,
    /// The operations behind the routes, used as the CLI would.
    operations: AdminOperations,
    /// Scenario database.
    database: Database,
}

impl Fixture {
    /// Builds the admin API, with invitation routes when `invitations` is set.
    async fn new(invitations: bool) -> Self {
        let url = piquel_common::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name a disposable PostgreSQL database");
        let database = Database::connect(
            DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5)).expect("config"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        let operations =
            AdminOperations::new(database.clone(), AUTH_ORIGIN.parse().expect("origin"));
        let policy = HttpSecurity {
            database: database.clone(),
            trusted_proxies: Arc::new(vec![]),
            request_timeout: std::time::Duration::from_secs(30),
            auth_origin: AUTH_ORIGIN.into(),
            settings_origin: "https://piquel.fr".into(),
            admin_origin: Some(ADMIN_ORIGIN.into()),
            client_origins: Arc::new(vec![]),
        };
        let router = AdminApplication {
            operations: operations.clone(),
            database: database.clone(),
            invitations,
        }
        .routes()
        .layer(middleware::from_fn_with_state(
            policy,
            HttpSecurity::protect,
        ));
        Self {
            router,
            operations,
            database,
        }
    }

    /// The CLI operator used by the scenarios.
    fn operator() -> Actor {
        Actor::Cli {
            os_user: "test".into(),
            host: "test".into(),
        }
    }

    /// Seeds an account and a session described by `seed`.
    async fn account(&self, seed: Seed) -> Account {
        let user_id = UserId::new();
        let username = format!("adm_{}", &user_id.to_string()[24..]);
        self.database
            .users()
            .insert(&InsertUser {
                id: user_id,
                username: username.clone(),
                display_name: "Admin test".into(),
            })
            .await
            .expect("user");
        if seed.administrator {
            self.operations
                .grant_administrator(&Self::operator(), &username)
                .await
                .expect("grant");
        }
        self.sign_in(user_id, username, seed).await
    }

    /// Seeds another session for an existing account, as described by `seed`.
    async fn sign_in(&self, user_id: UserId, username: String, seed: Seed) -> Account {
        let mut tx = self.database.begin().await.expect("transaction");
        let signed_in_at = Utc::now() - seed.age;
        let session_id = SessionId::new();
        tx.sessions()
            .insert(&InsertSession {
                id: session_id,
                user_id,
                authentication_methods: vec![seed.method],
                authenticated_at: signed_in_at,
                expires_at: signed_in_at + Duration::days(30),
                user_agent_family: None,
            })
            .await
            .expect("session");
        let secret = Secret::generate().expect("secret");
        tx.sessions()
            .insert_browser_secret(session_id, secret.digest().as_bytes())
            .await
            .expect("browser secret");
        if seed.confirmed {
            tx.sessions()
                .grant_management(session_id)
                .await
                .expect("confirmation");
        }
        tx.commit().await.expect("commit");
        Account {
            user_id,
            username,
            session_id,
            cookie: format!("{}={}", BrowserCookie::Session.as_str(), secret.encoded()),
        }
    }

    /// Sends a request with the selected session, origin, CSRF proof and JSON body,
    /// from a fresh client address so scenarios never share a request budget.
    async fn request(
        &self,
        method: &Method,
        path: &str,
        account: Option<&Account>,
        origin: &str,
        csrf: bool,
        body: Option<Value>,
    ) -> Response {
        let mut request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::ORIGIN, origin);
        if let Some(account) = account {
            request = request.header(header::COOKIE, &account.cookie);
        }
        if csrf {
            request = request.header("x-piquel-csrf", "1");
        }
        let body = match body {
            Some(body) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let mut request = request.body(body).expect("request");
        let peer = IpAddr::V6(Ipv6Addr::from(UserId::new().as_uuid().as_u128()));
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer, 4321)));
        self.router
            .clone()
            .oneshot(request)
            .await
            .expect("response")
    }

    /// Sends a request as `account` from the admin site, with CSRF proof.
    async fn admin(
        &self,
        method: Method,
        path: &str,
        account: &Account,
        body: Option<Value>,
    ) -> Response {
        self.request(&method, path, Some(account), ADMIN_ORIGIN, true, body)
            .await
    }

    /// Reads a JSON response body.
    async fn json(response: Response) -> Value {
        serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
                .await
                .expect("body"),
        )
        .expect("JSON")
    }

    /// Asserts `response` has `status` and the error message `message`.
    async fn rejected(response: Response, status: StatusCode, message: &str, context: &str) {
        assert_eq!(response.status(), status, "{context}");
        assert_eq!(Self::json(response).await["error"], message, "{context}");
    }

    /// Whether the account still has an active session.
    async fn signed_in(&self, account: &Account) -> bool {
        self.database
            .sessions()
            .find_active_by_id(account.session_id)
            .await
            .expect("session")
            .is_some()
    }
}

/// Fills a route's `{id}` placeholder.
fn path(route: &str, id: impl std::fmt::Display) -> String {
    route.replace("{id}", &id.to_string())
}

/// Every admin route rejects a missing session (401), a non-administrator (404, like an
/// unknown path), a social-only or stale administrator session, any other origin, and
/// mutations without CSRF proof or a recent passkey confirmation.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "Keep the complete route and rejection table together."
)]
async fn every_admin_route_enforces_admin_access() {
    let fixture = Fixture::new(true).await;
    let target = fixture.account(Seed::USER).await;
    let user = fixture.account(Seed::USER).await;
    let social = fixture
        .account(Seed {
            method: AuthenticationMethod::Federation,
            ..Seed::CONFIRMED_ADMIN
        })
        .await;
    let stale = fixture
        .account(Seed {
            age: Duration::hours(13),
            ..Seed::CONFIRMED_ADMIN
        })
        .await;
    let unconfirmed = fixture.account(Seed::ADMIN).await;
    let confirmed = fixture.account(Seed::CONFIRMED_ADMIN).await;
    let routes = [
        (Method::GET, routes::admin::USERS.to_owned()),
        (Method::GET, path(routes::admin::USER, target.user_id)),
        (
            Method::POST,
            path(routes::admin::USER_DISABLE, target.user_id),
        ),
        (
            Method::POST,
            path(routes::admin::USER_ENABLE, target.user_id),
        ),
        (
            Method::POST,
            path(routes::admin::USER_SESSIONS_REVOKE, target.user_id),
        ),
        (
            Method::DELETE,
            path(routes::admin::SESSION, target.session_id),
        ),
        (Method::GET, routes::admin::INVITATIONS.to_owned()),
        (Method::POST, routes::admin::INVITATIONS.to_owned()),
        (
            Method::DELETE,
            path(routes::admin::INVITATION, TokenId::new()),
        ),
        (Method::GET, routes::admin::CLIENTS.to_owned()),
        (Method::GET, path(routes::admin::CLIENT, "client")),
        (Method::GET, routes::admin::AUDIT.to_owned()),
    ];
    let body = Some(json!({ "reason": "Test" }));
    for (method, route) in &routes {
        let mutation = *method != Method::GET;
        let mut cases = vec![
            (
                None,
                ADMIN_ORIGIN,
                true,
                StatusCode::UNAUTHORIZED,
                "Sign in to continue.".to_owned(),
            ),
            (
                Some(&user),
                ADMIN_ORIGIN,
                true,
                StatusCode::NOT_FOUND,
                "Not found.".into(),
            ),
            (
                Some(&social),
                ADMIN_ORIGIN,
                true,
                StatusCode::FORBIDDEN,
                "Sign in with a passkey to use the admin API.".into(),
            ),
            (
                Some(&stale),
                ADMIN_ORIGIN,
                true,
                StatusCode::UNAUTHORIZED,
                "Sign in again with a passkey: the admin API accepts sign-ins up to 12 hours old."
                    .into(),
            ),
            (
                Some(&confirmed),
                AUTH_ORIGIN,
                true,
                StatusCode::FORBIDDEN,
                "This endpoint does not accept requests from this origin.".into(),
            ),
        ];
        if mutation {
            cases.extend([
                (
                    Some(&confirmed),
                    ADMIN_ORIGIN,
                    false,
                    StatusCode::FORBIDDEN,
                    "This request must come from a Piquel page, with the x-piquel-csrf header."
                        .into(),
                ),
                (
                    Some(&unconfirmed),
                    ADMIN_ORIGIN,
                    true,
                    StatusCode::FORBIDDEN,
                    "Confirm with a passkey to make admin changes for two minutes.".into(),
                ),
            ]);
        }
        for (account, origin, csrf, status, message) in cases {
            let response = fixture
                .request(method, route, account, origin, csrf, body.clone())
                .await;
            Fixture::rejected(response, status, &message, &format!("{method} {route}")).await;
        }
    }
    assert!(fixture.signed_in(&target).await, "no rejection acted");
    // Invitation routes exist only while signup requires invitations.
    let fixture = Fixture::new(false).await;
    for method in [Method::GET, Method::POST] {
        let response = fixture
            .admin(method, routes::admin::INVITATIONS, &confirmed, None)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

/// The admin API refuses to change administrator accounts, the caller's included, and
/// no route changes administrator rights. Only the CLI can act on administrators.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn admin_api_cannot_act_on_administrators() {
    let fixture = Fixture::new(true).await;
    let caller = fixture.account(Seed::CONFIRMED_ADMIN).await;
    let other = fixture.account(Seed::ADMIN).await;
    for target in [&other, &caller] {
        for (method, route, body) in [
            (
                Method::POST,
                path(routes::admin::USER_DISABLE, target.user_id),
                Some(json!({ "reason": "Takeover" })),
            ),
            (
                Method::POST,
                path(routes::admin::USER_ENABLE, target.user_id),
                None,
            ),
            (
                Method::POST,
                path(routes::admin::USER_SESSIONS_REVOKE, target.user_id),
                None,
            ),
            (
                Method::DELETE,
                path(routes::admin::SESSION, target.session_id),
                None,
            ),
        ] {
            let response = fixture.admin(method, &route, &caller, body).await;
            Fixture::rejected(
                response,
                StatusCode::FORBIDDEN,
                "Administrator accounts can only be changed with the auth-service CLI.",
                &route,
            )
            .await;
        }
        assert!(fixture.signed_in(target).await);
    }
    let administrators: Vec<_> = fixture
        .operations
        .list_administrators()
        .await
        .expect("administrators")
        .into_iter()
        .map(|admin| admin.user_id)
        .collect();
    assert!(administrators.contains(&caller.user_id));
    assert!(administrators.contains(&other.user_id));
    // The CLI may still repair an administrator account.
    let operator = Fixture::operator();
    fixture
        .operations
        .revoke_user_sessions(&operator, other.user_id)
        .await
        .expect("CLI revokes an administrator's sessions");
    assert!(!fixture.signed_in(&other).await);
}

/// Administrator rights are granted and revoked by username, once, and never to a
/// disabled account.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn cli_grants_and_revokes_administrators() {
    let fixture = Fixture::new(true).await;
    let operator = Fixture::operator();
    let account = fixture.account(Seed::USER).await;
    let operations = &fixture.operations;
    assert!(matches!(
        operations
            .grant_administrator(&operator, "no_such_user")
            .await,
        Err(AdminError::UserNotFound)
    ));
    operations
        .grant_administrator(&operator, &account.username)
        .await
        .expect("grant");
    assert!(matches!(
        operations
            .grant_administrator(&operator, &account.username)
            .await,
        Err(AdminError::AlreadyAdministrator)
    ));
    let granted = operations
        .list_administrators()
        .await
        .expect("list")
        .into_iter()
        .find(|admin| admin.user_id == account.user_id)
        .expect("listed");
    assert_eq!(granted.granted_by, operator);
    operations
        .revoke_administrator(&operator, &account.username)
        .await
        .expect("revoke");
    assert!(matches!(
        operations
            .revoke_administrator(&operator, &account.username)
            .await,
        Err(AdminError::NotAdministrator)
    ));
    operations
        .disable_user(
            &operator,
            account.user_id,
            &Reason::parse("Test".into()).expect("reason"),
        )
        .await
        .expect("disable");
    assert!(matches!(
        operations
            .grant_administrator(&operator, &account.username)
            .await,
        Err(AdminError::AccountDisabled)
    ));
    let audit = fixture
        .database
        .audit_events()
        .list_for_user(account.user_id)
        .await
        .expect("audit");
    assert!(
        audit
            .iter()
            .any(|(action, _)| *action == AuditAction::AdminGrant)
    );
    assert!(
        audit
            .iter()
            .any(|(action, _)| *action == AuditAction::AdminRevoke)
    );
}

/// Each admin operation works through the API and records an entry attributed to the
/// administrator: search, viewing, session revocation, disabling with a reason,
/// reactivation, invitations, clients and the audit log.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "Keep one account's administration story together."
)]
async fn admin_operations_work_through_the_api_and_are_audited() {
    let fixture = Fixture::new(true).await;
    let admin = fixture.account(Seed::CONFIRMED_ADMIN).await;
    let actor = json!({
        "kind": "admin",
        "user_id": admin.user_id,
        "session_id": admin.session_id,
    });
    let target = fixture.account(Seed::USER).await;
    let email = format!("{}@example.com", target.username);
    fixture
        .database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: target.user_id,
            normalized_email: email.clone(),
            is_primary: true,
            verified_at: Utc::now(),
        })
        .await
        .expect("email");

    // Search by part of the username or email, or by exact ID.
    for query in [
        target.username[4..].to_uppercase(),
        email.clone(),
        target.user_id.to_string(),
    ] {
        let response = fixture
            .admin(
                Method::GET,
                &format!("{}?q={query}", routes::admin::USERS),
                &admin,
                None,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let page = Fixture::json(response).await;
        assert_eq!(page["users"][0]["id"], json!(target.user_id), "{query}");
    }

    // Viewing an account is recorded, since it exposes personal data.
    let response = fixture
        .admin(
            Method::GET,
            &path(routes::admin::USER, target.user_id),
            &admin,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let detail = Fixture::json(response).await;
    assert_eq!(detail["administrator"], false);
    assert_eq!(detail["emails"][0]["normalized_email"], email);
    assert_eq!(detail["sessions"][0]["id"], json!(target.session_id));

    // One session ends; the account stays usable.
    let response = fixture
        .admin(
            Method::DELETE,
            &path(routes::admin::SESSION, target.session_id),
            &admin,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!fixture.signed_in(&target).await);
    let response = fixture
        .admin(
            Method::DELETE,
            &path(routes::admin::SESSION, target.session_id),
            &admin,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Disabling needs a reason and ends every session.
    let target = fixture
        .sign_in(target.user_id, target.username, Seed::USER)
        .await;
    let bystander = fixture.account(Seed::USER).await;
    let disable = path(routes::admin::USER_DISABLE, target.user_id);
    let response = fixture
        .admin(
            Method::POST,
            &disable,
            &admin,
            Some(json!({ "reason": " " })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = fixture
        .admin(
            Method::POST,
            &disable,
            &admin,
            Some(json!({ "reason": "Account takeover" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = fixture
        .admin(
            Method::POST,
            &disable,
            &admin,
            Some(json!({ "reason": "Again" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        fixture
            .database
            .users()
            .find_by_id(target.user_id)
            .await
            .expect("user")
            .expect("exists")
            .status,
        AccountStatus::Disabled
    );
    assert!(
        fixture
            .database
            .sessions()
            .list_active_for_user(target.user_id)
            .await
            .expect("sessions")
            .is_empty()
    );
    assert!(!fixture.signed_in(&target).await);
    assert!(
        fixture.signed_in(&bystander).await,
        "other accounts unaffected"
    );

    // Disabling released the email; reactivation fails while another account owns it.
    let claimant = fixture.account(Seed::USER).await;
    fixture
        .database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: claimant.user_id,
            normalized_email: email.clone(),
            is_primary: true,
            verified_at: Utc::now(),
        })
        .await
        .expect("claim released email");
    let enable = path(routes::admin::USER_ENABLE, target.user_id);
    Fixture::rejected(
        fixture.admin(Method::POST, &enable, &admin, None).await,
        StatusCode::CONFLICT,
        "Another active account has claimed one of this account's verified emails.",
        "enable",
    )
    .await;
    let mut tx = fixture.database.begin().await.expect("transaction");
    tx.users()
        .set_status(claimant.user_id, AccountStatus::Disabled)
        .await
        .expect("release claim");
    tx.commit().await.expect("commit");
    let response = fixture.admin(Method::POST, &enable, &admin, None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Every account action is in the audit log with its actor, and reason if any.
    let response = fixture
        .admin(
            Method::GET,
            &format!("{}?user={}", routes::admin::AUDIT, target.user_id),
            &admin,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let entries = Fixture::json(response).await["entries"].clone();
    let actions: Vec<_> = entries
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| {
            assert_eq!(entry["metadata"]["actor"], actor);
            entry["action"].as_str().expect("action").to_owned()
        })
        .collect();
    assert_eq!(
        actions,
        [
            AuditAction::AdminUserEnable,
            AuditAction::AdminUserDisable,
            AuditAction::AdminSessionRevoke,
            AuditAction::AdminUserView,
        ]
        .map(|action| action.as_str().to_owned())
    );
    assert_eq!(entries[1]["metadata"]["reason"], "Account takeover");
    let response = fixture
        .admin(
            Method::GET,
            &format!(
                "{}?user={}&action={}",
                routes::admin::AUDIT,
                target.user_id,
                AuditAction::AdminUserDisable
            ),
            &admin,
            None,
        )
        .await;
    assert_eq!(
        Fixture::json(response).await["entries"]
            .as_array()
            .expect("entries")
            .len(),
        1
    );

    // Invitation links are shown once; revoked invitations cannot be redeemed.
    let response = fixture
        .admin(
            Method::POST,
            routes::admin::INVITATIONS,
            &admin,
            Some(json!({ "expires_in": "24h" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = Fixture::json(response).await;
    let link = url::Url::parse(created["url"].as_str().expect("url")).expect("link");
    assert_eq!(link.origin().ascii_serialization(), AUTH_ORIGIN);
    let secret = link
        .query_pairs()
        .find(|(name, _)| name == "invitation")
        .expect("invitation secret")
        .1;
    let digest = Secret::parse(&secret).expect("secret").digest();
    assert!(
        fixture
            .database
            .security()
            .invitation_active(digest.as_bytes())
            .await
            .expect("active")
    );
    let response = fixture
        .admin(Method::GET, routes::admin::INVITATIONS, &admin, None)
        .await;
    let listed = Fixture::json(response).await;
    let invitation = listed
        .as_array()
        .expect("invitations")
        .iter()
        .find(|invitation| invitation["id"] == created["id"])
        .expect("listed");
    assert_eq!(invitation["created_by"], actor);
    assert!(invitation.get("secret_digest").is_none());
    let revoke = path(
        routes::admin::INVITATION,
        created["id"].as_str().expect("id"),
    );
    let response = fixture.admin(Method::DELETE, &revoke, &admin, None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = fixture.admin(Method::DELETE, &revoke, &admin, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        !fixture
            .database
            .security()
            .invitation_active(digest.as_bytes())
            .await
            .expect("revoked")
    );

    // Clients are listed without their secret digests.
    let client = BootstrapOidcClient {
        id: format!("admin-{}", &admin.user_id.to_string()[24..]),
        display_name: "Admin test client".into(),
        redirect_uris: vec!["https://client.example/callback".into()],
        post_logout_uris: vec![],
        allowed_scopes: vec!["openid".into()],
        allowed_audiences: vec!["admin-test".into()],
        allow_refresh: false,
        enabled: true,
        trusted: false,
        client_secret_hash: Some(vec![0; 32]),
    };
    fixture
        .database
        .oidc()
        .bootstrap_client(&client)
        .await
        .expect("client");
    let response = fixture
        .admin(Method::GET, routes::admin::CLIENTS, &admin, None)
        .await;
    assert!(
        Fixture::json(response)
            .await
            .as_array()
            .expect("clients")
            .iter()
            .any(|listed| listed["id"] == client.id.as_str())
    );
    let response = fixture
        .admin(
            Method::GET,
            &path(routes::admin::CLIENT, &client.id),
            &admin,
            None,
        )
        .await;
    let view = Fixture::json(response).await;
    assert_eq!(view["token_endpoint_auth_method"], "client_secret_basic");
    assert!(view.get("client_secret_hash").is_none());
}
