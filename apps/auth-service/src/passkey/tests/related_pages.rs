//! Sign-in from related pages on approved origins.

use super::*;
use crate::{
    ClientRegistry,
    tests::{change, operator, register, until_blocked},
};
use piquel_common::clients::RelatedOrigin;

/// PKCE verifier of the pushed requests related pages complete.
const PAGE_VERIFIER: &str = "related-page-verifier-0123456789-abcdefghijklmnop";

/// A trusted client whose page, on its approved origin, signs the fixture's account in.
struct RelatedPage {
    /// The page's client.
    client: piquel_common::clients::ClientRegistration,
    /// The page's approved origin.
    origin: RelatedOrigin,
}

impl RelatedPage {
    /// Registers a trusted public client on a fresh subdomain of auth's own domain,
    /// which counts only as `piquel`, as every such origin does, and approves its origin.
    async fn approved(database: &Database) -> Self {
        let origin: RelatedOrigin = format!("https://{}.auth.piquel.fr", TokenId::new())
            .parse()
            .expect("origin");
        let client = piquel_common::clients::ClientRegistration {
            trusted: true,
            ..crate::tests::registration(
                piquel_common::clients::ClientKind::Public,
                origin.as_str(),
            )
        };
        register(database, &client).await.expect("client");
        change(database, async |registry| {
            registry
                .approve_origin(&client.id, &origin, "auth.piquel.fr")
                .await
        })
        .await
        .expect("approved origin");
        Self { client, origin }
    }
}

impl Fixture {
    /// Pushes `page`'s authorization request, with `extra` parameters, and returns
    /// its `request_uri`.
    async fn push(&self, page: &RelatedPage, extra: &[(&str, &str)]) -> String {
        let challenge = piquel_crypto::Pkce::challenge(PAGE_VERIFIER).expect("PKCE");
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", page.client.id.as_str()),
                ("response_type", "code"),
                ("redirect_uri", page.client.redirect_uris[0].as_str()),
                ("scope", "openid"),
                ("state", "page-state"),
                ("code_challenge_method", "S256"),
                ("code_challenge", &challenge),
            ])
            .extend_pairs(extra.iter().copied())
            .finish();
        let request = Request::builder()
            .method(Method::POST)
            .uri(routes::oidc::PAR)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        let response = self.send(request, form).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        Self::json(response).await["request_uri"]
            .as_str()
            .expect("request_uri")
            .to_owned()
    }
    /// Posts JSON from a page on `origin`, which sends no cookies.
    async fn post_from(&self, origin: &str, path: &str, body: Value) -> Response {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json");
        self.send(request, body.to_string()).await
    }
    /// Starts `page`'s sign-in for `request_uri`.
    async fn start_related(&self, page: &RelatedPage, request_uri: &str) -> Response {
        self.post_from(
            page.origin.as_str(),
            routes::passkey::RELATED_START,
            json!({"request_uri":request_uri}),
        )
        .await
    }
    /// Signs `page`'s started sign-in for its own origin and finishes it from there.
    async fn finish_related(&mut self, page: &RelatedPage, started: &Value) -> Response {
        let assertion = self.assertion_for(page.origin.url().clone(), started);
        self.post_from(
            page.origin.as_str(),
            routes::passkey::RELATED_FINISH,
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await
    }
    /// Redeems `code` for `page`'s client with `verifier`.
    async fn redeem(&self, page: &RelatedPage, code: &str, verifier: &str) -> Response {
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("client_id", page.client.id.as_str()),
                ("redirect_uri", page.client.redirect_uris[0].as_str()),
                ("code", code),
                ("code_verifier", verifier),
            ])
            .finish();
        let request = Request::builder()
            .method(Method::POST)
            .uri(routes::oidc::TOKEN)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        self.send(request, form).await
    }
    /// Lists the origins `/.well-known/webauthn` publishes.
    async fn related_origins(&self) -> Vec<String> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(routes::passkey::RELATED_ORIGINS);
        let response = self.send(request, String::new()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=300, no-transform"
        );
        assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        serde_json::from_value(Self::json(response).await["origins"].take()).expect("origins")
    }
}

/// A page on an approved origin signs its account in without a cookie, and gets a
/// code that only its PKCE verifier redeems, once. The sign-in creates a session
/// recorded with the page's client and origin.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn related_pages_sign_in_for_pkce_bound_codes() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    fixture.on(&replicas.a);
    let page = RelatedPage::approved(&fixture.app.database).await;
    assert!(
        fixture
            .related_origins()
            .await
            .contains(&page.origin.to_string())
    );
    let mut codes = Vec::new();
    for _ in 0..2 {
        let request_uri = fixture.push(&page, &[]).await;
        let started = fixture.start_related(&page, &request_uri).await;
        assert_eq!(started.status(), StatusCode::OK);
        let headers = started.headers().clone();
        assert_eq!(
            headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            page.origin.as_str()
        );
        assert!(
            headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "pages sign in without cookies"
        );
        assert!(headers.get(header::SET_COOKIE).is_none());
        let started = Fixture::json(started).await;
        // Signed on one replica, finished on the other.
        let finished = fixture
            .on(&replicas.b)
            .finish_related(&page, &started)
            .await;
        assert_eq!(finished.status(), StatusCode::OK);
        assert!(finished.headers().get(header::SET_COOKIE).is_none());
        let answer = Fixture::json(finished).await;
        assert_eq!(answer["state"], "page-state");
        assert_eq!(answer["iss"], AUTH_ORIGIN);
        codes.push(answer["code"].as_str().expect("code").to_owned());
        // The ceremony and its request are spent.
        let assertion = fixture.assertion_for(page.origin.url().clone(), &started);
        let replay = fixture
            .post_from(
                page.origin.as_str(),
                routes::passkey::RELATED_FINISH,
                json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
            )
            .await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        let reused = fixture.start_related(&page, &request_uri).await;
        assert_eq!(reused.status(), StatusCode::BAD_REQUEST);
    }
    let wrong = "another-verifier-0123456789-abcdefghijklmnopqrstu";
    let redeemed = fixture.redeem(&page, &codes[0], wrong).await;
    assert_eq!(redeemed.status(), StatusCode::BAD_REQUEST);
    let redeemed = fixture.redeem(&page, &codes[1], PAGE_VERIFIER).await;
    assert_eq!(redeemed.status(), StatusCode::OK);
    let DomainEvent::SignedIn {
        session_id,
        method: AuthenticationMethod::Passkey,
        inline: Some(inline),
    } = fixture
        .events()
        .await
        .into_iter()
        .find(|event| matches!(event, DomainEvent::SignedIn { .. }))
        .expect("sign-in")
    else {
        panic!("an inline passkey sign-in");
    };
    assert_eq!(inline.client_id, page.client.id);
    assert_eq!(inline.origin, page.origin.into(), "kept as personal data");
    let session = fixture
        .app
        .database
        .sessions()
        .find_active_by_id(session_id)
        .await
        .expect("session lookup")
        .expect("active session");
    assert_eq!(
        SessionAuthentication::from(&session).acr,
        Acr::PhishingResistant
    );
}

/// Sign-in is refused to unapproved origins, for another client's request, from
/// another origin than its start, for an assertion signed for another origin and
/// without user verification. A request needing auth's pages stays usable there.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn related_sign_in_refuses_other_origins_requests_and_unverified_users() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    fixture.on(&replicas.a);
    let page = RelatedPage::approved(&fixture.app.database).await;
    let other = RelatedPage::approved(&fixture.app.database).await;

    let request_uri = fixture.push(&page, &[]).await;
    let unapproved = fixture
        .post_from(
            "https://unapproved.example",
            routes::passkey::RELATED_START,
            json!({"request_uri":request_uri}),
        )
        .await;
    assert_eq!(unapproved.status(), StatusCode::FORBIDDEN);
    assert!(
        unapproved
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
    // Another client's page cannot claim the request, which stays its client's.
    let claimed = fixture.start_related(&other, &request_uri).await;
    assert_eq!(claimed.status(), StatusCode::BAD_REQUEST);
    let started = fixture.start_related(&page, &request_uri).await;
    assert_eq!(started.status(), StatusCode::OK);
    let started = Fixture::json(started).await;
    // The ceremony finishes only on the page that started it.
    let assertion = fixture.assertion_for(other.origin.url().clone(), &started);
    let moved = fixture
        .post_from(
            other.origin.as_str(),
            routes::passkey::RELATED_FINISH,
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(moved.status(), StatusCode::FORBIDDEN);

    // The verifier accepts auth's own origin too, but the page must have signed.
    let started = Fixture::json(
        fixture
            .start_related(&page, &fixture.push(&page, &[]).await)
            .await,
    )
    .await;
    let assertion = fixture.assertion(&started);
    let elsewhere = fixture
        .post_from(
            page.origin.as_str(),
            routes::passkey::RELATED_FINISH,
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(elsewhere.status(), StatusCode::BAD_REQUEST);

    let mut started = Fixture::json(
        fixture
            .start_related(&page, &fixture.push(&page, &[]).await)
            .await,
    )
    .await;
    started["public_key"]["publicKey"]["userVerification"] = json!("discouraged");
    let unverified = fixture.finish_related(&page, &started).await;
    assert_eq!(unverified.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        fixture.events().await.first(),
        Some(&DomainEvent::SignInFailed {
            method: AuthenticationMethod::Passkey,
            reason: SignInFailure::InvalidCredential,
        })
    );

    // `prompt=consent` needs the consent page: the request is left for it.
    let request_uri = fixture.push(&page, &[("prompt", "consent")]).await;
    let refused = fixture.start_related(&page, &request_uri).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(Fixture::json(refused).await["code"], "interaction_required");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("client_id", page.client.id.as_str()),
            ("request_uri", &request_uri),
        ])
        .finish();
    let redirect = fixture
        .request(
            &format!("{}?{query}", routes::oidc::AUTHORIZE),
            Method::GET,
            "",
            json!({}),
        )
        .await;
    assert_eq!(redirect.status(), StatusCode::SEE_OTHER);

    // A removed origin's pages stop at once.
    change(&fixture.app.database, async |registry| {
        registry.remove_origin(&page.client.id, &page.origin).await
    })
    .await
    .expect("removed");
    assert!(
        !fixture
            .related_origins()
            .await
            .contains(&page.origin.to_string())
    );
    let removed = fixture
        .start_related(&page, &fixture.push(&page, &[]).await)
        .await;
    assert_eq!(removed.status(), StatusCode::FORBIDDEN);
}

/// An account scheduled for deletion signs in on no related page: only auth's
/// sign-in page offers to restore it, so the page is told to send the user there.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_account_being_deleted_signs_in_on_auths_pages_only() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    fixture.on(&replicas.a);
    let page = RelatedPage::approved(fixture.database()).await;
    let mut tx = fixture.app.database.begin().await.expect("transaction");
    tx.users()
        .set_status(fixture.user_id, AccountStatus::Deleting)
        .await
        .expect("status");
    tx.deletions()
        .schedule(
            fixture.user_id,
            chrono::Utc::now() + chrono::Duration::days(30),
        )
        .await
        .expect("schedule");
    tx.commit().await.expect("commit");

    let request_uri = fixture.push(&page, &[]).await;
    let started = Fixture::json(fixture.start_related(&page, &request_uri).await).await;
    let refused = fixture.finish_related(&page, &started).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(refused.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(Fixture::json(refused).await["code"], "interaction_required");
}

/// While the account has a recovery that can still be undone, no passkey signs in
/// on a related page: only auth's pages ask whether it was the owner's, as every
/// sign-in for an app does meanwhile, so the page is answered
/// `interaction_required`. That holds for the owner's passkey while the link is
/// unused, and for the passkey the link enrolled, whose probation sign-in also
/// meets no `phr`.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_probation_passkey_signs_in_on_auths_pages_only() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    fixture.on(&replicas.a);
    let page = RelatedPage::approved(fixture.database()).await;
    let recovery = piquel_common::RecoveryId::new();
    let mut recoveries = fixture.database().recoveries();
    recoveries
        .insert(&piquel_repository::InsertRecovery {
            id: recovery,
            user_id: fixture.user_id,
            secret_digest: &recovery.as_uuid().as_bytes().repeat(2),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        })
        .await
        .expect("recovery");
    // A sign-in on the related page, for `target`, refused for `why`.
    let refused = async |fixture: &mut Fixture, target: &[(&str, &str)], why: &str| {
        let request_uri = fixture.push(&page, target).await;
        let started = Fixture::json(fixture.start_related(&page, &request_uri).await).await;
        let refused = fixture.finish_related(&page, &started).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        let body = Fixture::json(refused).await;
        assert_eq!(body["code"], "interaction_required");
        let error = body["error"].as_str().expect("error");
        assert!(error.contains(why), "{error}");
    };
    let undoable = "recovery that can still be undone";
    refused(&mut fixture, &[], undoable).await;

    let mut recoveries = fixture.database().recoveries();
    let completed = recoveries
        .complete(
            fixture.user_id,
            recovery,
            fixture.key_id,
            crate::recovery::PROBATION,
        )
        .await;
    assert!(completed.expect("complete"));

    refused(&mut fixture, &[("acr_values", "phr")], "does not meet").await;
    refused(&mut fixture, &[], undoable).await;
}

/// Removing a page's origin while its sign-in finishes refuses the sign-in:
/// completing it checks the origin again under its client's lock, which the
/// removal holds until it commits.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn removing_an_origin_during_a_sign_in_refuses_it() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    fixture.on(&replicas.a);
    let page = RelatedPage::approved(&fixture.app.database).await;
    let request_uri = fixture.push(&page, &[]).await;
    let started = Fixture::json(fixture.start_related(&page, &request_uri).await).await;
    let assertion = fixture.assertion_for(page.origin.url().clone(), &started);
    let database = fixture.app.database.clone();
    let mut removal = database.begin().await.expect("transaction");
    ClientRegistry::new(&mut removal, operator().context())
        .remove_origin(&page.client.id, &page.origin)
        .await
        .expect("removed");

    let finish = fixture.post_from(
        page.origin.as_str(),
        routes::passkey::RELATED_FINISH,
        json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
    );
    let (finished, ()) = tokio::join!(finish, async {
        until_blocked(&mut removal, 1).await;
        removal.commit().await.expect("commit");
    });
    assert_eq!(finished.status(), StatusCode::BAD_REQUEST);
    let events = fixture.events().await;
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, DomainEvent::SignedIn { .. })),
        "{events:?}"
    );
}
