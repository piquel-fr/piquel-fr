//! Bearer rejections against the shared challenge vectors.

use super::*;
use sourceorigin_common::protocol::challenge::BearerChallenge;

/// The status and header of a challenge vector, without its `error_description`,
/// which the extractors do not send.
fn expected(name: &str) -> (StatusCode, String) {
    let case = Case::all("challenges")
        .into_iter()
        .find(|case| case.name.ends_with(&format!("/{name}.json")))
        .expect("challenge vector");
    let challenge: BearerChallenge =
        serde_json::from_value(case.input("challenge").clone()).expect("vector challenge");
    let challenge = BearerChallenge {
        error_description: None,
        ..challenge
    };
    let status = StatusCode::from_u16(challenge.status()).expect("status");
    (status, challenge.to_string())
}

/// The response's status and `WWW-Authenticate` value.
fn challenge(response: &Response) -> (StatusCode, String) {
    let header = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|value| value.to_str().expect("text").to_owned())
        .unwrap_or_default();
    (response.status(), header)
}

/// Routes behind a bearer layer for `resource`, at the vectors' clock.
fn bearer_app(resource: Resource) -> Router {
    let validator = issuer(&token_case("access-valid")).resource(resource);
    Router::new()
        .route("/me", get(|_: Authenticated| async {}))
        .route("/public", get(|| async {}))
        .route("/read", get(|_: Scoped<notes::Read>| async {}))
        .route("/write", get(|_: Scoped<notes::Write>| async {}))
        .route(
            "/edit",
            get(|_: Scoped<(notes::Read, notes::Write)>| async {}),
        )
        .route("/all", get(|_: Scoped<notes::All>| async {}))
        .route(
            "/step-up",
            get(|_: RequireAuthentication<RecentPasskey>| async {}),
        )
        .layer(BearerLayer::new(validator))
}

/// Each rejection answers with the status and exact header of its challenge vector.
#[tokio::test]
async fn bearer_rejections_match_the_challenge_vectors() {
    let bearer = |name: &str| format!("Bearer {}", vector_token(name));
    let (valid, expired) = (bearer("access-valid"), bearer("access-expired"));
    let plain = bearer_app(Resource::new(RESOURCE).expect("resource"));
    let metadata = format!("{RESOURCE}/.well-known/oauth-protected-resource");
    let described = bearer_app(
        Resource::new(RESOURCE)
            .expect("resource")
            .with_metadata(metadata.parse().expect("metadata URL")),
    );

    let response = get_with(&plain, "/me", &[]).await;
    assert_eq!(challenge(&response), expected("missing-token"));
    let response = get_with(&described, "/read", &[]).await;
    assert_eq!(challenge(&response), expected("missing-token-scope"));
    for path in ["/edit", "/all"] {
        let response = get_with(&described, path, &[(header::AUTHORIZATION, &valid)]).await;
        assert_eq!(
            challenge(&response),
            expected("insufficient-scope"),
            "{path}"
        );
    }
    let response = get_with(&described, "/read", &[(header::AUTHORIZATION, &expired)]).await;
    assert_eq!(challenge(&response), expected("invalid-token"));
    let response = get_with(&described, "/step-up", &[(header::AUTHORIZATION, &valid)]).await;
    assert_eq!(
        challenge(&response),
        expected("insufficient-user-authentication")
    );
    let twice = [
        (header::AUTHORIZATION, valid.as_str()),
        (header::AUTHORIZATION, &valid),
    ];
    let response = get_with(&plain, "/me", &twice).await;
    assert_eq!(challenge(&response), expected("invalid-request"));
    let response = get_with(&plain, "/me", &[(header::AUTHORIZATION, "Bearer")]).await;
    assert_eq!(challenge(&response), expected("invalid-request"));
    // Only the extractors reject a malformed header: public routes still answer.
    for headers in [&twice[..], &[(header::AUTHORIZATION, "Bearer")]] {
        let response = get_with(&plain, "/public", headers).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    // Other schemes are not bearer tokens: the request has none.
    let response = get_with(&plain, "/me", &[(header::AUTHORIZATION, "Basic abc")]).await;
    assert_eq!(challenge(&response), expected("missing-token"));

    let response = get_with(&plain, "/read", &[(header::AUTHORIZATION, &valid)]).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// A read-only token is refused where writing is required, and the challenge names
/// the scope the handler enforces.
#[tokio::test]
async fn scoped_write_rejects_a_read_only_token() {
    let app = bearer_app(Resource::new(RESOURCE).expect("resource"));
    let token = format!("Bearer {}", vector_token("access-valid"));
    let response = get_with(&app, "/write", &[(header::AUTHORIZATION, &token)]).await;
    assert_eq!(
        challenge(&response),
        (
            StatusCode::FORBIDDEN,
            r#"Bearer error="insufficient_scope", scope="notes:write""#.to_owned()
        )
    );
}

/// Keys that cannot be fetched are the server failing, not the token: the request is
/// answered 503 without a challenge, so the client retries instead of signing out.
#[tokio::test]
async fn unavailable_keys_answer_503() {
    let server = KeyServer::start(Vec::new(), None).await;
    let clock = token_case("access-valid").clock();
    let issuer = Issuer::with_keys(
        metadata(),
        server.keys(&clock),
        Http::plain(reqwest::Client::builder()),
        Arc::new(clock),
    );
    let app = Router::new()
        .route("/me", get(|_: Authenticated| async {}))
        .layer(BearerLayer::new(
            issuer.resource(Resource::new(RESOURCE).expect("resource")),
        ));
    let token = format!("Bearer {}", vector_token("access-valid"));
    let response = get_with(&app, "/me", &[(header::AUTHORIZATION, &token)]).await;
    assert_eq!(
        challenge(&response),
        (StatusCode::SERVICE_UNAVAILABLE, String::new())
    );
}
