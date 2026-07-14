#![allow(missing_docs)]

use auth_service::{
    Es256KeyProvider, FederationApplication, OidcApplication, ProviderConfiguration, router,
};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use piquel_auth_protocol::TokenId;
use piquel_configuration::SecretReference;
use piquel_repository::{BootstrapOidcClient, Database, DatabaseConfig};
use serde_json::Value;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tower::ServiceExt;
use url::Url;

async fn database() -> Database {
    let url = env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
    Database::connect(
        DatabaseConfig::new_development(url, 5, Duration::from_secs(5))
            .expect("test database configuration"),
    )
    .await
    .expect("connect test database")
}

fn request(uri: &str) -> Request<Body> {
    let mut request = Request::get(uri).body(Body::empty()).expect("request");
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:4242".parse::<SocketAddr>().expect("peer"),
    ));
    request
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL after migrations"]
#[allow(clippy::too_many_lines)]
async fn public_protocol_routes_execute_across_http_and_postgres() {
    let database = database().await;
    let client_id = format!("browser-test-{}", TokenId::new());
    database
        .oidc()
        .bootstrap_client(&BootstrapOidcClient {
            id: client_id.clone(),
            display_name: "Browser test client".into(),
            redirect_uris: vec!["https://client.example/callback".into()],
            post_logout_uris: vec!["https://client.example/logout".into()],
            allowed_scopes: vec!["openid".into(), "profile".into()],
            allowed_audiences: vec!["client-api".into()],
            allow_refresh: true,
        })
        .await
        .expect("bootstrap client");

    let issuer = Url::parse("http://127.0.0.1:4180").expect("issuer");
    let keys = Arc::new(Es256KeyProvider::generate_for_development("http-flow"));
    let oidc = OidcApplication::new_development(database.clone(), &issuer, &[7; 32], keys)
        .expect("OIDC application");
    let provider = || ProviderConfiguration {
        client_id: "test-provider-client".into(),
        client_secret: SecretReference::parse("env://AUTH_TEST_PROVIDER_SECRET")
            .expect("provider secret reference"),
    };
    let federation =
        FederationApplication::new_development(database, &issuer, provider(), provider())
            .expect("federation application");
    let app = router(None, Some(oidc), Some(federation), None);

    let discovery = app
        .clone()
        .oneshot(request("/.well-known/openid-configuration"))
        .await
        .expect("discovery response");
    assert_eq!(discovery.status(), StatusCode::OK);
    let discovery: Value = serde_json::from_slice(
        &axum::body::to_bytes(discovery.into_body(), 64 * 1024)
            .await
            .expect("discovery body"),
    )
    .expect("discovery JSON");
    assert_eq!(discovery["issuer"], issuer.as_str().trim_end_matches('/'));
    assert_eq!(discovery["code_challenge_methods_supported"][0], "S256");

    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", "https://client.example/callback")
        .append_pair("scope", "openid profile")
        .append_pair("state", "client-state")
        .append_pair("nonce", "client-nonce")
        .append_pair(
            "code_challenge",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .append_pair("code_challenge_method", "S256")
        .append_pair("audience", "client-api")
        .finish();
    let authorization = app
        .clone()
        .oneshot(request(&format!("/oauth/authorize?{query}")))
        .await
        .expect("authorization response");
    assert_eq!(authorization.status(), StatusCode::SEE_OTHER);
    let continuation = authorization
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("continuation location");
    assert!(continuation.starts_with("http://127.0.0.1:4180/login?transaction=par_v1_"));

    let attacker_query = query.replace(
        "https%3A%2F%2Fclient.example%2Fcallback",
        "https%3A%2F%2Fattacker.example%2Fcallback",
    );
    let invalid_redirect = app
        .clone()
        .oneshot(request(&format!("/oauth/authorize?{attacker_query}")))
        .await
        .expect("invalid redirect response");
    assert_eq!(invalid_redirect.status(), StatusCode::BAD_REQUEST);
    assert!(invalid_redirect.headers().get(header::LOCATION).is_none());

    for provider in ["github", "google"] {
        let response = app
            .clone()
            .oneshot(request(&format!(
                "/login/{provider}?return_to=%2Fauthorize%3Ftransaction%3Dcontinuation"
            )))
            .await
            .expect("provider response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("provider location");
        assert!(location.contains("code_challenge_method=S256"));
        if provider == "google" {
            assert!(location.starts_with("https://accounts.google.com/"));
            assert!(location.contains("nonce="));
        } else {
            assert!(location.starts_with("https://github.com/"));
        }
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("provider cookie");
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
    }
}
