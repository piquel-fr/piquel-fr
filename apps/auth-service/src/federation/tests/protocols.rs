//! Provider protocols: credential resolution and Google ID-token verification.

use super::*;
use crate::federation::providers::{GoogleClaims, GoogleProtocol};
use piquel_auth::{KeyCache, KeySet};
use piquel_common::protocol::jwt::{Algorithm, TokenType};
use piquel_crypto::Rs256Key;
use std::collections::HashMap;
use tracing::Instrument;

impl TestApp {
    /// Borrows Google's replaceable verification facts from the fixture.
    fn google_protocol(&self) -> &GoogleProtocol {
        match &self.app.endpoints[&Provider::Google].identity {
            IdentityStrategy::Google(protocol) => protocol,
            IdentityStrategy::GitHub(_) => panic!("Google must use signed ID tokens"),
        }
    }
}

/// Google evidence requires trusted signatures and claims but does not require email.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn google_mock_validates_signature_audience_nonce_and_expiry_without_requiring_email() {
    let mut test = TestApp::new().await;
    let rsa = Rs256Key::generate("google-test").expect("RSA test key");
    let sign = |key: &Rs256Key, claims: &serde_json::Value| {
        key.sign(TokenType::Id, claims).expect("signed token")
    };
    let mut claims = serde_json::json!({"iss":"https://accounts.google.com","sub":"12345","aud":"test-client","iat":Utc::now().timestamp(),"exp":Utc::now().timestamp()+300,"nonce":"test-nonce"});
    let valid = sign(&rsa, &claims);
    claims["aud"] = serde_json::json!("another-client");
    let wrong_audience = sign(&rsa, &claims);
    claims["aud"] = serde_json::json!("test-client");
    claims["exp"] = serde_json::json!(Utc::now().timestamp() - 120);
    let expired = sign(&rsa, &claims);
    let other_rsa = Rs256Key::generate("google-test").expect("untrusted key");
    claims["exp"] = serde_json::json!(Utc::now().timestamp() + 300);
    let wrong_signature = sign(&other_rsa, &claims);
    let keys = rsa.jwks().clone();
    let tokens = Arc::new(HashMap::from([
        ("valid".to_owned(), valid),
        ("wrong-audience".to_owned(), wrong_audience),
        ("expired".to_owned(), expired),
        ("wrong-signature".to_owned(), wrong_signature),
    ]));
    let mock = Router::new()
        .route(
            "/keys",
            get(move || {
                let keys = keys.clone();
                async move { Json(keys) }
            }),
        )
        .route(
            "/token/{kind}",
            get(move |Path(kind): Path<String>| {
                let tokens = tokens.clone();
                async move { Json(serde_json::json!({"id_token":tokens[&kind]})) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        axum::serve(listener, mock).await.expect("mock server");
    });
    match &mut test
        .app
        .endpoints
        .get_mut(&Provider::Google)
        .expect("Google facts")
        .identity
    {
        IdentityStrategy::Google(protocol) => {
            protocol.keys = KeyCache::new(
                format!("{base}/keys").parse().expect("mock key URL"),
                reqwest::Client::new(),
            );
        }
        IdentityStrategy::GitHub(_) => panic!("Google must use signed ID tokens"),
    }
    let response = test
        .app
        .client
        .get(format!("{base}/token/valid"))
        .send()
        .await
        .expect("valid response");
    let identity = test
        .app
        .google_identity(
            response,
            "test-client",
            "test-nonce",
            test.google_protocol(),
        )
        .await
        .expect("valid Google identity without email");
    assert_eq!(identity.subject, "12345");
    assert!(identity.email.is_none());
    for (kind, nonce, expected) in [
        ("valid", "wrong-nonce", "nonce does not match"),
        ("wrong-audience", "test-nonce", "not for this client"),
        ("expired", "test-nonce", "has expired"),
        ("wrong-signature", "test-nonce", "failed verification"),
    ] {
        let response = test
            .app
            .client
            .get(format!("{base}/token/{kind}"))
            .send()
            .await
            .expect("mock response");
        let error = test
            .app
            .google_identity(response, "test-client", nonce, test.google_protocol())
            .await
            .err()
            .expect("rejected");
        assert!(error.to_string().contains(expected), "{kind}: {error}");
    }
    task.abort();
}

/// Fetching Google's signing keys is a client span of the request that needed them,
/// with its method, host and status only.
#[tokio::test]
async fn google_key_fetch_is_a_client_span_of_its_request() {
    let capture = piquel_telemetry::Telemetry::capture(crate::TELEMETRY_FILTER);
    let rsa = Rs256Key::generate("google-test").expect("RSA test key");
    let token = rsa
        .sign(TokenType::Id, &serde_json::json!({}))
        .expect("signed token");
    let keys = rsa.jwks().clone();
    let mock = Router::new().route("/keys", get(move || async move { Json(keys) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener");
    let url = format!(
        "http://{}/keys?client=secret",
        listener.local_addr().expect("address")
    );
    let task = tokio::spawn(async move {
        axum::serve(listener, mock).await.expect("mock server");
    });
    let cache = KeyCache::new(url.parse().expect("mock key URL"), reqwest::Client::new());
    let jws = piquel_auth::Jws::parse(&token).expect("JWS");
    let request = tracing::info_span!("request");
    cache
        .verify(&jws, Algorithm::Rs256)
        .instrument(request)
        .await
        .expect("verified");
    task.abort();

    let spans = capture.spans();
    let request = spans
        .iter()
        .find(|span| span.name == "request")
        .expect("request span");
    let fetch = spans
        .iter()
        .find(|span| span.name == "GET")
        .expect("key fetch span");
    assert_eq!(fetch.parent_span_id, request.span_context.span_id());
    assert_eq!(format!("{:?}", fetch.span_kind), "Client");
    let attributes: Vec<_> = fetch
        .attributes
        .iter()
        .map(|attribute| format!("{}={}", attribute.key, attribute.value))
        .collect();
    for expected in [
        "http.request.method=GET",
        "http.response.status_code=200",
        "server.address=127.0.0.1",
    ] {
        assert!(
            attributes.iter().any(|a| a == expected),
            "{expected}: {attributes:?}"
        );
    }
    assert!(
        !attributes
            .iter()
            .any(|attribute| attribute.contains("/keys") || attribute.contains("secret")),
        "no path or query: {attributes:?}"
    );
    let status = fetch
        .attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == "http.response.status_code")
        .expect("status");
    assert_eq!(
        format!("{:?}", status.value),
        "I64(200)",
        "an integer status"
    );
}

/// ID-token verification rejects malformed claims, untrusted issuers and additional audiences.
#[tokio::test]
async fn google_signed_tokens_require_well_typed_trusted_issuer_and_audience() {
    let rsa = Rs256Key::generate("google-test").expect("RSA key");
    let IdentityStrategy::Google(mut protocol) =
        ProviderEndpoints::new(Provider::Google, &reqwest::Client::new())
            .expect("Google facts")
            .identity
    else {
        panic!("Google must use signed ID tokens");
    };
    protocol.keys = KeyCache::fixed(
        KeySet::parse(&serde_json::to_vec(&rsa.jwks()).expect("JWKS")).expect("key set"),
    );
    let valid = serde_json::json!({"iss":"https://accounts.google.com","aud":"client","sub":"subject","iat":Utc::now().timestamp(),"exp":Utc::now().timestamp()+300,"nonce":"nonce"});
    let verify = async |claims: &serde_json::Value| {
        let token = rsa.sign(TokenType::Id, claims).expect("signed token");
        GoogleClaims::verify(&token, &protocol, "client", "nonce").await
    };
    assert!(verify(&valid).await.is_ok());
    for field in ["iss", "aud", "exp", "sub"] {
        let mut claims = valid.clone();
        claims.as_object_mut().expect("object").remove(field);
        assert!(verify(&claims).await.is_err(), "missing {field}");
        for value in [
            serde_json::Value::Null,
            serde_json::json!(123),
            serde_json::json!({}),
        ] {
            claims[field] = value;
            // Numeric expiry is valid only while it lies in the future; 123 is expired.
            assert!(verify(&claims).await.is_err(), "invalid {field}");
        }
    }
    for audience in [
        serde_json::json!([]),
        serde_json::json!(["client", "untrusted"]),
        serde_json::json!(["client", 123]),
        serde_json::json!("other"),
    ] {
        let mut claims = valid.clone();
        claims["aud"] = audience;
        assert!(verify(&claims).await.is_err());
    }
    let mut claims = valid.clone();
    claims["aud"] = serde_json::json!(["client"]);
    assert!(verify(&claims).await.is_ok());
    claims["iss"] = serde_json::json!("https://untrusted.example");
    assert!(verify(&claims).await.is_err());
    claims = valid;
    claims["azp"] = serde_json::json!("other");
    assert!(verify(&claims).await.is_err());
}

/// Resolved credentials fail at startup with variable context and the original source.
#[test]
fn provider_secrets_fail_early_with_context() {
    let path = std::env::temp_dir().join(format!("piquel-provider-secret-{}", TokenId::new()));
    let config = || ProviderConfig::test(&path);
    let error = config()
        .resolve(Provider::GitHub)
        .err()
        .expect("missing file rejected");
    assert!(
        error
            .to_string()
            .starts_with(ProviderConfig::variables(Provider::GitHub).1.name())
    );
    assert!(std::error::Error::source(&error).is_some());
    for contents in [b"".as_slice(), &[0xff]] {
        std::fs::write(&path, contents).expect("secret file");
        assert!(config().resolve(Provider::Google).is_err());
    }
    std::fs::write(&path, "secret").expect("secret file");
    let resolved = config().resolve(Provider::Google).expect("valid secret");
    std::fs::remove_file(path).expect("remove secret");
    assert_eq!(resolved.client_secret.expose_secret(), b"secret");
}
