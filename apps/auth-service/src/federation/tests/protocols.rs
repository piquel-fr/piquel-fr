//! Provider protocols: credential resolution and Google ID-token verification.

use super::*;
use crate::federation::providers::{GoogleClaims, GoogleProtocol};
use sourceorigin_auth::{KeyCache, KeySet};
use sourceorigin_common::protocol::jwt::{Algorithm, TokenType};
use sourceorigin_crypto::Rs256Key;
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

/// A key cache fetching `path` from `router`, served over TLS on localhost, since the
/// SDK fetches keys only over https.
async fn tls_keys(router: Router, path: &str) -> KeyCache {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock TLS listener");
    let url = format!(
        "https://localhost:{}{path}",
        tcp.local_addr().expect("address").port()
    );
    let certificate = crate::tests::TlsListener::serve(tcp, router);
    KeyCache::new(
        url.parse().expect("mock key URL"),
        reqwest::Client::builder().add_root_certificate(certificate),
    )
    .expect("mock key cache")
}

/// Google's code-exchange response yields the identity its ID token vouches for,
/// which needs no email. `google_signed_tokens_are_verified` covers the token's
/// checks.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn google_token_responses_yield_identities_without_email() {
    let mut test = TestApp::new().await;
    let rsa = Rs256Key::generate("google-test").expect("RSA test key");
    let token = rsa
        .sign(
            TokenType::Id,
            &serde_json::json!({"iss":"https://accounts.google.com","sub":"12345","aud":"test-client","iat":Utc::now().timestamp(),"exp":Utc::now().timestamp()+300,"nonce":"test-nonce"}),
        )
        .expect("signed token");
    let mock = Router::new().route(
        "/token",
        get(move || async move { Json(serde_json::json!({"id_token":token})) }),
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
            protocol.keys = KeyCache::fixed(
                KeySet::parse(&serde_json::to_vec(&rsa.jwks()).expect("JWKS")).expect("key set"),
            );
        }
        IdentityStrategy::GitHub(_) => panic!("Google must use signed ID tokens"),
    }
    let response = test
        .app
        .client
        .get(format!("{base}/token"))
        .send()
        .await
        .expect("token response");
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
    task.abort();
}

/// Fetching Google's signing keys is a client span of the request that needed them,
/// with its method, host and status only.
#[tokio::test]
async fn google_key_fetch_is_a_client_span_of_its_request() {
    let capture = sourceorigin_telemetry::Telemetry::capture(crate::TELEMETRY_FILTER);
    let rsa = Rs256Key::generate("google-test").expect("RSA test key");
    let token = rsa
        .sign(TokenType::Id, &serde_json::json!({}))
        .expect("signed token");
    let keys = rsa.jwks().clone();
    let mock = Router::new().route("/keys", get(move || async move { Json(keys) }));
    let cache = tls_keys(mock, "/keys?client=secret").await;
    let jws = sourceorigin_auth::Jws::parse(&token).expect("JWS");
    let request = tracing::info_span!("request");
    cache
        .verify(&jws, Algorithm::Rs256)
        .instrument(request)
        .await
        .expect("verified");

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
        "server.address=localhost",
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

/// ID-token verification rejects untrusted signatures, malformed claims, untrusted
/// issuers, other or additional audiences, another nonce, and tokens expired or
/// issued in the future.
#[tokio::test]
async fn google_signed_tokens_are_verified() {
    let rsa = Rs256Key::generate("google-test").expect("RSA key");
    let IdentityStrategy::Google(mut protocol) = ProviderEndpoints::new(Provider::Google)
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
    let untrusted = Rs256Key::generate("google-test").expect("untrusted key");
    let token = untrusted.sign(TokenType::Id, &valid).expect("signed token");
    assert_eq!(
        GoogleClaims::verify(&token, &protocol, "client", "nonce")
            .await
            .map_err(|error| error.to_string())
            .err()
            .as_deref(),
        Some("Google ID token failed verification")
    );
    for (field, value, error) in [
        (
            "nonce",
            serde_json::json!("other"),
            "Google ID token nonce does not match this sign-in attempt",
        ),
        (
            "iat",
            serde_json::json!(Utc::now().timestamp() + 3600),
            "Google ID token is issued in the future",
        ),
        // Expiry has no leeway: a token that expired a second ago is refused.
        (
            "exp",
            serde_json::json!(Utc::now().timestamp() - 1),
            "Google ID token has expired",
        ),
    ] {
        let mut claims = valid.clone();
        claims[field] = value;
        assert_eq!(
            verify(&claims)
                .await
                .map_err(|error| error.to_string())
                .err()
                .as_deref(),
            Some(error),
            "{field}"
        );
    }
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

/// Google vouches only for the addresses it hosts, Gmail's and its Workspace
/// domain's, and only once it verified them.
#[test]
fn google_is_authoritative_only_for_verified_addresses_it_hosts() {
    let authoritative = |email: &str, verified: bool, hd: Option<&str>| {
        serde_json::from_value::<GoogleClaims>(serde_json::json!({
            "iss": "https://accounts.google.com", "aud": "client", "sub": "subject",
            "iat": 0, "exp": 0, "nonce": "nonce",
            "email": email, "email_verified": verified, "hd": hd,
        }))
        .expect("claims")
        .authoritative()
    };
    assert!(authoritative("ada@gmail.com", true, None));
    assert!(authoritative("ada@Example.com", true, Some("example.com")));
    assert!(!authoritative("ada@gmail.com", false, None));
    assert!(!authoritative("ada@example.com", true, None));
    assert!(!authoritative(
        "ada@example.com",
        true,
        Some("other.example")
    ));
    assert!(!authoritative(
        "ada@sub.example.com",
        true,
        Some("example.com")
    ));
}

/// Resolved credentials fail at startup with variable context and the original source.
#[test]
fn provider_secrets_fail_early_with_context() {
    let path =
        std::env::temp_dir().join(format!("sourceorigin-provider-secret-{}", TokenId::new()));
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

/// A provider's picture is kept only on its own picture host, over HTTPS, and
/// asks for the stored size.
#[test]
fn provider_pictures_stay_on_the_provider_s_host() {
    let parsed = |provider, url: &str| {
        ProviderPicture::parse(provider, url).map(|picture| picture.as_str().to_owned())
    };
    assert_eq!(
        parsed(
            Provider::GitHub,
            "https://avatars.githubusercontent.com/u/1?v=4&s=40"
        )
        .as_deref(),
        Some("https://avatars.githubusercontent.com/u/1?v=4&s=512")
    );
    assert_eq!(
        parsed(
            Provider::Google,
            "https://lh3.googleusercontent.com/a/ACg8oc=s96-c"
        )
        .as_deref(),
        Some("https://lh3.googleusercontent.com/a/ACg8oc=s512-c")
    );
    for (provider, url) in [
        (Provider::GitHub, "http://avatars.githubusercontent.com/u/1"),
        (
            Provider::GitHub,
            "https://avatars.githubusercontent.com:8443/u/1",
        ),
        (
            Provider::GitHub,
            "https://user@avatars.githubusercontent.com/u/1",
        ),
        (
            Provider::GitHub,
            "https://avatars.githubusercontent.com.example/u/1",
        ),
        (
            Provider::GitHub,
            "https://lh3.googleusercontent.com/a/x=s96-c",
        ),
        (
            Provider::Google,
            "https://avatars.githubusercontent.com/u/1",
        ),
        (
            Provider::Google,
            "https://googleusercontent.com.example/a=s96-c",
        ),
        (Provider::Google, "https://127.0.0.1/a=s96-c"),
        (Provider::Google, "not a URL"),
    ] {
        assert_eq!(parsed(provider, url), None, "{url}");
    }
    let long = format!("https://avatars.githubusercontent.com/{}", "a".repeat(2048));
    assert_eq!(parsed(Provider::GitHub, &long), None);
    // Within the limit as reported, past it once it asks for the size.
    let host = "https://avatars.githubusercontent.com/";
    let near = format!("{host}{}", "a".repeat(2048 - host.len()));
    assert_eq!(parsed(Provider::GitHub, &near), None);
}
