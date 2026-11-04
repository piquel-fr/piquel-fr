//! Telemetry of a sign-in and code exchange exports no secret.

use super::*;

impl Fixture {
    /// Signs in with the passkey, and returns the session cookie pair and every
    /// secret the ceremony carried: its cookie and ID, the challenge and signature.
    async fn login_with_secrets(&mut self) -> (String, Vec<String>) {
        let username = json!({"handle": self.username});
        let (started, browser) = self
            .start("/webauthn/authenticate/start", "", username)
            .await;
        let assertion = self.assertion(&started);
        let signature =
            serde_json::to_value(&assertion).expect("assertion")["response"]["signature"]
                .as_str()
                .expect("signature")
                .to_owned();
        let finished = self
            .request(
                "/webauthn/authenticate/finish",
                Method::POST,
                &browser,
                json!({"ceremony_id": started["ceremony_id"], "credential": assertion}),
            )
            .await;
        assert_eq!(finished.status(), StatusCode::NO_CONTENT);
        let session = Self::cookie(&finished);
        let cookie = |pair: &str| pair.split_once('=').expect("cookie pair").1.to_owned();
        let secrets = vec![
            cookie(&session),
            cookie(&browser),
            started["ceremony_id"]
                .as_str()
                .expect("ceremony")
                .to_owned(),
            started["public_key"]["publicKey"]["challenge"]
                .as_str()
                .expect("challenge")
                .to_owned(),
            signature,
        ];
        (session, secrets)
    }

    /// Authorizes the trusted `client` for the browser holding `session`, exchanges
    /// the code, and returns every secret the flow carried: the authorization
    /// query's state, nonce and PKCE challenge, the code, its verifier and the tokens.
    async fn exchange_with_secrets(
        &self,
        session: &str,
        client: &piquel_common::clients::ClientRegistration,
    ) -> Vec<String> {
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let challenge = piquel_crypto::Pkce::challenge(verifier).expect("PKCE");
        let mut authorize = Url::parse(&format!("{AUTH_ORIGIN}/oauth/authorize")).expect("URL");
        authorize.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", client.id.as_str()),
            ("redirect_uri", client.redirect_uris[0].as_str()),
            ("scope", "openid offline_access"),
            ("state", "state-in-the-query"),
            ("nonce", "nonce-in-the-query"),
            ("code_challenge_method", "S256"),
            ("code_challenge", &challenge),
        ]);
        let send = |request: Request<Body>| self.router.clone().oneshot(request);
        let authorized = send(
            Request::builder()
                .uri(format!(
                    "{}?{}",
                    authorize.path(),
                    authorize.query().expect("query")
                ))
                .header(header::COOKIE, session)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(authorized.status(), StatusCode::SEE_OTHER);
        let redirect = Url::parse(
            authorized.headers()[header::LOCATION]
                .to_str()
                .expect("location"),
        )
        .expect("redirect");
        let code = redirect
            .query_pairs()
            .find(|(name, _)| name == "code")
            .expect("code")
            .1
            .into_owned();
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("client_id", client.id.as_str()),
                ("redirect_uri", client.redirect_uris[0].as_str()),
                ("code", &code),
                ("code_verifier", verifier),
            ])
            .finish();
        let exchanged = send(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(exchanged.status(), StatusCode::OK);
        let tokens = Self::json(exchanged).await;
        let mut secrets = vec![
            "state-in-the-query".to_owned(),
            "nonce-in-the-query".to_owned(),
            challenge,
            code,
            verifier.to_owned(),
        ];
        for token in ["access_token", "id_token", "refresh_token"] {
            secrets.push(tokens[token].as_str().expect("token").to_owned());
        }
        secrets
    }
}

/// A passkey sign-in, then an authorization code exchanged for tokens, through
/// replicas of the whole service, export no secret: no cookie, ceremony, `WebAuthn`
/// challenge or assertion, authorization query, code, PKCE verifier or token. Each
/// request is one trace holding its queries, and the events it records are logged
/// in it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn telemetry_exports_no_secret_of_a_sign_in_and_code_exchange() {
    use piquel_telemetry::Telemetry;

    let capture = Telemetry::capture(crate::TELEMETRY_FILTER);
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    let client = piquel_common::clients::ClientRegistration {
        trusted: true,
        ..crate::tests::registration(
            piquel_common::clients::ClientKind::Public,
            "https://client.example",
        )
    };
    crate::tests::register(&fixture.app.database, &client)
        .await
        .expect("client");
    let (session, mut secrets) = fixture.on(&replicas.a).login_with_secrets().await;
    secrets.extend(
        fixture
            .on(&replicas.b)
            .exchange_with_secrets(&session, &client)
            .await,
    );
    let exported = capture.exported_text();
    for secret in &secrets {
        assert!(
            exported.iter().all(|text| !text.contains(secret.as_str())),
            "telemetry exported {secret}"
        );
    }

    let spans = capture.spans();
    let exchange = spans
        .iter()
        .find(|span| span.name == "POST /oauth/token")
        .expect("token request span");
    let trace = exchange.span_context.trace_id();
    assert!(
        spans.iter().any(|span| {
            span.span_context.trace_id() == trace
                && span
                    .attributes
                    .iter()
                    .any(|attribute| attribute.key.as_str() == "db.query.text")
        }),
        "the exchange's queries are spans of its trace"
    );
    let logged = capture
        .logs()
        .into_iter()
        .find(|log| {
            log.attributes_iter().any(|(key, value)| {
                key.as_str() == "event.kind" && format!("{value:?}").contains("grant_issued")
            })
        })
        .expect("the issued grant is logged");
    assert_eq!(
        logged.trace_context().map(|context| context.trace_id),
        Some(trace),
        "the event's log line links to the exchange's trace"
    );
}
