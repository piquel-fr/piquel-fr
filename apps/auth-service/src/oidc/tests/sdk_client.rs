//! The Rust SDK's login client against the real provider.

use super::*;

/// The Rust SDK signs in, validates, refreshes, revokes and logs out against the real
/// provider over HTTPS, and rejects a mixed-up callback before any code exchange.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "The scenario follows one login from authorization through logout."
)]
async fn sdk_login_client_runs_against_the_provider() {
    use piquel_auth::{
        AuthorizeRequest, CallbackParams, ClientConfig, Credentials, LoginError, OAuthError,
        Resource, Scopes, Subject,
    };
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider");
    let port = tcp.local_addr().expect("provider address").port();
    let origin = format!("https://localhost:{port}");
    let flow = Flow::at(&origin, true, false).await;
    let certificate = TlsListener::serve(tcp, flow.app.clone().routes());
    let http = reqwest::Client::builder()
        .add_root_certificate(certificate)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client");
    let issuer = piquel_auth::Issuer::builder()
        .http_client(http)
        .discover(&origin)
        .await
        .expect("discover the provider");
    let client = issuer.client(ClientConfig {
        client_id: flow.client.id.clone(),
        credentials: Credentials::Secret(flow.secret.clone().expect("confidential").into()),
        redirect_uri: flow.client.redirect_uris[0]
            .as_str()
            .parse()
            .expect("callback"),
    });
    let (url, pending) = client
        .authorize(&AuthorizeRequest {
            scopes: "profile email offline_access".parse().expect("scopes"),
            ..AuthorizeRequest::default()
        })
        .await
        .expect("authorization URL");

    let mixed_up = CallbackParams {
        code: Some("pac_v1_unused".into()),
        state: Some(pending.state().into()),
        iss: Some("https://evil.example".into()),
        ..CallbackParams::default()
    };
    assert!(matches!(
        client.complete(pending.clone(), &mixed_up).await,
        Err(LoginError::IssuerMismatch { .. })
    ));

    let browser = flow
        .request(
            Method::GET,
            &format!("{}?{}", url.path(), url.query().expect("query")),
            &[],
            None,
        )
        .await;
    let callback = flow.consent(browser).await;
    let parameters: CallbackParams = serde_json::from_value(Value::Object(
        callback
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), Value::String(value.into_owned())))
            .collect(),
    ))
    .expect("callback parameters");
    let tokens = client
        .complete(pending, &parameters)
        .await
        .expect("complete the login");
    let id_token = tokens.id_token.as_ref().expect("ID token");
    assert_eq!(id_token.user_id().expect("account"), flow.user_id);

    let access = issuer
        .resource(Resource::new(flow.client.id.as_str()).expect("resource"))
        .validate::<Scopes>(tokens.access_token.expose())
        .await
        .expect("valid access token");
    assert_eq!(access.subject, Subject::User(flow.user_id));
    assert!(access.scopes.contains(Scope::OfflineAccess.as_str()));

    let user = client
        .userinfo(&tokens.access_token, id_token.claims())
        .await
        .expect("UserInfo");
    assert_eq!(user.sub, flow.user_id.to_string());
    assert!(user.profile.email.is_some());

    // A confidential client keeps its refresh token, so a refresh returns none. Auth
    // carries the sign-in over to the refreshed ID token (OIDC Core §12.2), which
    // the SDK requires.
    let first = tokens.refresh_token.expect("refresh token");
    let refreshed = client
        .refresh(&first, id_token.claims())
        .await
        .expect("refresh");
    assert!(refreshed.id_token.is_some());
    assert!(refreshed.refresh_token.is_none());
    client.revoke(&first).await.expect("revoke");
    assert!(matches!(
        client.refresh(&first, id_token.claims()).await,
        Err(OAuthError::Rejected { response, .. })
            if response.error == OAuthCode::InvalidGrant
    ));

    let post_logout: Url = flow.client.post_logout_uris[0]
        .as_str()
        .parse()
        .expect("post-logout URI");
    let logout = client.logout_url(Some(id_token), Some(&post_logout));
    let confirmation = location(
        &flow
            .request(
                Method::GET,
                &format!("{}?{}", logout.path(), logout.query().expect("query")),
                &[],
                None,
            )
            .await,
    );
    assert_eq!(confirmation.path(), routes::page::LOGOUT);
    let fields: Vec<(String, String)> = confirmation.query_pairs().into_owned().collect();
    let fields: Vec<_> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let confirmed = flow
        .request(Method::POST, routes::page::LOGOUT, &fields, None)
        .await;
    assert_eq!(location(&confirmed), post_logout);
}
