//! Back-channel logout to the clients of an ended session.

use super::*;
use crate::deliveries::{BackchannelLogoutSender, OutboundClient, Sender};
use sourceorigin_common::SessionId;
use sourceorigin_common::clients::{BackchannelLogoutUri, ClientOwner};
use sourceorigin_common::protocol::claims::BACKCHANNEL_LOGOUT_EVENT;
use sourceorigin_repository::BackchannelLogout;
use std::{collections::HashMap, sync::Mutex};

/// A client's back-channel logout endpoint on a local HTTPS port: its URI, a client
/// that reaches it, and the logout tokens it received.
async fn logout_receiver() -> (
    BackchannelLogoutUri,
    OutboundClient,
    Arc<Mutex<Vec<String>>>,
) {
    let posted = Arc::new(Mutex::new(Vec::new()));
    let receiver = axum::Router::new().route(
        "/backchannel-logout",
        axum::routing::post({
            let posted = Arc::clone(&posted);
            async move |axum::Form(form): axum::Form<HashMap<String, String>>| {
                posted
                    .lock()
                    .expect("posted tokens")
                    .push(form["logout_token"].clone());
                StatusCode::OK
            }
        }),
    );
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind receiver");
    let uri = format!(
        "https://localhost:{}/backchannel-logout",
        tcp.local_addr().expect("address").port()
    )
    .parse()
    .expect("logout URI");
    let outbound =
        OutboundClient::local(TlsListener::serve(tcp, receiver)).expect("local outbound client");
    (uri, outbound, posted)
}

/// Ending a session posts a logout token to each client that received tokens from it
/// and registered a back-channel logout URI (OIDC Back-Channel Logout 1.0 §2.4):
/// signed as `logout+jwt`, naming the client, the user and the ended session, with
/// the delivery's ID as `jti`, valid for two minutes, and never with a `nonce`. A
/// client that got no tokens from the session is not told.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn logout_posts_a_logout_token_to_the_clients_of_the_session() {
    let flow = Flow::new(true, true).await;
    let (uri, outbound, posted) = logout_receiver().await;
    let sender =
        BackchannelLogoutSender::new(flow.app.issuer.clone(), flow.app.keys.clone(), outbound);
    let told = ClientRegistration {
        backchannel_logout_uri: Some(uri.clone()),
        ..flow.client.clone()
    };
    let untold = ClientRegistration {
        backchannel_logout_uri: Some(uri),
        ..crate::tests::registration(ClientKind::Public, "https://untold.example")
    };
    crate::tests::change(&flow.app.database, async |registry| {
        registry
            .update(&told.id, |_| {
                Ok::<_, crate::ClientRegistryError>(told.clone())
            })
            .await?;
        // A client without tokens from the session.
        registry.create(ClientOwner::Operator, &untold, None).await
    })
    .await
    .expect("register the logout URIs");
    let code = flow.code(Scope::OpenId.as_str()).await;
    let (_, id_token) = flow
        .id_token(
            flow.exchange(&code, Flow::verifier(), flow.basic.as_deref())
                .await,
        )
        .await;
    let response = flow.log_out(&[("client_id", told.id.as_str())]).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Other scenarios share the database: send only this session's deliveries.
    let mut sent = Vec::new();
    while let Some(delivery) = flow
        .app
        .database
        .deliveries()
        .claim::<BackchannelLogout>(
            std::time::Duration::from_mins(1),
            BackchannelLogoutSender::MAX_AGE,
        )
        .await
        .expect("claim")
    {
        if delivery.recipient.sid.to_string() == id_token["sid"] {
            sender.send(&delivery).await.expect("the client accepts it");
            sent.push((delivery.id, delivery.recipient.client_id));
        }
    }
    let [(delivery, client)] =
        <[_; 1]>::try_from(sent).expect("one delivery for the one client told");
    assert_eq!(client, told.id);
    let [token] = <[_; 1]>::try_from(posted.lock().expect("posted tokens").clone())
        .expect("one token posted");
    let claims: Value = flow
        .app
        .keys
        .current()
        .expect("fresh keys")
        .verify(&token, TokenType::Logout, &flow.app.issuer)
        .expect("a logout token signed by auth");
    let issued_at = claims["iat"].as_i64().expect("iat");
    assert!(
        (issued_at - Utc::now().timestamp()).abs() < 60,
        "signed when sent"
    );
    assert_eq!(
        claims,
        json!({
            "iss": flow.app.issuer,
            "aud": told.id,
            "iat": issued_at,
            "exp": issued_at + 120,
            "jti": delivery,
            "sub": flow.user_id,
            "sid": id_token["sid"],
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        })
    );
}

/// A client whose code redemption failed received nothing from the session, so the
/// session's logout tells it nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_failed_redemption_leaves_the_client_out_of_logout() {
    let flow = Flow::new(true, true).await;
    let (uri, _, _) = logout_receiver().await;
    let client = ClientRegistration {
        backchannel_logout_uri: Some(uri.clone()),
        ..flow.client.clone()
    };
    crate::tests::replace(&flow.app.database, &client)
        .await
        .expect("register the logout URI");
    let code = flow.code(Scope::OpenId.as_str()).await;
    let response = flow.exchange(&code, "wrong", flow.basic.as_deref()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = flow.log_out(&[("client_id", client.id.as_str())]).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let queued = flow
        .app
        .database
        .deliveries()
        .payloads(uri.as_str())
        .await
        .expect("deliveries");
    assert!(queued.is_empty(), "{queued:?}");
}

/// A deleted client hears of no logout, though it received tokens from the session.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_deleted_client_is_left_out_of_logout() {
    let flow = Flow::new(true, true).await;
    let (uri, _, _) = logout_receiver().await;
    let client = ClientRegistration {
        backchannel_logout_uri: Some(uri.clone()),
        ..flow.client.clone()
    };
    crate::tests::replace(&flow.app.database, &client)
        .await
        .expect("register the logout URI");
    let code = flow.code(Scope::OpenId.as_str()).await;
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    crate::tests::change(&flow.app.database, async |registry| {
        registry.delete(&client.id).await
    })
    .await
    .expect("delete the client");
    assert_eq!(flow.log_out(&[]).await.status(), StatusCode::SEE_OTHER);

    let queued = flow
        .app
        .database
        .deliveries()
        .payloads(uri.as_str())
        .await
        .expect("deliveries");
    assert!(queued.is_empty(), "{queued:?}");
}

/// The scenario's ID token, from a fresh code exchange, and its `sid`.
async fn id_token(flow: &Flow) -> (String, SessionId) {
    let code = flow.code(Scope::OpenId.as_str()).await;
    let (tokens, claims) = flow
        .id_token(
            flow.exchange(&code, Flow::verifier(), flow.basic.as_deref())
                .await,
        )
        .await;
    let sid = claims["sid"]
        .as_str()
        .expect("sid")
        .parse()
        .expect("session ID");
    (
        tokens["id_token"].as_str().expect("ID token").to_owned(),
        sid,
    )
}

/// An ID token alone never ends a session with a cookie: confirming a logout
/// from another browser, with no cookie at auth, leaves the session its hint
/// names. Only an application's inline sign-in, which has none, ends by its hint.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_hint_never_ends_a_session_with_a_cookie() {
    let flow = Flow::new(true, true).await;
    let (hint, sid) = id_token(&flow).await;
    let elsewhere = Flow {
        cookie: String::new(),
        ..flow.clone()
    };
    let response = elsewhere
        .log_out(&[
            ("id_token_hint", &hint),
            ("client_id", flow.client.id.as_str()),
        ])
        .await;
    assert_eq!(location(&response).path(), routes::page::LOGIN);
    let session = flow
        .app
        .database
        .sessions()
        .find_active_by_id(sid)
        .await
        .expect("session lookup");
    assert!(session.is_some(), "the cookie session stays");
}

/// A hint auth can't verify doesn't block the logout: the page says so, and the
/// browser stays on auth, rather than going to the redirect the request named.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_unverifiable_hint_still_signs_out_and_stays_on_auth() {
    let flow = Flow::new(true, true).await;
    let fields = [
        ("id_token_hint", "eyJhbGciOiJSUzI1NiJ9.e30.forged"),
        ("client_id", flow.client.id.as_str()),
        (
            "post_logout_redirect_uri",
            flow.client.post_logout_uris[0].as_str(),
        ),
    ];
    assert!(
        flow.logout_page(&fields)
            .await
            .contains("couldn’t verify the app’s request")
    );
    let browser = flow.owner().await.session().id;
    let response = flow.log_out(&fields).await;
    assert_eq!(location(&response).path(), routes::page::LOGIN);
    assert!(
        flow.app
            .database
            .sessions()
            .find_active_by_id(browser)
            .await
            .expect("session lookup")
            .is_none(),
        "the browser signed out"
    );
}

/// A hint naming another account than the browser's is shown on the page. An
/// application posts its request cross-site, without auth's cookie, so its page
/// can't tell: confirming then shows the warning, and signs out only once the
/// page warned.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_hint_naming_another_account_says_so() {
    let flow = Flow::new(true, true).await;
    let (hint, sid) = id_token(&flow).await;
    let other = crate::tests::Browser::new_account(&flow.app.database).await;
    let elsewhere = Flow {
        cookie: other.cookie,
        ..flow.clone()
    };
    let fields = [("id_token_hint", hint.as_str())];
    let page = elsewhere.logout_page(&fields).await;
    assert!(page.contains("a different account"), "{page}");

    let cross_site = Flow {
        cookie: String::new(),
        ..flow.clone()
    };
    let page = cross_site.logout_page(&fields).await;
    assert!(!page.contains("a different account"), "{page}");
    let warned = elsewhere
        .request(Method::POST, routes::page::LOGOUT, &fields, None)
        .await;
    assert_eq!(warned.status(), StatusCode::OK);
    let page = Flow::text(warned).await;
    assert!(page.contains("a different account"), "{page}");
    assert!(page.contains(r#"name="warned""#), "{page}");
    let database = &flow.app.database;
    let active = |session| async move {
        database
            .sessions()
            .find_active_by_id(session)
            .await
            .expect("session lookup")
            .is_some()
    };
    assert!(active(sid).await, "nothing ended before the warning");
    assert!(
        active(other.session_id).await,
        "nothing ended before the warning"
    );

    let signed_out = elsewhere
        .request(
            Method::POST,
            routes::page::LOGOUT,
            &[
                ("id_token_hint", hint.as_str()),
                ("warned", "another_account"),
            ],
            None,
        )
        .await;
    assert_eq!(signed_out.status(), StatusCode::SEE_OTHER);
    assert!(
        active(sid).await,
        "the hinted session has a cookie, so it stays"
    );
    assert!(!active(other.session_id).await, "the browser signed out");
}
