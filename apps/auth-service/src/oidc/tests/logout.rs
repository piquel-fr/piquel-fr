//! Back-channel logout to the clients of an ended session.

use super::*;
use crate::deliveries::{BackchannelLogoutSender, OutboundClient, Sender};
use piquel_common::clients::{ClientOwner, RedirectUri};
use piquel_common::protocol::claims::BACKCHANNEL_LOGOUT_EVENT;
use piquel_repository::BackchannelLogout;
use std::{collections::HashMap, sync::Mutex};

/// A client's back-channel logout endpoint on a local HTTPS port: its URI, a client
/// that reaches it, and the logout tokens it received.
async fn logout_receiver() -> (RedirectUri, OutboundClient, Arc<Mutex<Vec<String>>>) {
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
    let outbound = OutboundClient::local(TlsListener::serve(tcp, receiver));
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
    let response = flow
        .request(
            Method::POST,
            routes::page::LOGOUT,
            &[("client_id", told.id.as_str())],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Other scenarios share the database: send only this session's deliveries.
    let mut sent = Vec::new();
    while let Some(delivery) = flow
        .app
        .database
        .deliveries()
        .claim::<BackchannelLogout>(std::time::Duration::from_mins(1))
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
    let response = flow
        .request(
            Method::POST,
            routes::page::LOGOUT,
            &[("client_id", client.id.as_str())],
            None,
        )
        .await;
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
