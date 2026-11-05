//! The account API's picture upload, through the whole service.

use crate::{
    routes::pictures,
    security::CSRF_HEADER,
    tests::{AUTH_ORIGIN, Browser, MAX_RESPONSE_BYTES, Replicas, detailed_png},
};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use serde_json::Value;
use tower::ServiceExt;

/// `PUT /account/picture` makes the raw body the owner's picture, lifting the API's
/// default body limit for it, and answers the picture as the owner's reads then show
/// it. Without a session it sets none.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_account_api_uploads_a_picture() {
    let replicas = Replicas::new().await;
    let owner = Browser::new_account(&Replicas::database().await).await;
    // As a Piquel page sends it, with the browser's cookies.
    let upload = async |browser: &Browser| {
        let mut request = Request::put(pictures::OWN)
            .header(header::ORIGIN, AUTH_ORIGIN)
            .header(CSRF_HEADER, "1")
            .header(header::CONTENT_TYPE, "image/png");
        request
            .headers_mut()
            .expect("headers")
            .extend(browser.headers());
        let request = request.body(Body::from(detailed_png())).expect("request");
        let response = replicas.a.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice::<Value>(&body).expect("JSON"),
        )
    };

    let (status, refused) = upload(&Browser::signed_out()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");

    let (status, uploaded) = upload(&owner).await;
    assert_eq!(status, StatusCode::OK, "{uploaded}");
    assert!(
        uploaded["url"]
            .as_str()
            .is_some_and(|url| url.starts_with("/pictures/")),
        "{uploaded}"
    );
    let (status, read) = owner.call(&replicas.a, Method::GET, pictures::OWN).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read, uploaded);
}
