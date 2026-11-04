//! The account API's picture upload, through the whole service, and importing a
//! provider's picture into an account.

use super::PictureError;
use crate::{
    account::{AccountError, AccountService},
    deliveries::OutboundClient,
    federation::ProviderPicture,
    routes::pictures,
    security::{CSRF_HEADER, RequestContext},
    tests::{AUTH_ORIGIN, Browser, MAX_RESPONSE_BYTES, Replicas, TlsListener, detailed_png},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    routing::get,
};
use piquel_common::events::Actor;
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

/// A signup's provider picture becomes the account's first picture; a second
/// import leaves a picture the account already has; a picture that is not there
/// fails, changing nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_provider_picture_is_imported_once() {
    let database = Replicas::database().await;
    let user = Browser::new_account(&database).await.user_id;
    let png = |side| {
        let mut png = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(side, side)
            .write_to(&mut png, image::ImageFormat::Png)
            .expect("PNG");
        png.into_inner()
    };
    let (first, second) = (png(40), png(80));
    let provider = Router::new()
        .route("/first", get(move || std::future::ready(first.clone())))
        .route("/second", get(move || std::future::ready(second.clone())));
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider");
    let origin = format!(
        "https://localhost:{}",
        tcp.local_addr().expect("address").port()
    );
    let client = OutboundClient::local(TlsListener::serve(tcp, provider));
    let account = AccountService::new(database.clone());
    let context = RequestContext::TEST.actor(Actor::User {
        user_id: user,
        session_id: None,
    });
    let import = async |path: &str| {
        let url = ProviderPicture::local(&format!("{origin}{path}"));
        account.import_picture(&client, user, &context, &url).await
    };
    let current = async || database.pictures().find(user).await.expect("read");

    import("/first").await.expect("imported");
    let imported = current().await.expect("a picture");
    import("/second").await.expect("kept");
    assert_eq!(current().await, Some(imported), "an existing picture stays");

    database.pictures().remove(user).await.expect("remove");
    assert!(matches!(
        import("/missing").await,
        Err(AccountError::Picture(PictureError::Fetch(_)))
    ));
    assert_eq!(current().await, None);
}
