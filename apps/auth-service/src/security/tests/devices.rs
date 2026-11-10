//! The device cookie: which sign-ins are a new device's, and the cookie itself.

use super::*;
use crate::tests::Browser;
use axum::http::HeaderValue;
use sourceorigin_common::{events::DomainEvent, notifications::Notification};

/// The `new_device` flags of `user_id`'s sign-ins, oldest first, and the
/// notifications they wrote.
async fn sign_ins(database: &Database, user_id: UserId) -> (Vec<bool>, Vec<Notification>) {
    let events = database
        .events()
        .history_for_user(user_id, 50)
        .await
        .expect("history");
    let flags = events
        .iter()
        .rev()
        .filter_map(|stored| match stored.event.known() {
            Some(DomainEvent::SignedIn { new_device, .. }) => Some(*new_device),
            _ => None,
        })
        .collect();
    let notifications = database
        .notifications()
        .list(user_id, None, 50)
        .await
        .expect("notifications")
        .into_iter()
        .filter_map(|stored| stored.notification)
        .collect();
    (flags, notifications)
}

/// Signs `user_id` in, as `enrolling` says, from a browser sending `cookie`, and
/// returns the cookies the answer sets.
async fn sign_in(
    database: &Database,
    user_id: UserId,
    cookie: Option<&str>,
    enrolling: bool,
) -> Vec<String> {
    let mut headers = HeaderMap::new();
    if let Some(cookie) = cookie {
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(cookie).expect("cookie"),
        );
    }
    let mut tx = database.begin().await.expect("transaction");
    let credential = Credential::Passkey(sourceorigin_common::PasskeyId::new());
    let signed_in = if enrolling {
        Session::sign_in_anew(&mut tx, RequestContext::TEST, &headers, user_id, credential).await
    } else {
        Session::sign_in(&mut tx, RequestContext::TEST, &headers, user_id, credential).await
    }
    .expect("sign-in");
    tx.commit().await.expect("commit");
    let mut response = axum::http::Response::new(());
    signed_in.set_on(&mut response).expect("cookies");
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|cookie| cookie.to_str().expect("text").to_owned())
        .collect()
}

/// The `name=value` of the device cookie among `set`.
fn device(set: &[String]) -> String {
    set.iter()
        .find(|cookie| cookie.starts_with(BrowserCookie::Device.as_str()))
        .and_then(|cookie| cookie.split(';').next())
        .expect("a device cookie")
        .to_owned()
}

/// A browser without a known device cookie signs in as a new device, which
/// notifies the owner; its next sign-in, with the cookie it got, does not.
/// Enrolling, as signing up and a recovery's link do, makes a browser known
/// without an alert.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn only_an_unknown_browser_signs_in_as_a_new_device() {
    let database = crate::tests::Replicas::database().await;
    let user_id = Browser::new_account(&database).await.user_id;
    let first = sign_in(&database, user_id, None, false).await;
    sign_in(&database, user_id, Some(&device(&first)), false).await;
    let enrolled = sign_in(&database, user_id, None, true).await;
    sign_in(&database, user_id, Some(&device(&enrolled)), false).await;
    // A cookie another account's browser holds is new to this one.
    let other = Browser::new_account(&database).await.user_id;
    let elsewhere = sign_in(&database, other, None, true).await;
    sign_in(&database, user_id, Some(&device(&elsewhere)), false).await;
    let (flags, notifications) = sign_ins(&database, user_id).await;
    assert_eq!(flags, [false, true, false, false, false, true]);
    assert_eq!(
        notifications,
        [Notification::NewDeviceSignIn, Notification::NewDeviceSignIn]
    );
    let known = database
        .sessions()
        .known_devices(user_id)
        .await
        .expect("known devices");
    assert_eq!(known.len(), 3, "{known:?}");
}

/// The device cookie is host-only, `Secure`, `HttpOnly` and `SameSite=Lax`, and
/// lives 400 days.
#[test]
fn the_device_cookie_is_a_host_cookie_kept_400_days() {
    let mut response = axum::http::Response::new(());
    BrowserCookie::Device
        .set_on(
            &mut response,
            &sourceorigin_crypto::Secret::generate().expect("secret"),
        )
        .expect("cookie");
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .expect("text");
    assert!(
        cookie.starts_with("__Host-sourceorigin_device="),
        "{cookie}"
    );
    assert!(
        cookie.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=34560000"),
        "{cookie}"
    );
    assert!(!cookie.contains("Domain="), "{cookie}");
}
