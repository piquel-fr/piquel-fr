//! The sign-in pages' query.
use super::*;

/// A field an old or edited link gets wrong reads as absent, never losing where
/// the browser goes on to; the invitation's old name still reads.
#[test]
fn a_wrong_field_keeps_the_rest_of_the_query() {
    let query: LoginQuery = serde_urlencoded::from_str(
        "transaction=t&acr=gold&return_to=%2Fsettings&invite=i&error=nope&social=maybe&handle=",
    )
    .expect("query");
    assert_eq!(
        query,
        LoginQuery {
            transaction: Some("t".into()),
            return_to: Some("/settings".into()),
            invitation: Some("i".into()),
            handle: Checkbox(true),
            ..LoginQuery::default()
        }
    );
    let known: LoginQuery =
        serde_urlencoded::from_str("acr=phr&error=social_failed&social=link").expect("query");
    assert_eq!(
        (known.acr, known.error, known.social),
        (
            Some(Acr::PhishingResistant),
            Some(CallbackError::Failed),
            Some(PendingDestination::Link)
        )
    );
    assert_eq!(
        known.on("/login").expect("link"),
        "/login?acr=phr&error=social_failed&social=link"
    );
}
