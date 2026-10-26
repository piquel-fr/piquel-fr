//! The sign-in pages through the whole service, as a browser uses them.

use super::Continuation;
use crate::{
    AuthConfig,
    federation::ReturnTo,
    routes::page::{LOGIN, REGISTER, settings},
    security::BrowserCookie,
    tests::{
        AUTH_ORIGIN, Browser, OWN_PAGE, Replicas, location, parameter, pending_sign_in, redirect,
        register, registration, unusable_passkey,
    },
    web::tests::{authorize, cookie, html, policy, value_after},
};
use axum::http::{StatusCode, header};
use piquel_common::{
    AuthenticationMethod, Provider, UserId,
    clients::{ClientKind, ClientRegistration},
};
use piquel_crypto::Secret;
use piquel_repository::{Database, PendingFederation};
use piquel_ui::{Checkbox, LoginChange, LoginQuery, PendingDestination, Query};
use url::Position;

/// The test service's configuration, which `invite_required` needs or not.
fn config(invite_required: bool) -> AuthConfig {
    let mut config = AuthConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"));
    config.passkey.invite_required = invite_required;
    config
}

/// The sign-in page `page` with `query`, as its links and forms write it.
fn link(page: &str, query: &LoginQuery) -> String {
    query.on(page).expect("link")
}

/// The sign-in page's address waiting on the provider's sign-in, for `social`, going
/// on to `return_to`.
fn waiting(social: PendingDestination, return_to: &str) -> String {
    let query = LoginQuery {
        return_to: Some(return_to.to_owned()),
        social: Some(social),
        ..LoginQuery::default()
    };
    link(LOGIN, &query)
}

/// `href` as an attribute writes it.
fn attribute(href: &str) -> String {
    href.replace('&', "&amp;")
}

/// A GitHub sign-in waiting in a new browser, as `pending` describes it, and the
/// cookie's value, which holds its secret.
async fn pending(
    database: &Database,
    pending: impl FnOnce(PendingFederation) -> PendingFederation,
) -> (PendingFederation, String) {
    let secret = Secret::generate().expect("browser secret");
    let evidence = pending(pending_sign_in(&secret));
    database
        .federation()
        .insert_pending(&evidence)
        .await
        .expect("pending sign-in");
    (evidence, secret.encoded())
}

/// Gives `user_id`'s account a passkey, which linking requires.
async fn passkey(database: &Database, user_id: UserId) {
    database
        .passkeys()
        .insert(&unusable_passkey(user_id))
        .await
        .expect("passkey");
}

/// How many times `page` says `text`.
fn count(page: &str, text: &str) -> usize {
    page.matches(text).count()
}

/// A provider's sign-in started for an application returns to the path resuming
/// its authorization, which continues it again. A path that is not auth's goes to
/// the settings. The query's authorization comes first, then where a pending
/// sign-in returns to, then the query's path.
#[test]
fn a_provider_sign_in_continues_the_authorization_it_started_for() {
    let authorization = Continuation::Authorization("ar_pending".into());
    let resume = authorization.return_to().expect("path");
    assert_eq!(resume, "/oauth/authorize/resume?transaction=ar_pending");
    assert_eq!(Continuation::parse(Some(&resume)), authorization);
    let query = |transaction: Option<&str>| LoginQuery {
        transaction: transaction.map(str::to_owned),
        return_to: Some(settings::EMAILS.to_owned()),
        ..LoginQuery::default()
    };
    let pending = Some(settings::SESSIONS);
    assert_eq!(
        Continuation::new(&query(Some("ar_pending")), pending),
        authorization
    );
    assert_eq!(
        Continuation::new(&query(None), pending),
        Continuation::Path(ReturnTo::parse(pending).expect("path"))
    );
    assert_eq!(
        Continuation::new(&query(None), Some(&resume)),
        authorization
    );
    for elsewhere in [Some("//evil.example"), Some("https://evil.example"), None] {
        assert_eq!(
            Continuation::parse(elsewhere),
            Continuation::Path(ReturnTo::default()),
            "{elsewhere:?}"
        );
    }
}

/// The sign-in page offers one passkey button, the enabled providers' and a handle;
/// once the handle is asked for, the form takes it. Its forms may redirect to the
/// providers, and its link to create an account keeps where the browser goes on to.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_in_offers_passkeys_providers_and_a_handle() {
    let replicas = Replicas::with_github(config(false)).await;
    let browser = Browser::signed_out();
    let query = LoginQuery {
        return_to: Some(settings::SESSIONS.to_owned()),
        ..LoginQuery::default()
    };
    let response = browser.visit(&replicas.a, &link(LOGIN, &query)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let policy = policy(&response).to_owned();
    assert!(
        policy.ends_with("; form-action 'self' https://github.com"),
        "{policy}"
    );
    let page = html(response).await;
    assert!(page.contains("<title>Sign in · Piquel</title>"), "{page}");
    assert!(page.contains("<h1>Welcome back.</h1>"), "{page}");
    assert!(
        page.contains("Sign in with a passkey, or use a linked social account."),
        "{page}"
    );
    let action = attribute(&link(LOGIN, &query));
    assert!(
        page.contains(&format!(
            r#"<form class="stack" method="post" action="{action}" data-passkey-sign-in="">"#
        )),
        "{page}"
    );
    assert!(
        page.contains(r#"<input type="hidden" name="action" value="signed_in">"#),
        "{page}"
    );
    assert_eq!(
        count(&page, ">Sign in with a passkey</button>"),
        1,
        "{page}"
    );
    assert!(
        page.contains(r#"<div class="divider">or continue with</div>"#),
        "{page}"
    );
    assert!(
        page.contains(r#"<input type="hidden" name="provider" value="github">"#),
        "{page}"
    );
    assert!(page.contains(">GitHub</button>"), "{page}");
    assert!(page.contains(">Use a handle instead</button>"), "{page}");
    assert!(!page.contains(r#"name="username""#), "{page}");
    let register = attribute(&link(REGISTER, &query));
    assert!(
        page.contains(&format!(
            r#"New to Piquel? <a href="{register}">Create an account</a>"#
        )),
        "{page}"
    );

    let handle = LoginQuery {
        handle: Checkbox(true),
        ..query
    };
    let page = html(browser.visit(&replicas.a, &link(LOGIN, &handle)).await).await;
    assert!(
        page.contains(r#"name="username" autocomplete="username webauthn""#),
        "{page}"
    );
    assert!(page.contains(">Handle<"), "{page}");
    assert!(!page.contains("Use a handle instead"), "{page}");
    assert_eq!(
        count(&page, ">Sign in with a passkey</button>"),
        1,
        "{page}"
    );
}

/// Once the SDK signed the browser in, its form sends it on to the path on auth it
/// asked for, or to the settings when it asked for none or for another site.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_in_goes_on_to_the_path_asked_for() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    for (return_to, to) in [
        (Some(settings::SESSIONS), settings::SESSIONS),
        (Some("https://evil.example"), settings::HOME),
        (None, settings::HOME),
    ] {
        let query = LoginQuery {
            return_to: return_to.map(str::to_owned),
            ..LoginQuery::default()
        };
        let signed_in = browser
            .post(&replicas, &link(LOGIN, &query), &LoginChange::SignedIn {})
            .await;
        assert_eq!(signed_in.status(), StatusCode::SEE_OTHER, "{return_to:?}");
        assert_eq!(redirect(&signed_in), to, "{return_to:?}");
    }
}

/// Signing in for an application lets the page's forms redirect on to it, and its
/// form continues the authorization: to the application, or a page linking to one
/// no policy can name, such as a native application's loopback callback. Once
/// used, the authorization explains itself, on the page and to its form.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_in_continues_the_authorization() {
    let database = Replicas::database().await;
    for origin in ["https://client.example", "http://127.0.0.1:8080"] {
        let replicas = Replicas::new().await;
        let client = ClientRegistration {
            trusted: true,
            ..registration(ClientKind::Public, origin)
        };
        register(&database, &client).await.expect("client");
        let browser = Browser::signed_out();
        let sign_in = location(&browser.visit(&replicas.a, &authorize(&client, &[])).await);
        assert_eq!(sign_in.path(), LOGIN, "{origin}");
        let transaction = parameter(&sign_in, "transaction");
        let query = LoginQuery {
            transaction: Some(transaction.clone()),
            ..LoginQuery::default()
        };
        let page = browser
            .visit(&replicas.a, &sign_in[Position::BeforePath..])
            .await;
        let form_action = match origin {
            "https://client.example" => "form-action 'self' https://client.example",
            _ => "form-action 'self'",
        };
        assert!(policy(&page).ends_with(form_action), "{origin}");
        let page = html(page).await;
        let action = attribute(&link(LOGIN, &query));
        assert!(page.contains(&format!(r#"action="{action}""#)), "{page}");
        let handle = format!(
            r#"<form method="get" action="{LOGIN}"><input type="hidden" name="transaction" value="{transaction}"><input type="hidden" name="handle" value="on"><button class="text-button">Use a handle instead</button>"#
        );
        assert!(page.contains(&handle), "{page}");

        let account = Browser::new_account(&database).await;
        let signed_in = account
            .post(&replicas, &link(LOGIN, &query), &LoginChange::SignedIn {})
            .await;
        if origin == "https://client.example" {
            assert_eq!(signed_in.status(), StatusCode::SEE_OTHER);
            let callback = location(&signed_in);
            assert_eq!(
                &callback[..Position::AfterPath],
                client.redirect_uris[0].as_str()
            );
            assert!(!parameter(&callback, "code").is_empty(), "{callback}");
        } else {
            assert_eq!(signed_in.status(), StatusCode::OK);
            let page = html(signed_in).await;
            let onward = format!(r#"<a class="button" href="{origin}/callback?code="#);
            assert!(page.contains(&onward), "{page}");
        }

        for used in [
            browser.visit(&replicas.a, &link(LOGIN, &query)).await,
            account
                .post(&replicas, &link(LOGIN, &query), &LoginChange::SignedIn {})
                .await,
        ] {
            assert_eq!(used.status(), StatusCode::BAD_REQUEST, "{origin}");
            let page = html(used).await;
            assert!(
                page.contains("This sign-in request is invalid or expired."),
                "{page}"
            );
            assert!(
                page.contains("transaction is unknown, expired or already used"),
                "{page}"
            );
        }
    }
}

/// An application asking for a passkey gets only passkeys, as its stored request
/// says, whatever the link says. A field an old or edited link gets wrong is
/// ignored, and never loses the authorization the sign-in continues.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn passkey_only_sign_in_reads_the_authorization() {
    let replicas = Replicas::with_github(config(false)).await;
    let database = Replicas::database().await;
    let client = registration(ClientKind::Public, "https://client.example");
    register(&database, &client).await.expect("client");
    let browser = Browser::signed_out();
    let phr = [("acr_values", "phr")];
    let sign_in = location(&browser.visit(&replicas.a, &authorize(&client, &phr)).await);
    assert_eq!(parameter(&sign_in, "acr"), "phr");
    let transaction = parameter(&sign_in, "transaction");
    let edited = format!(
        "{LOGIN}?transaction={transaction}&acr=gold&error=nope&social=maybe&return_to=%2F%2Fevil"
    );
    let page = html(browser.visit(&replicas.a, &edited).await).await;
    assert!(
        page.contains("This app asks you to sign in with a passkey."),
        "{page}"
    );
    assert!(!page.contains("or continue with"), "{page}");
    assert!(!page.contains(r#"role="alert">"#), "{page}");
    let kept = LoginQuery {
        transaction: Some(transaction),
        ..LoginQuery::default()
    };
    let action = attribute(&link(LOGIN, &kept));
    assert!(page.contains(&format!(r#"action="{action}""#)), "{page}");
}

/// A provider's sign-in starts at the provider, with the cookie binding it to the
/// browser, and comes back to where the browser goes on to: the path asked for, or
/// the authorization the sign-in continues. A provider the user already allowed
/// sends the browser straight back and on to the application, so for one no policy
/// can name, the page links to the provider instead of redirecting there.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn social_sign_in_starts_at_the_provider() {
    let replicas = Replicas::with_github(config(false)).await;
    let database = Replicas::database().await;
    let browser = Browser::signed_out();
    let social = LoginChange::Social {
        provider: Provider::GitHub,
    };
    let path = LoginQuery {
        return_to: Some(settings::SESSIONS.to_owned()),
        ..LoginQuery::default()
    };
    let mut starts = vec![(path, settings::SESSIONS.to_owned(), StatusCode::SEE_OTHER)];
    for (origin, status) in [
        ("https://client.example", StatusCode::SEE_OTHER),
        ("http://127.0.0.1:8080", StatusCode::OK),
    ] {
        let client = ClientRegistration {
            trusted: true,
            ..registration(ClientKind::Public, origin)
        };
        register(&database, &client).await.expect("client");
        let sign_in = location(&browser.visit(&replicas.a, &authorize(&client, &[])).await);
        let transaction = parameter(&sign_in, "transaction");
        let resume = format!("/oauth/authorize/resume?transaction={transaction}");
        let query = LoginQuery {
            transaction: Some(transaction),
            ..LoginQuery::default()
        };
        starts.push((query, resume, status));
    }
    for (query, return_to, status) in starts {
        let started = browser.post(&replicas, &link(LOGIN, &query), &social).await;
        assert_eq!(started.status(), status, "{return_to}");
        let (value, _) = cookie(&started, BrowserCookie::Federation);
        let value = value.to_owned();
        let to = if status == StatusCode::OK {
            let page = html(started).await;
            assert!(page.contains("<h1>Continue with GitHub</h1>"), "{page}");
            value_after(&page, r#"<a class="button" href=""#).replace("&amp;", "&")
        } else {
            redirect(&started).to_owned()
        };
        let to = url::Url::parse(&to).expect("provider URL");
        assert_eq!(
            &to[..Position::AfterPath],
            "https://github.com/login/oauth/authorize"
        );
        let flow = database
            .federation()
            .consume_transaction(
                Provider::GitHub,
                Secret::parse(&parameter(&to, "state"))
                    .expect("state")
                    .digest()
                    .as_bytes(),
                Secret::parse(&value).expect("cookie").digest().as_bytes(),
            )
            .await
            .expect("the sign-in's transaction");
        assert_eq!(flow.return_to, return_to);
        assert_eq!(flow.link_user_id, None);
    }
}

/// Creating an account starts with the invitation its link holds, under its old
/// name too, and asks for the handle and the passkey's name. Once the SDK created
/// it, the browser goes on to the settings.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_up_starts_with_the_invitation() {
    let replicas = Replicas::of(&config(true)).await;
    let database = Replicas::database().await;
    let response = Browser::signed_out()
        .visit(&replicas.a, &format!("{REGISTER}?invite=invited"))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = html(response).await;
    assert!(
        page.contains("<title>Create your account · Piquel</title>"),
        "{page}"
    );
    assert!(
        page.contains("<h1>Your account starts here.</h1>"),
        "{page}"
    );
    assert!(page.contains("data-passkey-register"), "{page}");
    assert!(
        page.contains(r#"<input type="hidden" name="action" value="registered">"#),
        "{page}"
    );
    assert!(
        page.contains(r#"name="username" autocomplete="username""#),
        "{page}"
    );
    assert!(
        page.contains(r#"pattern="[a-z0-9]+(-[a-z0-9]+)*""#),
        "{page}"
    );
    assert!(page.contains(">Passkey name<"), "{page}");
    assert!(
        page.contains(r#"<input name="friendly_name" value="My passkey""#),
        "{page}"
    );
    assert!(
        page.contains(r#"<input name="invitation" value="invited" required"#),
        "{page}"
    );
    assert_eq!(
        count(&page, ">Create account with a passkey</button>"),
        1,
        "{page}"
    );
    assert!(
        page.contains(r#"Already have an account? <a href="/login">Sign in</a>"#),
        "{page}"
    );

    let query = LoginQuery {
        invitation: Some("invited".into()),
        ..LoginQuery::default()
    };
    let registered = Browser::new_account(&database)
        .await
        .post(
            &replicas,
            &link(REGISTER, &query),
            &LoginChange::Registered {},
        )
        .await;
    assert_eq!(registered.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&registered), settings::HOME);
}

/// A provider's new identity creates an account with its first passkey: the form
/// names the evidence, asks for the invitation the round trip lost, and keeps where
/// the browser goes on to, since creating the account consumes the evidence.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn social_signup_names_its_evidence_and_keeps_where_it_goes() {
    let replicas = Replicas::of(&config(true)).await;
    let database = Replicas::database().await;
    let (evidence, secret) = pending(&database, |pending| PendingFederation {
        return_to: settings::SESSIONS.into(),
        ..pending
    })
    .await;
    let browser = Browser::signed_out().with_cookie(BrowserCookie::FederationPending, &secret);
    let here = waiting(PendingDestination::Signup, settings::SESSIONS);
    let page = html(
        browser
            .visit(&replicas.a, &format!("{LOGIN}?social=signup"))
            .await,
    )
    .await;
    assert!(
        page.contains(
            r#"<p class="notice">Finish creating your account to add GitHub sign-in.</p>"#
        ),
        "{page}"
    );
    assert!(
        page.contains(&format!(
            r#"<input type="hidden" name="pending_signup" value="{}">"#,
            evidence.id
        )),
        "{page}"
    );
    assert!(
        page.contains(r#"<input name="invitation" required"#),
        "{page}"
    );
    assert!(
        page.contains(&format!(r#"action="{}""#, attribute(&here))),
        "{page}"
    );

    database
        .federation()
        .cancel_pending(Secret::parse(&secret).expect("secret").digest().as_bytes())
        .await
        .expect("registration consumes the evidence");
    let registered = Browser::new_account(&database)
        .await
        .with_cookie(BrowserCookie::FederationPending, &secret)
        .post(&replicas, &here, &LoginChange::Registered {})
        .await;
    assert_eq!(registered.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&registered), settings::SESSIONS);
}

/// Linking a provider whose email matches an account confirms that account with a
/// passkey: a browser signed out signs in first, one whose session confirmed long
/// ago confirms, and is asked again if it posts anyway, and one that confirmed
/// recently links at once, going on to where the sign-in started.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn linking_confirms_the_account_with_a_passkey() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    passkey(&database, owner.user_id).await;
    let email = format!("{}@example.com", owner.user_id);
    let (evidence, secret) = pending(&database, |pending| PendingFederation {
        email: Some(email.clone()),
        return_to: settings::SESSIONS.into(),
        link_user_id: Some(owner.user_id),
        ..pending
    })
    .await;
    let here = waiting(PendingDestination::Link, settings::SESSIONS);
    let holding =
        |browser: &Browser| browser.with_cookie(BrowserCookie::FederationPending, &secret);
    let handle = database
        .users()
        .find_by_id(owner.user_id)
        .await
        .expect("account")
        .expect("active")
        .username;
    let signed_in_as = format!("Signed in as @{handle}.");

    let signed_out = holding(&Browser::signed_out());
    let page = html(signed_out.visit(&replicas.a, &here).await).await;
    assert!(
        page.contains("<title>Link social sign-in · Piquel</title>"),
        "{page}"
    );
    assert!(page.contains("<h1>Add this sign-in method?</h1>"), "{page}");
    assert!(
        page.contains("GitHub uses an email associated with an existing account. Verify that account with its passkey to add this provider."),
        "{page}"
    );
    assert!(
        page.contains(&format!(r#"<p class="notice">{email}</p>"#)),
        "{page}"
    );
    assert!(page.contains("data-passkey-sign-in"), "{page}");
    assert!(
        page.contains(r#"<input type="hidden" name="action" value="link">"#),
        "{page}"
    );
    let handle = format!(
        r#"<form method="get" action="{LOGIN}"><input type="hidden" name="return_to" value="{}"><input type="hidden" name="social" value="link"><input type="hidden" name="handle" value="on"><button class="text-button">Use a handle instead</button>"#,
        settings::SESSIONS
    );
    assert!(page.contains(&handle), "{page}");
    assert!(page.contains(">Cancel linking</button>"), "{page}");
    assert!(!page.contains("Signed in as"), "{page}");
    assert!(!page.contains("Use a different account"), "{page}");
    let refused = signed_out
        .post(&replicas, &here, &LoginChange::Link {})
        .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(html(refused).await.contains("Sign in to continue."));

    let stale = holding(
        &Browser::sign_in_with(&database, owner.user_id, AuthenticationMethod::Federation).await,
    );
    let page = html(stale.visit(&replicas.a, &here).await).await;
    assert!(page.contains(&signed_in_as), "{page}");
    assert!(page.contains("data-passkey-confirm"), "{page}");
    assert!(
        page.contains(">Verify passkey and add provider</button>"),
        "{page}"
    );
    assert!(page.contains(">Use a different account</button>"), "{page}");
    let refused = stale.post(&replicas, &here, &LoginChange::Link {}).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let page = html(refused).await;
    assert!(
        page.contains("Confirm with your passkey to continue."),
        "{page}"
    );
    assert!(page.contains("data-passkey-confirm"), "{page}");

    let recent = holding(&owner);
    let page = html(recent.visit(&replicas.a, &here).await).await;
    assert!(page.contains(&signed_in_as), "{page}");
    assert!(!page.contains("data-passkey-confirm"), "{page}");
    let linked = recent.post(&replicas, &here, &LoginChange::Link {}).await;
    assert_eq!(linked.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&linked), settings::SESSIONS);
    let (cleared, attributes) = cookie(&linked, BrowserCookie::FederationPending);
    assert_eq!(cleared, "");
    assert!(attributes.ends_with("Max-Age=0"), "{attributes}");
    let identity = database
        .federation()
        .find_active(&evidence.issuer, &evidence.subject)
        .await
        .expect("identity")
        .expect("linked");
    assert_eq!(identity.user_id, owner.user_id);
}

/// Cancelling a link abandons the provider's sign-in: one the settings started goes
/// back there, and one an email matched offers to sign in before going on. Only an
/// email match offers another account the link: one the settings started belongs to
/// their session.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn cancelling_a_link_abandons_it() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    let explicit = |pending| PendingFederation {
        link_user_id: Some(owner.user_id),
        link_session_id: Some(owner.session_id),
        ..pending
    };
    let email = |pending| PendingFederation {
        return_to: settings::SESSIONS.into(),
        link_user_id: Some(owner.user_id),
        ..pending
    };
    let sign_in = LoginQuery {
        return_to: Some(settings::SESSIONS.to_owned()),
        ..LoginQuery::default()
    };
    for (evidence, lead, switch, to) in [
        (
            pending(&database, explicit).await,
            "Verify your passkey to add GitHub sign-in to your account.",
            false,
            settings::HOME.to_owned(),
        ),
        (
            pending(&database, email).await,
            "GitHub uses an email associated with an existing account.",
            true,
            link(LOGIN, &sign_in),
        ),
    ] {
        let (evidence, secret) = evidence;
        let browser = owner.with_cookie(BrowserCookie::FederationPending, &secret);
        let here = waiting(PendingDestination::Link, &evidence.return_to);
        let page = html(browser.visit(&replicas.a, &here).await).await;
        assert!(page.contains(lead), "{page}");
        assert_eq!(page.contains("Use a different account"), switch, "{page}");
        let cancelled = browser
            .post(&replicas, &here, &LoginChange::CancelLink {})
            .await;
        assert_eq!(cancelled.status(), StatusCode::SEE_OTHER, "{lead}");
        assert_eq!(redirect(&cancelled), to, "{lead}");
        assert_eq!(cookie(&cancelled, BrowserCookie::FederationPending).0, "");
        let digest = Secret::parse(&secret).expect("secret").digest();
        let left = database
            .federation()
            .pending(digest.as_bytes())
            .await
            .expect("lookup");
        assert!(left.is_none(), "{lead}");
    }
}

/// Another account may take an email match's link: switching signs this browser
/// out, keeping the link waiting.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn switching_accounts_signs_out_and_keeps_the_link() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    let other = Browser::new_account(&database).await;
    let (evidence, secret) = pending(&database, |pending| PendingFederation {
        link_user_id: Some(owner.user_id),
        ..pending
    })
    .await;
    let browser = other.with_cookie(BrowserCookie::FederationPending, &secret);
    let here = waiting(PendingDestination::Link, &evidence.return_to);
    let switched = browser
        .post(&replicas, &here, &LoginChange::SwitchAccount {})
        .await;
    assert_eq!(switched.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&switched), here);
    let (cleared, attributes) = cookie(&switched, BrowserCookie::Session);
    assert_eq!(cleared, "");
    assert!(attributes.ends_with("Max-Age=0"), "{attributes}");
    let pending = format!("{}=", BrowserCookie::FederationPending);
    assert!(
        !switched
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|cookie| cookie.as_bytes().starts_with(pending.as_bytes())),
        "the browser keeps its pending link"
    );
    let session = database
        .sessions()
        .find_active_by_id(other.session_id)
        .await
        .expect("lookup");
    assert!(session.is_none(), "the browser signed out");
    let digest = Secret::parse(&secret).expect("secret").digest();
    let left = database
        .federation()
        .pending(digest.as_bytes())
        .await
        .expect("lookup");
    assert!(left.is_some(), "the link still waits");
}

/// Why a provider's sign-in failed, why no sign-in waits, why a change was refused
/// and a form from an older page each say so above the page, which still offers to
/// sign in.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn failures_are_said_above_the_page() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::signed_out();
    for (error, message) in [
        (
            "social_cancelled",
            "Social sign-in was cancelled. You can try again or use a passkey.",
        ),
        (
            "social_failed",
            "Social sign-in could not be verified. Please try again or use a passkey.",
        ),
        (
            "passkey_required",
            "You last confirmed this session with a passkey. Use your passkey to sign in again.",
        ),
    ] {
        let failed = format!("{LOGIN}?error={error}&return_to=%2Fsettings%2Fsessions");
        let page = html(browser.visit(&replicas.a, &failed).await).await;
        let alert = format!(r#"<p class="notice error" role="alert">{message}</p>"#);
        assert!(page.contains(&alert), "{page}");
        assert!(!page.contains(&format!("error={error}")), "{page}");
        assert_eq!(
            count(&page, ">Sign in with a passkey</button>"),
            1,
            "{page}"
        );
    }

    let page = html(
        browser
            .visit(&replicas.a, &format!("{LOGIN}?social=link"))
            .await,
    )
    .await;
    assert!(
        page.contains("No provider sign-in is waiting in this browser. Please start again."),
        "{page}"
    );
    assert!(page.contains("<h1>Welcome back.</h1>"), "{page}");

    let owner = Browser::new_account(&database).await;
    passkey(&database, owner.user_id).await;
    let (evidence, secret) = pending(&database, |pending| PendingFederation {
        link_user_id: Some(owner.user_id),
        ..pending
    })
    .await;
    let here = waiting(PendingDestination::Link, &evidence.return_to);
    let other = Browser::new_account(&database)
        .await
        .with_cookie(BrowserCookie::FederationPending, &secret);
    let refused = other.post(&replicas, &here, &LoginChange::Link {}).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let page = html(refused).await;
    assert!(
        page.contains("Sign in with a passkey for the account this provider should be linked to."),
        "{page}"
    );

    let stale = other
        .submit(&replicas.b, &here, &[("action", "everything")], OWN_PAGE)
        .await;
    assert_eq!(stale.status(), StatusCode::BAD_REQUEST);
    assert!(
        html(stale)
            .await
            .contains("This page was out of date. Try again.")
    );
}
