//! Token exchange and refresh: kept and rotated tokens, replay, concurrency, key changes,
//! policy and claims.

use super::*;
use crate::config::PolicyLinks;
use sourceorigin_common::AccountStatus;
use sourceorigin_common::clients::{AllowedScopes, ScopeName};
use sourceorigin_common::events::GrantRevocation;
use sourceorigin_repository::SessionScope;

/// Checks refresh narrowing, that a confidential client keeps its token, client
/// binding and logout.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "The scenario follows one refresh family through narrowing, reuse and logout."
)]
async fn confidential_refresh_keeps_its_token_logout_and_client_binding() {
    let flow = Flow::new(true, true).await;
    let code = flow.code(EMAIL_REFRESH_SCOPES).await;
    // Without credentials, the client is refused unchallenged (RFC 6749 §5.2).
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = Flow::json(response).await;
    let claims: IdTokenClaims = flow
        .app
        .keys
        .current()
        .expect("fresh keys")
        .verify(
            tokens["id_token"]
                .as_str()
                .expect("token response contains an ID token"),
            TokenType::Id,
            &flow.app.issuer,
        )
        .expect("verify confidential client ID token");
    assert_eq!(
        claims.profile.email,
        Some(format!("{}@example.com", flow.user_id))
    );
    assert_eq!(claims.profile.email_verified, Some(true));
    let old = tokens["refresh_token"]
        .as_str()
        .expect("token response contains a refresh token");
    let other = Flow::new(false, true).await;
    assert_eq!(other.refresh(old).await.status(), StatusCode::BAD_REQUEST);
    let invalid = flow
        .request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", GrantType::RefreshToken.as_str()),
                ("client_id", flow.client.id.as_str()),
                ("refresh_token", old),
                ("scope", UNGRANTED_SCOPES),
            ],
            flow.basic.as_deref(),
        )
        .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(invalid).await["error"],
        OAuthCode::InvalidScope.as_str()
    );
    let response = flow
        .request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", GrantType::RefreshToken.as_str()),
                ("client_id", flow.client.id.as_str()),
                ("refresh_token", old),
                ("scope", Scope::OpenId.as_str()),
            ],
            flow.basic.as_deref(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let narrowed = Flow::json(response).await;
    assert_eq!(narrowed["scope"], Scope::OpenId.as_str());
    let narrowed_claims: IdTokenClaims = flow
        .app
        .keys
        .current()
        .expect("fresh keys")
        .verify(
            narrowed["id_token"]
                .as_str()
                .expect("refresh response contains an ID token"),
            TokenType::Id,
            &flow.app.issuer,
        )
        .expect("verify narrowed ID token");
    assert!(narrowed_claims.profile.email.is_none());
    assert!(narrowed.get("refresh_token").is_none(), "{narrowed}");
    assert_eq!(flow.refresh(old).await.status(), StatusCode::OK, "kept");
    let code = flow.code(REFRESH_SCOPES).await;
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    let tokens = Flow::json(response).await;
    let response = flow
        .request(
            Method::POST,
            routes::page::LOGOUT,
            &[
                ("client_id", flow.client.id.as_str()),
                (
                    "post_logout_redirect_uri",
                    flow.client.post_logout_uris[0].as_str(),
                ),
            ],
            None,
        )
        .await;
    assert_eq!(
        location(&response).as_str(),
        flow.client.post_logout_uris[0].as_str()
    );
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .expect("Set-Cookie header is valid text")
            .contains("Max-Age=0")
    );
    assert_eq!(
        flow.refresh(
            tokens["refresh_token"]
                .as_str()
                .expect("token response contains a refresh token")
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        parameter(
            &flow.client_redirect(
                &flow
                    .authorize(Scope::OpenId.as_str(), Some(Prompt::None.as_str()))
                    .await
            ),
            "error"
        ),
        OAuthCode::LoginRequired.as_str()
    );
    let events = flow.events().await;
    assert!(
        matches!(
            &events[0],
            DomainEvent::SessionRevoked {
                reason: RevocationReason::RelyingPartyLogout { client_id },
                ..
            } if *client_id == flow.client.id
        ),
        "{events:?}"
    );
}

/// Replaying a redeemed code revokes the refresh family it produced, while the same
/// code ID with a guessed secret revokes nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn code_replay_revokes_its_refresh_family() {
    let flow = Flow::new(false, true).await;
    let code = flow.code(REFRESH_SCOPES).await;
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = Flow::json(response).await;
    let guessed = OpaqueToken {
        id: OpaqueToken::parse(TokenPrefix::AuthorizationCode, &code)
            .expect("issued code parses")
            .id,
        ..OpaqueToken::new(TokenPrefix::AuthorizationCode).expect("random secret")
    }
    .encoded();
    assert_eq!(
        flow.exchange(&guessed, Flow::verifier(), flow.basic.as_deref())
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow
        .refresh(
            tokens["refresh_token"]
                .as_str()
                .expect("token response contains a refresh token"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK, "a guess revokes nothing");
    let rotated = Flow::json(response).await["refresh_token"]
        .as_str()
        .expect("refresh response contains the rotated token")
        .to_owned();
    let replay = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(replay).await["error"],
        OAuthCode::InvalidGrant.as_str()
    );
    assert_eq!(
        flow.refresh(&rotated).await.status(),
        StatusCode::BAD_REQUEST
    );
    let events = flow.events().await;
    let [
        DomainEvent::GrantRevoked {
            family_id: revoked,
            reason: GrantRevocation::CodeReplay,
            ..
        },
        DomainEvent::CodeReplayed { .. },
        DomainEvent::GrantIssued {
            family_id: Some(issued),
            ..
        },
        ..,
    ] = events.as_slice()
    else {
        panic!("{events:?}");
    };
    assert_eq!(revoked, issued, "the replay revoked the code's own family");
}

/// Replaying a redeemed code after its account is disabled is still recorded as
/// a replay, and revokes the code's refresh family.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_disabled_accounts_code_replay_is_recorded() {
    let flow = Flow::new(false, true).await;
    let code = flow.code(REFRESH_SCOPES).await;
    let response = flow.exchange(&code, Flow::verifier(), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    flow.disable().await;
    Flow::assert_invalid_grant(flow.exchange(&code, Flow::verifier(), None).await).await;
    let events = flow.events().await;
    let [
        DomainEvent::GrantRevoked {
            reason: GrantRevocation::CodeReplay,
            ..
        },
        DomainEvent::CodeReplayed { .. },
        ..,
    ] = events.as_slice()
    else {
        panic!("{events:?}");
    };
}

/// Another client presenting a disabled account's code gets the rejection it
/// gets for an active account's, so it doesn't learn the account is disabled.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn another_client_isnt_told_an_account_is_disabled() {
    let flow = Flow::new(false, true).await;
    let other = crate::tests::registration(ClientKind::Public, "https://other.example");
    crate::tests::register(&flow.app.database, &other)
        .await
        .expect("register another client");
    let other = Flow {
        client: other,
        ..flow.clone()
    };
    let (active, disabled) = (
        flow.code(REFRESH_SCOPES).await,
        flow.code(REFRESH_SCOPES).await,
    );
    let rejection = async |code: &str| {
        let response = other.exchange(code, Flow::verifier(), None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Flow::json(response).await
    };
    let expected = rejection(&active).await;
    flow.disable().await;
    assert_eq!(rejection(&disabled).await, expected);
}

/// The same refresh token, refreshed on two replicas at once: a public client's
/// rotates once, and both refreshes answer with that one successor. Presented
/// after the reuse window, the old token is a replay, which revokes the family.
/// A confidential client's serves both and stays valid.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn concurrent_refreshes_across_replicas() {
    let replicas = Replicas::new().await;
    for confidential in [false, true] {
        let flow = Flow::new(confidential, true).await;
        let (a, b) = (flow.on(&replicas.a), flow.on(&replicas.b));
        let code = a.code(REFRESH_SCOPES).await;
        let response = b
            .exchange(&code, Flow::verifier(), b.basic.as_deref())
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let token = Flow::json(response).await["refresh_token"]
            .as_str()
            .expect("token response contains a refresh token")
            .to_owned();
        let (first, second) = tokio::join!(a.refresh(&token), b.refresh(&token));
        let mut successors = Vec::new();
        for response in [first, second] {
            assert_eq!(response.status(), StatusCode::OK);
            successors.push(Flow::json(response).await["refresh_token"].clone());
        }
        if confidential {
            assert!(
                successors.iter().all(serde_json::Value::is_null),
                "{successors:?}"
            );
            assert_eq!(a.refresh(&token).await.status(), StatusCode::OK, "kept");
            continue;
        }
        assert_eq!(successors[0], successors[1], "one successor");
        let successor = successors[0].as_str().expect("the successor").to_owned();
        assert_ne!(successor, token);
        let mut tx = flow.app.database.begin().await.expect("transaction");
        tx.tokens()
            .end_reuse_window(
                OpaqueToken::parse(TokenPrefix::RefreshToken, &token)
                    .expect("issued token parses")
                    .id,
            )
            .await
            .expect("the window ends");
        tx.commit().await.expect("commit");
        assert_eq!(a.refresh(&token).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            b.refresh(&successor).await.status(),
            StatusCode::BAD_REQUEST,
            "the replay revoked the family"
        );
        assert!(flow.events().await.iter().any(|event| matches!(
            event,
            DomainEvent::GrantRevoked {
                reason: GrantRevocation::RefreshReplay,
                ..
            }
        )));
    }
}

/// A refresh that waits for the account lock while a recovery undo ends every
/// session, or while the account is disabled, fails once they commit and issues
/// nothing: it reads its session and account again under the lock, whether its
/// client rotates its token or keeps it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_refresh_that_waits_for_an_undo_or_disablement_issues_nothing() {
    for (confidential, disable) in [(false, false), (false, true), (true, false), (true, true)] {
        let flow = Flow::new(confidential, true).await;
        let tokens = Flow::json(
            flow.exchange(
                &flow.code(REFRESH_SCOPES).await,
                Flow::verifier(),
                flow.basic.as_deref(),
            )
            .await,
        )
        .await;
        let token = tokens["refresh_token"]
            .as_str()
            .expect("refresh token")
            .to_owned();
        let database = flow.app.database.clone();
        let mut holder = database.begin().await.expect("transaction");
        holder
            .users()
            .find_active_by_id_for_update(flow.user_id)
            .await
            .expect("lock")
            .expect("user");
        let refreshing = flow.clone();
        let refresh = tokio::spawn(async move { refreshing.refresh(&token).await });
        until_blocked(&mut holder, 1).await;
        if disable {
            holder
                .users()
                .set_status(flow.user_id, AccountStatus::Disabled)
                .await
                .expect("disable");
        } else {
            let context = RequestContext::TEST.actor(Actor::Anonymous);
            holder
                .revoke_sessions(
                    &context,
                    flow.user_id,
                    SessionScope::All,
                    &RevocationReason::CredentialRemoved,
                )
                .await
                .expect("every session ends");
        }
        holder.commit().await.expect("commit");
        Flow::assert_invalid_grant(refresh.await.expect("refresh")).await;
    }
}

/// A new signing key and a new token digest key leave outstanding codes and
/// refresh tokens valid, since the old digest key is still accepted. What
/// replaces them is digested under the new key alone.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn changing_keys_keeps_codes_and_refresh_tokens() {
    let flow = Flow::new(false, true).await;
    let code = flow.code(REFRESH_SCOPES).await;
    let tokens = Flow::json(
        flow.exchange(
            &flow.code(REFRESH_SCOPES).await,
            Flow::verifier(),
            flow.basic.as_deref(),
        )
        .await,
    )
    .await;
    let token = tokens["refresh_token"].as_str().expect("refresh token");
    let app = OidcApplication::new(
        flow.app.database.clone(),
        &OidcConfig {
            origin: flow.app.issuer.parse().expect("issuer"),
            digest_keys: Arc::new(TokenDigestKeys::new(
                TokenDigestKey::derive(&[8; 32]),
                Some(TokenDigestKey::derive(&[7; 32])),
            )),
            policies: PolicyLinks::on(&crate::tests::WEB_ORIGIN.parse().expect("web origin")),
        },
        SigningKeys::new(KeySet::single(
            Rs256Key::generate("rotated").expect("new signing key"),
        )),
    )
    .expect("OIDC application");
    let changed = Flow {
        router: app.clone().routes(),
        app,
        ..flow.clone()
    };
    let exchanged = changed
        .exchange(&code, Flow::verifier(), changed.basic.as_deref())
        .await;
    assert_eq!(exchanged.status(), StatusCode::OK);
    let refreshed = changed.refresh(token).await;
    assert_eq!(refreshed.status(), StatusCode::OK);
    let rotated = Flow::json(refreshed).await["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_owned();
    assert_eq!(
        flow.refresh(&rotated).await.status(),
        StatusCode::BAD_REQUEST,
        "only the new digest key made the rotated token"
    );
    assert_eq!(changed.refresh(&rotated).await.status(), StatusCode::OK);
}

/// Checks that policy reductions reject new requests and invalidate outstanding grants,
/// and that unsafe logout redirects are refused.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn policy_reduction_blocks_outstanding_codes_and_refresh() {
    let mut flow = Flow::new(false, true).await;
    let code = flow.code(EMAIL_SCOPES).await;
    let database = flow.app.database.clone();
    flow.client.allowed_scopes =
        AllowedScopes::new([Scope::OpenId, Scope::OfflineAccess].map(ScopeName::from))
            .expect("reduced scopes");
    let client = flow.client.clone();
    crate::tests::replace(&database, &client)
        .await
        .expect("apply reduced client scope policy");
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        parameter(
            &flow.client_redirect(&flow.authorize(EMAIL_SCOPES, None).await),
            "error"
        ),
        OAuthCode::InvalidScope.as_str()
    );
    let code = flow.code(REFRESH_SCOPES).await;
    let tokens = Flow::json(flow.exchange(&code, Flow::verifier(), None).await).await;
    flow.client.allow_refresh = false;
    let client = flow.client.clone();
    crate::tests::replace(&database, &client)
        .await
        .expect("disable client refresh permission");
    assert_eq!(
        flow.refresh(
            tokens["refresh_token"]
                .as_str()
                .expect("token response contains a refresh token")
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow
        .request(
            Method::GET,
            "/oidc/logout?client_id=unknown&post_logout_redirect_uri=https%3A%2F%2Fevil.example",
            &[],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// A new picture and a rename each bump the profile version, and the next token
/// carries them: the picture's URL on auth's origin as `picture`, and the new
/// `preferred_username`.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn profile_changes_reach_the_next_token() {
    let flow = Flow::new(true, true).await;
    let code = flow.code(PROFILE_REFRESH_SCOPES).await;
    let (tokens, claims) = flow
        .id_token(
            flow.exchange(&code, Flow::verifier(), flow.basic.as_deref())
                .await,
        )
        .await;
    assert_eq!(claims.get("picture"), None, "no picture yet");
    let database = &flow.app.database;
    let picture = sourceorigin_common::PictureId::new();
    database
        .pictures()
        .set(flow.user_id, picture, b"jpeg")
        .await
        .expect("picture");
    let renamed =
        Handle::parse(&format!("renamed-{}", &flow.user_id.to_string()[24..])).expect("handle");
    let mut tx = database.begin().await.expect("transaction");
    assert!(
        tx.rename_handle(flow.user_id, &renamed)
            .await
            .expect("rename")
    );
    tx.commit().await.expect("commit");
    let (_, refreshed) = flow
        .id_token(
            flow.refresh(tokens["refresh_token"].as_str().expect("refresh token"))
                .await,
        )
        .await;
    let issuer = refreshed["iss"].as_str().expect("issuer");
    assert_eq!(refreshed["picture"], format!("{issuer}/pictures/{picture}"));
    assert_eq!(refreshed["preferred_username"], renamed.as_str());
    assert_eq!(
        refreshed["profile_version"],
        claims["profile_version"].as_u64().expect("version") + 2
    );
}

/// The picture is a profile claim: only the `profile` scope releases it.
#[test]
fn the_picture_needs_the_profile_scope() {
    let claims = ProfileClaims {
        picture: Some(format!(
            "{AUTH_ORIGIN}/pictures/{}",
            sourceorigin_common::PictureId::new()
        )),
        ..ProfileClaims::default()
    };
    let released = |scopes: &str| {
        Scopes::parse(scopes)
            .expect("scopes")
            .release(claims.clone())
            .picture
    };
    assert_eq!(released("openid email"), None);
    assert_eq!(released("openid profile"), claims.picture);
}
