//! Token exchange and refresh: rotation, replay, concurrency, key changes, policy and claims.

use super::*;
use crate::config::PolicyLinks;
use piquel_common::clients::{AllowedScopes, ScopeName};
use piquel_common::events::GrantRevocation;

/// Checks refresh narrowing, replay revocation, client binding and logout.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "The scenario follows one refresh family through narrowing, replay and logout."
)]
async fn confidential_refresh_rotation_logout_and_client_binding() {
    let flow = Flow::new(true, true).await;
    let code = flow.code(EMAIL_REFRESH_SCOPES).await;
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::UNAUTHORIZED
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
    let fresh = narrowed["refresh_token"]
        .as_str()
        .expect("refresh response contains the rotated token")
        .to_owned();
    assert_eq!(flow.refresh(old).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(flow.refresh(&fresh).await.status(), StatusCode::BAD_REQUEST);
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
    assert!(events.iter().any(|event| matches!(
        event,
        DomainEvent::GrantRevoked {
            reason: GrantRevocation::RefreshReplay,
            ..
        }
    )));
}

/// Replaying a redeemed code revokes the refresh family it produced, while the same
/// code ID with a guessed secret revokes nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn code_replay_revokes_its_refresh_family() {
    let flow = Flow::new(true, true).await;
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

/// The same refresh token, rotated on two replicas at once, rotates exactly once. The
/// other attempt is a replay, which revokes the family.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn concurrent_refresh_across_replicas_rotates_once() {
    let flow = Flow::new(true, true).await;
    let replicas = Replicas::new().await;
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
    let (rotated, replayed) = if first.status() == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(rotated.status(), StatusCode::OK);
    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
    let rotated = Flow::json(rotated).await["refresh_token"]
        .as_str()
        .expect("refresh response contains the rotated token")
        .to_owned();
    assert_eq!(
        a.refresh(&rotated).await.status(),
        StatusCode::BAD_REQUEST,
        "the replay revoked the family"
    );
}

/// A new signing key and a new token digest key leave outstanding codes and
/// refresh tokens valid, since the old digest key is still accepted. What
/// replaces them is digested under the new key alone.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn changing_keys_keeps_codes_and_refresh_tokens() {
    let flow = Flow::new(true, true).await;
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
                TokenDigestKey::derive(&[8; 32]).expect("new digest key"),
                Some(TokenDigestKey::derive(&[7; 32]).expect("old digest key")),
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

/// A rename bumps the profile version, and the next token carries the new
/// `preferred_username`.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn renames_reach_the_next_token() {
    let flow = Flow::new(true, true).await;
    let code = flow.code(PROFILE_REFRESH_SCOPES).await;
    let (tokens, claims) = flow
        .id_token(
            flow.exchange(&code, Flow::verifier(), flow.basic.as_deref())
                .await,
        )
        .await;
    let database = &flow.app.database;
    let user = database
        .users()
        .find_by_id(flow.user_id)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(claims["preferred_username"], user.handle.as_str());
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
    assert_eq!(refreshed["preferred_username"], renamed.as_str());
    assert_eq!(refreshed["profile_version"], user.profile_version + 1);
}
