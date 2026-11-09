//! Authentication class targets (`acr_values`), recorded authentication and probation sign-ins.

use super::*;
use crate::recovery::ProbationPasskey;
use crate::security::Credential;
use sourceorigin_common::RecoveryId;
use sourceorigin_repository::{InsertPasskey, InsertRecovery};

/// Tokens report the class and time of the grant's authentication: a refresh keeps
/// them after the session re-authenticates, and `acr_values` makes a weaker session
/// sign in again while unknown values are ignored.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn acr_targets_and_grants_keep_their_authentication() {
    let mut flow = Flow::new(true, true).await;
    let code = flow.code(REFRESH_SCOPES).await;
    let (tokens, claims) = flow
        .id_token(
            flow.exchange(&code, Flow::verifier(), flow.basic.as_deref())
                .await,
        )
        .await;
    assert_eq!(claims["acr"], Acr::PhishingResistant.as_str());
    assert_eq!(claims["amr"], json!(["pop", "mfa", "user"]));
    let session = claims["sid"]
        .as_str()
        .expect("sid")
        .parse()
        .expect("session ID");
    flow.app
        .database
        .sessions()
        .confirm_passkey(
            session,
            PasskeyId::new(),
            Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("re-authenticate");
    let (_, refreshed) = flow
        .id_token(
            flow.refresh(tokens["refresh_token"].as_str().expect("refresh token"))
                .await,
        )
        .await;
    assert_eq!(refreshed["auth_time"], claims["auth_time"]);
    assert_eq!(refreshed["acr"], claims["acr"]);

    flow.sign_in_again(AuthenticationMethod::Federation).await;
    let phr = [("acr_values", "urn:example:gold phr")];
    let response = flow
        .authorize_with(
            Method::GET,
            Scope::OpenId.as_str(),
            Some(Prompt::None.as_str()),
            &phr,
        )
        .await;
    assert_eq!(
        parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::LoginRequired.as_str()
    );
    let response = flow
        .authorize_with(Method::GET, Scope::OpenId.as_str(), None, &phr)
        .await;
    let login = location(&response);
    assert_eq!(login.path(), routes::page::LOGIN);
    assert_eq!(parameter(&login, "acr"), Acr::PhishingResistant.as_str());
    for acr_values in ["urn:example:gold", "urn:sourceorigin:acr:social phr"] {
        let response = flow
            .authorize_with(
                Method::GET,
                Scope::OpenId.as_str(),
                Some(Prompt::None.as_str()),
                &[("acr_values", acr_values)],
            )
            .await;
        let code = parameter(&flow.client_redirect(&response), "code");
        let (_, claims) = flow
            .id_token(
                flow.exchange(&code, Flow::verifier(), flow.basic.as_deref())
                    .await,
            )
            .await;
        assert_eq!(claims["acr"], Acr::Social.as_str(), "{acr_values}");
        assert_eq!(claims["amr"], json!(["fed"]));
    }
}

/// A browser that signed in for an authorization with a recovered passkey during
/// its probation cannot reach `phr` by signing in again, so the client hears
/// `unmet_authentication_requirements` instead of its user looping through
/// sign-in. A social sign-in, which a passkey could still step up, and a
/// probation sign-in from before the request go to sign in, as before. Without a
/// target, a probation sign-in is enough, once the sign-in page asked whether the
/// recovery was the owner's.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_probation_sign_in_short_of_the_target_answers_the_client() {
    let mut flow = Flow::new(true, true).await;
    flow.sign_in_again(AuthenticationMethod::Federation).await;
    let phr = [("acr_values", "phr")];
    let response = flow
        .authorize_with(Method::GET, Scope::OpenId.as_str(), None, &phr)
        .await;
    let transaction = parameter(&location(&response), "transaction");
    let resume = format!(
        "{}?transaction={transaction}",
        routes::oidc::AUTHORIZE_RESUME
    );

    flow.sign_in_again(AuthenticationMethod::Federation).await;
    let response = flow.request(Method::GET, &resume, &[], None).await;
    assert_eq!(location(&response).path(), routes::page::LOGIN, "social");

    let database = flow.app.database.clone();
    let passkey = PasskeyId::new();
    database
        .passkeys()
        .insert(&InsertPasskey {
            id: passkey,
            credential_id: passkey.as_uuid().as_bytes().to_vec(),
            user_id: flow.user_id,
            credential: json!({}),
            friendly_name: "Recovered".into(),
        })
        .await
        .expect("passkey");
    let recovery = RecoveryId::new();
    database
        .recoveries()
        .insert(&InsertRecovery {
            id: recovery,
            user_id: flow.user_id,
            secret_digest: &recovery.as_uuid().as_bytes().repeat(2),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        })
        .await
        .expect("recovery");
    let probation = crate::recovery::PROBATION;
    let mut recoveries = database.recoveries();
    let completed = recoveries
        .complete(flow.user_id, recovery, passkey, probation)
        .await;
    assert!(completed.expect("complete"));
    let stored = recoveries
        .find(recovery)
        .await
        .expect("lookup")
        .expect("recovery");
    let credential = Credential::Probation(ProbationPasskey::of(&stored).expect("probation"));
    let user_id = flow.user_id;
    let probation_sign_in = || async {
        let mut tx = database.begin().await.expect("transaction");
        let session = Session::create(&mut tx, RequestContext::TEST, user_id, credential).await;
        tx.commit().await.expect("commit");
        let cookie = BrowserCookie::Session.as_str();
        format!("{cookie}={}", session.expect("session").encoded())
    };
    let before_the_request = probation_sign_in().await;
    let response = flow
        .authorize_with(Method::GET, Scope::OpenId.as_str(), None, &phr)
        .await;
    let transaction = parameter(&location(&response), "transaction");
    let resume = format!(
        "{}?transaction={transaction}",
        routes::oidc::AUTHORIZE_RESUME
    );
    flow.cookie = before_the_request;
    let response = flow.request(Method::GET, &resume, &[], None).await;
    assert_eq!(location(&response).path(), routes::page::LOGIN, "not fresh");

    flow.cookie = probation_sign_in().await;
    let response = flow.request(Method::GET, &resume, &[], None).await;
    assert_eq!(
        parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::UnmetAuthenticationRequirements.as_str()
    );
    // Signing in again for a request without a target is enough.
    let response = flow.authorize(Scope::OpenId.as_str(), Some("login")).await;
    let transaction = parameter(&location(&response), "transaction");
    let resume = format!(
        "{}?transaction={transaction}",
        routes::oidc::AUTHORIZE_RESUME
    );
    flow.cookie = probation_sign_in().await;
    let response = flow.request(Method::GET, &resume, &[], None).await;
    let asked = location(&response);
    assert_eq!(asked.path(), routes::page::LOGIN, "no target, no refusal");
    assert_eq!(parameter(&asked, "recovery"), "on", "the recovery question");
}
