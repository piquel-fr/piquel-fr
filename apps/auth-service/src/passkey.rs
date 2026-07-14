//! `WebAuthn` registration/authentication with database-backed single-use state.

use crate::account::{validate_display_name, validate_username};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use piquel_auth_protocol::{AuthenticationMethod, SessionId, TokenId, UserId};
use piquel_repository::{
    AppendAuditEvent, AppendInternalEvent, Database, DatabaseError, InsertCeremony, InsertPasskey,
    InsertSession, InsertUser,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use url::Url;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{
        CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
        PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
    },
};

/// Runnable passkey HTTP application state.
#[derive(Clone)]
pub struct PasskeyApplication {
    database: Database,
    webauthn: Arc<Webauthn>,
}

#[derive(Debug, Error)]
pub enum PasskeyConfigurationError {
    #[error("invalid WebAuthn relying-party configuration")]
    Invalid,
}

impl PasskeyApplication {
    /// Builds exact origin/RP validation. Subdomains and alternate ports are not enabled.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin and RP identifier are not an exact valid pair.
    pub fn new(
        database: Database,
        rp_id: &str,
        origin: &Url,
    ) -> Result<Self, PasskeyConfigurationError> {
        validate_rp_origin(rp_id, origin)?;
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .map_err(|_| PasskeyConfigurationError::Invalid)?
            .rp_name("Piquel")
            .build()
            .map_err(|_| PasskeyConfigurationError::Invalid)?;
        Ok(Self {
            database,
            webauthn: Arc::new(webauthn),
        })
    }
}

fn validate_rp_origin(rp_id: &str, origin: &Url) -> Result<(), PasskeyConfigurationError> {
    if origin.scheme() != "https"
        || origin.username() != ""
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(PasskeyConfigurationError::Invalid);
    }
    let host = origin
        .host_str()
        .ok_or(PasskeyConfigurationError::Invalid)?;
    if host != rp_id
        && !host
            .strip_suffix(rp_id)
            .is_some_and(|prefix| prefix.ends_with('.'))
    {
        return Err(PasskeyConfigurationError::Invalid);
    }
    Ok(())
}

pub(super) fn routes(application: PasskeyApplication) -> Router {
    Router::new()
        .route("/webauthn/register/start", post(start_registration))
        .route("/webauthn/register/finish", post(finish_registration))
        .route("/webauthn/authenticate/start", post(start_authentication))
        .route("/webauthn/authenticate/finish", post(finish_authentication))
        .route("/session/logout", post(logout))
        .with_state(application)
}

#[derive(Deserialize)]
struct RegistrationStart {
    username: String,
    display_name: String,
}
#[derive(Serialize)]
struct RegistrationStarted {
    ceremony_id: TokenId,
    public_key: CreationChallengeResponse,
}
#[derive(Serialize, Deserialize)]
struct RegistrationState {
    user_id: UserId,
    username: String,
    display_name: String,
    webauthn: PasskeyRegistration,
}
#[derive(Deserialize)]
struct RegistrationFinish {
    ceremony_id: TokenId,
    credential: RegisterPublicKeyCredential,
    #[serde(default = "default_passkey_name")]
    friendly_name: String,
}
fn default_passkey_name() -> String {
    "Passkey".into()
}

async fn start_registration(
    State(app): State<PasskeyApplication>,
    Json(input): Json<RegistrationStart>,
) -> Result<Json<RegistrationStarted>, ApiError> {
    validate_username(&input.username).map_err(|()| ApiError)?;
    validate_display_name(&input.display_name).map_err(|()| ApiError)?;
    let user_id = UserId::new();
    let (challenge, webauthn) = app
        .webauthn
        .start_passkey_registration(
            user_id.as_uuid(),
            &input.username,
            &input.display_name,
            None,
        )
        .map_err(|_| ApiError)?;
    let state = RegistrationState {
        user_id,
        username: input.username,
        display_name: input.display_name,
        webauthn,
    };
    let state = serde_json::to_value(state).map_err(|_| ApiError)?;
    let serialized = serde_json::to_vec(&state).map_err(|_| ApiError)?;
    let ceremony_id = TokenId::new();
    app.database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: ceremony_id,
            user_id: Some(user_id),
            session_id: None,
            kind: "registration".into(),
            challenge_digest: Sha256::digest(serialized).to_vec(),
            state,
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .await
        .map_err(|_| ApiError)?;
    Ok(Json(RegistrationStarted {
        ceremony_id,
        public_key: challenge,
    }))
}

async fn finish_registration(
    State(app): State<PasskeyApplication>,
    Json(input): Json<RegistrationFinish>,
) -> Result<Response, ApiError> {
    if input.friendly_name.trim().is_empty() || input.friendly_name.chars().count() > 80 {
        return Err(ApiError);
    }
    let mut transaction = app.database.begin().await.map_err(|_| ApiError)?;
    let ceremony = transaction
        .passkeys()
        .consume_ceremony(input.ceremony_id, "registration")
        .await
        .map_err(|_| ApiError)?;
    let state: RegistrationState = serde_json::from_value(ceremony.state).map_err(|_| ApiError)?;
    let passkey = app
        .webauthn
        .finish_passkey_registration(&input.credential, &state.webauthn)
        .map_err(|_| ApiError)?;
    let credential_id = passkey.cred_id().as_ref().to_vec();
    let credential = serde_json::to_value(passkey).map_err(|_| ApiError)?;
    transaction
        .users()
        .insert(&InsertUser {
            id: state.user_id,
            username: state.username,
            display_name: state.display_name,
        })
        .await
        .map_err(|_| ApiError)?;
    transaction
        .passkeys()
        .insert(&InsertPasskey {
            id: TokenId::new(),
            credential_id,
            user_id: state.user_id,
            credential,
            friendly_name: input.friendly_name,
        })
        .await
        .map_err(|_| ApiError)?;
    let cookie = create_session(&mut transaction, state.user_id).await?;
    transaction
        .audit_events()
        .append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(state.user_id),
            action: "passkey.enroll".into(),
            outcome: "success".into(),
            request_metadata: serde_json::json!({}),
        })
        .await
        .map_err(|_| ApiError)?;
    transaction
        .internal_events()
        .append(&AppendInternalEvent {
            id: TokenId::new(),
            aggregate_type: "user".into(),
            aggregate_id: state.user_id,
            event_type: "passkey.enrolled".into(),
            schema_version: 1,
            payload: serde_json::json!({}),
        })
        .await
        .map_err(|_| ApiError)?;
    transaction.commit().await.map_err(|_| ApiError)?;
    no_content_with_cookie(&cookie)
}

#[derive(Deserialize)]
struct AuthenticationStart {
    user_id: UserId,
}
#[derive(Serialize)]
struct AuthenticationStarted {
    ceremony_id: TokenId,
    public_key: RequestChallengeResponse,
}
#[derive(Serialize, Deserialize)]
struct AuthenticationState {
    user_id: UserId,
    webauthn: PasskeyAuthentication,
}
#[derive(Deserialize)]
struct AuthenticationFinish {
    ceremony_id: TokenId,
    credential: PublicKeyCredential,
}

async fn start_authentication(
    State(app): State<PasskeyApplication>,
    Json(input): Json<AuthenticationStart>,
) -> Result<Json<AuthenticationStarted>, ApiError> {
    let stored = app
        .database
        .passkeys()
        .list_active(input.user_id, 20)
        .await
        .map_err(|_| ApiError)?;
    if stored.is_empty() {
        return Err(ApiError);
    }
    let passkeys = stored
        .into_iter()
        .map(|stored| serde_json::from_value::<Passkey>(stored.credential).map_err(|_| ApiError))
        .collect::<Result<Vec<_>, _>>()?;
    let (challenge, webauthn) = app
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| ApiError)?;
    let state = serde_json::to_value(AuthenticationState {
        user_id: input.user_id,
        webauthn,
    })
    .map_err(|_| ApiError)?;
    let serialized = serde_json::to_vec(&state).map_err(|_| ApiError)?;
    let ceremony_id = TokenId::new();
    app.database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: ceremony_id,
            user_id: Some(input.user_id),
            session_id: None,
            kind: "authentication".into(),
            challenge_digest: Sha256::digest(serialized).to_vec(),
            state,
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .await
        .map_err(|_| ApiError)?;
    Ok(Json(AuthenticationStarted {
        ceremony_id,
        public_key: challenge,
    }))
}

async fn finish_authentication(
    State(app): State<PasskeyApplication>,
    Json(input): Json<AuthenticationFinish>,
) -> Result<Response, ApiError> {
    let mut transaction = app.database.begin().await.map_err(|_| ApiError)?;
    let ceremony = transaction
        .passkeys()
        .consume_ceremony(input.ceremony_id, "authentication")
        .await
        .map_err(|_| ApiError)?;
    let state: AuthenticationState =
        serde_json::from_value(ceremony.state).map_err(|_| ApiError)?;
    let result = app
        .webauthn
        .finish_passkey_authentication(&input.credential, &state.webauthn)
        .map_err(|_| ApiError)?;
    if !result.user_verified() {
        return Err(ApiError);
    }
    let stored = transaction
        .passkeys()
        .find_active_by_credential_id(result.cred_id().as_ref())
        .await
        .map_err(|_| ApiError)?
        .filter(|credential| credential.user_id == state.user_id)
        .ok_or(ApiError)?;
    let mut passkey: Passkey = serde_json::from_value(stored.credential).map_err(|_| ApiError)?;
    passkey.update_credential(&result).ok_or(ApiError)?;
    let credential = serde_json::to_value(passkey).map_err(|_| ApiError)?;
    transaction
        .passkeys()
        .update_after_authentication(result.cred_id().as_ref(), &credential)
        .await
        .map_err(|_| ApiError)?;
    let cookie = create_session(&mut transaction, state.user_id).await?;
    transaction
        .audit_events()
        .append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(state.user_id),
            action: "passkey.authenticate".into(),
            outcome: "success".into(),
            request_metadata: serde_json::json!({}),
        })
        .await
        .map_err(|_| ApiError)?;
    transaction.commit().await.map_err(|_| ApiError)?;
    no_content_with_cookie(&cookie)
}

async fn create_session(
    transaction: &mut piquel_repository::DatabaseTransaction<'_>,
    user_id: UserId,
) -> Result<String, ApiError> {
    let session_id = SessionId::new();
    let now = Utc::now();
    let mut secret = [0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    transaction
        .sessions()
        .insert(&InsertSession {
            id: session_id,
            user_id,
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: now,
            expires_at: now + Duration::days(30),
            user_agent_family: None,
        })
        .await
        .map_err(|_| ApiError)?;
    transaction
        .sessions()
        .insert_browser_secret(session_id, &Sha256::digest(secret))
        .await
        .map_err(|_| ApiError)?;
    Ok(format!(
        "__Host-piquel_session={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000",
        URL_SAFE_NO_PAD.encode(secret)
    ))
}

fn no_content_with_cookie(cookie: &str) -> Result<Response, ApiError> {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(cookie).map_err(|_| ApiError)?,
    );
    Ok(response)
}

async fn logout(
    State(app): State<PasskeyApplication>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let secret = session_secret(&headers).ok_or(ApiError)?;
    if let Some(session) = app
        .database
        .sessions()
        .find_active_by_browser_secret(&Sha256::digest(secret))
        .await
        .map_err(|_| ApiError)?
    {
        app.database
            .sessions()
            .revoke(session.id)
            .await
            .map_err(|_| ApiError)?;
    }
    no_content_with_cookie(
        "__Host-piquel_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
    )
}

fn session_secret(headers: &HeaderMap) -> Option<Vec<u8>> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|cookie| cookie.strip_prefix("__Host-piquel_session="))
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        .filter(|secret| secret.len() == 32)
}

#[derive(Debug)]
struct ApiError;
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"authentication_failed"})),
        )
            .into_response()
    }
}
impl From<DatabaseError> for ApiError {
    fn from(_: DatabaseError) -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

    #[test]
    fn rp_origin_rejects_attacker_controlled_urls() {
        for origin in [
            "https://example.com.evil",
            "https://evil.test/example.com",
            "https://example.com@evil.test",
        ] {
            let url = Url::parse(origin).expect("URL fixture");
            assert!(
                validate_rp_origin("example.com", &url).is_err(),
                "accepted {origin}"
            );
        }
        assert!(
            validate_rp_origin(
                "example.com",
                &Url::parse("https://example.com").expect("valid URL")
            )
            .is_ok()
        );
    }

    #[test]
    fn cookie_parser_requires_exact_secret_size() {
        let secret = [7_u8; 32];
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "__Host-piquel_session={}",
                URL_SAFE_NO_PAD.encode(secret)
            ))
            .expect("cookie"),
        );
        assert_eq!(session_secret(&headers), Some(secret.to_vec()));
    }

    #[test]
    fn standards_conformant_authenticator_registers_and_authenticates() {
        let origin = Url::parse("https://auth.example.com").expect("origin");
        let webauthn = WebauthnBuilder::new("example.com", &origin)
            .expect("builder")
            .rp_name("Piquel Test")
            .build()
            .expect("webauthn");
        let user_id = UserId::new();
        let (challenge, registration_state) = webauthn
            .start_passkey_registration(user_id.as_uuid(), "test_user", "Test User", None)
            .expect("registration start");
        // The software authenticator has no physical verification gesture. Enable its
        // explicit test-only UV simulation so the ceremony exercises our required-UV
        // policy instead of weakening production configuration for this test.
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let registration = authenticator
            .do_registration(origin.clone(), challenge)
            .expect("authenticator registration");
        let passkey = webauthn
            .finish_passkey_registration(&registration, &registration_state)
            .expect("registration finish");
        let (challenge, authentication_state) = webauthn
            .start_passkey_authentication(&[passkey])
            .expect("authentication start");
        let assertion = authenticator
            .do_authentication(origin, challenge)
            .expect("authenticator assertion");
        let result = webauthn
            .finish_passkey_authentication(&assertion, &authentication_state)
            .expect("authentication finish");
        assert!(result.user_verified());
    }
}
