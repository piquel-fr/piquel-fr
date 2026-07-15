//! `WebAuthn` registration/authentication with database-backed single-use state.

use crate::{
    Es256KeyProvider,
    account::{validate_display_name, validate_username},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use piquel_auth_protocol::{AuthenticationMethod, SessionId, TokenId, UserId};
use piquel_repository::{
    AppendAuditEvent, AppendInternalEvent, Database, DatabaseError, InsertCeremony, InsertPasskey,
    InsertPurposeAuthorization, InsertSession, InsertUser, StoredSession,
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
    origin: Arc<str>,
    purpose_keys: Arc<Es256KeyProvider>,
}

const PURPOSE_TOKEN_TYPE: &str = "purpose+jwt";
const PURPOSE_AUDIENCE: &str = "piquel-account-management";
const MANAGE_PASSKEYS_PURPOSE: &str = "manage-passkeys";
const PURPOSE_TOKEN_SECONDS: i64 = 120;

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
        purpose_keys: Arc<Es256KeyProvider>,
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
            origin: origin.as_str().trim_end_matches('/').into(),
            purpose_keys,
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
        .route("/account/passkeys/enroll/start", post(start_enrollment))
        .route("/account/passkeys/enroll/finish", post(finish_enrollment))
        .route(
            "/account/passkeys/authorize/start",
            post(start_purpose_authorization),
        )
        .route(
            "/account/passkeys/authorize/finish",
            post(finish_purpose_authorization),
        )
        .route("/account/passkeys", get(list_passkeys))
        .route(
            "/account/passkeys/{id}",
            patch(rename_passkey).delete(revoke_passkey),
        )
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
            // Bootstrap users do not exist until the registration response is
            // verified and the account is created atomically at finish time.
            user_id: None,
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
    // Consumption is intentionally committed before processing the response:
    // invalid responses and downstream failures must not make a challenge
    // reusable.
    let ceremony = app
        .database
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
    let mut transaction = app.database.begin().await.map_err(|_| ApiError)?;
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
    username: String,
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
    validate_username(&input.username).map_err(|()| ApiError)?;
    let user = app
        .database
        .users()
        .find_active_by_username(&input.username)
        .await
        .map_err(|_| ApiError)?
        .ok_or(ApiError)?;
    let passkeys = active_passkeys(&app.database, user.id).await?;
    let (challenge, webauthn) = app
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| ApiError)?;
    let state = serde_json::to_value(AuthenticationState {
        user_id: user.id,
        webauthn,
    })
    .map_err(|_| ApiError)?;
    let serialized = serde_json::to_vec(&state).map_err(|_| ApiError)?;
    let ceremony_id = TokenId::new();
    app.database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: ceremony_id,
            user_id: Some(user.id),
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
    let ceremony = app
        .database
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
    let mut transaction = app.database.begin().await.map_err(|_| ApiError)?;
    let stored = transaction
        .passkeys()
        .find_active_by_credential_id_for_update(result.cred_id().as_ref())
        .await
        .map_err(|_| ApiError)?
        .filter(|credential| credential.user_id == state.user_id)
        .ok_or(ApiError)?;
    let mut passkey: Passkey = serde_json::from_value(stored.credential).map_err(|_| ApiError)?;
    passkey.update_credential(&result).ok_or(ApiError)?;
    let credential = serde_json::to_value(passkey).map_err(|_| ApiError)?;
    let updated = transaction
        .passkeys()
        .update_after_authentication(result.cred_id().as_ref(), &credential)
        .await
        .map_err(|_| ApiError)?;
    if !updated {
        return Err(ApiError);
    }
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

async fn active_passkeys(database: &Database, user_id: UserId) -> Result<Vec<Passkey>, ApiError> {
    let stored = database
        .passkeys()
        .list_active(user_id)
        .await
        .map_err(|_| ApiError)?;
    if stored.is_empty() {
        return Err(ApiError);
    }
    stored
        .into_iter()
        .map(|stored| serde_json::from_value(stored.credential).map_err(|_| ApiError))
        .collect()
}

#[derive(Serialize, Deserialize)]
struct PurposeAuthenticationState {
    user_id: UserId,
    session_id: SessionId,
    webauthn: PasskeyAuthentication,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PurposeTokenClaims {
    iss: String,
    sub: UserId,
    aud: String,
    purpose: String,
    sid: SessionId,
    auth_time: i64,
    iat: i64,
    exp: i64,
    jti: TokenId,
}

impl PurposeTokenClaims {
    fn is_valid_for(&self, issuer: &str, user_id: UserId, session_id: SessionId, now: i64) -> bool {
        self.iss == issuer
            && self.sub == user_id
            && self.aud == PURPOSE_AUDIENCE
            && self.purpose == MANAGE_PASSKEYS_PURPOSE
            && self.sid == session_id
            && self.exp > now
            && self.exp > self.iat
            && self.exp - self.iat <= PURPOSE_TOKEN_SECONDS
            && self.iat <= now + 30
            && self.auth_time <= self.iat
            && self.iat - self.auth_time <= 30
    }
}

#[derive(Serialize)]
struct PurposeAuthorized {
    purpose_token: String,
    token_type: &'static str,
    expires_in: i64,
}

async fn start_purpose_authorization(
    State(app): State<PasskeyApplication>,
    headers: HeaderMap,
) -> Result<Json<AuthenticationStarted>, ApiError> {
    let session = active_session(&app.database, &headers).await?;
    let passkeys = active_passkeys(&app.database, session.user_id).await?;
    let (challenge, webauthn) = app
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| ApiError)?;
    let state = serde_json::to_value(PurposeAuthenticationState {
        user_id: session.user_id,
        session_id: session.id,
        webauthn,
    })
    .map_err(|_| ApiError)?;
    let serialized = serde_json::to_vec(&state).map_err(|_| ApiError)?;
    let ceremony_id = TokenId::new();
    app.database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: ceremony_id,
            user_id: Some(session.user_id),
            session_id: Some(session.id),
            kind: "purpose_authentication".into(),
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

async fn finish_purpose_authorization(
    State(app): State<PasskeyApplication>,
    headers: HeaderMap,
    Json(input): Json<AuthenticationFinish>,
) -> Result<Response, ApiError> {
    let session = active_session(&app.database, &headers).await?;
    let ceremony = app
        .database
        .passkeys()
        .consume_ceremony(input.ceremony_id, "purpose_authentication")
        .await
        .map_err(|_| ApiError)?;
    let state: PurposeAuthenticationState =
        serde_json::from_value(ceremony.state).map_err(|_| ApiError)?;
    if state.user_id != session.user_id || state.session_id != session.id {
        return Err(ApiError);
    }
    let result = app
        .webauthn
        .finish_passkey_authentication(&input.credential, &state.webauthn)
        .map_err(|_| ApiError)?;
    if !result.user_verified() {
        return Err(ApiError);
    }

    let now = Utc::now();
    let authorization_id = TokenId::new();
    let claims = PurposeTokenClaims {
        iss: app.origin.to_string(),
        sub: session.user_id,
        aud: PURPOSE_AUDIENCE.into(),
        purpose: MANAGE_PASSKEYS_PURPOSE.into(),
        sid: session.id,
        auth_time: now.timestamp(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(PURPOSE_TOKEN_SECONDS)).timestamp(),
        jti: authorization_id,
    };
    let token = app
        .purpose_keys
        .sign(PURPOSE_TOKEN_TYPE, &claims)
        .map_err(|()| ApiError)?;

    let mut transaction = app.database.begin().await.map_err(|_| ApiError)?;
    let stored = transaction
        .passkeys()
        .find_active_by_credential_id_for_update(result.cred_id().as_ref())
        .await
        .map_err(|_| ApiError)?
        .filter(|credential| credential.user_id == session.user_id)
        .ok_or(ApiError)?;
    let mut passkey: Passkey = serde_json::from_value(stored.credential).map_err(|_| ApiError)?;
    passkey.update_credential(&result).ok_or(ApiError)?;
    let updated = transaction
        .passkeys()
        .update_after_authentication(
            result.cred_id().as_ref(),
            &serde_json::to_value(passkey).map_err(|_| ApiError)?,
        )
        .await
        .map_err(|_| ApiError)?;
    if !updated {
        return Err(ApiError);
    }
    transaction
        .passkeys()
        .insert_purpose_authorization(&InsertPurposeAuthorization {
            id: authorization_id,
            user_id: session.user_id,
            session_id: session.id,
            purpose: MANAGE_PASSKEYS_PURPOSE.into(),
            expires_at: now + Duration::seconds(PURPOSE_TOKEN_SECONDS),
        })
        .await
        .map_err(|_| ApiError)?;
    transaction
        .audit_events()
        .append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(session.user_id),
            action: "passkey.authorize_management".into(),
            outcome: "success".into(),
            request_metadata: serde_json::json!({}),
        })
        .await
        .map_err(|_| ApiError)?;
    transaction.commit().await.map_err(|_| ApiError)?;

    let mut response = Json(PurposeAuthorized {
        purpose_token: token,
        token_type: "Bearer",
        expires_in: PURPOSE_TOKEN_SECONDS,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Serialize, Deserialize)]
struct EnrollmentState {
    user_id: UserId,
    session_id: SessionId,
    authorization_id: TokenId,
    webauthn: PasskeyRegistration,
}

async fn start_enrollment(
    State(app): State<PasskeyApplication>,
    headers: HeaderMap,
) -> Result<Json<RegistrationStarted>, ApiError> {
    validate_mutation_origin(&app, &headers)?;
    let session = active_session(&app.database, &headers).await?;
    let authorization = require_purpose_authorization(&app, &headers, &session).await?;
    let user = app
        .database
        .users()
        .find_by_id(session.user_id)
        .await
        .map_err(|_| ApiError)?
        .ok_or(ApiError)?;
    let (challenge, webauthn) = app
        .webauthn
        .start_passkey_registration(user.id.as_uuid(), &user.username, &user.display_name, None)
        .map_err(|_| ApiError)?;
    let state = serde_json::to_value(EnrollmentState {
        user_id: user.id,
        session_id: session.id,
        authorization_id: authorization.jti,
        webauthn,
    })
    .map_err(|_| ApiError)?;
    let serialized = serde_json::to_vec(&state).map_err(|_| ApiError)?;
    let ceremony_id = TokenId::new();
    app.database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: ceremony_id,
            user_id: Some(user.id),
            session_id: Some(session.id),
            kind: "enrollment".into(),
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

async fn finish_enrollment(
    State(app): State<PasskeyApplication>,
    headers: HeaderMap,
    Json(input): Json<RegistrationFinish>,
) -> Result<StatusCode, ApiError> {
    validate_mutation_origin(&app, &headers)?;
    if input.friendly_name.trim().is_empty() || input.friendly_name.chars().count() > 80 {
        return Err(ApiError);
    }
    let session = active_session(&app.database, &headers).await?;
    let authorization = require_purpose_authorization(&app, &headers, &session).await?;
    let ceremony = app
        .database
        .passkeys()
        .consume_ceremony(input.ceremony_id, "enrollment")
        .await
        .map_err(|_| ApiError)?;
    let state: EnrollmentState = serde_json::from_value(ceremony.state).map_err(|_| ApiError)?;
    if state.user_id != session.user_id
        || state.session_id != session.id
        || state.authorization_id != authorization.jti
    {
        return Err(ApiError);
    }
    let passkey = app
        .webauthn
        .finish_passkey_registration(&input.credential, &state.webauthn)
        .map_err(|_| ApiError)?;
    let mut transaction = app.database.begin().await.map_err(|_| ApiError)?;
    let consumed = transaction
        .passkeys()
        .consume_purpose_authorization(
            authorization.jti,
            session.user_id,
            session.id,
            MANAGE_PASSKEYS_PURPOSE,
        )
        .await
        .map_err(|_| ApiError)?;
    if !consumed {
        return Err(ApiError);
    }
    transaction
        .passkeys()
        .insert(&InsertPasskey {
            id: TokenId::new(),
            credential_id: passkey.cred_id().as_ref().to_vec(),
            user_id: session.user_id,
            credential: serde_json::to_value(passkey).map_err(|_| ApiError)?,
            friendly_name: input.friendly_name,
        })
        .await
        .map_err(|_| ApiError)?;
    transaction
        .audit_events()
        .append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(session.user_id),
            action: "passkey.enroll".into(),
            outcome: "success".into(),
            request_metadata: serde_json::json!({}),
        })
        .await
        .map_err(|_| ApiError)?;
    transaction.commit().await.map_err(|_| ApiError)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct PasskeyView {
    id: TokenId,
    friendly_name: String,
}

async fn list_passkeys(
    State(app): State<PasskeyApplication>,
    headers: HeaderMap,
) -> Result<Json<Vec<PasskeyView>>, ApiError> {
    let session = active_session(&app.database, &headers).await?;
    let keys = app
        .database
        .passkeys()
        .list_active(session.user_id)
        .await
        .map_err(|_| ApiError)?;
    Ok(Json(
        keys.into_iter()
            .map(|key| PasskeyView {
                id: key.id,
                friendly_name: key.friendly_name,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct RenamePasskey {
    friendly_name: String,
}

async fn rename_passkey(
    State(app): State<PasskeyApplication>,
    headers: HeaderMap,
    Path(id): Path<TokenId>,
    Json(input): Json<RenamePasskey>,
) -> Result<StatusCode, ApiError> {
    if input.friendly_name.trim().is_empty() || input.friendly_name.chars().count() > 80 {
        return Err(ApiError);
    }
    validate_mutation_origin(&app, &headers)?;
    let session = active_session(&app.database, &headers).await?;
    app.database
        .passkeys()
        .rename(id, session.user_id, &input.friendly_name)
        .await
        .map_err(|_| ApiError)?
        .then_some(StatusCode::NO_CONTENT)
        .ok_or(ApiError)
}

async fn revoke_passkey(
    State(app): State<PasskeyApplication>,
    headers: HeaderMap,
    Path(id): Path<TokenId>,
) -> Result<StatusCode, ApiError> {
    validate_mutation_origin(&app, &headers)?;
    let session = active_session(&app.database, &headers).await?;
    let authorization = require_purpose_authorization(&app, &headers, &session).await?;
    let mut transaction = app.database.begin().await.map_err(|_| ApiError)?;
    let consumed = transaction
        .passkeys()
        .consume_purpose_authorization(
            authorization.jti,
            session.user_id,
            session.id,
            MANAGE_PASSKEYS_PURPOSE,
        )
        .await
        .map_err(|_| ApiError)?;
    if !consumed {
        return Err(ApiError);
    }
    let revoked = transaction
        .passkeys()
        .revoke_if_not_last(id, session.user_id)
        .await
        .map_err(|_| ApiError)?;
    if !revoked {
        return Err(ApiError);
    }
    transaction
        .audit_events()
        .append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(session.user_id),
            action: "passkey.revoke".into(),
            outcome: "success".into(),
            request_metadata: serde_json::json!({}),
        })
        .await
        .map_err(|_| ApiError)?;
    transaction.commit().await.map_err(|_| ApiError)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn active_session(
    database: &Database,
    headers: &HeaderMap,
) -> Result<piquel_repository::StoredSession, ApiError> {
    let secret = session_secret(headers).ok_or(ApiError)?;
    database
        .sessions()
        .find_active_by_browser_secret(&Sha256::digest(secret))
        .await
        .map_err(|_| ApiError)?
        .ok_or(ApiError)
}

async fn require_purpose_authorization(
    app: &PasskeyApplication,
    headers: &HeaderMap,
    session: &StoredSession,
) -> Result<PurposeTokenClaims, ApiError> {
    let token = bearer_token(headers).ok_or(ApiError)?;
    let claims: PurposeTokenClaims = app
        .purpose_keys
        .verify(PURPOSE_TOKEN_TYPE, token)
        .map_err(|()| ApiError)?;
    if !claims.is_valid_for(
        &app.origin,
        session.user_id,
        session.id,
        Utc::now().timestamp(),
    ) {
        return Err(ApiError);
    }
    let active = app
        .database
        .passkeys()
        .purpose_authorization_is_active(
            claims.jti,
            session.user_id,
            session.id,
            MANAGE_PASSKEYS_PURPOSE,
        )
        .await
        .map_err(|_| ApiError)?;
    active.then_some(claims).ok_or(ApiError)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    (!token.is_empty() && !token.bytes().any(|byte| byte.is_ascii_whitespace())).then_some(token)
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
    validate_mutation_origin(&app, &headers)?;
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

fn validate_mutation_origin(app: &PasskeyApplication, headers: &HeaderMap) -> Result<(), ApiError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError)?;
    if origin.trim_end_matches('/') == app.origin.as_ref() {
        Ok(())
    } else {
        Err(ApiError)
    }
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
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use piquel_repository::DatabaseConfig;
    use std::{env, time::Duration as StdDuration};
    use tower::ServiceExt;
    use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

    fn http_request(
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        purpose_token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        if let Some(token) = purpose_token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = if let Some(body) = body {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&body).expect("request JSON"))
        } else {
            Body::empty()
        };
        builder.body(body).expect("request")
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("response body");
        serde_json::from_slice(&bytes).expect("response JSON")
    }

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
    fn purpose_tokens_are_exactly_bound_and_short_lived() {
        let keys = Es256KeyProvider::generate_for_tests("purpose-test");
        let user_id = UserId::new();
        let session_id = SessionId::new();
        let now = Utc::now().timestamp();
        let claims = PurposeTokenClaims {
            iss: "https://auth.example.com".into(),
            sub: user_id,
            aud: PURPOSE_AUDIENCE.into(),
            purpose: MANAGE_PASSKEYS_PURPOSE.into(),
            sid: session_id,
            auth_time: now,
            iat: now,
            exp: now + PURPOSE_TOKEN_SECONDS,
            jti: TokenId::new(),
        };
        let token = keys
            .sign(PURPOSE_TOKEN_TYPE, &claims)
            .expect("purpose token");
        let verified: PurposeTokenClaims = keys
            .verify(PURPOSE_TOKEN_TYPE, &token)
            .expect("verify purpose token");
        assert!(verified.is_valid_for("https://auth.example.com", user_id, session_id, now));
        assert!(!verified.is_valid_for("https://attacker.example", user_id, session_id, now));
        assert!(!verified.is_valid_for("https://auth.example.com", UserId::new(), session_id, now));
        assert!(!verified.is_valid_for("https://auth.example.com", user_id, SessionId::new(), now));
        let mut wrong_audience = verified.clone();
        wrong_audience.aud = "another-audience".into();
        assert!(!wrong_audience.is_valid_for("https://auth.example.com", user_id, session_id, now));
        let mut wrong_purpose = verified.clone();
        wrong_purpose.purpose = "delete-account".into();
        assert!(!wrong_purpose.is_valid_for("https://auth.example.com", user_id, session_id, now));
        assert!(!verified.is_valid_for(
            "https://auth.example.com",
            user_id,
            session_id,
            now + PURPOSE_TOKEN_SECONDS
        ));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("authorization header"),
        );
        assert_eq!(bearer_token(&headers), Some(token.as_str()));
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

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    #[allow(clippy::too_many_lines)]
    async fn purpose_authorization_is_required_and_single_use_over_http() {
        let database_url = env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
        let database = Database::connect(
            DatabaseConfig::new_development(database_url, 5, StdDuration::from_secs(5))
                .expect("database configuration"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");

        let origin = Url::parse("https://auth.example.com").expect("origin");
        let application = PasskeyApplication::new(
            database,
            "example.com",
            &origin,
            Arc::new(Es256KeyProvider::generate_for_tests("purpose-http")),
        )
        .expect("passkey application");
        let app = routes(application);
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let suffix = UserId::new().to_string();
        let username = format!("purpose_{}", &suffix[suffix.len() - 12..]);

        let response = app
            .clone()
            .oneshot(http_request(
                Method::POST,
                "/webauthn/register/start",
                None,
                None,
                Some(serde_json::json!({
                    "username": username,
                    "display_name": "Purpose Test"
                })),
            ))
            .await
            .expect("registration start");
        assert_eq!(response.status(), StatusCode::OK);
        let started = response_json(response).await;
        let creation: CreationChallengeResponse =
            serde_json::from_value(started["public_key"].clone()).expect("creation options");
        let registered = authenticator
            .do_registration(origin.clone(), creation)
            .expect("registration response");
        let response = app
            .clone()
            .oneshot(http_request(
                Method::POST,
                "/webauthn/register/finish",
                None,
                None,
                Some(serde_json::json!({
                    "ceremony_id": started["ceremony_id"],
                    "credential": registered,
                    "friendly_name": "Primary"
                })),
            ))
            .await
            .expect("registration finish");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .expect("session cookie")
            .to_str()
            .expect("cookie text")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_owned();

        let response = app
            .clone()
            .oneshot(http_request(
                Method::POST,
                "/account/passkeys/enroll/start",
                Some(&cookie),
                None,
                None,
            ))
            .await
            .expect("unauthorized enrollment");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .clone()
            .oneshot(http_request(
                Method::POST,
                "/account/passkeys/authorize/start",
                Some(&cookie),
                None,
                None,
            ))
            .await
            .expect("purpose start");
        assert_eq!(response.status(), StatusCode::OK);
        let purpose_started = response_json(response).await;
        let request: RequestChallengeResponse =
            serde_json::from_value(purpose_started["public_key"].clone())
                .expect("authentication options");
        let assertion = authenticator
            .do_authentication(origin.clone(), request)
            .expect("purpose assertion");
        let response = app
            .clone()
            .oneshot(http_request(
                Method::POST,
                "/account/passkeys/authorize/finish",
                Some(&cookie),
                None,
                Some(serde_json::json!({
                    "ceremony_id": purpose_started["ceremony_id"],
                    "credential": assertion
                })),
            ))
            .await
            .expect("purpose finish");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let authorized = response_json(response).await;
        let purpose_token = authorized["purpose_token"]
            .as_str()
            .expect("purpose token")
            .to_owned();

        let response = app
            .clone()
            .oneshot(http_request(
                Method::POST,
                "/account/passkeys/enroll/start",
                Some(&cookie),
                Some(&purpose_token),
                None,
            ))
            .await
            .expect("enrollment start");
        assert_eq!(response.status(), StatusCode::OK);
        let enrollment = response_json(response).await;
        let creation: CreationChallengeResponse =
            serde_json::from_value(enrollment["public_key"].clone()).expect("creation options");
        let registered = authenticator
            .do_registration(origin, creation)
            .expect("backup registration response");
        let response = app
            .clone()
            .oneshot(http_request(
                Method::POST,
                "/account/passkeys/enroll/finish",
                Some(&cookie),
                Some(&purpose_token),
                Some(serde_json::json!({
                    "ceremony_id": enrollment["ceremony_id"],
                    "credential": registered,
                    "friendly_name": "Backup"
                })),
            ))
            .await
            .expect("enrollment finish");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(http_request(
                Method::POST,
                "/account/passkeys/enroll/start",
                Some(&cookie),
                Some(&purpose_token),
                None,
            ))
            .await
            .expect("replayed purpose token");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
