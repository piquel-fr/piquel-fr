//! Browser-bound `WebAuthn` ceremonies and passkey-only management authorization.
use crate::security::{self, ApiError, BrowserCookie, BrowserSecret};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use chrono::{Duration, Utc};
use piquel_auth_protocol::{AuthenticationMethod, SessionId, TokenId, UserId};
use piquel_configuration::PublicUrl;
use piquel_repository::{
    AppendAuditEvent, Database, DatabaseTransaction, InsertCeremony, InsertPasskey, InsertUser,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use url::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::*};
use webauthn_rs_proto::ResidentKeyRequirement;

#[derive(Clone)]
pub struct PasskeyApplication {
    database: Database,
    webauthn: Arc<Webauthn>,
    invite_required: bool,
}

#[derive(Serialize, Deserialize)]
enum Ceremony {
    Register {
        user_id: UserId,
        username: String,
        display_name: String,
        invitation: Option<Vec<u8>>,
        pending: Option<TokenId>,
        state: PasskeyRegistration,
    },
    Login {
        user_id: UserId,
        state: PasskeyAuthentication,
    },
    Discover {
        state: DiscoverableAuthentication,
    },
    Manage {
        user_id: UserId,
        session_id: SessionId,
        state: PasskeyAuthentication,
    },
    Enroll {
        user_id: UserId,
        session_id: SessionId,
        state: PasskeyRegistration,
    },
}
#[derive(Serialize, Deserialize)]
struct BoundCeremony {
    browser_digest: Vec<u8>,
    ceremony: Ceremony,
}
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PasskeyKind {
    #[default]
    Standard,
    GooglePasswordManager,
}
#[derive(Default, Deserialize)]
struct EnrollmentStart {
    #[serde(default)]
    passkey_kind: PasskeyKind,
}
#[derive(Deserialize)]
struct RegistrationStart {
    #[serde(default)]
    passkey_kind: PasskeyKind,
    username: String,
    #[serde(default)]
    display_name: String,
    invitation: Option<String>,
}
#[derive(Deserialize)]
struct RegistrationFinish {
    ceremony_id: TokenId,
    credential: RegisterPublicKeyCredential,
    #[serde(default = "RegistrationFinish::default_name")]
    friendly_name: String,
}
impl RegistrationFinish {
    fn default_name() -> String {
        "Passkey".into()
    }
}
#[derive(Deserialize)]
struct LoginStart {
    username: Option<String>,
}
#[derive(Deserialize)]
struct AuthenticationFinish {
    ceremony_id: TokenId,
    credential: PublicKeyCredential,
}
#[derive(Deserialize)]
struct Rename {
    friendly_name: String,
}

impl PasskeyApplication {
    pub fn new(
        database: Database,
        rp_id: &str,
        origin: &Url,
        invite_required: bool,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            origin.host_str() == Some(rp_id)
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none(),
            "WebAuthn origin must exactly match its RP ID"
        );
        // WebAuthn RP IDs are domains, so loopback IP literals can never work.
        anyhow::ensure!(
            origin
                .host()
                .is_some_and(|host| matches!(host, url::Host::Domain(_))),
            "WebAuthn requires a domain name, not an IP address; use localhost in development"
        );
        anyhow::ensure!(
            origin.scheme() == "https"
                || (origin.scheme() == "http" && PublicUrl::has_loopback_host(origin)),
            "WebAuthn requires HTTPS outside localhost development"
        );
        Ok(Self {
            database,
            webauthn: Arc::new(
                WebauthnBuilder::new(rp_id, origin)?
                    .rp_name("Piquel")
                    .build()?,
            ),
            invite_required,
        })
    }

    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route("/webauthn/register/start", post(Self::start_registration))
            .route("/webauthn/register/finish", post(Self::finish_registration))
            .route("/webauthn/authenticate/start", post(Self::start_login))
            .route("/webauthn/authenticate/finish", post(Self::finish_login))
            .route(
                "/account/passkeys/authorize/start",
                post(Self::start_management),
            )
            .route(
                "/account/passkeys/authorize/finish",
                post(Self::finish_management),
            )
            .route(
                "/account/passkeys/enroll/start",
                post(Self::start_enrollment),
            )
            .route(
                "/account/passkeys/enroll/finish",
                post(Self::finish_enrollment),
            )
            .route("/account/passkeys", get(Self::list))
            .route(
                "/account/passkeys/{id}",
                patch(Self::rename).delete(Self::revoke),
            )
            .route("/session", get(Self::session_view))
            .route("/session/logout", post(Self::logout))
            .with_state(self)
    }

    fn valid_name(name: &str) -> bool {
        !name.trim().is_empty() && name.chars().count() <= 80 && !name.chars().any(char::is_control)
    }
    fn failed(error: impl std::fmt::Debug) -> ApiError {
        // Authentication errors are intentionally generic; credential/challenge contents are never logged.
        tracing::debug!(?error, "WebAuthn request rejected");
        ApiError::bad_request("Passkey verification failed. Please try again.")
    }
    fn response(value: impl Serialize, cookie: Option<String>) -> Result<Response, ApiError> {
        let mut response = Json(value).into_response();
        if let Some(cookie) = cookie {
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie).map_err(ApiError::internal)?,
            );
        }
        Ok(response)
    }
    fn signed_in(cookie: &str) -> Result<Response, ApiError> {
        let mut response = StatusCode::NO_CONTENT.into_response();
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(cookie).map_err(ApiError::internal)?,
        );
        Ok(response)
    }

    async fn start(
        &self,
        headers: &HeaderMap,
        kind: &str,
        user_id: Option<UserId>,
        session_id: Option<SessionId>,
        ceremony: Ceremony,
        challenge: impl Serialize,
    ) -> Result<Response, ApiError> {
        let browser = BrowserCookie::Ceremony
            .read(headers)
            .unwrap_or_else(BrowserSecret::new);
        let id = TokenId::new();
        self.database
            .passkeys()
            .insert_ceremony(&InsertCeremony {
                id,
                user_id,
                session_id,
                kind: kind.into(),
                challenge_digest: browser.digest(),
                state: serde_json::to_value(BoundCeremony {
                    browser_digest: browser.digest(),
                    ceremony,
                })
                .map_err(ApiError::internal)?,
                expires_at: Utc::now() + Duration::minutes(5),
            })
            .await?;
        Self::response(
            json!({"ceremony_id":id,"public_key":challenge}),
            Some(BrowserCookie::Ceremony.set(&browser)),
        )
    }
    async fn consume(
        &self,
        headers: &HeaderMap,
        id: TokenId,
        kind: &str,
    ) -> Result<Ceremony, ApiError> {
        let browser = BrowserCookie::Ceremony.read(headers).ok_or_else(|| {
            ApiError::bad_request("Please restart the passkey flow in this browser.")
        })?;
        let record = self.database.passkeys().consume_ceremony(id, kind).await?;
        let bound: BoundCeremony =
            serde_json::from_value(record.state).map_err(ApiError::internal)?;
        if bound.browser_digest != browser.digest() {
            return Err(Self::failed("browser mismatch"));
        }
        Ok(bound.ceremony)
    }
    async fn keys(&self, user_id: UserId) -> Result<Vec<Passkey>, ApiError> {
        self.database
            .passkeys()
            .list_active(user_id)
            .await?
            .into_iter()
            .map(|v| serde_json::from_value(v.credential).map_err(ApiError::internal))
            .collect()
    }
    fn registration(
        &self,
        user_id: UserId,
        username: &str,
        name: &str,
        exclusions: Option<Vec<CredentialID>>,
        kind: PasskeyKind,
        headers: &HeaderMap,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), ApiError> {
        if matches!(kind, PasskeyKind::GooglePasswordManager) {
            if !headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("Android"))
            {
                return Err(ApiError::bad_request(
                    "Choose Google Password Manager only on an Android device with Google services.",
                ));
            }
            return self
                .webauthn
                .start_google_passkey_in_google_password_manager_only_registration(
                    user_id.as_uuid(),
                    username,
                    name,
                    exclusions,
                )
                .map_err(Self::failed);
        }
        let (mut challenge, state) = self
            .webauthn
            .start_passkey_registration(user_id.as_uuid(), username, name, exclusions)
            .map_err(Self::failed)?;
        // Prefer account-picker credentials while retaining security keys that need a username.
        if let Some(selection) = challenge.public_key.authenticator_selection.as_mut() {
            selection.resident_key = Some(ResidentKeyRequirement::Preferred);
            selection.require_resident_key = false;
        }
        Ok((challenge, state))
    }
    async fn audit(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        action: &str,
    ) -> Result<(), ApiError> {
        tx.audit_events()
            .append(&AppendAuditEvent {
                id: TokenId::new(),
                user_id: Some(user_id),
                action: action.into(),
                outcome: "success".into(),
                request_metadata: json!({}),
            })
            .await?;
        Ok(())
    }
    async fn update_credential(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        result: &AuthenticationResult,
    ) -> Result<(), ApiError> {
        if !result.user_verified() {
            return Err(Self::failed("user verification required"));
        }
        tx.users()
            .find_active_by_id_for_update(user_id)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        let stored = tx
            .passkeys()
            .find_active_by_credential_id_for_update(result.cred_id().as_ref())
            .await?
            .filter(|v| v.user_id == user_id)
            .ok_or_else(ApiError::unauthorized)?;
        // The ceremony contains a credential snapshot. Check the latest counter under
        // the row lock as well, so overlapping ceremonies cannot accept a regression.
        let counter = stored
            .credential
            .pointer("/cred/counter")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                ApiError::internal(anyhow::anyhow!("stored passkey counter is missing"))
            })?;
        if (counter > 0 || result.counter() > 0) && u64::from(result.counter()) <= counter {
            return Err(Self::failed("credential counter did not increase"));
        }
        let mut credential: Passkey =
            serde_json::from_value(stored.credential).map_err(ApiError::internal)?;
        credential
            .update_credential(result)
            .ok_or_else(|| Self::failed("credential mismatch"))?;
        if !tx
            .passkeys()
            .update_after_authentication(
                result.cred_id().as_ref(),
                &serde_json::to_value(credential).map_err(ApiError::internal)?,
            )
            .await?
        {
            return Err(Self::failed("revoked credential"));
        }
        Ok(())
    }
    async fn lock_management(
        tx: &mut DatabaseTransaction<'_>,
        session: &piquel_repository::StoredSession,
    ) -> Result<(), ApiError> {
        tx.users()
            .find_active_by_id_for_update(session.user_id)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        if !tx.sessions().management_active(session.id).await? {
            return Err(ApiError::forbidden(
                "Your management window expired. Confirm with a passkey again.",
            ));
        }
        Ok(())
    }

    async fn start_registration(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(mut input): Json<RegistrationStart>,
    ) -> Result<Response, ApiError> {
        if input.username.len() < 3
            || input.username.len() > 32
            || !input
                .username
                .bytes()
                .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'_' || v == b'-')
        {
            return Err(ApiError::bad_request(
                "Use 3–32 lowercase letters, numbers, underscores or hyphens for your username.",
            ));
        }
        if input.display_name.is_empty() {
            input.display_name = input.username.clone();
        }
        if !Self::valid_name(&input.display_name) {
            return Err(ApiError::bad_request(
                "Choose a display name of at most 80 characters.",
            ));
        }
        let invitation = input
            .invitation
            .as_deref()
            .and_then(BrowserSecret::parse)
            .map(|v| v.digest());
        if app.invite_required {
            let digest = invitation
                .as_ref()
                .ok_or_else(|| ApiError::forbidden("A valid invitation is required."))?;
            if !app.database.security().invitation_active(digest).await? {
                return Err(ApiError::forbidden(
                    "This invitation has expired or has already been used.",
                ));
            }
        }
        let pending = crate::federation::pending_signup(&app.database, &headers).await?;
        let user_id = UserId::new();
        let (challenge, state) = app.registration(
            user_id,
            &input.username,
            &input.display_name,
            None,
            input.passkey_kind,
            &headers,
        )?;
        app.start(
            &headers,
            "registration",
            None,
            None,
            Ceremony::Register {
                user_id,
                username: input.username,
                display_name: input.display_name,
                invitation,
                pending: pending.map(|v| v.id),
                state,
            },
            challenge,
        )
        .await
    }
    async fn finish_registration(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RegistrationFinish>,
    ) -> Result<Response, ApiError> {
        if !Self::valid_name(&input.friendly_name) {
            return Err(ApiError::bad_request(
                "Choose a passkey name of at most 80 characters.",
            ));
        }
        let Ceremony::Register {
            user_id,
            username,
            display_name,
            invitation,
            pending,
            state,
        } = app
            .consume(&headers, input.ceremony_id, "registration")
            .await?
        else {
            return Err(Self::failed("wrong ceremony"));
        };
        let key = app
            .webauthn
            .finish_passkey_registration(&input.credential, &state)
            .map_err(Self::failed)?;
        let mut tx = app.database.begin().await?;
        if app.invite_required
            && !tx
                .security()
                .redeem_invitation(
                    invitation
                        .as_deref()
                        .ok_or_else(|| ApiError::forbidden("Invitation required."))?,
                )
                .await?
        {
            return Err(ApiError::forbidden(
                "This invitation has expired or has already been used.",
            ));
        }
        tx.users()
            .insert(&InsertUser {
                id: user_id,
                username,
                display_name,
            })
            .await?;
        tx.passkeys()
            .insert(&InsertPasskey {
                id: TokenId::new(),
                credential_id: key.cred_id().as_ref().to_vec(),
                user_id,
                credential: serde_json::to_value(key).map_err(ApiError::internal)?,
                friendly_name: input.friendly_name,
            })
            .await?;
        if let Some(pending) = pending {
            crate::federation::attach_signup(&mut tx, pending, &headers, user_id).await?;
        }
        let cookie =
            security::create_session(&mut tx, user_id, AuthenticationMethod::Passkey).await?;
        Self::audit(&mut tx, user_id, "account.create").await?;
        tx.commit().await?;
        let mut response = Self::signed_in(&cookie)?;
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&BrowserCookie::FederationPending.clear())
                .map_err(ApiError::internal)?,
        );
        Ok(response)
    }
    async fn start_login(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<LoginStart>,
    ) -> Result<Response, ApiError> {
        if let Some(username) = input.username.filter(|v| !v.is_empty()) {
            let user = app
                .database
                .users()
                .find_active_by_username(&username)
                .await?
                .ok_or_else(|| Self::failed("account unavailable"))?;
            let (challenge, state) = app
                .webauthn
                .start_passkey_authentication(&app.keys(user.id).await?)
                .map_err(Self::failed)?;
            app.start(
                &headers,
                "authentication",
                Some(user.id),
                None,
                Ceremony::Login {
                    user_id: user.id,
                    state,
                },
                challenge,
            )
            .await
        } else {
            let (mut challenge, state) = app
                .webauthn
                .start_discoverable_authentication()
                .map_err(Self::failed)?;
            challenge.mediation = None;
            app.start(
                &headers,
                "authentication",
                None,
                None,
                Ceremony::Discover { state },
                challenge,
            )
            .await
        }
    }
    async fn finish_login(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<AuthenticationFinish>,
    ) -> Result<Response, ApiError> {
        let (user_id, result) = match app
            .consume(&headers, input.ceremony_id, "authentication")
            .await?
        {
            Ceremony::Login { user_id, state } => (
                user_id,
                app.webauthn
                    .finish_passkey_authentication(&input.credential, &state)
                    .map_err(Self::failed)?,
            ),
            Ceremony::Discover { state } => {
                let (uuid, _) = app
                    .webauthn
                    .identify_discoverable_authentication(&input.credential)
                    .map_err(Self::failed)?;
                let user_id = UserId::from_uuid(uuid).map_err(Self::failed)?;
                let keys: Vec<DiscoverableKey> = app
                    .keys(user_id)
                    .await?
                    .iter()
                    .map(DiscoverableKey::from)
                    .collect();
                (
                    user_id,
                    app.webauthn
                        .finish_discoverable_authentication(&input.credential, state, &keys)
                        .map_err(Self::failed)?,
                )
            }
            _ => return Err(Self::failed("wrong ceremony")),
        };
        let mut tx = app.database.begin().await?;
        Self::update_credential(&mut tx, user_id, &result).await?;
        let cookie =
            security::create_session(&mut tx, user_id, AuthenticationMethod::Passkey).await?;
        Self::audit(&mut tx, user_id, "passkey.login").await?;
        tx.commit().await?;
        Self::signed_in(&cookie)
    }
    async fn start_management(
        State(app): State<Self>,
        headers: HeaderMap,
    ) -> Result<Response, ApiError> {
        let session = security::session(&app.database, &headers).await?;
        let (challenge, state) = app
            .webauthn
            .start_passkey_authentication(&app.keys(session.user_id).await?)
            .map_err(Self::failed)?;
        app.start(
            &headers,
            "purpose_authentication",
            Some(session.user_id),
            Some(session.id),
            Ceremony::Manage {
                user_id: session.user_id,
                session_id: session.id,
                state,
            },
            challenge,
        )
        .await
    }
    async fn finish_management(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<AuthenticationFinish>,
    ) -> Result<Response, ApiError> {
        let session = security::session(&app.database, &headers).await?;
        let Ceremony::Manage {
            user_id,
            session_id,
            state,
        } = app
            .consume(&headers, input.ceremony_id, "purpose_authentication")
            .await?
        else {
            return Err(Self::failed("wrong ceremony"));
        };
        if session.user_id != user_id || session.id != session_id {
            return Err(Self::failed("session changed"));
        }
        let result = app
            .webauthn
            .finish_passkey_authentication(&input.credential, &state)
            .map_err(Self::failed)?;
        let mut tx = app.database.begin().await?;
        Self::update_credential(&mut tx, user_id, &result).await?;
        let expires = tx.sessions().grant_management(session_id).await?;
        Self::audit(&mut tx, user_id, "settings.unlock").await?;
        tx.commit().await?;
        Self::response(
            json!({"expires_in":120,"management_expires_at":expires}),
            None,
        )
    }
    async fn start_enrollment(
        State(app): State<Self>,
        headers: HeaderMap,
        input: Option<Json<EnrollmentStart>>,
    ) -> Result<Response, ApiError> {
        let session = security::management(&app.database, &headers).await?;
        let user = app
            .database
            .users()
            .find_by_id(session.user_id)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        let exclusions = app
            .keys(user.id)
            .await?
            .iter()
            .map(|v| v.cred_id().clone())
            .collect();
        let (challenge, state) = app.registration(
            user.id,
            &user.username,
            &user.display_name,
            Some(exclusions),
            input.map(|Json(v)| v.passkey_kind).unwrap_or_default(),
            &headers,
        )?;
        app.start(
            &headers,
            "enrollment",
            Some(user.id),
            Some(session.id),
            Ceremony::Enroll {
                user_id: user.id,
                session_id: session.id,
                state,
            },
            challenge,
        )
        .await
    }
    async fn finish_enrollment(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RegistrationFinish>,
    ) -> Result<StatusCode, ApiError> {
        if !Self::valid_name(&input.friendly_name) {
            return Err(ApiError::bad_request(
                "Choose a passkey name of at most 80 characters.",
            ));
        }
        let session = security::management(&app.database, &headers).await?;
        let Ceremony::Enroll {
            user_id,
            session_id,
            state,
        } = app
            .consume(&headers, input.ceremony_id, "enrollment")
            .await?
        else {
            return Err(Self::failed("wrong ceremony"));
        };
        if user_id != session.user_id || session_id != session.id {
            return Err(Self::failed("session changed"));
        }
        let key = app
            .webauthn
            .finish_passkey_registration(&input.credential, &state)
            .map_err(Self::failed)?;
        let mut tx = app.database.begin().await?;
        Self::lock_management(&mut tx, &session).await?;
        tx.passkeys()
            .insert(&InsertPasskey {
                id: TokenId::new(),
                credential_id: key.cred_id().as_ref().to_vec(),
                user_id,
                credential: serde_json::to_value(key).map_err(ApiError::internal)?,
                friendly_name: input.friendly_name,
            })
            .await?;
        Self::audit(&mut tx, user_id, "passkey.add").await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT)
    }
    async fn list(State(app): State<Self>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
        let session = security::session(&app.database, &headers).await?;
        Ok(Json(json!(
            app.database
                .passkeys()
                .list_active(session.user_id)
                .await?
                .into_iter()
                .map(|v| json!({"id":v.id,"friendly_name":v.friendly_name}))
                .collect::<Vec<_>>()
        )))
    }
    async fn rename(
        State(app): State<Self>,
        headers: HeaderMap,
        Path(id): Path<TokenId>,
        Json(input): Json<Rename>,
    ) -> Result<StatusCode, ApiError> {
        if !Self::valid_name(&input.friendly_name) {
            return Err(ApiError::bad_request(
                "Choose a passkey name of at most 80 characters.",
            ));
        }
        let session = security::management(&app.database, &headers).await?;
        let mut tx = app.database.begin().await?;
        Self::lock_management(&mut tx, &session).await?;
        if !tx
            .passkeys()
            .rename(id, session.user_id, &input.friendly_name)
            .await?
        {
            return Err(ApiError::bad_request("Passkey not found."));
        }
        Self::audit(&mut tx, session.user_id, "passkey.rename").await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT)
    }
    async fn revoke(
        State(app): State<Self>,
        headers: HeaderMap,
        Path(id): Path<TokenId>,
    ) -> Result<StatusCode, ApiError> {
        let session = security::management(&app.database, &headers).await?;
        let mut tx = app.database.begin().await?;
        Self::lock_management(&mut tx, &session).await?;
        if !tx
            .passkeys()
            .revoke_if_not_last(id, session.user_id)
            .await?
        {
            return Err(ApiError::bad_request(
                "Keep at least one passkey on your account.",
            ));
        }
        tx.sessions()
            .revoke_other(session.user_id, session.id)
            .await?;
        Self::audit(&mut tx, session.user_id, "passkey.remove").await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT)
    }
    async fn session_view(
        State(app): State<Self>,
        headers: HeaderMap,
    ) -> Result<Json<Value>, ApiError> {
        let session = security::session(&app.database, &headers).await?;
        let user = app
            .database
            .users()
            .find_by_id(session.user_id)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        let expires = app
            .database
            .sessions()
            .management_expiry(session.id)
            .await?;
        Ok(Json(
            json!({"user":{"id":user.id,"username":user.username,"display_name":user.display_name},"management_expires_at":expires}),
        ))
    }
    async fn logout(State(app): State<Self>, headers: HeaderMap) -> Result<Response, ApiError> {
        if let Some(session) = security::optional_session(&app.database, &headers).await? {
            app.database.sessions().revoke(session.id).await?;
        }
        Self::signed_in(&BrowserCookie::Session.clear())
    }
}

#[cfg(test)]
mod tests;
