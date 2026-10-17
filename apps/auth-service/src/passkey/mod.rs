//! Browser-bound `WebAuthn` ceremonies, passkey management and session confirmation.
use crate::config::PasskeyConfig;
use crate::federation::FederationApplication;
use crate::routes;
use crate::security::{self, ApiError, BrowserCookie};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use piquel_auth_protocol::{AuthenticationMethod, TokenId, UserId};
use piquel_crypto::Secret;
use piquel_repository::{
    AuditAction, Database, DatabaseError, DatabaseTransaction, InsertPasskey, InsertUser,
    StoredPasskey,
};
use serde_json::Value;
use std::sync::Arc;
use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::*};
use webauthn_rs_proto::ResidentKeyRequirement;

/// Typed challenge payloads and browser binding.
mod ceremonies;
/// Stable decoy credentials for usernames without an active account or passkey.
mod decoy;
pub(crate) use decoy::DecoyKey;
/// Passkey failures and their browser response mapping.
mod error;
/// Validated names and browser request/response bodies.
mod types;

use ceremonies::{
    AuthenticationCeremony, Ceremony, ConfirmationCeremony, DiscoverCeremony, EnrollmentCeremony,
    LoginCeremony, RegistrationCeremony,
};
pub use error::PasskeyConfigError;
use error::PasskeyError;
use types::{
    AuthenticationFinish, DisplayName, EnrollmentStart, LoginStart, PasskeyKind, PasskeyName,
    PasskeyView, RegistrationFinish, RegistrationStart, Rename, SessionView, UserView, Username,
};

/// Browser passkey ceremonies, passkey management and session confirmation.
#[derive(Clone)]
pub struct PasskeyApplication {
    /// Database holding users, passkeys, ceremonies and sessions.
    database: Database,
    /// Configured relying party and credential verifier.
    webauthn: Arc<Webauthn>,
    /// Whether ordinary registration needs an invitation.
    invite_required: bool,
    /// Derives the decoy credentials of unknown usernames.
    decoy_key: DecoyKey,
}

/// Human-readable `WebAuthn` relying party name.
const RELYING_PARTY_NAME: &str = "Piquel";
/// Android UA marker is a compatibility gate, never an authentication claim.
const ANDROID_USER_AGENT: &str = "Android";
/// Signature counter location in webauthn-rs's serialized passkey representation.
const CREDENTIAL_COUNTER_POINTER: &str = "/cred/counter";
/// Stable telemetry event name for a signature counter regression, a sign of a copied passkey.
const COUNTER_REGRESSION_EVENT: &str = "auth.passkey_counter_regression";

impl PasskeyApplication {
    /// Builds `WebAuthn` from the already validated origin and admission policy.
    pub(crate) fn new(
        database: Database,
        config: &PasskeyConfig,
    ) -> Result<Self, PasskeyConfigError> {
        let origin = config.origin.as_url();
        let rp_id = config.origin.host();
        Ok(Self {
            database,
            webauthn: Arc::new(
                WebauthnBuilder::new(rp_id, origin)?
                    .rp_name(RELYING_PARTY_NAME)
                    .build()?,
            ),
            invite_required: config.invite_required,
            decoy_key: config.decoy_key.clone(),
        })
    }

    /// Returns every passkey and browser-session endpoint.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(
                routes::passkey::REGISTER_START,
                post(Self::start_registration),
            )
            .route(
                routes::passkey::REGISTER_FINISH,
                post(Self::finish_registration),
            )
            .route(routes::passkey::AUTHENTICATE_START, post(Self::start_login))
            .route(
                routes::passkey::AUTHENTICATE_FINISH,
                post(Self::finish_login),
            )
            .route(
                routes::passkey::CONFIRM_START,
                post(Self::start_confirmation),
            )
            .route(
                routes::passkey::CONFIRM_FINISH,
                post(Self::finish_confirmation),
            )
            .route(routes::passkey::ENROLL_START, post(Self::start_enrollment))
            .route(
                routes::passkey::ENROLL_FINISH,
                post(Self::finish_enrollment),
            )
            .route(routes::passkey::LIST, get(Self::list))
            .route(
                routes::passkey::ITEM,
                patch(Self::rename).delete(Self::revoke),
            )
            .route(routes::passkey::SESSION, get(Self::session_view))
            .route(routes::passkey::SESSION_LOGOUT, post(Self::logout))
            .with_state(self)
    }

    /// Stores a verified credential with its validated label inside the account transaction.
    async fn insert_passkey(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        key: Passkey,
        friendly_name: PasskeyName,
    ) -> Result<(), PasskeyError> {
        tx.passkeys()
            .insert(&InsertPasskey {
                id: TokenId::new(),
                credential_id: key.cred_id().as_ref().to_vec(),
                user_id,
                credential: serde_json::to_value(key).map_err(PasskeyError::Serialization)?,
                friendly_name: friendly_name.into(),
            })
            .await
            .map_err(|error| match error {
                DatabaseError::Conflict(_) => PasskeyError::PasskeyAlreadyRegistered(error),
                DatabaseError::NotFound
                | DatabaseError::Timeout(_)
                | DatabaseError::InvalidStoredData { .. }
                | DatabaseError::Operation(_) => error.into(),
            })?;
        Ok(())
    }

    /// Commits the account operation, its audit event and the passkey sign-in together.
    /// A browser already signed in as `user_id` keeps its session, now confirmed.
    async fn complete_sign_in(
        mut tx: DatabaseTransaction<'_>,
        headers: &HeaderMap,
        user_id: UserId,
        action: AuditAction,
    ) -> Result<Response, PasskeyError> {
        let session =
            security::Session::sign_in(&mut tx, headers, user_id, AuthenticationMethod::Passkey)
                .await?;
        tx.audit_events().record(user_id, action, None).await?;
        tx.commit().await?;
        let mut response = StatusCode::NO_CONTENT.into_response();
        BrowserCookie::Session.set_on(&mut response, &session)?;
        Ok(response)
    }

    /// Decodes the account's active passkeys for `WebAuthn`.
    async fn keys(&self, user_id: UserId) -> Result<Vec<Passkey>, PasskeyError> {
        Self::decode(self.database.passkeys().list_active(user_id).await?)
    }

    /// Decodes stored passkey rows into `WebAuthn` credentials.
    fn decode(keys: Vec<StoredPasskey>) -> Result<Vec<Passkey>, PasskeyError> {
        keys.into_iter()
            .map(|key| {
                serde_json::from_value(key.credential).map_err(PasskeyError::StoredCredential)
            })
            .collect()
    }
    /// Starts a registration challenge for the chosen passkey kind.
    fn registration(
        &self,
        user_id: UserId,
        username: &str,
        name: &str,
        exclusions: Option<Vec<CredentialID>>,
        kind: PasskeyKind,
        headers: &HeaderMap,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PasskeyError> {
        match kind {
            PasskeyKind::GooglePasswordManager => {
                // The library forbids this workaround outside Android with GMS Core.
                // UA gating excludes other devices; the explicit UI choice acknowledges
                // Google services because their presence cannot be proven from a UA.
                if !headers
                    .get(header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.contains(ANDROID_USER_AGENT))
                {
                    return Err(PasskeyError::GooglePasswordManagerRequiresAndroid);
                }
                Ok(self
                    .webauthn
                    .start_google_passkey_in_google_password_manager_only_registration(
                        user_id.as_uuid(),
                        username,
                        name,
                        exclusions,
                    )?)
            }
            PasskeyKind::Standard => {
                let (mut challenge, state) = self.webauthn.start_passkey_registration(
                    user_id.as_uuid(),
                    username,
                    name,
                    exclusions,
                )?;
                // Prefer account-picker credentials while keeping security keys that need a username.
                if let Some(selection) = challenge.public_key.authenticator_selection.as_mut() {
                    selection.resident_key = Some(ResidentKeyRequirement::Preferred);
                    selection.require_resident_key = false;
                }
                Ok((challenge, state))
            }
        }
    }

    /// Checks the latest stored counter under lock before updating the credential.
    async fn update_credential(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        result: &AuthenticationResult,
    ) -> Result<(), PasskeyError> {
        if !result.user_verified() {
            return Err(PasskeyError::UserVerificationRequired);
        }
        tx.users()
            .find_active_by_id_for_update(user_id)
            .await?
            .ok_or(PasskeyError::AccountInactive)?;
        let stored = tx
            .passkeys()
            .find_active_by_credential_id_for_update(result.cred_id().as_ref())
            .await?
            .filter(|stored| stored.user_id == user_id)
            .ok_or(PasskeyError::AccountInactive)?;
        // The ceremony contains a credential snapshot. Check the latest counter under
        // the row lock as well, so overlapping ceremonies cannot accept a regression.
        let counter = stored
            .credential
            .pointer(CREDENTIAL_COUNTER_POINTER)
            .and_then(Value::as_u64)
            .ok_or(PasskeyError::MissingCounter)?;
        if (counter > 0 || result.counter() > 0) && u64::from(result.counter()) <= counter {
            return Err(PasskeyError::CounterRegression);
        }
        let mut credential: Passkey =
            serde_json::from_value(stored.credential).map_err(PasskeyError::StoredCredential)?;
        credential
            .update_credential(result)
            .ok_or(PasskeyError::CredentialMismatch)?;
        if !tx
            .passkeys()
            .update_after_authentication(
                result.cred_id().as_ref(),
                &serde_json::to_value(credential).map_err(PasskeyError::Serialization)?,
            )
            .await?
        {
            return Err(PasskeyError::CredentialRevoked);
        }
        Ok(())
    }

    /// Takes `WebAuthn`'s verdict on an assertion for `user_id` and, once the latest
    /// credential state also accepts it, opens the transaction that completes the
    /// authentication. The ceremony was already consumed. A
    /// [`PasskeyError::CounterRegression`] rolls back any transaction it opened, then
    /// commits its audit entry on the pool so the record outlives the rejection.
    async fn accept_credential(
        &self,
        user_id: UserId,
        verified: Result<AuthenticationResult, WebauthnError>,
    ) -> Result<DatabaseTransaction<'_>, PasskeyError> {
        let (error, tx) = match verified {
            Ok(result) => {
                let mut tx = self.database.begin().await?;
                match Self::update_credential(&mut tx, user_id, &result).await {
                    Ok(()) => return Ok(tx),
                    Err(error) => (error, Some(tx)),
                }
            }
            Err(error) => (error.into(), None),
        };
        let PasskeyError::CounterRegression = error else {
            return Err(error);
        };
        // Logged first so the signal survives a database failure.
        tracing::warn!(
            event = COUNTER_REGRESSION_EVENT,
            %user_id,
            "passkey signature counter regression rejected"
        );
        // A failed rollback is only logged: the audit entry matters more, and a broken
        // connection releases its locks anyway.
        if let Some(tx) = tx
            && let Err(rollback) = tx.rollback().await
        {
            tracing::error!(
                error = %piquel_common::ErrorChain(&rollback),
                "passkey authentication rollback failed"
            );
        }
        self.database
            .audit_events()
            .record_rejection(user_id, AuditAction::PasskeyCounterRegression)
            .await?;
        Err(error)
    }

    /// Validates signup and starts the first passkey ceremony without creating an account.
    async fn start_registration(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RegistrationStart>,
    ) -> Result<Response, ApiError> {
        let username = Username::parse(input.username)?;
        let display_name = DisplayName::parse(if input.display_name.is_empty() {
            username.as_str().to_owned()
        } else {
            input.display_name
        })?;
        let invitation = input
            .invitation
            .as_deref()
            .and_then(|value| Secret::parse(value).ok())
            .map(|secret| secret.digest().as_bytes().to_vec());
        if app.invite_required {
            let digest = invitation
                .as_ref()
                .ok_or(PasskeyError::InvitationRequired)?;
            if !app.database.security().invitation_active(digest).await? {
                return Err(PasskeyError::InvitationExpired.into());
            }
        }
        let pending = match input.pending_signup {
            Some(id) => {
                Some(FederationApplication::pending_signup(&app.database, &headers, id).await?)
            }
            None => None,
        };
        let user_id = UserId::new();
        let (challenge, state) = app.registration(
            user_id,
            username.as_str(),
            display_name.as_str(),
            None,
            input.passkey_kind,
            &headers,
        )?;
        Ok(app
            .start(
                &headers,
                Ceremony::Register(RegistrationCeremony {
                    user_id,
                    username,
                    display_name,
                    invitation,
                    pending,
                    state,
                }),
                challenge,
            )
            .await?)
    }

    /// Verifies the first passkey and atomically creates the account, invitation claim and session.
    async fn finish_registration(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RegistrationFinish>,
    ) -> Result<Response, ApiError> {
        let friendly_name = PasskeyName::parse(input.friendly_name)?;
        let RegistrationCeremony {
            user_id,
            username,
            display_name,
            invitation,
            pending,
            state,
        } = app
            .consume::<RegistrationCeremony>(&headers, input.ceremony_id)
            .await?;
        let key = app
            .webauthn
            .finish_passkey_registration(&input.credential, &state)
            .map_err(PasskeyError::from)?;
        let mut tx = app.database.begin().await?;
        if app.invite_required
            && !tx
                .security()
                .redeem_invitation(
                    invitation
                        .as_deref()
                        .ok_or(PasskeyError::InvitationMissingAtFinish)?,
                )
                .await?
        {
            return Err(PasskeyError::InvitationExpired.into());
        }
        tx.users()
            .insert(&InsertUser {
                id: user_id,
                username: username.into(),
                display_name: display_name.into(),
            })
            .await
            .map_err(|error| match error {
                DatabaseError::Conflict(_) => PasskeyError::UsernameTaken(error),
                DatabaseError::NotFound
                | DatabaseError::Timeout(_)
                | DatabaseError::InvalidStoredData { .. }
                | DatabaseError::Operation(_) => error.into(),
            })?;
        Self::insert_passkey(&mut tx, user_id, key, friendly_name).await?;
        if let Some(pending) = pending {
            FederationApplication::attach_signup(&mut tx, pending, &headers, user_id).await?;
        }
        let mut response =
            Self::complete_sign_in(tx, &headers, user_id, AuditAction::AccountCreate).await?;
        // Ordinary registration leaves any unrelated pending social flow untouched.
        if pending.is_some() {
            BrowserCookie::FederationPending
                .clear_on(&mut response)
                .map_err(PasskeyError::CookieHeader)?;
        }
        Ok(response)
    }

    /// Starts username-based authentication or lets the authenticator identify the account.
    ///
    /// A username without an active account or passkey gets the same response as one
    /// with them: one lookup query, a stored ceremony and a challenge built by the same
    /// call, listing stable decoy credentials. That ceremony fails at finish like an
    /// unregistered passkey, so the username field reveals no account.
    async fn start_login(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<LoginStart>,
    ) -> Result<Response, ApiError> {
        let (ceremony, challenge) =
            if let Some(username) = input.username.filter(|username| !username.is_empty()) {
                let keys = app
                    .database
                    .passkeys()
                    .list_active_by_username(&username)
                    .await?;
                let user_id = keys.first().map(|key| key.user_id);
                let (mut challenge, state) = app
                    .webauthn
                    .start_passkey_authentication(&Self::decode(keys)?)
                    .map_err(PasskeyError::from)?;
                let ceremony = if let Some(user_id) = user_id {
                    Ceremony::Login(LoginCeremony { user_id, state })
                } else {
                    challenge.public_key.allow_credentials = app
                        .decoy_key
                        .credentials(&username)
                        .map_err(PasskeyError::Crypto)?;
                    Ceremony::Decoy
                };
                (ceremony, challenge)
            } else {
                let (mut challenge, state) = app
                    .webauthn
                    .start_discoverable_authentication()
                    .map_err(PasskeyError::from)?;
                challenge.mediation = None;
                (Ceremony::Discover(DiscoverCeremony { state }), challenge)
            };
        Ok(app.start(&headers, ceremony, challenge).await?)
    }

    /// Verifies the assertion and latest credential state before signing the browser in.
    async fn finish_login(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<AuthenticationFinish>,
    ) -> Result<Response, ApiError> {
        let (user_id, verified) = match app
            .consume::<AuthenticationCeremony>(&headers, input.ceremony_id)
            .await?
        {
            AuthenticationCeremony::Login(LoginCeremony { user_id, state }) => (
                user_id,
                app.webauthn
                    .finish_passkey_authentication(&input.credential, &state),
            ),
            AuthenticationCeremony::Decoy => return Err(PasskeyError::AccountUnavailable.into()),
            AuthenticationCeremony::Discover(DiscoverCeremony { state }) => {
                let (uuid, _) = app
                    .webauthn
                    .identify_discoverable_authentication(&input.credential)
                    .map_err(PasskeyError::from)?;
                let user_id = UserId::from_uuid(uuid).map_err(PasskeyError::InvalidUserHandle)?;
                let keys: Vec<DiscoverableKey> = app
                    .keys(user_id)
                    .await?
                    .iter()
                    .map(DiscoverableKey::from)
                    .collect();
                (
                    user_id,
                    app.webauthn.finish_discoverable_authentication(
                        &input.credential,
                        state,
                        &keys,
                    ),
                )
            }
        };
        let tx = app.accept_credential(user_id, verified).await?;
        Ok(Self::complete_sign_in(tx, &headers, user_id, AuditAction::PasskeyLogin).await?)
    }

    /// Starts a passkey proof tied to the current signed-in session.
    async fn start_confirmation(
        State(app): State<Self>,
        security::Session(session): security::Session,
        headers: HeaderMap,
    ) -> Result<Response, ApiError> {
        let (challenge, state) = app
            .webauthn
            .start_passkey_authentication(&app.keys(session.user_id).await?)
            .map_err(PasskeyError::from)?;
        Ok(app
            .start(
                &headers,
                Ceremony::Confirm(ConfirmationCeremony {
                    user_id: session.user_id,
                    session_id: session.id,
                    state,
                }),
                challenge,
            )
            .await?)
    }

    /// Confirms the session after a fresh passkey proof started by that same session,
    /// replacing its cookie like any re-authentication.
    async fn finish_confirmation(
        State(app): State<Self>,
        security::Session(session): security::Session,
        headers: HeaderMap,
        Json(input): Json<AuthenticationFinish>,
    ) -> Result<Response, ApiError> {
        let ConfirmationCeremony {
            user_id,
            session_id,
            state,
        } = app
            .consume::<ConfirmationCeremony>(&headers, input.ceremony_id)
            .await?;
        if session.user_id != user_id || session.id != session_id {
            return Err(PasskeyError::SessionChanged.into());
        }
        let verified = app
            .webauthn
            .finish_passkey_authentication(&input.credential, &state);
        let mut tx = app.accept_credential(user_id, verified).await?;
        let secret =
            security::Session::reauthenticate(&mut tx, &session, AuthenticationMethod::Passkey)
                .await?;
        tx.audit_events()
            .record(user_id, AuditAction::SessionPasskeyConfirmed, None)
            .await?;
        tx.commit().await?;
        let mut response = StatusCode::NO_CONTENT.into_response();
        BrowserCookie::Session
            .set_on(&mut response, &secret)
            .map_err(PasskeyError::CookieHeader)?;
        Ok(response)
    }

    /// Starts another passkey registration, excluding the account's current credentials.
    async fn start_enrollment(
        State(app): State<Self>,
        security::Confirmed(session): security::Confirmed,
        headers: HeaderMap,
        input: Option<Json<EnrollmentStart>>,
    ) -> Result<Response, ApiError> {
        let user = app
            .database
            .users()
            .find_by_id(session.user_id)
            .await?
            .ok_or(PasskeyError::AccountInactive)?;
        let exclusions = app
            .keys(user.id)
            .await?
            .iter()
            .map(|key| key.cred_id().clone())
            .collect();
        let (challenge, state) = app.registration(
            user.id,
            &user.username,
            &user.display_name,
            Some(exclusions),
            input
                .map(|Json(input)| input.passkey_kind)
                .unwrap_or_default(),
            &headers,
        )?;
        Ok(app
            .start(
                &headers,
                Ceremony::Enroll(EnrollmentCeremony {
                    user_id: user.id,
                    session_id: session.id,
                    state,
                }),
                challenge,
            )
            .await?)
    }

    /// Adds a verified credential under the session lock. The confirmation authorized
    /// the ceremony at start, and the ceremony belongs to this session and expires on
    /// its own, so a confirmation lapsing at the authenticator never discards the new
    /// credential.
    async fn finish_enrollment(
        State(app): State<Self>,
        security::Session(session): security::Session,
        headers: HeaderMap,
        Json(input): Json<RegistrationFinish>,
    ) -> Result<StatusCode, ApiError> {
        let friendly_name = PasskeyName::parse(input.friendly_name)?;

        let EnrollmentCeremony {
            user_id,
            session_id,
            state,
        } = app
            .consume::<EnrollmentCeremony>(&headers, input.ceremony_id)
            .await?;
        if user_id != session.user_id || session_id != session.id {
            return Err(PasskeyError::SessionChanged.into());
        }
        let key = app
            .webauthn
            .finish_passkey_registration(&input.credential, &state)
            .map_err(PasskeyError::from)?;
        let mut tx = app.database.begin().await?;
        security::Session::lock(&mut tx, &session).await?;
        Self::insert_passkey(&mut tx, user_id, key, friendly_name).await?;
        tx.audit_events()
            .record(user_id, AuditAction::PasskeyAdd, None)
            .await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists public labels and identifiers of the account's active passkeys.
    async fn list(
        State(app): State<Self>,
        security::Session(session): security::Session,
    ) -> Result<Json<Vec<PasskeyView>>, ApiError> {
        Ok(Json(
            app.database
                .passkeys()
                .list_active(session.user_id)
                .await?
                .into_iter()
                .map(|key| PasskeyView {
                    id: key.id,
                    friendly_name: key.friendly_name,
                })
                .collect(),
        ))
    }

    /// Changes a credential label. A name grants nothing, so a session is enough.
    async fn rename(
        State(app): State<Self>,
        security::Session(session): security::Session,
        Path(id): Path<TokenId>,
        Json(input): Json<Rename>,
    ) -> Result<StatusCode, ApiError> {
        let friendly_name = PasskeyName::parse(input.friendly_name)?;

        let mut tx = app.database.begin().await?;
        if !tx
            .passkeys()
            .rename(id, session.user_id, friendly_name.as_str())
            .await?
        {
            return Err(PasskeyError::PasskeyNotFound.into());
        }
        tx.audit_events()
            .record(session.user_id, AuditAction::PasskeyRename, None)
            .await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Removes a passkey while retaining another and revoking the account's other sessions.
    async fn revoke(
        State(app): State<Self>,
        confirmed: security::Confirmed,
        Path(id): Path<TokenId>,
    ) -> Result<StatusCode, ApiError> {
        let session = &confirmed.0;
        let mut tx = app.database.begin().await?;
        confirmed.lock(&mut tx).await?;
        if !tx
            .passkeys()
            .revoke_if_not_last(id, session.user_id)
            .await?
        {
            return Err(PasskeyError::LastPasskey.into());
        }
        tx.sessions()
            .revoke_other(session.user_id, session.id)
            .await?;
        tx.audit_events()
            .record(session.user_id, AuditAction::PasskeyRemove, None)
            .await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Returns the current account identity.
    async fn session_view(
        State(app): State<Self>,
        security::Session(session): security::Session,
    ) -> Result<Json<SessionView>, ApiError> {
        let user = app
            .database
            .users()
            .find_by_id(session.user_id)
            .await?
            .ok_or(PasskeyError::AccountInactive)?;
        Ok(Json(SessionView {
            user: UserView {
                id: user.id,
                username: user.username,
                display_name: user.display_name,
            },
        }))
    }

    /// Revokes the current session if present and clears its browser cookie.
    async fn logout(
        State(app): State<Self>,
        security::OptionalSession(session): security::OptionalSession,
    ) -> Result<Response, ApiError> {
        if let Some(session) = session {
            app.database.sessions().revoke(session.id).await?;
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        BrowserCookie::Session
            .clear_on(&mut response)
            .map_err(PasskeyError::CookieHeader)?;
        Ok(response)
    }
}

/// Supplies the shared database boundary to browser-session extractors.
impl axum::extract::FromRef<PasskeyApplication> for Database {
    /// Shares persistence with the session extractors without duplicating lookups.
    fn from_ref(application: &PasskeyApplication) -> Self {
        application.database.clone()
    }
}

#[cfg(test)]
mod tests;
