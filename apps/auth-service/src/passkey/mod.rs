//! Browser-bound `WebAuthn` ceremonies, passkey management and session confirmation.
use crate::account::{AccountError, AccountService, Owner, Subject, Viewer};
use crate::config::PasskeyConfig;
use crate::federation::FederationApplication;
use crate::recovery::{RecoveryAccount, RecoveryError, RecoveryView};
use crate::routes;
use crate::security::{self, ApiError, BrowserCookie, Credential, RequestContext};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use piquel_common::{
    AuthenticationMethod, Handle, PasskeyId, RecoveryId, UserId,
    events::{Actor, DomainEvent, EventContext, RevocationReason},
    protocol::api,
};
use piquel_crypto::Secret;
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertPasskey, InsertUser, SessionScope,
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
    LoginCeremony, RecoveryCeremony, RegistrationCeremony,
};
pub use error::PasskeyConfigError;
pub(crate) use error::PasskeyError;
use types::{
    AuthenticationFinish, DisplayName, EnrollmentStart, LoginStart, PasskeyKind, RecoveryStart,
    RecoveryToken, RecoveryUndo, RegistrationFinish, RegistrationStart, SessionView, UserView,
};
pub(crate) use types::{PasskeyName, Rename};

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

    /// Returns the passkey ceremonies and browser-session endpoints. Listing,
    /// renaming and removing passkeys are shared settings, which
    /// [`AccountService`] serves.
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
            .route(routes::passkey::SESSION, get(Self::session_view))
            .route(routes::passkey::SESSION_LOGOUT, post(Self::logout))
            .route(routes::recovery::CHECK, post(Self::check_recovery))
            .route(routes::recovery::START, post(Self::start_recovery))
            .route(routes::recovery::FINISH, post(Self::finish_recovery))
            .route(routes::recovery::STATUS, get(Self::recovery))
            .route(routes::recovery::UNDO, post(Self::undo_recovery))
            .with_state(self)
    }

    /// Stores a verified credential with its validated label inside the account
    /// transaction, records its addition, and returns its ID.
    async fn insert_passkey(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user_id: UserId,
        key: Passkey,
        friendly_name: PasskeyName,
    ) -> Result<PasskeyId, PasskeyError> {
        let passkey_id = PasskeyId::new();
        tx.passkeys()
            .insert(&InsertPasskey {
                id: passkey_id,
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
        tx.record(
            context,
            Some(user_id),
            DomainEvent::PasskeyAdded { passkey_id },
        )
        .await?;
        Ok(passkey_id)
    }

    /// Commits the account operation together with the sign-in with `passkey`. A
    /// browser already signed in as `user_id` keeps its session, now confirmed.
    async fn complete_sign_in(
        mut tx: DatabaseTransaction<'_>,
        context: RequestContext,
        headers: &HeaderMap,
        user_id: UserId,
        passkey: PasskeyId,
    ) -> Result<Response, PasskeyError> {
        let session = security::Session::sign_in(
            &mut tx,
            context,
            headers,
            user_id,
            Credential::Passkey(passkey),
        )
        .await?;
        tx.commit().await?;
        let mut response = StatusCode::NO_CONTENT.into_response();
        BrowserCookie::Session.set_on(&mut response, &session)?;
        Ok(response)
    }

    /// The account operations, over this application's database.
    fn service(&self) -> AccountService {
        AccountService::new(self.database.clone())
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

    /// Checks the latest stored counter under lock before updating the credential,
    /// and returns the passkey's ID.
    async fn update_credential(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        result: &AuthenticationResult,
    ) -> Result<PasskeyId, PasskeyError> {
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
        Ok(stored.id)
    }

    /// Takes `WebAuthn`'s verdict on an assertion for `user_id` and, once the latest
    /// credential state also accepts it, opens the transaction that completes the
    /// authentication, and returns it with the asserting passkey's ID. The ceremony was already consumed. A rejection rolls back any
    /// transaction it opened, then is recorded as `actor`'s failed sign-in in a
    /// transaction of its own, so the record outlives the rejection.
    async fn accept_credential(
        &self,
        context: RequestContext,
        actor: Actor,
        user_id: UserId,
        verified: Result<AuthenticationResult, WebauthnError>,
    ) -> Result<(DatabaseTransaction<'_>, PasskeyId), PasskeyError> {
        let (error, tx) = match verified {
            Ok(result) => {
                let mut tx = self.database.begin().await?;
                match Self::update_credential(&mut tx, user_id, &result).await {
                    Ok(passkey) => return Ok((tx, passkey)),
                    Err(error) => (error, Some(tx)),
                }
            }
            Err(error) => (error.into(), None),
        };
        if let PasskeyError::CounterRegression = error {
            // Logged first so the signal survives a database failure.
            tracing::warn!(
                event = COUNTER_REGRESSION_EVENT,
                %user_id,
                "passkey signature counter regression rejected"
            );
        }
        // A failed rollback is only logged: the record matters more, and a broken
        // connection releases its locks anyway.
        if let Some(tx) = tx
            && let Err(rollback) = tx.rollback().await
        {
            tracing::error!(
                error = %piquel_common::ErrorChain(&rollback),
                "passkey authentication rollback failed"
            );
        }
        Err(self.reject(context, actor, Some(user_id), error).await)
    }

    /// Records `error` as `actor`'s failed passkey authentication of `subject`, when
    /// it describes the attempt, then returns it, or the database failure that
    /// prevented recording it.
    async fn reject(
        &self,
        context: RequestContext,
        actor: Actor,
        subject: Option<UserId>,
        error: PasskeyError,
    ) -> PasskeyError {
        let Some(reason) = error.sign_in_failure() else {
            return error;
        };
        match context
            .record_sign_in_failure(
                &self.database,
                actor,
                subject,
                AuthenticationMethod::Passkey,
                reason,
            )
            .await
        {
            Ok(()) => error,
            Err(database) => database.into(),
        }
    }

    /// Validates signup and starts the first passkey ceremony without creating an account.
    async fn start_registration(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RegistrationStart>,
    ) -> Result<Response, ApiError> {
        let username = Handle::parse(&input.username)?;
        username.ensure_unreserved()?;
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
        context: RequestContext,
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
                handle: username,
                display_name: display_name.into(),
            })
            .await
            .map_err(|error| match error {
                DatabaseError::Conflict(_) => PasskeyError::HandleTaken(error),
                DatabaseError::NotFound
                | DatabaseError::Timeout(_)
                | DatabaseError::InvalidStoredData { .. }
                | DatabaseError::Operation(_) => error.into(),
            })?;
        let actor = context.actor(Actor::User {
            user_id,
            session_id: None,
        });
        tx.record(
            &actor,
            Some(user_id),
            DomainEvent::AccountCreated {
                method: if pending.is_some() {
                    AuthenticationMethod::Federation
                } else {
                    AuthenticationMethod::Passkey
                },
                invited: app.invite_required,
            },
        )
        .await?;
        let passkey = Self::insert_passkey(&mut tx, &actor, user_id, key, friendly_name).await?;
        if let Some(pending) = pending {
            FederationApplication::attach_signup(&mut tx, &actor, pending, &headers, user_id)
                .await?;
        }
        let mut response = Self::complete_sign_in(tx, context, &headers, user_id, passkey).await?;
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
        context: RequestContext,
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
            AuthenticationCeremony::Decoy => {
                return Err(app
                    .reject(
                        context,
                        Actor::Anonymous,
                        None,
                        PasskeyError::AccountUnavailable,
                    )
                    .await
                    .into());
            }
            AuthenticationCeremony::Discover(DiscoverCeremony { state }) => {
                let (user_id, keys) = match app.discover(&input.credential).await {
                    Ok(discovered) => discovered,
                    Err(error) => {
                        return Err(app
                            .reject(context, Actor::Anonymous, None, error)
                            .await
                            .into());
                    }
                };
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
        let (tx, passkey) = app
            .accept_credential(context, Actor::Anonymous, user_id, verified)
            .await?;
        Ok(Self::complete_sign_in(tx, context, &headers, user_id, passkey).await?)
    }

    /// Reads the account a discoverable credential names, and that account's keys.
    async fn discover(
        &self,
        credential: &PublicKeyCredential,
    ) -> Result<(UserId, Vec<DiscoverableKey>), PasskeyError> {
        let (uuid, _) = self
            .webauthn
            .identify_discoverable_authentication(credential)?;
        let user_id = UserId::from_uuid(uuid).map_err(PasskeyError::InvalidUserHandle)?;
        let keys = self
            .keys(user_id)
            .await?
            .iter()
            .map(DiscoverableKey::from)
            .collect();
        Ok((user_id, keys))
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
        context: RequestContext,
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
        let actor = Actor::User {
            user_id,
            session_id: Some(session_id),
        };
        let (mut tx, passkey) = app
            .accept_credential(context, actor, user_id, verified)
            .await?;
        let secret =
            security::Session::reauthenticate(&mut tx, &session, Credential::Passkey(passkey))
                .await?;
        tx.record(
            &context.user(&session),
            Some(user_id),
            DomainEvent::PasskeyConfirmed { session_id },
        )
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

    /// Finishes the owner's enrollment of another passkey: the ceremony must be
    /// the one this session started, and the authenticator's credential must
    /// verify against it.
    async fn finish_enrollment(
        State(app): State<Self>,
        owner: Owner,
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
        if user_id != owner.user() || session_id != owner.session().id {
            return Err(PasskeyError::SessionChanged.into());
        }
        let key = app
            .webauthn
            .finish_passkey_registration(&input.credential, &state)
            .map_err(PasskeyError::from)?;
        app.service()
            .add_passkey(&owner, key, friendly_name)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Describes the account a recovery link recovers, without using the link, so
    /// its page can say whose passkey it adds. Never a `GET`, since mail scanners
    /// follow links.
    async fn check_recovery(
        State(app): State<Self>,
        Json(input): Json<RecoveryToken>,
    ) -> Result<Json<RecoveryAccount>, ApiError> {
        let recovery = app.service().open_recovery(&input.token).await?;
        Ok(Json(recovery.into_account()))
    }

    /// Starts enrolling a passkey with a recovery link, excluding the account's
    /// current credentials. The link's token authorizes it, without a session.
    async fn start_recovery(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RecoveryStart>,
    ) -> Result<Response, ApiError> {
        let recovery = app.service().open_recovery(&input.token).await?;
        let user_id = recovery.user_id();
        let exclusions = app
            .keys(user_id)
            .await?
            .iter()
            .map(|key| key.cred_id().clone())
            .collect();
        let account = recovery.account();
        let (challenge, state) = app.registration(
            user_id,
            &account.username,
            &account.display_name,
            Some(exclusions),
            input.passkey_kind,
            &headers,
        )?;
        Ok(app
            .start(
                &headers,
                Ceremony::Recover(RecoveryCeremony {
                    recovery_id: recovery.id(),
                    user_id,
                    state,
                }),
                challenge,
            )
            .await?)
    }

    /// Finishes enrolling a passkey with a recovery link: uses the link, and signs
    /// the browser in with the new passkey.
    async fn finish_recovery(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        Json(input): Json<RegistrationFinish>,
    ) -> Result<Response, ApiError> {
        let friendly_name = PasskeyName::parse(input.friendly_name)?;
        let RecoveryCeremony {
            recovery_id,
            user_id,
            state,
        } = app
            .consume::<RecoveryCeremony>(&headers, input.ceremony_id)
            .await?;
        let key = app
            .webauthn
            .finish_passkey_registration(&input.credential, &state)
            .map_err(PasskeyError::from)?;
        let mut tx = app.database.begin().await?;
        let passkey = AccountService::complete_recovery(
            &mut tx,
            recovery_id,
            user_id,
            key,
            friendly_name,
            context,
        )
        .await?;
        Ok(Self::complete_sign_in(tx, context, &headers, user_id, passkey).await?)
    }

    /// Describes the owner's newest recovery they could undo, if any.
    async fn recovery(
        State(app): State<Self>,
        owner: Owner,
    ) -> Result<Json<Option<RecoveryView>>, ApiError> {
        Ok(Json(app.service().recovery(&owner).await?))
    }

    /// Undoes the recovery the owner's undo page showed, from a session an older
    /// passkey signed in.
    async fn undo_recovery(
        State(app): State<Self>,
        owner: Owner,
        Json(input): Json<RecoveryUndo>,
    ) -> Result<StatusCode, ApiError> {
        app.service()
            .undo_recovery(&owner, input.recovery_id)
            .await?;
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
        context: RequestContext,
        security::OptionalSession(session): security::OptionalSession,
    ) -> Result<Response, ApiError> {
        if let Some(session) = session {
            let mut tx = app.database.begin().await?;
            security::Session::revoke(
                &mut tx,
                context,
                &session,
                SessionScope::One(session.id),
                RevocationReason::Logout,
            )
            .await?;
            tx.commit().await?;
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        BrowserCookie::Session
            .clear_on(&mut response)
            .map_err(PasskeyError::CookieHeader)?;
        Ok(response)
    }
}

/// The passkey a recovery's link enrolls, which its token authorizes.
impl AccountService {
    /// Completes recovery `recovery_id` of `user_id` with `key`, a passkey its
    /// link's ceremony verified, in the caller's transaction, which signs the
    /// browser in with it on commit. Stores the passkey and records the completion
    /// as the browser's, which the link authorized, not a session. Fails, rolling
    /// the passkey back, if the link stopped working since the ceremony started.
    pub(crate) async fn complete_recovery(
        tx: &mut DatabaseTransaction<'_>,
        recovery_id: RecoveryId,
        user_id: UserId,
        key: Passkey,
        friendly_name: PasskeyName,
        request: RequestContext,
    ) -> Result<PasskeyId, AccountError> {
        tx.users()
            .find_active_by_id_for_update(user_id)
            .await?
            .ok_or(RecoveryError::InvalidLink)?;
        let context = request.actor(Actor::Anonymous);
        let passkey_id =
            PasskeyApplication::insert_passkey(tx, &context, user_id, key, friendly_name).await?;
        if !tx
            .recoveries()
            .complete(user_id, recovery_id, passkey_id)
            .await?
        {
            return Err(RecoveryError::InvalidLink.into());
        }
        tx.record(
            &context,
            Some(user_id),
            DomainEvent::RecoveryCompleted {
                recovery_id,
                passkey_id,
            },
        )
        .await?;
        Ok(passkey_id)
    }
}

/// Passkey settings any administrator may also change: listing, renaming and
/// removing. Only the owner adds a passkey, since it is a way to sign in.
impl AccountService {
    /// Adds `key`, a passkey the owner's browser registered and the enrollment
    /// ceremony verified, under the owner's session lock. A recent confirmation
    /// authorized the ceremony at its start, and the ceremony belongs to this
    /// session and expires on its own, so a confirmation lapsing at the
    /// authenticator never discards the new credential.
    pub(crate) async fn add_passkey(
        &self,
        owner: &Owner,
        key: Passkey,
        friendly_name: PasskeyName,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        owner.lock(&mut tx).await?;
        PasskeyApplication::insert_passkey(
            &mut tx,
            &owner.context(),
            owner.user(),
            key,
            friendly_name,
        )
        .await?;
        Ok(tx.commit().await?)
    }

    /// Lists public labels and identifiers of the account's active passkeys.
    pub(crate) async fn passkeys(
        &self,
        viewer: &Viewer,
    ) -> Result<Vec<api::Passkey>, AccountError> {
        viewer.authorize(&self.database).await?;
        let passkeys = self.database.passkeys().list_active(viewer.user()).await?;
        Ok(passkeys.into_iter().map(Into::into).collect())
    }

    /// Changes a passkey's label. A name grants nothing, so the owner needs no
    /// passkey confirmation.
    pub(crate) async fn rename_passkey(
        &self,
        subject: &Subject,
        id: PasskeyId,
        name: String,
    ) -> Result<(), AccountError> {
        let friendly_name = PasskeyName::parse(name)?;
        let mut tx = self.database.begin().await?;
        subject.lock(&mut tx).await?;
        if !tx
            .passkeys()
            .rename(id, subject.user(), friendly_name.as_str())
            .await?
        {
            return Err(PasskeyError::PasskeyNotFound.into());
        }
        tx.record(
            &subject.context(),
            Some(subject.user()),
            DomainEvent::PasskeyRenamed { passkey_id: id },
        )
        .await?;
        subject.commit(tx).await
    }

    /// Removes a passkey and signs the account out elsewhere. One active passkey
    /// always remains, even with a social identity linked.
    pub(crate) async fn revoke_passkey(
        &self,
        subject: &Subject,
        id: PasskeyId,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        subject.lock_confirmed(&mut tx).await?;
        if !tx.passkeys().revoke_if_not_last(id, subject.user()).await? {
            return Err(PasskeyError::LastPasskey.into());
        }
        let context = subject.context();
        tx.record(
            &context,
            Some(subject.user()),
            DomainEvent::PasskeyRemoved { passkey_id: id },
        )
        .await?;
        tx.revoke_sessions(
            &context,
            subject.user(),
            subject.others(),
            &RevocationReason::CredentialRemoved,
        )
        .await?;
        subject.commit(tx).await
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
pub(crate) mod tests;
