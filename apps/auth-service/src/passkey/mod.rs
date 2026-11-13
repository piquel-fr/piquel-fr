//! Browser-bound `WebAuthn` ceremonies, passkey management and session confirmation,
//! passkey sign-in on the pages of approved related origins, and the admin
//! dashboard's own passkey confirmation, on its origin.
use crate::account::AccountService;
use crate::config::{EmailConfig, PasskeyConfig};
use crate::deliveries::OutboundClient;
use crate::invitations::InvitationLinks;
use crate::oidc::OidcApplication;
use crate::routes;
use crate::security::{self, BrowserCookie, Credential, RequestContext, SignedIn};
use axum::{
    Router,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use sourceorigin_common::{
    PasskeyId, UserId,
    config::Origin,
    events::{DomainEvent, EventContext},
};
use sourceorigin_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertPasskey, InvitationKey, OpenInvitation,
    PasskeyRepository, StoredPasskey,
};
use std::sync::Arc;
use url::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::*};
use webauthn_rs_proto::ResidentKeyRequirement;

/// Accepting verified assertions by what each ceremony accepts of them.
mod acceptance;
/// Typed challenge payloads and browser binding.
mod ceremonies;
/// Proofs a signed-in session gives: confirmation, the admin dashboard's, and enrollment.
mod confirmation;
/// Passkey failures and their browser response mapping.
mod error;
/// Account registration and passkey sign-in on auth's own pages.
mod login;
/// Account recovery with a link, and undoing it with an older passkey.
mod recovery;
/// Passkey sign-in on the pages of approved related origins.
mod related;
/// Passkey settings of the account service.
mod settings;
/// Validated names and browser request/response bodies.
mod types;

pub(crate) use confirmation::AdminProof;
pub use error::PasskeyConfigError;
pub(crate) use error::PasskeyError;
pub(crate) use recovery::VerifiedRecoveryUndo;
use types::PasskeyKind;
pub(crate) use types::{AuthenticationFinish, DisplayName, PasskeyName, Rename};

/// Browser passkey ceremonies, passkey management and session confirmation.
#[derive(Clone)]
pub struct PasskeyApplication {
    /// Database holding users, passkeys, ceremonies and sessions.
    database: Database,
    /// Auth's origin, whose host is the `WebAuthn` RP ID.
    origin: Origin,
    /// Configured relying party and credential verifier for auth's own pages.
    webauthn: Arc<Webauthn>,
    /// Completes the authorization requests of related origins' sign-ins.
    oidc: OidcApplication,
    /// The admin dashboard's origin, if auth serves one: a related origin whose
    /// pages confirm the dashboard with a passkey.
    dashboard: Option<Origin>,
    /// Whether ordinary registration needs an invitation.
    invite_required: bool,
    /// Fetches the picture a social signup's provider reported.
    outbound: OutboundClient,
    /// Whether email is sent, which importing a social signup's address needs.
    email: EmailConfig,
}

/// Human-readable `WebAuthn` relying party name.
const RELYING_PARTY_NAME: &str = "Origin Account";
/// Android UA marker is a compatibility gate, never an authentication claim.
const ANDROID_USER_AGENT: &str = "Android";

impl PasskeyApplication {
    /// Builds `WebAuthn` from the already validated origin and admission policy.
    /// `oidc` completes the authorization requests of related origins' sign-ins,
    /// and the admin dashboard at `dashboard`, if auth serves one, confirms with
    /// passkeys on its own pages. `email` verifies the addresses social signups
    /// bring.
    pub(crate) fn new(
        database: Database,
        config: &PasskeyConfig,
        email: &EmailConfig,
        dashboard: Option<&Origin>,
        oidc: OidcApplication,
    ) -> Result<Self, PasskeyConfigError> {
        Ok(Self {
            database,
            webauthn: Arc::new(Self::webauthn(&config.origin, None)?),
            origin: config.origin.clone(),
            oidc,
            dashboard: dashboard.cloned(),
            invite_required: config.invite_required,
            outbound: OutboundClient::new().map_err(PasskeyConfigError::Outbound)?,
            email: email.clone(),
        })
    }

    /// The invitation whose token a browser `presented`, if it can still be
    /// used, as the sign-up page and signup find it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the lookup fails.
    pub(crate) async fn invitation(
        &self,
        presented: &str,
    ) -> Result<Option<OpenInvitation>, DatabaseError> {
        let Some(digest) = InvitationLinks::digest(presented) else {
            return Ok(None);
        };
        self.database
            .security()
            .open_invitation(InvitationKey::Digest(&digest))
            .await
    }

    /// A verifier for auth's RP ID that accepts assertions signed for `origin`, and
    /// for the origin of `related` too when given.
    fn webauthn(origin: &Origin, related: Option<&Url>) -> Result<Webauthn, WebauthnError> {
        let mut builder =
            WebauthnBuilder::new(origin.host(), origin.as_url())?.rp_name(RELYING_PARTY_NAME);
        if let Some(related) = related {
            builder = builder.append_allowed_origin(related);
        }
        builder.build()
    }

    /// Returns the passkey ceremonies. Listing, renaming and removing passkeys are
    /// shared settings, which [`AccountService`] serves.
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
            .route(routes::passkey::RELATED_ORIGINS, get(Self::related_origins))
            .route(
                routes::passkey::RELATED_START,
                post(Self::start_related_login),
            )
            .route(
                routes::passkey::RELATED_FINISH,
                post(Self::finish_related_login),
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
            .route(routes::recovery::START, post(Self::start_recovery))
            .route(routes::recovery::FINISH, post(Self::finish_recovery))
            .route(routes::recovery::STATUS, get(Self::recovery))
            .route(routes::recovery::UNDO_START, post(Self::start_undo))
            .route(routes::recovery::UNDO_FINISH, post(Self::finish_undo))
            .route(
                routes::passkey::ADMIN_PROOF_START,
                post(Self::start_admin_proof),
            )
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
                DatabaseError::Refused(_) => PasskeyError::TooManyPasskeys(Some(error)),
                DatabaseError::NotFound
                | DatabaseError::Timeout(_)
                | DatabaseError::Cancelled(_)
                | DatabaseError::LockUnavailable(_)
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

    /// Commits the account operation together with the sign-in with `credential`.
    /// A browser already signed in as `user_id` keeps its session, now confirmed
    /// unless the credential is a recovery's passkey during its probation.
    async fn complete_sign_in(
        mut tx: DatabaseTransaction<'_>,
        context: RequestContext,
        headers: &HeaderMap,
        user_id: UserId,
        credential: Credential,
    ) -> Result<Response, PasskeyError> {
        let session =
            security::Session::sign_in(&mut tx, context, headers, user_id, credential).await?;
        Self::signed_in(tx, &session).await
    }

    /// Commits the new account `user_id` that `tx` created together with its first
    /// sign-in with `credential`, whose browser becomes one of the account's
    /// devices without an alert.
    async fn complete_sign_up(
        mut tx: DatabaseTransaction<'_>,
        context: RequestContext,
        headers: &HeaderMap,
        user_id: UserId,
        credential: Credential,
    ) -> Result<Response, PasskeyError> {
        let session =
            security::Session::sign_in_anew(&mut tx, context, headers, user_id, credential).await?;
        Self::signed_in(tx, &session).await
    }

    /// Commits `tx`, which signed the browser in as `session` says, and answers
    /// with its cookies.
    async fn signed_in(
        tx: DatabaseTransaction<'_>,
        session: &SignedIn,
    ) -> Result<Response, PasskeyError> {
        tx.commit().await?;
        let mut response = StatusCode::NO_CONTENT.into_response();
        session.set_on(&mut response)?;
        // An offer an earlier sign-in left to restore another account no longer
        // stands: this one signed in.
        BrowserCookie::Restore.clear_on(&mut response)?;
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

    /// The credentials a new registration for `user_id` excludes: all its active
    /// ones. Refuses an account that already keeps the most passkeys, before the
    /// authenticator creates one the account could not store.
    async fn exclusions(&self, user_id: UserId) -> Result<Vec<CredentialID>, PasskeyError> {
        let stored = self.database.passkeys().list_active(user_id).await?;
        if stored.len() >= PasskeyRepository::LIMIT {
            return Err(PasskeyError::TooManyPasskeys(None));
        }
        Ok(Self::decode(stored)?
            .iter()
            .map(|key| key.cred_id().clone())
            .collect())
    }

    /// Decodes stored passkey rows into `WebAuthn` credentials.
    fn decode(keys: Vec<StoredPasskey>) -> Result<Vec<Passkey>, PasskeyError> {
        keys.into_iter()
            .map(|key| {
                serde_json::from_value(key.credential).map_err(PasskeyError::StoredCredential)
            })
            .collect()
    }

    /// Whether the browser behind `headers` may save a passkey with Google Password
    /// Manager: only on Android. The library forbids this workaround outside Android
    /// with GMS Core. The User-Agent gate excludes other devices, and the explicit
    /// choice acknowledges Google services, whose presence a User-Agent cannot prove.
    /// The pages offer the choice by it, and registration enforces it.
    pub(crate) fn offers_google_password_manager(headers: &HeaderMap) -> bool {
        headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains(ANDROID_USER_AGENT))
    }

    /// Starts a registration challenge for the chosen passkey kind.
    fn registration(
        &self,
        user_id: UserId,
        handle: &str,
        name: &str,
        exclusions: Option<Vec<CredentialID>>,
        kind: PasskeyKind,
        headers: &HeaderMap,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PasskeyError> {
        match kind {
            PasskeyKind::GooglePasswordManager => {
                if !Self::offers_google_password_manager(headers) {
                    return Err(PasskeyError::GooglePasswordManagerRequiresAndroid);
                }
                Ok(self
                    .webauthn
                    .start_google_passkey_in_google_password_manager_only_registration(
                        user_id.as_uuid(),
                        handle,
                        name,
                        exclusions,
                    )?)
            }
            PasskeyKind::Standard => {
                let (mut challenge, state) = self.webauthn.start_passkey_registration(
                    user_id.as_uuid(),
                    handle,
                    name,
                    exclusions,
                )?;
                // Sign-in lists no credentials (`docs/dev/security/handles.md`), so only
                // a discoverable credential can sign in: refuse to create any other.
                if let Some(selection) = challenge.public_key.authenticator_selection.as_mut() {
                    selection.resident_key = Some(ResidentKeyRequirement::Required);
                    selection.require_resident_key = true;
                }
                Ok((challenge, state))
            }
        }
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
