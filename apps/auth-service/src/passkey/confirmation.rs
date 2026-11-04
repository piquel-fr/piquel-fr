//! Passkey proofs a signed-in session gives: confirming the session, proving a
//! handoff to the admin dashboard, and enrolling another passkey.

use super::{
    PasskeyApplication, PasskeyError, PasskeyName,
    ceremonies::{AdminProofCeremony, Ceremony, ConfirmationCeremony, EnrollmentCeremony},
    types::{AuthenticationFinish, EnrollmentStart, RegistrationFinish},
};
use crate::account::Owner;
use crate::recovery::RecoveryError;
use crate::security::{self, ApiError, BrowserCookie, Credential, RequestContext};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use piquel_common::{
    SessionId,
    events::{Actor, DomainEvent},
};

impl PasskeyApplication {
    /// Starts a passkey proof tied to the current signed-in session.
    pub(super) async fn start_confirmation(
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
    pub(super) async fn finish_confirmation(
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
        let (mut tx, credential) = app
            .accept_credential(context, actor, user_id, verified)
            .await?;
        let credential = match credential {
            // A recovery's passkey never confirms a session during its probation.
            Credential::Probation(probation) => {
                let settles_at = probation.settles_at();
                return Err(RecoveryError::Probation { settles_at }.into());
            }
            Credential::Passkey(_) | Credential::Federation => credential,
        };
        let secret = security::Session::reauthenticate(&mut tx, &session, credential).await?;
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

    /// Starts the passkey proof of a handoff to the admin dashboard, tied to the
    /// current signed-in session. Its page posts the assertion with the handoff,
    /// which [`Self::verify_admin_proof`] checks.
    pub(super) async fn start_admin_proof(
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
                Ceremony::AdminProof(AdminProofCeremony {
                    user_id: session.user_id,
                    session_id: session.id,
                    state,
                }),
                challenge,
            )
            .await?)
    }

    /// Verifies the passkey `assertion` a handoff to the admin dashboard posted, as
    /// JSON, for `owner`: the browser's admin proof ceremony, which `owner`'s
    /// session started, is consumed, and its assertion accepted. The session stays
    /// as it was. A recovery's passkey during its probation proves nothing.
    pub(crate) async fn verify_admin_proof(
        &self,
        headers: &HeaderMap,
        owner: &Owner,
        assertion: &str,
    ) -> Result<AdminProof, ApiError> {
        let input: AuthenticationFinish = serde_json::from_str(assertion)
            .map_err(|_| ApiError::bad_request("The passkey proof is malformed. Try again."))?;
        let AdminProofCeremony {
            user_id,
            session_id,
            state,
        } = self
            .consume::<AdminProofCeremony>(headers, input.ceremony_id)
            .await?;
        let session = owner.session();
        if session.user_id != user_id || session.id != session_id {
            return Err(PasskeyError::SessionChanged.into());
        }
        let verified = self
            .webauthn
            .finish_passkey_authentication(&input.credential, &state);
        let actor = Actor::User {
            user_id,
            session_id: Some(session_id),
        };
        let (tx, credential) = self
            .accept_credential::<Credential>(owner.request(), actor, user_id, verified)
            .await?;
        if let Credential::Probation(probation) = credential {
            let settles_at = probation.settles_at();
            return Err(RecoveryError::Probation { settles_at }.into());
        }
        tx.commit().await.map_err(PasskeyError::from)?;
        Ok(AdminProof {
            session_id,
            at: chrono::Utc::now(),
        })
    }

    /// Starts another passkey registration, excluding the account's current credentials.
    pub(super) async fn start_enrollment(
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
            user.handle.as_str(),
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
    pub(super) async fn finish_enrollment(
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
        if user_id != owner.user() || session_id != owner.session_id() {
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
}

/// A passkey proof of a handoff to the admin dashboard: its ceremony, which the
/// session handing off started, was consumed and its assertion accepted. Only
/// [`PasskeyApplication::verify_admin_proof`] builds one, so a dashboard session
/// counts as confirmed only after a passkey proved it, for it.
pub(crate) struct AdminProof {
    /// The session that started the ceremony.
    session_id: SessionId,
    /// When the passkey proved it.
    at: chrono::DateTime<chrono::Utc>,
}

impl AdminProof {
    /// The session that started the ceremony.
    pub(crate) const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// When the passkey proved it.
    pub(crate) const fn at(&self) -> chrono::DateTime<chrono::Utc> {
        self.at
    }

    /// A proof of `session_id` at `at`, as if verified: a fixture for the
    /// handoff's own checks.
    #[cfg(test)]
    pub(crate) const fn unverified(
        session_id: SessionId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self { session_id, at }
    }
}
