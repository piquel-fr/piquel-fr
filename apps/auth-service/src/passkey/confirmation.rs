//! Passkey proofs a signed-in session gives: confirming the session, proving a
//! handoff to the admin dashboard or confirming the dashboard on its own page,
//! and enrolling another passkey.

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
use sourceorigin_common::{
    SessionId, UserId,
    events::{Actor, DomainEvent},
};
use url::Url;

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
        app.start_proof(&headers, session.user_id, session.id).await
    }

    /// Starts the passkey proof that confirms the admin dashboard for `user_id`'s
    /// auth session `session_id`, on whose page the browser whose cookies
    /// `headers` carries runs it: an admin proof, bound to that browser, as
    /// auth's handoff page starts. [`Self::verify_dashboard_proof`] checks it.
    pub(crate) async fn start_proof(
        &self,
        headers: &HeaderMap,
        user_id: UserId,
        session_id: SessionId,
    ) -> Result<Response, ApiError> {
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(&self.keys(user_id).await?)
            .map_err(PasskeyError::from)?;
        Ok(self
            .start(
                headers,
                Ceremony::AdminProof(AdminProofCeremony {
                    user_id,
                    session_id,
                    state,
                }),
                challenge,
            )
            .await?)
    }

    /// Verifies the passkey `assertion` a handoff to the admin dashboard posted, as
    /// JSON, for `owner`, as [`Self::prove`] does. The assertion must be signed for
    /// auth's own origin.
    pub(crate) async fn verify_admin_proof(
        &self,
        headers: &HeaderMap,
        owner: &Owner,
        assertion: &str,
    ) -> Result<AdminProof, ApiError> {
        let input: AuthenticationFinish = serde_json::from_str(assertion)
            .map_err(|_| ApiError::bad_request("The passkey proof is malformed. Try again."))?;
        let session = owner.session();
        self.prove(
            headers,
            owner.request(),
            (session.user_id, session.id),
            &input,
            None,
        )
        .await
    }

    /// Verifies the passkey assertion `input` the admin dashboard's page posted, as
    /// [`Self::prove`] does, for `user_id`'s auth session `session_id`, which the
    /// dashboard's session rests on, from `context`. The assertion must be signed
    /// for the dashboard's origin, a related origin of auth's RP ID.
    pub(crate) async fn verify_dashboard_proof(
        &self,
        headers: &HeaderMap,
        context: RequestContext,
        user_id: UserId,
        session_id: SessionId,
        input: &AuthenticationFinish,
    ) -> Result<AdminProof, ApiError> {
        let dashboard = self
            .dashboard
            .as_ref()
            .ok_or(PasskeyError::OriginNotApproved)?;
        self.prove(
            headers,
            context,
            (user_id, session_id),
            input,
            Some(dashboard.as_url()),
        )
        .await
    }

    /// Verifies `input`, a passkey assertion for `user_id`'s session `session_id`:
    /// the browser's admin proof ceremony, which that session started, is
    /// consumed, and its assertion, signed for `related`'s origin when given and
    /// auth's own otherwise, accepted, and recorded as a confirmation of the
    /// session. The session stays as it was. A recovery's passkey during its
    /// probation proves nothing.
    async fn prove(
        &self,
        headers: &HeaderMap,
        context: RequestContext,
        (user_id, session_id): (UserId, SessionId),
        input: &AuthenticationFinish,
        related: Option<&Url>,
    ) -> Result<AdminProof, ApiError> {
        let started = self
            .consume::<AdminProofCeremony>(headers, input.ceremony_id)
            .await?;
        if started.user_id != user_id || started.session_id != session_id {
            return Err(PasskeyError::SessionChanged.into());
        }
        let actor = Actor::User {
            user_id,
            session_id: Some(session_id),
        };
        let verified = match related {
            // The verifier also accepts auth's own origin, so the related one is
            // checked here.
            Some(origin) => {
                if let Err(error) = Self::signed_for(&input.credential, origin) {
                    return Err(self
                        .reject(context, actor.clone(), Some(user_id), error)
                        .await
                        .into());
                }
                Self::webauthn(&self.origin, Some(origin))
                    .map_err(PasskeyError::from)?
                    .finish_passkey_authentication(&input.credential, &started.state)
            }
            None => self
                .webauthn
                .finish_passkey_authentication(&input.credential, &started.state),
        };
        let (mut tx, credential) = self
            .accept_credential::<Credential>(context, actor.clone(), user_id, verified)
            .await?;
        if let Credential::Probation(probation) = credential {
            let settles_at = probation.settles_at();
            return Err(RecoveryError::Probation { settles_at }.into());
        }
        tx.record(
            &context.actor(actor),
            Some(user_id),
            DomainEvent::PasskeyConfirmed { session_id },
        )
        .await?;
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
        let exclusions = app.exclusions(user.id).await?;
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

/// A passkey proof for the admin dashboard, from a handoff or the dashboard's own
/// page: its ceremony, which the session the dashboard rests on started, was
/// consumed and its assertion accepted. Only [`PasskeyApplication`]'s
/// verifications build one, so a dashboard session counts as confirmed only after
/// a passkey proved it, for it.
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
