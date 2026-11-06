//! Account registration and passkey sign-in on auth's own pages, by handle or
//! with an account picker.

use super::{
    PasskeyApplication, PasskeyError, PasskeyName,
    acceptance::SignIn,
    ceremonies::{
        AuthenticationCeremony, Ceremony, DiscoverCeremony, LoginCeremony, RegistrationCeremony,
    },
    types::{AuthenticationFinish, DisplayName, LoginStart, RegistrationFinish, RegistrationStart},
};
use crate::deletion::Deletions;
use crate::federation::FederationApplication;
use crate::handles::{Handles, HandlesError};
use crate::security::{ApiError, BrowserCookie, Credential, RequestContext};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use piquel_common::{
    AuthenticationMethod, ErrorChain, Handle, UserId,
    events::{Actor, DomainEvent},
};
use piquel_crypto::Secret;
use piquel_repository::{DatabaseError, InsertUser};
use tracing::Instrument;
use webauthn_rs::{Webauthn, prelude::*};

impl PasskeyApplication {
    /// Validates signup and starts the first passkey ceremony without creating an account.
    pub(super) async fn start_registration(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RegistrationStart>,
    ) -> Result<Response, ApiError> {
        let handle = Handle::parse(&input.handle).map_err(HandlesError::from)?;
        Handles::new(&app.database)
            .ensure_unreserved(&handle)
            .await?;
        let display_name = DisplayName::parse(if input.display_name.is_empty() {
            handle.as_str().to_owned()
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
        // Only once admitted, so an uninvited signup hears about its invitation first.
        Handles::new(&app.database)
            .claimable(&handle, None)
            .await
            .map_err(PasskeyError::from)?;
        let user_id = UserId::new();
        let (challenge, state) = app.registration(
            user_id,
            handle.as_str(),
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
                    handle,
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
    pub(super) async fn finish_registration(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        Json(input): Json<RegistrationFinish>,
    ) -> Result<Response, ApiError> {
        let friendly_name = PasskeyName::parse(input.friendly_name)?;
        let RegistrationCeremony {
            user_id,
            handle,
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
        let inserted = tx
            .users()
            .insert(&InsertUser {
                id: user_id,
                handle: handle.clone(),
                display_name: display_name.into(),
            })
            .await;
        if let Err(DatabaseError::Conflict(_)) = inserted {
            // Another account claimed the handle, or one like it, since the start.
            // Roll back first, so the lookup holds no second connection.
            tx.rollback().await?;
            let refused = Handles::new(&app.database).refusal(&handle, None).await;
            return Err(PasskeyError::from(refused).into());
        }
        inserted?;
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
        let picture = match pending {
            Some(pending) => {
                FederationApplication::attach_signup(
                    &mut tx,
                    &actor,
                    &app.email,
                    context.client_ip,
                    pending,
                    &headers,
                    user_id,
                )
                .await?
            }
            None => None,
        };
        let mut response =
            Self::complete_sign_in(tx, context, &headers, user_id, Credential::Passkey(passkey))
                .await?;
        // Once the account is committed, and off the request, so a slow provider or
        // uploads waiting to be decoded never hold up the sign-up. A picture that
        // cannot be imported is only logged: the owner may upload one.
        if let Some(picture) = picture {
            let (account, outbound) = (app.service(), app.outbound.clone());
            tokio::spawn(
                async move {
                    if let Err(error) = account
                        .import_picture(&outbound, user_id, &actor, &picture)
                        .await
                    {
                        tracing::warn!(error = %ErrorChain(&error), "provider picture not imported");
                    }
                }
                .in_current_span(),
            );
        }
        // Ordinary registration leaves any unrelated pending social flow untouched.
        if pending.is_some() {
            BrowserCookie::FederationPending
                .clear_on(&mut response)
                .map_err(PasskeyError::CookieHeader)?;
        }
        Ok(response)
    }

    /// Starts handle-based authentication or lets the authenticator identify the account.
    ///
    /// Handles are public (`docs/security/handles.md`), so a handle without an active
    /// account or passkey is refused at once, before any ceremony. Text that is not a
    /// handle names no account, so it is refused the same way.
    pub(super) async fn start_login(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<LoginStart>,
    ) -> Result<Response, ApiError> {
        let (ceremony, challenge) =
            if let Some(input) = input.handle.filter(|handle| !handle.is_empty()) {
                let keys = match Handle::parse(&input) {
                    Ok(handle) => {
                        app.database
                            .passkeys()
                            .list_active_by_handle(&handle)
                            .await?
                    }
                    Err(_) => Vec::new(),
                };
                let user_id = keys
                    .first()
                    .map(|key| key.user_id)
                    .ok_or(PasskeyError::UnknownHandle)?;
                let (challenge, state) = app
                    .webauthn
                    .start_passkey_authentication(&Self::decode(keys)?)
                    .map_err(PasskeyError::from)?;
                (Ceremony::Login(LoginCeremony { user_id, state }), challenge)
            } else {
                let (challenge, state) = app.discoverable()?;
                (Ceremony::Discover(state), challenge)
            };
        Ok(app.start(&headers, ceremony, challenge).await?)
    }

    /// Starts an account-picker sign-in, whose account the authenticator names.
    pub(super) fn discoverable(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverCeremony), PasskeyError> {
        let (mut challenge, state) = self.webauthn.start_discoverable_authentication()?;
        challenge.mediation = None;
        Ok((challenge, DiscoverCeremony { state }))
    }

    /// Verifies the assertion and latest credential state before signing the browser in.
    pub(super) async fn finish_login(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        Json(input): Json<AuthenticationFinish>,
    ) -> Result<Response, ApiError> {
        let ceremony = app
            .consume::<AuthenticationCeremony>(&headers, input.ceremony_id)
            .await?;
        let (user_id, verified) = app
            .verify(&app.webauthn, context, ceremony, &input.credential)
            .await?;
        let (tx, signed_in) = app
            .accept_credential(context, Actor::Anonymous, user_id, verified)
            .await?;
        match signed_in {
            SignIn::Session(credential) => {
                Ok(Self::complete_sign_in(tx, context, &headers, user_id, credential).await?)
            }
            SignIn::Restore(passkey) => {
                let mut response = StatusCode::NO_CONTENT.into_response();
                Deletions::offer_restore(tx, user_id, passkey)
                    .await?
                    .set_on(&mut response)
                    .map_err(PasskeyError::from)?;
                Ok(response)
            }
        }
    }

    /// Checks `credential` against a sign-in `ceremony` with `webauthn`, and
    /// returns the account it signs in to with `WebAuthn`'s verdict, which
    /// [`Self::accept_credential`] takes. A discoverable credential that names no
    /// account is rejected, and recorded, here.
    pub(super) async fn verify(
        &self,
        webauthn: &Webauthn,
        context: RequestContext,
        ceremony: AuthenticationCeremony,
        credential: &PublicKeyCredential,
    ) -> Result<(UserId, Result<AuthenticationResult, WebauthnError>), PasskeyError> {
        match ceremony {
            AuthenticationCeremony::Login(LoginCeremony { user_id, state }) => Ok((
                user_id,
                webauthn.finish_passkey_authentication(credential, &state),
            )),
            AuthenticationCeremony::Discover(DiscoverCeremony { state }) => {
                match self.discover(credential).await {
                    Ok((user_id, keys)) => Ok((
                        user_id,
                        webauthn.finish_discoverable_authentication(credential, state, &keys),
                    )),
                    Err(error) => Err(self.reject(context, Actor::Anonymous, None, error).await),
                }
            }
        }
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
}
