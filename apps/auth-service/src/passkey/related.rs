//! Passkey sign-in on the pages of approved related origins (`WebAuthn` Level 3
//! §5.11). A trusted client's page pushes an authorization request, runs the
//! ceremony for auth's RP ID, and receives the authorization code as JSON. No
//! cookie is read or set: the ceremony is bound to the page's origin and the
//! request, and the sign-in creates a session only the client's tokens use.

use super::{
    AuthenticationCeremony, LoginCeremony, PasskeyApplication, PasskeyError, SignIn,
    ceremonies::RelatedCeremony,
    types::{AuthenticationFinish, RelatedOrigins, RelatedStart},
};
use crate::{
    oidc::InlineResponse,
    security::{self, ApiError, CacheClass, Cached, RequestContext},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header},
    response::Response,
};
use piquel_common::{
    clients::RelatedOrigin,
    events::{Actor, InlineSignIn},
};
use serde::Deserialize;
use std::time::Duration;
use url::Url;
use webauthn_rs::prelude::PublicKeyCredential;

/// How long browsers may cache `/.well-known/webauthn`, so they drop a removed
/// origin within five minutes. Auth refuses its sign-ins at once.
const RELATED_ORIGINS_CACHE: CacheClass = CacheClass::Public {
    max_age: Duration::from_secs(300),
};

/// The part of an assertion's client data this module reads.
#[derive(Deserialize)]
struct ClientData {
    /// The origin the browser signed for.
    origin: Url,
}

impl PasskeyApplication {
    /// Lists the approved origins, which browsers fetch before letting their pages
    /// use auth's RP ID.
    pub(super) async fn related_origins(
        State(app): State<Self>,
    ) -> Result<Cached<Json<RelatedOrigins>>, ApiError> {
        let origins = app.database.oidc().related_origins().await?;
        Ok(Cached(
            RELATED_ORIGINS_CACHE,
            Json(RelatedOrigins {
                origins: origins.into_iter().map(|origin| origin.origin).collect(),
            }),
        ))
    }

    /// Claims the page's client's pushed request and starts its sign-in: with the
    /// passkeys of the account an `id_token_hint` names, or else an account picker.
    /// The claim and the ceremony commit together, so a refused start leaves the
    /// request for the redirect flow.
    pub(super) async fn start_related_login(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RelatedStart>,
    ) -> Result<Response, ApiError> {
        let origin = Self::page_origin(&headers)?;
        let client_id = app
            .database
            .oidc()
            .related_origin_client(origin.as_str())
            .await?
            .ok_or(PasskeyError::OriginNotApproved)?;
        let mut tx = app.database.begin().await?;
        let claim = app
            .oidc
            .claim_inline(&mut tx, &client_id, &input.request_uri)
            .await?;
        let (challenge, sign_in) = if let Some(user_id) = claim.hinted_user_id {
            // Read inside `tx`: a second connection per start could exhaust the pool.
            let keys = Self::decode(tx.passkeys().list_active(user_id).await?)?;
            if keys.is_empty() {
                return Err(ApiError::interaction_required(
                    "The account this application asked for signs in without a passkey.",
                ));
            }
            let (challenge, state) = app
                .webauthn
                .start_passkey_authentication(&keys)
                .map_err(PasskeyError::from)?;
            (
                challenge,
                AuthenticationCeremony::Login(LoginCeremony { user_id, state }),
            )
        } else {
            let (challenge, state) = app.discoverable()?;
            (challenge, AuthenticationCeremony::Discover(state))
        };
        let ceremony = RelatedCeremony {
            origin,
            client_id,
            claim,
            sign_in,
        };
        let response = Self::start_related(&mut tx, ceremony, challenge).await?;
        tx.commit().await?;
        Ok(response)
    }

    /// Verifies the assertion the page's browser signed for its own origin, creates
    /// the inline session and completes the claimed request with its code.
    pub(super) async fn finish_related_login(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        Json(input): Json<AuthenticationFinish>,
    ) -> Result<Json<InlineResponse>, ApiError> {
        let origin = Self::page_origin(&headers)?;
        let RelatedCeremony {
            origin: started,
            client_id,
            claim,
            sign_in,
        } = app.consume_related(input.ceremony_id).await?;
        // The origin may have been removed, or given to another client, since.
        if origin != started
            || app
                .database
                .oidc()
                .related_origin_client(origin.as_str())
                .await?
                .as_ref()
                != Some(&client_id)
        {
            return Err(PasskeyError::OriginNotApproved.into());
        }
        // The verifier also accepts auth's own origin, so the page's is checked here.
        if let Err(error) = Self::signed_for(&input.credential, &origin) {
            return Err(app
                .reject(context, Actor::Anonymous, None, error)
                .await
                .into());
        }
        let webauthn = Self::webauthn(&app.origin, Some(&origin)).map_err(PasskeyError::from)?;
        let (user_id, verified) = app
            .verify(&webauthn, context, sign_in, &input.credential)
            .await?;
        let (mut tx, signed_in) = app
            .accept_credential(context, Actor::Anonymous, user_id, verified)
            .await?;
        // Only auth's sign-in page offers to restore an account being deleted.
        let SignIn::Session(credential) = signed_in else {
            return Err(ApiError::interaction_required(
                "This account is scheduled for deletion. Sign in on Piquel's pages to restore it.",
            ));
        };
        let session = security::Session::create_inline(
            &mut tx,
            context,
            user_id,
            credential,
            InlineSignIn { client_id, origin },
        )
        .await
        .map_err(PasskeyError::from)?;
        let response = app.oidc.complete_inline(&mut tx, &claim, &session).await?;
        tx.commit().await?;
        Ok(Json(response))
    }

    /// The page's origin, from its `Origin` header. The security layer already
    /// allowed it for some trusted client.
    fn page_origin(headers: &HeaderMap) -> Result<RelatedOrigin, PasskeyError> {
        headers
            .get(header::ORIGIN)
            .and_then(|origin| origin.to_str().ok())
            .and_then(|origin| origin.parse().ok())
            .ok_or(PasskeyError::OriginNotApproved)
    }

    /// Requires `credential`'s client data to name `origin`, compared as an origin
    /// tuple: scheme, host and port.
    fn signed_for(
        credential: &PublicKeyCredential,
        origin: &RelatedOrigin,
    ) -> Result<(), PasskeyError> {
        let data: ClientData =
            serde_json::from_slice(credential.response.client_data_json.as_ref())
                .map_err(PasskeyError::ClientData)?;
        if data.origin.origin() == origin.url().origin() {
            Ok(())
        } else {
            Err(PasskeyError::SignedForAnotherOrigin)
        }
    }
}
