//! Pushed authorization requests (RFC 9126): storing one an authenticated client
//! pushes, and claiming it from its `request_uri`.

use super::{AuthorizationParameters, RecoveryQuestion};
use crate::{
    oidc::{
        AUTHORIZATION_REQUEST_MINUTES, OAuthCode, OAuthError, OidcApplication, OpaqueToken,
        PUSHED_REQUEST_SECONDS, Reject, TokenPrefix,
    },
    security::RequestContext,
};
use axum::{
    Form, Json,
    extract::{State, rejection::FormRejection},
    http::{HeaderMap, StatusCode},
};
use chrono::{Duration, Utc};
use piquel_repository::{OidcRepository, StoredAuthorizationRequest};
use serde::Serialize;
use url::Url;

/// Rejection of a `request_uri` that cannot be claimed.
const UNKNOWN_REQUEST_URI: &str =
    "request_uri is unknown, expired, already used or issued to another client";
/// Prefix of a pushed request's `request_uri` (RFC 9126 §2.2), followed by the
/// pushed request's [`OpaqueToken`].
const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// The pushed authorization endpoint's answer (RFC 9126 §2.2).
#[derive(Serialize)]
pub(in crate::oidc) struct PushedAuthorization {
    /// What the browser brings to the authorization endpoint, with `client_id`.
    request_uri: String,
    /// Seconds until `request_uri` expires.
    expires_in: i64,
}

impl OidcApplication {
    /// Stores a request pushed by an authenticated client (RFC 9126 §2), validated
    /// as at the authorization endpoint, and returns the `request_uri` the browser
    /// brings there. Every error is JSON: nothing goes through the browser.
    pub(in crate::oidc) async fn push_authorization(
        State(app): State<Self>,
        headers: HeaderMap,
        form: Result<Form<AuthorizationParameters>, FormRejection>,
    ) -> Result<(StatusCode, Json<PushedAuthorization>), OAuthError> {
        let Form(q) = form.map_err(|error| {
            OAuthCode::InvalidRequest.reject_with(
                format!("pushed authorization request is malformed: {error}"),
                error,
            )
        })?;
        let client = app
            .authenticate_client(&headers, q.client_id.as_deref())
            .await?;
        if q.request_uri.is_some() {
            return Err(OAuthCode::InvalidRequest.reject("request_uri cannot be pushed"));
        }
        q.redirect_uri(&client)?;
        let (opaque, request) = q.validate(&app, &client, true)?;
        app.database
            .oidc()
            .insert_authorization_request(&request)
            .await?;
        Ok((
            StatusCode::CREATED,
            Json(PushedAuthorization {
                request_uri: format!("{REQUEST_URI_PREFIX}{}", opaque.encoded()),
                expires_in: PUSHED_REQUEST_SECONDS,
            }),
        ))
    }

    /// Continues a pushed request from its `request_uri` (RFC 9126 §4). The
    /// request's other parameters are ignored, so none can override a pushed one.
    /// From then on, the browser carries a fresh transaction, as for a request it
    /// sent itself.
    pub(super) async fn claim_pushed(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
        client_id: &str,
        request_uri: &str,
    ) -> Result<Url, OAuthError> {
        let (opaque, _) = self
            .claim(self.database.oidc(), client_id, request_uri)
            .await?;
        self.continue_authorization(
            context,
            headers,
            opaque.encoded(),
            RecoveryQuestion::Unanswered,
        )
        .await
    }

    /// Claims the pushed request `request_uri` through `oidc`. Only `client_id` can
    /// claim it, and only once. Returns the request and the transaction token that
    /// now continues it.
    pub(in crate::oidc) async fn claim(
        &self,
        mut oidc: OidcRepository<'_>,
        client_id: &str,
        request_uri: &str,
    ) -> Result<(OpaqueToken, StoredAuthorizationRequest), OAuthError> {
        let unknown = || OAuthCode::InvalidRequestUri.reject(UNKNOWN_REQUEST_URI);
        // RFC 9126 §5: a pushed `request_uri` works whatever
        // `request_uri_parameter_supported` says, so the parameter is supported and
        // a client-hosted one is invalid rather than `request_uri_not_supported`.
        let token = request_uri
            .strip_prefix(REQUEST_URI_PREFIX)
            .ok_or_else(|| {
                OAuthCode::InvalidRequestUri
                    .reject("request_uri must come from the pushed authorization endpoint")
            })?;
        let pushed =
            OpaqueToken::parse(TokenPrefix::AuthorizationRequest, token).map_err(|error| {
                OAuthCode::InvalidRequestUri.reject_with(UNKNOWN_REQUEST_URI, error)
            })?;
        let opaque = pushed.renewed()?;
        let (new_digest, new_digest_key) = self.token_digest(&opaque)?;
        let request = oidc
            .claim_pushed_authorization_request(
                pushed.id,
                &self.accepted_digests(&pushed)?,
                client_id,
                &new_digest,
                &new_digest_key,
                Utc::now() + Duration::minutes(AUTHORIZATION_REQUEST_MINUTES),
            )
            .await?
            .ok_or_else(unknown)?;
        Ok((opaque, request))
    }
}
