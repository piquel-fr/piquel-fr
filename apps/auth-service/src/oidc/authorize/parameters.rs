//! Authorization request parameters, from the browser or pushed by the client,
//! validated the same way against the client's registration into a
//! [`ValidatedAuthorization`].

use crate::oidc::{
    AUTHORIZATION_REQUEST_MINUTES, Claim, CodeChallengeMethod, Interaction, MAX_STATE_BYTES,
    OAuthCode, OAuthError, OidcApplication, OpaqueToken, PUSHED_REQUEST_SECONDS, Prompt, Reject,
    ResponseMode, ResponseType, Scopes, TokenPrefix,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::Value;
use sourceorigin_common::{UserId, clients::ClientKind, protocol::claims::Acr};
use sourceorigin_repository::{InsertAuthorizationRequest, StoredOidcClient};
use url::Url;

/// Authorization request parameters, from the browser or pushed by the client.
/// None of them is trusted, and errors are not redirected, until `redirect_uri`
/// matches the client's registration.
#[derive(Default, Deserialize)]
#[serde(default)]
pub(in crate::oidc) struct AuthorizationParameters {
    /// Must be `code`.
    response_type: String,
    /// Client making the request.
    pub(super) client_id: Option<String>,
    /// Where to send the result; must exactly match a registered URI.
    redirect_uri: String,
    /// Requested scopes, space-separated.
    scope: String,
    /// Client value returned unchanged with the result, if sent.
    pub(super) state: Option<String>,
    /// Client value echoed in the ID token.
    nonce: Option<String>,
    /// PKCE challenge the code exchange must answer. Only a confidential client
    /// may leave it out.
    code_challenge: Option<String>,
    /// Must be `S256` when `code_challenge` is sent.
    code_challenge_method: Option<String>,
    /// Resource the access token is for; defaults to the client's first audience.
    audience: Option<String>,
    /// Space-separated [`Prompt`] values.
    pub(super) prompt: Option<String>,
    /// Maximum seconds since sign-in; zero forces a fresh sign-in.
    max_age: Option<i64>,
    /// Space-separated [`Acr`] values, most preferred first; unknown ones are ignored.
    acr_values: Option<String>,
    /// Previously issued ID token naming the expected account.
    id_token_hint: Option<String>,
    /// Signed request object; rejected as unsupported.
    request: Option<String>,
    /// Reference to a pushed request, which replaces every other parameter but
    /// `client_id`. Client-hosted request objects are not supported.
    pub(super) request_uri: Option<String>,
    /// Must be `query` when present.
    response_mode: Option<String>,
}

impl AuthorizationParameters {
    /// The redirect URI, which must be registered for `client`. Until it is, errors
    /// cannot be redirected.
    pub(super) fn redirect_uri(&self, client: &StoredOidcClient) -> Result<Url, OAuthError> {
        if !client.redirect_uris.contains(&self.redirect_uri) {
            return Err(OAuthCode::InvalidRequest
                .reject("redirect_uri is not registered for this client; it must match exactly"));
        }
        Url::parse(&self.redirect_uri).map_err(|error| {
            OAuthCode::InvalidRequest.reject_with("redirect_uri is not a valid URL", error)
        })
    }

    /// Validates every other parameter against `client`'s registration, the same
    /// way for browser and pushed requests, one step per check in this order, so
    /// the first that fails decides the error. Errors are not redirected.
    pub(super) fn validate(
        &self,
        app: &OidcApplication,
        client: &StoredOidcClient,
        pushed: bool,
    ) -> Result<ValidatedAuthorization, OAuthError> {
        self.supported()?;
        let hinted_user_id = self.hinted_user_id(app, client)?;
        self.response_type()?;
        let pkce_challenge = self.pkce(client)?;
        self.state()?;
        let scopes = self.scopes(client)?;
        let audience = self.audience(client)?;
        self.nonce()?;
        self.max_age()?;
        let interaction = self.interaction()?;
        let lifetime = if pushed {
            Duration::seconds(PUSHED_REQUEST_SECONDS)
        } else {
            Duration::minutes(AUTHORIZATION_REQUEST_MINUTES)
        };
        let token = OpaqueToken::new(TokenPrefix::AuthorizationRequest)?;
        let (secret_digest, digest_key) = app.token_digest(&token);
        let request = InsertAuthorizationRequest {
            id: token.id,
            secret_digest,
            pushed,
            digest_key,
            client_id: client.id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            client_state: self.state.clone(),
            pkce_challenge,
            nonce: self.nonce.clone(),
            scopes: scopes.into_stored(),
            audience,
            interaction,
            max_age: self.max_age,
            hinted_user_id,
            target_acr: self.acr_values.as_deref().and_then(Acr::select),
            expires_at: Utc::now() + lifetime,
        };
        Ok(ValidatedAuthorization { token, request })
    }

    /// Rejects request objects and any `response_mode` but `query`.
    fn supported(&self) -> Result<(), OAuthError> {
        if self.request.is_some() {
            return Err(OAuthCode::RequestNotSupported
                .reject("request objects are not supported; send the parameters directly"));
        }
        if let Some(mode) = &self.response_mode {
            match mode.parse::<ResponseMode>().map_err(|error| {
                OAuthCode::InvalidRequest.reject_with(
                    format!("response_mode must be {}", ResponseMode::Query),
                    error,
                )
            })? {
                ResponseMode::Query => {}
            }
        }
        Ok(())
    }

    /// The account named by a verified `id_token_hint`, which must have been
    /// issued to `client`.
    fn hinted_user_id(
        &self,
        app: &OidcApplication,
        client: &StoredOidcClient,
    ) -> Result<Option<UserId>, OAuthError> {
        let Some(hint) = &self.id_token_hint else {
            return Ok(None);
        };
        // An expired ID token still identifies the account.
        let claims = app
            .keys
            .current()?
            .verify_id_token_hint(hint, &app.issuer)
            .map_err(|error| {
                OAuthCode::InvalidRequest
                    .reject_with(format!("id_token_hint is invalid: {error}"), error)
            })?;
        if claims[Claim::Audience.as_str()] != client.id.as_str() {
            return Err(
                OAuthCode::InvalidRequest.reject("id_token_hint was issued to another client")
            );
        }
        if claims
            .get(Claim::ExpiresAt.as_str())
            .and_then(Value::as_i64)
            .is_none()
        {
            return Err(OAuthCode::InvalidRequest.reject("id_token_hint has no numeric exp claim"));
        }
        claims
            .get(Claim::Subject.as_str())
            .and_then(Value::as_str)
            .ok_or_else(|| OAuthCode::InvalidRequest.reject("id_token_hint has no sub claim"))?
            .parse()
            .map(Some)
            .map_err(|error| {
                OAuthCode::InvalidRequest
                    .reject_with("id_token_hint sub claim is not an account ID", error)
            })
    }

    /// Requires `response_type=code`: a missing one is a malformed request, and
    /// any other value one auth doesn't support.
    fn response_type(&self) -> Result<(), OAuthError> {
        if self.response_type.is_empty() {
            return Err(OAuthCode::InvalidRequest.reject("response_type is required"));
        }
        match self
            .response_type
            .parse::<ResponseType>()
            .map_err(|error| {
                OAuthCode::UnsupportedResponseType.reject_with(
                    format!("response_type must be {}", ResponseType::Code),
                    error,
                )
            })? {
            ResponseType::Code => Ok(()),
        }
    }

    /// Bounds `state`, which comes back with the result, so it is checked before
    /// any error goes back with it.
    pub(super) fn state(&self) -> Result<(), OAuthError> {
        if self
            .state
            .as_ref()
            .is_some_and(|state| state.len() > MAX_STATE_BYTES)
        {
            return Err(OAuthCode::InvalidRequest
                .reject(format!("state must be at most {MAX_STATE_BYTES} bytes")));
        }
        Ok(())
    }

    /// The PKCE challenge the code exchange must answer (RFC 7636): an `S256`
    /// SHA-256 digest. Public clients must send one. A confidential client may
    /// leave PKCE out, as RFC 9700 §2.1.1 allows, since it authenticates at the
    /// token endpoint; a challenge it sends is enforced all the same.
    fn pkce(&self, client: &StoredOidcClient) -> Result<Option<String>, OAuthError> {
        let Some(challenge) = &self.code_challenge else {
            return match (&self.code_challenge_method, client.kind) {
                (Some(_), _) => Err(OAuthCode::InvalidRequest
                    .reject("code_challenge_method was sent without a code_challenge")),
                (None, ClientKind::Confidential) => Ok(None),
                (None, ClientKind::Public) => Err(OAuthCode::InvalidRequest.reject(format!(
                    "public clients must send a code_challenge, with code_challenge_method={}",
                    CodeChallengeMethod::S256
                ))),
            };
        };
        let method = self.code_challenge_method.as_deref().unwrap_or_default();
        match method.parse::<CodeChallengeMethod>().map_err(|error| {
            OAuthCode::InvalidRequest.reject_with(
                format!(
                    "code_challenge_method must be {}",
                    CodeChallengeMethod::S256
                ),
                error,
            )
        })? {
            CodeChallengeMethod::S256 => {}
        }
        if !sourceorigin_crypto::Pkce::valid_challenge(challenge) {
            return Err(OAuthCode::InvalidRequest
                .reject("code_challenge must be a base64url SHA-256 digest, 43 characters long"));
        }
        Ok(Some(challenge.clone()))
    }

    /// Parses the scopes, which `client` must be allowed to request.
    fn scopes(&self, client: &StoredOidcClient) -> Result<Scopes, OAuthError> {
        let scopes = Scopes::parse(&self.scope)?;
        if !scopes.allowed_by(&client.allowed_scopes) {
            return Err(
                OAuthCode::InvalidScope.reject("scope includes values this client may not request")
            );
        }
        Ok(scopes)
    }

    /// The resource the access token is for: the one asked for, or `client`'s
    /// first audience, which must be registered for it.
    fn audience(&self, client: &StoredOidcClient) -> Result<String, OAuthError> {
        self.audience
            .clone()
            .or_else(|| client.allowed_audiences.first().cloned())
            .filter(|audience| client.allowed_audiences.contains(audience))
            .ok_or_else(|| {
                OAuthCode::InvalidTarget.reject("audience is not registered for this client")
            })
    }

    /// Bounds `nonce`, which comes back in the ID token.
    fn nonce(&self) -> Result<(), OAuthError> {
        if self
            .nonce
            .as_ref()
            .is_some_and(|nonce| nonce.is_empty() || nonce.len() > MAX_STATE_BYTES)
        {
            return Err(OAuthCode::InvalidRequest
                .reject(format!("nonce must be 1 to {MAX_STATE_BYTES} bytes")));
        }
        Ok(())
    }

    /// Rejects a negative `max_age`.
    fn max_age(&self) -> Result<(), OAuthError> {
        if self.max_age.is_some_and(|age| age < 0) {
            return Err(OAuthCode::InvalidRequest.reject("max_age cannot be negative"));
        }
        Ok(())
    }

    /// Parses `prompt`: known values, repeats allowed, and `none` alone.
    pub(super) fn interaction(&self) -> Result<Interaction, OAuthError> {
        let prompts = self
            .prompt
            .as_deref()
            .unwrap_or_default()
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<Prompt>, _>>()
            .map_err(|error| {
                let supported = Prompt::ALL.map(Prompt::as_str).join(", ");
                OAuthCode::InvalidRequest
                    .reject_with(format!("prompt values must be among: {supported}"), error)
            })?;
        Interaction::from_prompts(prompts).ok_or_else(|| {
            OAuthCode::InvalidRequest
                .reject("prompt=none cannot be combined with other prompt values")
        })
    }
}

/// An authorization request whose parameters all checked out against its
/// client's registration, from the browser or pushed by the client: the pending
/// authorization, and the token that continues it.
pub(super) struct ValidatedAuthorization {
    /// The browser's transaction, or the pushed request's `request_uri`.
    token: OpaqueToken,
    /// The pending authorization, as it is stored.
    pub(super) request: InsertAuthorizationRequest,
}

impl ValidatedAuthorization {
    /// Stores the pending authorization, and returns the encoded token that
    /// continues it.
    pub(super) async fn store(self, app: &OidcApplication) -> Result<String, OAuthError> {
        app.database
            .oidc()
            .insert_authorization_request(&self.request)
            .await?;
        Ok(self.token.encoded())
    }
}
