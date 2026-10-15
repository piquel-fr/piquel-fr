//! Token exchange, refresh rotation, revocation and `UserInfo`.

use super::{
    ACCESS_TOKEN_SECONDS, AuthScheme, Claim, GrantType, OAuthCode, OAuthError, OidcApplication,
    OpaqueToken, Scope, Scopes, TokenPrefix, TokenType,
};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use chrono::Utc;
use piquel_auth_protocol::{TokenId, UserId};
use piquel_repository::{
    AuditAction, CodeRedemptionError, ConsumedAuthorizationCode, DatabaseTransaction,
    InsertRefreshFamily, InsertRefreshToken, RefreshRotationError, StoredSession,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Untrusted grant parameters; parse grant type after authenticating the client.
#[derive(Deserialize)]
pub(super) struct TokenForm {
    /// Untrusted grant name, parsed after client authentication for protocol error ordering.
    grant_type: String,
    /// Registered relying-party identifier.
    client_id: Option<String>,
    /// Opaque, one-use authorization code.
    code: Option<String>,
    /// Exact registered authorization callback.
    redirect_uri: Option<String>,
    /// Secret verifier proving possession of the original PKCE challenge.
    code_verifier: Option<String>,
    /// Opaque rotating refresh token, when refresh policy permits one.
    refresh_token: Option<String>,
    /// Space-separated scopes requested or granted.
    scope: Option<String>,
}

impl TokenForm {
    /// Permits refresh scope narrowing while rejecting additions to the original grant.
    fn refresh_scopes(&self, granted: &[String]) -> Result<Scopes, OAuthError> {
        let Some(requested) = self.scope.as_deref() else {
            return Ok(Scopes::from_stored(granted));
        };
        let scopes = Scopes::parse(requested)?;
        if !scopes.allowed_by(granted) {
            return Err(
                OAuthCode::InvalidScope.reject("scope cannot add values to the original grant")
            );
        }
        Ok(scopes)
    }
}

/// Existing OAuth token JSON, omitting tokens not issued by the grant.
#[derive(Serialize)]
pub(super) struct TokenResponse {
    /// Short-lived signed bearer token for the resource audience.
    access_token: String,
    /// HTTP authentication scheme for the issued access token.
    token_type: AuthScheme,
    /// Access token lifetime in seconds.
    expires_in: i64,
    /// Space-separated scopes requested or granted.
    scope: String,
    /// Signed client-bound identity token, present only for openid grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    /// Opaque rotating refresh token, when refresh policy permits one.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

/// Client-bound claim policy shared by initial exchanges and refresh rotation.
struct TokenGrant<'a> {
    /// Client identifier bound into the token claims.
    client: &'a str,
    /// Registered resource audience receiving the access token.
    audience: &'a str,
    /// Granted or requested scope set.
    scopes: &'a Scopes,
    /// Client nonce echoed only in the ID token.
    nonce: Option<&'a str>,
}

impl TokenGrant<'_> {
    /// Signs access and optional ID tokens with only the claims allowed by granted scopes.
    fn issue(
        &self,
        app: &OidcApplication,
        user: &piquel_repository::StoredUser,
        session: &StoredSession,
        email: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let Self {
            client,
            audience,
            scopes,
            nonce,
        } = self;
        let now = Utc::now().timestamp();
        let mut claims = json!({(Claim::Issuer.as_str()):app.issuer,(Claim::Subject.as_str()):user.id,(Claim::Session.as_str()):session.id,(Claim::AuthTime.as_str()):session.authenticated_at.timestamp(),(Claim::Methods.as_str()):session.authentication_methods,(Claim::IssuedAt.as_str()):now,(Claim::ExpiresAt.as_str()):now+ACCESS_TOKEN_SECONDS});
        for scope in Scope::ALL {
            if !scopes.contains(scope) {
                continue;
            }
            match scope {
                Scope::Profile => {
                    claims[Claim::Username.as_str()] = json!(user.username);
                    claims[Claim::Name.as_str()] = json!(user.display_name);
                    claims[Claim::ProfileVersion.as_str()] = json!(user.profile_version);
                }
                Scope::Email => {
                    if let Some(email) = email {
                        claims[Claim::Email.as_str()] = json!(email);
                        claims[Claim::EmailVerified.as_str()] = json!(true);
                    }
                }
                // Identity-token and refresh issuance are handled separately below.
                Scope::OpenId | Scope::OfflineAccess => {}
            }
        }
        let mut access = claims.clone();
        access[Claim::Audience.as_str()] = json!(audience);
        access[Claim::Client.as_str()] = json!(client);
        access[Claim::TokenId.as_str()] = json!(TokenId::new());
        access[Claim::Scope.as_str()] = json!(scopes.wire());
        let access_token = app.keys.sign(TokenType::Access, &access)?;
        let id_token = if scopes.contains(Scope::OpenId) {
            claims[Claim::Audience.as_str()] = json!(client);
            if let Some(nonce) = nonce {
                claims[Claim::Nonce.as_str()] = json!(nonce);
            }
            Some(app.keys.sign(TokenType::Id, &claims)?)
        } else {
            None
        };
        Ok(TokenResponse {
            access_token,
            token_type: AuthScheme::Bearer,
            expires_in: ACCESS_TOKEN_SECONDS,
            scope: scopes.wire(),
            id_token,
            refresh_token: None,
        })
    }
}

/// Refresh token and client identity supplied to the revocation endpoint.
#[derive(Deserialize)]
pub(super) struct RevokeForm {
    /// Opaque token whose refresh family should be revoked.
    token: String,
    /// Registered relying-party identifier.
    client_id: Option<String>,
}

impl OidcApplication {
    /// Authenticates the client and dispatches an exhaustively matched token grant.
    pub(super) async fn token(
        State(app): State<Self>,
        headers: HeaderMap,
        form: Result<Form<TokenForm>, axum::extract::rejection::FormRejection>,
    ) -> Result<Json<TokenResponse>, OAuthError> {
        let Form(form) = form.map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with(format!("token request is malformed: {error}"), error)
        })?;
        let client = app
            .authenticate_client(&headers, form.client_id.as_deref())
            .await?;
        match form.grant_type.parse::<GrantType>().map_err(|error| {
            let supported = GrantType::ALL.map(GrantType::as_str).join(", ");
            OAuthCode::UnsupportedGrantType
                .reject_with(format!("grant_type must be one of: {supported}"), error)
        })? {
            GrantType::AuthorizationCode => app.exchange_code(form, &client.id).await.map(Json),
            GrantType::RefreshToken => app.rotate_refresh(form, &client.id).await.map(Json),
        }
    }

    /// Exchanges a one-use code for the authenticated client after checking its client,
    /// redirect and PKCE binding. A replayed code has its refresh family revoked and
    /// committed before the rejection.
    async fn exchange_code(
        &self,
        form: TokenForm,
        client_id: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let opaque = OpaqueToken::parse(
            TokenPrefix::AuthorizationCode,
            form.code
                .as_deref()
                .ok_or_else(|| OAuthCode::InvalidGrant.reject("code is required"))?,
        )?;
        let digest = self.token_digest(&opaque)?;
        let mut tx = self.database.begin().await?;
        let code = match tx
            .oidc()
            .consume_code(opaque.id, digest.as_bytes(), client_id)
            .await
        {
            Ok(code) => code,
            Err(error) => return Err(Self::code_rejection(tx, error).await),
        };
        if code.client_id != client_id {
            return Err(OAuthCode::InvalidGrant.reject("code was issued to another client"));
        }
        if form.redirect_uri.as_deref() != Some(&code.redirect_uri) {
            return Err(OAuthCode::InvalidGrant
                .reject("redirect_uri must match the one sent with the authorization request"));
        }
        piquel_crypto::Pkce::verify(
            form.code_verifier.as_deref().unwrap_or_default(),
            &code.pkce_challenge,
        )
        .map_err(|error| {
            OAuthCode::InvalidGrant.reject_with(format!("code_verifier is invalid: {error}"), error)
        })?;
        let user = tx
            .users()
            .find_active_by_id_for_update(code.user_id)
            .await?
            .ok_or_else(|| OAuthCode::InvalidGrant.reject(ACCOUNT_DISABLED))?;
        // Revalidate under lock: logout may have revoked the session since the code
        // was consumed, while this exchange waited for the account lock.
        let session = tx
            .sessions()
            .find_active_by_id_for_update(code.session_id)
            .await?
            .filter(|session| session.user_id == user.id)
            .ok_or_else(|| OAuthCode::InvalidGrant.reject(SESSION_ENDED))?;
        let client = tx
            .oidc()
            .find_client(&code.client_id)
            .await?
            .ok_or_else(|| OAuthCode::InvalidClient.reject("the client is no longer registered"))?;
        let email = tx.oidc().primary_email(user.id).await?;
        let scopes = Scopes::from_stored(&code.scopes);
        let tokens = TokenGrant {
            client: &client.id,
            audience: &code.audience,
            scopes: &scopes,
            nonce: code.nonce.as_deref(),
        }
        .issue(self, &user, &session, email.as_deref())?;
        let refresh = if client.allow_refresh && scopes.contains(Scope::OfflineAccess) {
            Some(self.create_refresh(&mut tx, code).await?)
        } else {
            None
        };
        tx.commit().await?;
        Ok(TokenResponse {
            refresh_token: refresh,
            ..tokens
        })
    }

    /// Rotates the authenticated client's valid token, and commits replay or policy
    /// revocation before rejecting it.
    async fn rotate_refresh(
        &self,
        form: TokenForm,
        client_id: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let opaque = OpaqueToken::parse(
            TokenPrefix::RefreshToken,
            form.refresh_token
                .as_deref()
                .ok_or_else(|| OAuthCode::InvalidGrant.reject("refresh_token is required"))?,
        )?;
        let digest = self.token_digest(&opaque)?;
        let mut tx = self.database.begin().await?;
        let rotated = match tx
            .tokens()
            .consume_for_rotation(opaque.id, digest.as_bytes(), client_id)
            .await
        {
            Ok(value) => value,
            Err(error) => return Err(Self::refresh_rejection(tx, error).await),
        };
        if rotated.client_id != client_id {
            return Err(
                OAuthCode::InvalidGrant.reject("refresh_token was issued to another client")
            );
        }
        let scopes = form.refresh_scopes(&rotated.scopes)?;
        let user = tx
            .users()
            .find_by_id(rotated.user_id)
            .await?
            .ok_or_else(|| OAuthCode::InvalidGrant.reject("the account no longer exists"))?;
        let session = tx
            .sessions()
            .find_by_id(rotated.session_id)
            .await?
            .ok_or_else(|| OAuthCode::InvalidGrant.reject(SESSION_ENDED))?;
        let opaque_refresh = OpaqueToken::new(TokenPrefix::RefreshToken)?;
        let raw = opaque_refresh.encoded();
        let new_digest = self.token_digest(&opaque_refresh)?;
        tx.tokens()
            .insert_token(&InsertRefreshToken {
                id: opaque_refresh.id,
                family_id: rotated.family_id,
                secret_digest: new_digest.as_bytes().to_vec(),
                expires_at: session.expires_at,
            })
            .await?;
        let email = tx.oidc().primary_email(user.id).await?;
        let mut tokens = TokenGrant {
            client: &rotated.client_id,
            audience: &rotated.audience,
            scopes: &scopes,
            nonce: None,
        }
        .issue(self, &user, &session, email.as_deref())?;
        tokens.refresh_token = Some(raw);
        tx.commit().await?;
        Ok(tokens)
    }

    /// Creates the refresh family of a redeemed code, linked to the code so a replay
    /// can revoke it, and its first token bounded by the browser session lifetime.
    async fn create_refresh(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        code: ConsumedAuthorizationCode,
    ) -> Result<String, OAuthError> {
        let session = tx
            .sessions()
            .find_active_by_id(code.session_id)
            .await?
            .ok_or_else(|| OAuthCode::InvalidGrant.reject(SESSION_ENDED))?;
        let family_id = TokenId::new();
        let opaque = OpaqueToken::new(TokenPrefix::RefreshToken)?;
        let raw = opaque.encoded();
        let digest = self.token_digest(&opaque)?;
        tx.tokens()
            .insert_family(
                &InsertRefreshFamily {
                    id: family_id,
                    user_id: code.user_id,
                    client_id: code.client_id,
                    session_id: code.session_id,
                    authorization_code_id: code.id,
                    audience: code.audience,
                    scopes: code.scopes,
                },
                &InsertRefreshToken {
                    id: opaque.id,
                    family_id,
                    secret_digest: digest.as_bytes().to_vec(),
                    expires_at: session.expires_at,
                },
            )
            .await?;
        Ok(raw)
    }

    /// Revokes the authenticated client’s refresh family, concealing invalid-token existence.
    pub(super) async fn revoke(
        State(app): State<Self>,
        headers: HeaderMap,
        form: Result<Form<RevokeForm>, axum::extract::rejection::FormRejection>,
    ) -> Result<StatusCode, OAuthError> {
        let Form(form) = form.map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with(format!("revocation request is malformed: {error}"), error)
        })?;
        let client = app
            .authenticate_client(&headers, form.client_id.as_deref())
            .await?;
        // RFC 7009 requires success even for malformed or unknown tokens.
        if let Ok(opaque) = OpaqueToken::parse(TokenPrefix::RefreshToken, &form.token) {
            let digest = app.token_digest(&opaque)?;
            let mut tx = app.database.begin().await?;
            tx.tokens()
                .revoke_family_for_client_token(opaque.id, digest.as_bytes(), &client.id)
                .await?;
            tx.commit().await?;
        }
        Ok(StatusCode::OK)
    }

    /// Verifies a bearer access token and exposes only its granted identity claims.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Axum requires an owned HeaderMap extractor; synchronous verification borrows it."
    )]
    pub(super) fn userinfo(
        State(app): State<Self>,
        headers: HeaderMap,
    ) -> std::future::Ready<Result<Json<Value>, OAuthError>> {
        std::future::ready(app.userinfo_response(&headers))
    }

    /// Builds scoped identity JSON after synchronous verification of the supplied bearer token.
    fn userinfo_response(&self, headers: &HeaderMap) -> Result<Json<Value>, OAuthError> {
        let bearer = || format!("send an access token as {} credentials", AuthScheme::Bearer);
        let authorization = headers
            .get(header::AUTHORIZATION)
            .ok_or_else(|| OAuthCode::InvalidToken.reject(bearer()))?
            .to_str()
            .map_err(|error| OAuthCode::InvalidToken.reject_with(bearer(), error))?;
        let token = AuthScheme::Bearer
            .credentials(authorization)
            .ok_or_else(|| OAuthCode::InvalidToken.reject(bearer()))?;
        let claims = self
            .keys
            .verify(token, TokenType::Access, &self.issuer)
            .map_err(|error| {
                OAuthCode::InvalidToken
                    .reject_with(format!("access token is invalid: {error}"), error)
            })?;
        let scopes = Scopes::parse(
            claims
                .get(Claim::Scope.as_str())
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
        .map_err(|error| {
            OAuthCode::InvalidToken.reject_with("access token has no valid scope claim", error)
        })?;
        if !scopes.contains(Scope::OpenId) {
            return Err(OAuthCode::InvalidToken.reject(format!(
                "access token was not granted the {} scope",
                Scope::OpenId
            )));
        }
        let mut response = json!({(Claim::Subject.as_str()):claims.get(Claim::Subject.as_str())});
        if scopes.contains(Scope::Profile) {
            response[Claim::Username.as_str()] = claims
                .get(Claim::Username.as_str())
                .cloned()
                .unwrap_or(Value::Null);
            response[Claim::Name.as_str()] = claims
                .get(Claim::Name.as_str())
                .cloned()
                .unwrap_or(Value::Null);
            response[Claim::ProfileVersion.as_str()] = claims
                .get(Claim::ProfileVersion.as_str())
                .cloned()
                .unwrap_or(Value::Null);
        }
        if scopes.contains(Scope::Email) {
            for claim in [Claim::Email, Claim::EmailVerified] {
                let name = claim.as_str();
                if let Some(value) = claims.get(name) {
                    response[name] = value.clone();
                }
            }
        }
        Ok(Json(response))
    }

    /// Persists replay/policy rejection before returning the preserved rotation failure.
    async fn refresh_rejection(
        tx: DatabaseTransaction<'_>,
        error: RefreshRotationError,
    ) -> OAuthError {
        let (user_id, action) = match error {
            RefreshRotationError::Replay { user_id } => (user_id, AuditAction::RefreshReplay),
            RefreshRotationError::Policy { user_id } => {
                (user_id, AuditAction::RefreshPolicyRejected)
            }
            RefreshRotationError::Invalid | RefreshRotationError::Database(_) => {
                return error.into();
            }
        };
        // Logged first so the signal survives a database failure.
        if action == AuditAction::RefreshReplay {
            tracing::warn!(
                event = REFRESH_REPLAY_EVENT,
                %user_id,
                "refresh token replay rejected"
            );
        }
        Self::commit_rejection(tx, user_id, action, error).await
    }

    /// Persists the family revocation of a replayed code before returning the
    /// preserved redemption failure. Access tokens already issued from the code
    /// cannot be revoked and simply expire.
    ///
    /// The browser session behind the code stays signed in: a leaked code exposes
    /// the client's callback, not the session cookie, and anyone holding the code
    /// could otherwise sign the user out of every application.
    async fn code_rejection(tx: DatabaseTransaction<'_>, error: CodeRedemptionError) -> OAuthError {
        let user_id = match error {
            CodeRedemptionError::Replay { user_id } => user_id,
            CodeRedemptionError::Invalid | CodeRedemptionError::Database(_) => {
                return error.into();
            }
        };
        // Logged first so the signal survives a database failure.
        tracing::warn!(
            event = CODE_REPLAY_EVENT,
            %user_id,
            "authorization code replay rejected"
        );
        Self::commit_rejection(tx, user_id, AuditAction::AuthorizationCodeReplay, error).await
    }

    /// Commits the revocation a rejected grant already made in `tx`, together with
    /// its rejected audit event, then returns the grant's `error`, or the database
    /// failure that prevented the commit.
    async fn commit_rejection(
        mut tx: DatabaseTransaction<'_>,
        user_id: UserId,
        action: AuditAction,
        error: impl Into<OAuthError>,
    ) -> OAuthError {
        let committed = async {
            tx.audit_events().record_rejection(user_id, action).await?;
            tx.commit().await
        }
        .await;
        match committed {
            Ok(()) => error.into(),
            Err(source) => source.into(),
        }
    }
}

/// Rejection of a grant whose account was disabled.
const ACCOUNT_DISABLED: &str = "the account is disabled";
/// Rejection of a grant whose browser session ended.
const SESSION_ENDED: &str = "the sign-in session behind this grant has ended";

/// Stable telemetry event name for refresh-token replay rejection.
const REFRESH_REPLAY_EVENT: &str = "auth.refresh_replay";
/// Stable telemetry event name for authorization-code replay rejection.
const CODE_REPLAY_EVENT: &str = "auth.code_replay";
