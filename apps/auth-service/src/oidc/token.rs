//! Token exchange, refresh, revocation and `UserInfo`.

use super::{
    ACCESS_TOKEN_SECONDS, AuthScheme, GrantType, OAuthCode, OAuthError, OidcApplication,
    OpaqueToken, Reject, Scope, Scopes, TokenPrefix, TokenType, policy::ClientPolicy,
};
use crate::{
    routes,
    security::{ApiError, RequestContext},
};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sourceorigin_common::{
    ClientId, SessionId, TokenId, UserId,
    events::{CodeRedemptionFailure, DomainEvent, EventContext, GrantRevocation},
    protocol::{
        claims::{
            AccessTokenClaims, Audience, AuthenticationClaims, IdTokenClaims, ProfileClaims,
            UserInfo,
        },
        oauth,
    },
};
use sourceorigin_repository::{
    CodeRedemptionError, ConsumedAuthorizationCode, DatabaseTransaction, InsertRefreshFamily,
    InsertRefreshToken, RefreshOutcome, RefreshRedemption, RefreshRedemptionError,
    RefreshSuccessor, SessionAuthentication, StoredOidcClient,
};
use sourceorigin_telemetry::{Counter, Label};

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
    /// Opaque refresh token to redeem.
    refresh_token: Option<String>,
    /// Space-separated scopes requested or granted.
    scope: Option<String>,
}

impl TokenForm {
    /// Whether this form redeems the locked `code` for the authenticated
    /// `client_id`: the code was issued to it, for this `redirect_uri`, and this
    /// `code_verifier` matches its PKCE challenge, or neither was sent. Answers why
    /// it does not, with the rejection.
    fn redeems(
        &self,
        code: &ConsumedAuthorizationCode,
        client_id: &ClientId,
    ) -> Result<(), (CodeRedemptionFailure, OAuthError)> {
        if &code.client_id != client_id {
            return Err((
                CodeRedemptionFailure::WrongClient,
                OAuthCode::InvalidGrant.reject("code was issued to another client"),
            ));
        }
        if self.redirect_uri.as_deref() != Some(&code.redirect_uri) {
            return Err((
                CodeRedemptionFailure::RedirectMismatch,
                OAuthCode::InvalidGrant
                    .reject("redirect_uri must match the one sent with the authorization request"),
            ));
        }
        match (&code.pkce_challenge, self.code_verifier.as_deref()) {
            (Some(challenge), verifier) => {
                sourceorigin_crypto::Pkce::verify(verifier.unwrap_or_default(), challenge).map_err(
                    |error| {
                        (
                            CodeRedemptionFailure::InvalidVerifier,
                            OAuthCode::InvalidGrant
                                .reject_with(format!("code_verifier is invalid: {error}"), error),
                        )
                    },
                )
            }
            // A confidential client sent no challenge, so it sends no verifier.
            (None, None) => Ok(()),
            // RFC 9700 §2.1.1: a verifier for a code issued without a challenge
            // may be an attacker's downgrade of a request that had one.
            (None, Some(_)) => Err((
                CodeRedemptionFailure::InvalidVerifier,
                OAuthCode::InvalidGrant.reject(
                    "code_verifier was sent, but the authorization request had no code_challenge",
                ),
            )),
        }
    }

    /// Permits refresh scope narrowing while rejecting additions to the original grant.
    fn refresh_scopes(&self, granted: &[String]) -> Result<Scopes, OAuthError> {
        let Some(requested) = self.scope.as_deref() else {
            return Ok(Scopes::from_stored(granted)?);
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
    scope: oauth::Scopes,
    /// Signed client-bound identity token, present only for openid grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    /// Opaque refresh token: the first of a grant refresh policy permits, or the
    /// replacement of a rotated one. A client that keeps its token gets none.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

impl TokenResponse {
    /// Counts each token issued by `grant`, once its transaction committed, by
    /// the response field it is sent in.
    fn count(&self, grant: GrantType) {
        let issued = [
            ("access_token", true),
            ("id_token", self.id_token.is_some()),
            ("refresh_token", self.refresh_token.is_some()),
        ];
        for (token, _) in issued.into_iter().filter(|(_, issued)| *issued) {
            TOKENS_ISSUED.add(1, &[("grant_type", grant.as_str()), ("token_type", token)]);
        }
    }
}

/// Tokens issued by the token endpoint, by grant and token type.
static TOKENS_ISSUED: Counter<[Label; 2]> = Counter::new(
    "sourceorigin.auth.tokens.issued",
    "{token}",
    "Tokens issued by the token endpoint, by grant type and token type.",
);

/// Client-bound claim policy shared by initial exchanges and refreshes.
struct TokenGrant<'a> {
    /// Client identifier bound into the token claims.
    client: &'a ClientId,
    /// Registered resource audience receiving the access token.
    audience: &'a str,
    /// Granted or requested scope set.
    scopes: &'a Scopes,
    /// Client nonce echoed only in the ID token.
    nonce: Option<&'a str>,
    /// Browser session that authorized the grant.
    session: SessionId,
    /// How that session had authenticated when the grant's code was issued.
    authentication: &'a SessionAuthentication,
}

impl TokenGrant<'_> {
    /// Signs access and optional ID tokens with only the claims allowed by granted scopes.
    fn issue(
        &self,
        app: &OidcApplication,
        user: &sourceorigin_repository::StoredUser,
        email: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let Self {
            client,
            audience,
            scopes,
            nonce,
            session,
            authentication,
        } = self;
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(ACCESS_TOKEN_SECONDS);
        let authentication = AuthenticationClaims {
            sid: Some(*session),
            auth_time: Some(authentication.auth_time),
            amr: authentication.amr.clone(),
            acr: Some(authentication.acr),
        };
        let profile = scopes.release(ProfileClaims {
            preferred_username: Some(user.handle.to_string()),
            name: Some(user.display_name.clone()),
            picture: user
                .picture
                .map(|picture| routes::pictures::url(&app.origin, picture)),
            profile_version: Some(user.profile_version),
            email: email.map(str::to_owned),
            email_verified: email.map(|_| true),
        });
        let keys = app.keys.current()?;
        let access_token = keys.sign(
            TokenType::Access,
            &AccessTokenClaims {
                iss: app.issuer.clone(),
                sub: user.id.to_string(),
                aud: Audience::One((*audience).to_owned()),
                client_id: (*client).clone(),
                jti: TokenId::new(),
                scope: scopes.wire().clone(),
                iat: issued_at,
                exp: expires_at,
                nbf: None,
                authentication: authentication.clone(),
                act: None,
                cnf: None,
                profile: profile.clone(),
                extra: (),
            },
        )?;
        let id_token = if scopes.contains(Scope::OpenId) {
            Some(keys.sign(
                TokenType::Id,
                &IdTokenClaims {
                    iss: app.issuer.clone(),
                    sub: user.id.to_string(),
                    aud: Audience::One(client.to_string()),
                    azp: None,
                    iat: issued_at,
                    exp: expires_at,
                    nbf: None,
                    nonce: nonce.map(str::to_owned),
                    authentication,
                    profile,
                },
            )?)
        } else {
            None
        };
        Ok(TokenResponse {
            access_token,
            token_type: AuthScheme::Bearer,
            expires_in: ACCESS_TOKEN_SECONDS,
            scope: scopes.wire().clone(),
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
        context: RequestContext,
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
        let grant = form.grant_type.parse::<GrantType>().map_err(|error| {
            let supported = GrantType::ALL.map(GrantType::as_str).join(", ");
            OAuthCode::UnsupportedGrantType
                .reject_with(format!("grant_type must be one of: {supported}"), error)
        })?;
        let context = context.client(&client.id);
        let tokens = match grant {
            GrantType::AuthorizationCode => app.exchange_code(form, &client.id, &context).await,
            GrantType::RefreshToken => app.refresh(form, &client, &context).await,
        }?;
        tokens.count(grant);
        // After the grant committed, outside its transaction: concurrent refreshes
        // of one client each hold their family and share-lock the client, so the
        // hourly write, which needs the client exclusively, would deadlock them if
        // two made it inside. The tokens are issued, so a failure here only leaves
        // the time older, and is logged rather than answered.
        if let Err(error) = app.database.oidc().touch_client(&client.id).await {
            ApiError::log_error(&error);
        }
        Ok(Json(tokens))
    }

    /// Exchanges a one-use code for the authenticated client after checking its client,
    /// redirect and PKCE binding, that the client's current policy still allows it,
    /// and that an untrusted client still has the user's consent, then records the
    /// grant. A replayed code has its refresh family revoked and committed before
    /// the rejection; a code redeemed with the wrong client, redirect or verifier
    /// expires, and is recorded, before it.
    async fn exchange_code(
        &self,
        form: TokenForm,
        client_id: &ClientId,
        context: &EventContext,
    ) -> Result<TokenResponse, OAuthError> {
        let opaque = OpaqueToken::parse(
            TokenPrefix::AuthorizationCode,
            form.code
                .as_deref()
                .ok_or_else(|| OAuthCode::InvalidGrant.reject("code is required"))?,
        )?;
        let digests = self.accepted_digests(&opaque);
        let mut tx = self.database.begin().await?;
        // Lock the account before the code, as a refresh and removing an app
        // do: a removal then either commits first and expires the code, or waits
        // for this exchange and revokes the refresh family it creates. The lock
        // is taken whatever the account's status, and refuses nothing: a disabled
        // account's code goes through the checks below like any other, so its
        // replay is recorded, and a client it wasn't issued to isn't told that the
        // account is disabled.
        if let Some(user) = tx.oidc().code_user(opaque.id, &digests).await? {
            tx.users().find_by_id_for_update(user).await?;
        }
        // Checked with the code locked, before it is consumed: a failed redemption
        // still uses the code up, and is recorded, so a code is tried once. It
        // expires rather than being consumed, so its client is not taken to hold
        // tokens from the session.
        if let Some(code) = tx.oidc().lock_code(opaque.id, &digests).await?
            && let Err((reason, error)) = form.redeems(&code, client_id)
        {
            tx.oidc().expire_code(code.id).await?;
            let failed = DomainEvent::CodeRedemptionFailed {
                client_id: client_id.clone(),
                reason,
            };
            return Err(Self::commit_rejection(tx, context, code.user_id, [failed], error).await);
        }
        let code = match tx.oidc().consume_code(opaque.id, &digests, client_id).await {
            Ok(code) => code,
            Err(error) => return Err(Self::code_rejection(tx, context, client_id, error).await),
        };
        let user = tx
            .users()
            .find_active_by_id_for_update(code.user_id)
            .await?
            .ok_or_else(|| OAuthCode::InvalidGrant.reject(ACCOUNT_DISABLED))?;
        // Revalidate under the session's lock: logout takes no account lock, so it may
        // have revoked the session since the code was issued.
        let session = tx
            .sessions()
            .find_active_by_id_for_update(code.session_id)
            .await?
            .filter(|session| session.user_id == user.id)
            .ok_or_else(|| OAuthCode::InvalidGrant.reject(SESSION_ENDED))?;
        // Share-locked until the grant commits, so no change to the client, such as
        // a suspension, commits between this check and the tokens.
        let policy = ClientPolicy::share(&mut tx, client_id).await?;
        policy
            .allows_code(&code)
            .map_err(|refusal| refusal.reject(OAuthCode::InvalidGrant))?;
        let client = policy.client();
        // Reread under the account lock: authorization checks remembered consent
        // before taking it, so it may issue a code just as the consent is withdrawn.
        if !client.trusted
            && !tx
                .oidc()
                .consented(user.id, &client.id, &code.audience, &code.scopes)
                .await?
        {
            return Err(OAuthCode::InvalidGrant.reject(CONSENT_WITHDRAWN));
        }
        let email = tx.oidc().primary_email(user.id).await?;
        let scopes = Scopes::from_stored(&code.scopes)?;
        let tokens = TokenGrant {
            client: &client.id,
            audience: &code.audience,
            scopes: &scopes,
            nonce: code.nonce.as_deref(),
            session: session.id,
            authentication: &code.authentication,
        }
        .issue(self, &user, email.as_deref())?;
        let (family_id, refresh) = if client.allow_refresh && scopes.contains(Scope::OfflineAccess)
        {
            let (family_id, refresh) = self.create_refresh(&mut tx, code).await?;
            (Some(family_id), Some(refresh))
        } else {
            (None, None)
        };
        tx.record(
            context,
            Some(user.id),
            DomainEvent::GrantIssued {
                client_id: client.id.clone(),
                family_id,
                scopes: scopes.into_stored(),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(TokenResponse {
            refresh_token: refresh,
            ..tokens
        })
    }

    /// Redeems the authenticated client's valid token, and commits replay or policy
    /// revocation before rejecting it. A public client's token rotates: the response
    /// carries its replacement. The same token presented again within seconds of
    /// its rotation, by a second tab or a retry, is answered with that same
    /// replacement and writes nothing. A confidential client keeps its token, so the
    /// response carries none and the refresh writes nothing. The new tokens report
    /// the grant's original authentication, not the session's current one (OIDC
    /// Core §12.2).
    async fn refresh(
        &self,
        form: TokenForm,
        client: &StoredOidcClient,
        context: &EventContext,
    ) -> Result<TokenResponse, OAuthError> {
        let opaque = OpaqueToken::parse(
            TokenPrefix::RefreshToken,
            form.refresh_token
                .as_deref()
                .ok_or_else(|| OAuthCode::InvalidGrant.reject("refresh_token is required"))?,
        )?;
        let digests = self.accepted_digests(&opaque);
        let redemption = RefreshRedemption::from(client.kind);
        let mut tx = self.database.begin().await?;
        let redeemed = match tx
            .tokens()
            .redeem_refresh(opaque.id, &digests, client.id.as_str(), redemption)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                return Err(Self::refresh_rejection(tx, context, &client.id, error).await);
            }
        };
        if redeemed.client_id != client.id.as_str() {
            return Err(
                OAuthCode::InvalidGrant.reject("refresh_token was issued to another client")
            );
        }
        let scopes = form.refresh_scopes(&redeemed.scopes)?;
        let user = tx
            .users()
            .find_by_id(redeemed.user_id)
            .await?
            .ok_or_else(|| OAuthCode::InvalidGrant.reject("the account no longer exists"))?;
        let session = tx
            .sessions()
            .find_by_id(redeemed.session_id)
            .await?
            .ok_or_else(|| OAuthCode::InvalidGrant.reject(SESSION_ENDED))?;
        let refresh_token = match &redeemed.outcome {
            RefreshOutcome::Kept => None,
            RefreshOutcome::Rotated => {
                let (token, raw) =
                    self.new_refresh(redeemed.family_id, session.expires_at, Some(&opaque))?;
                tx.tokens().insert_token(&token).await?;
                Some(raw)
            }
            RefreshOutcome::Retried(successor) => Some(self.rebuild_successor(&opaque, successor)?),
        };
        let email = tx.oidc().primary_email(user.id).await?;
        let tokens = TokenGrant {
            client: &client.id,
            audience: &redeemed.audience,
            scopes: &scopes,
            nonce: None,
            session: session.id,
            authentication: &redeemed.authentication,
        }
        .issue(self, &user, email.as_deref())?;
        tx.commit().await?;
        Ok(TokenResponse {
            refresh_token,
            ..tokens
        })
    }

    /// Creates the refresh family of a redeemed code, linked to the code so a replay
    /// can revoke it, and its first token bounded by the browser session lifetime.
    /// Returns the family and the encoded token.
    async fn create_refresh(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        code: ConsumedAuthorizationCode,
    ) -> Result<(TokenId, String), OAuthError> {
        let session = tx
            .sessions()
            .find_active_by_id(code.session_id)
            .await?
            .ok_or_else(|| OAuthCode::InvalidGrant.reject(SESSION_ENDED))?;
        let family_id = TokenId::new();
        let (token, raw) = self.new_refresh(family_id, session.expires_at, None)?;
        tx.tokens()
            .insert_family(
                &InsertRefreshFamily {
                    id: family_id,
                    user_id: code.user_id,
                    client_id: code.client_id.into(),
                    session_id: code.session_id,
                    authorization_code_id: code.id,
                    audience: code.audience,
                    scopes: code.scopes,
                    authentication: code.authentication,
                },
                &token,
            )
            .await?;
        Ok((family_id, raw))
    }

    /// Generates a refresh token of `family_id`, accepted until `expires_at`, the
    /// end of its browser session. A family's first token is random; the
    /// successor of a rotated `predecessor` has its secret derived from the
    /// predecessor's, so a retry can be answered with it again
    /// ([`Self::rebuild_successor`]). Returns the row to insert and the encoded
    /// token.
    fn new_refresh(
        &self,
        family_id: TokenId,
        expires_at: DateTime<Utc>,
        predecessor: Option<&OpaqueToken>,
    ) -> Result<(InsertRefreshToken, String), OAuthError> {
        let opaque = match predecessor {
            None => OpaqueToken::new(TokenPrefix::RefreshToken)?,
            Some(predecessor) => {
                let id = TokenId::new();
                OpaqueToken {
                    id,
                    secret: self.digest_keys.successor(id, &predecessor.secret),
                    prefix: TokenPrefix::RefreshToken,
                }
            }
        };
        let (secret_digest, digest_key) = self.token_digest(&opaque);
        let token = InsertRefreshToken {
            id: opaque.id,
            family_id,
            secret_digest,
            digest_key,
            expires_at,
            predecessor_id: predecessor.map(|predecessor| predecessor.id),
        };
        Ok((token, opaque.encoded()))
    }

    /// The encoded `successor` that the rotation of `presented` issued moments
    /// ago, rebuilt from `presented`, since only its digest is stored. Fails only
    /// if the token digest key changed in between and no accepted key derives it
    /// any more: the refresh is then refused, and revokes nothing.
    fn rebuild_successor(
        &self,
        presented: &OpaqueToken,
        successor: &RefreshSuccessor,
    ) -> Result<String, OAuthError> {
        let secret = self
            .digest_keys
            .rebuild_successor(successor.id, &presented.secret, &successor.secret_digest)
            .ok_or_else(|| {
                OAuthCode::InvalidGrant
                    .reject("refresh_token was already replaced; use its replacement")
            })?;
        Ok(OpaqueToken {
            id: successor.id,
            secret,
            prefix: TokenPrefix::RefreshToken,
        }
        .encoded())
    }

    /// Revokes the authenticated client’s refresh family, concealing invalid-token existence.
    pub(super) async fn revoke(
        State(app): State<Self>,
        context: RequestContext,
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
            let digests = app.accepted_digests(&opaque);
            let mut tx = app.database.begin().await?;
            if let Some(family) = tx
                .tokens()
                .revoke_family_for_client_token(opaque.id, &digests, client.id.as_str())
                .await?
            {
                tx.record(
                    &context.client(&client.id),
                    Some(family.user_id),
                    DomainEvent::GrantRevoked {
                        client_id: client.id.clone(),
                        family_id: family.id,
                        reason: GrantRevocation::ClientRevoked,
                    },
                )
                .await?;
            }
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
    ) -> std::future::Ready<Result<Json<UserInfo>, OAuthError>> {
        std::future::ready(app.userinfo_response(&headers))
    }

    /// Builds scoped identity claims after synchronous verification of the supplied bearer token.
    fn userinfo_response(&self, headers: &HeaderMap) -> Result<Json<UserInfo>, OAuthError> {
        let bearer = || format!("send an access token as {} credentials", AuthScheme::Bearer);
        let authorization = headers
            .get(header::AUTHORIZATION)
            .ok_or_else(|| OAuthCode::InvalidToken.reject(bearer()))?
            .to_str()
            .map_err(|error| OAuthCode::InvalidToken.reject_with(bearer(), error))?;
        let token = AuthScheme::Bearer
            .credentials(authorization)
            .ok_or_else(|| OAuthCode::InvalidToken.reject(bearer()))?;
        let claims: AccessTokenClaims = self
            .keys
            .current()?
            .verify(token, TokenType::Access, &self.issuer)
            .map_err(|error| {
                OAuthCode::InvalidToken
                    .reject_with(format!("access token is invalid: {error}"), error)
            })?;
        let scopes = Scopes::from_wire(claims.scope);
        if !scopes.contains(Scope::OpenId) {
            return Err(OAuthCode::InvalidToken.reject(format!(
                "access token was not granted the {} scope",
                Scope::OpenId
            )));
        }
        Ok(Json(UserInfo {
            sub: claims.sub,
            profile: scopes.release(claims.profile),
        }))
    }

    /// Persists replay/policy revocation, recorded as a revoked grant, before
    /// returning the preserved redemption failure.
    async fn refresh_rejection(
        tx: DatabaseTransaction<'_>,
        context: &EventContext,
        client_id: &ClientId,
        error: RefreshRedemptionError,
    ) -> OAuthError {
        let (user_id, family_id, reason) = match error {
            RefreshRedemptionError::Replay { user_id, family_id } => {
                (user_id, family_id, GrantRevocation::RefreshReplay)
            }
            RefreshRedemptionError::Policy { user_id, family_id } => {
                (user_id, family_id, GrantRevocation::PolicyRejected)
            }
            RefreshRedemptionError::Invalid | RefreshRedemptionError::Database(_) => {
                return error.into();
            }
        };
        // Logged first so the signal survives a database failure.
        if reason == GrantRevocation::RefreshReplay {
            tracing::warn!(
                event = REFRESH_REPLAY_EVENT,
                %user_id,
                "refresh token replay rejected"
            );
        }
        let revoked = DomainEvent::GrantRevoked {
            client_id: client_id.clone(),
            family_id,
            reason,
        };
        Self::commit_rejection(tx, context, user_id, [revoked], error).await
    }

    /// Persists the family revocation of a replayed code, recording the replay and
    /// each revoked grant, before returning the preserved redemption failure. Access
    /// tokens already issued from the code cannot be revoked and simply expire.
    ///
    /// The browser session behind the code stays signed in: a leaked code exposes
    /// the client's callback, not the session cookie, and anyone holding the code
    /// could otherwise sign the user out of every application.
    async fn code_rejection(
        tx: DatabaseTransaction<'_>,
        context: &EventContext,
        client_id: &ClientId,
        error: CodeRedemptionError,
    ) -> OAuthError {
        let CodeRedemptionError::Replay {
            user_id,
            ref revoked_families,
        } = error
        else {
            return error.into();
        };
        // Logged first so the signal survives a database failure.
        tracing::warn!(
            event = CODE_REPLAY_EVENT,
            %user_id,
            "authorization code replay rejected"
        );
        let client_id = client_id.clone();
        let events: Vec<_> = std::iter::once(DomainEvent::CodeReplayed {
            client_id: client_id.clone(),
        })
        .chain(
            revoked_families
                .iter()
                .map(|&family_id| DomainEvent::GrantRevoked {
                    client_id: client_id.clone(),
                    family_id,
                    reason: GrantRevocation::CodeReplay,
                }),
        )
        .collect();
        Self::commit_rejection(tx, context, user_id, events, error).await
    }

    /// Commits the revocation a rejected grant already made in `tx`, together with
    /// the `events` recording it, then returns the grant's `error`, or the database
    /// failure that prevented the commit.
    async fn commit_rejection(
        mut tx: DatabaseTransaction<'_>,
        context: &EventContext,
        user_id: UserId,
        events: impl IntoIterator<Item = DomainEvent>,
        error: impl Into<OAuthError>,
    ) -> OAuthError {
        let committed = async {
            for event in events {
                tx.record(context, Some(user_id), event).await?;
            }
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
/// Rejection of a code whose consent the user withdrew since it was issued.
const CONSENT_WITHDRAWN: &str = "the user withdrew consent for this application";
/// Rejection of a grant whose browser session ended.
const SESSION_ENDED: &str = "the sign-in session behind this grant has ended";

/// Stable telemetry event name for refresh-token replay rejection.
const REFRESH_REPLAY_EVENT: &str = "auth.refresh_replay";
/// Stable telemetry event name for authorization-code replay rejection.
const CODE_REPLAY_EVENT: &str = "auth.code_replay";
