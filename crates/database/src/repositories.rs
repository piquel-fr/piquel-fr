//! Domain repository handles backed by a private pool or transaction connection.

use crate::{
    AppendAuditEvent, AppendInternalEvent, BootstrapOidcClient, BootstrapServiceIdentity,
    ConsumedAuthorizationCode, ConsumedCeremony, ConsumedFederationTransaction, DatabaseError,
    InsertAuthorizationCode, InsertAuthorizationRequest, InsertCeremony, InsertExternalIdentity,
    InsertFederationTransaction, InsertPasskey, InsertRefreshFamily, InsertRefreshToken,
    InsertSession, InsertUser, InsertVerifiedEmail, RefreshRotationError, RotatedRefreshToken,
    StoredAuthorizationRequest, StoredEmail, StoredExternalIdentity, StoredOidcClient,
    StoredPasskey, StoredServiceIdentity, StoredSession, StoredUser, UpdateUserProfile,
};
use piquel_auth_protocol::{AccountStatus, SessionId, TokenId, UserId};
use sqlx::{PgConnection, PgPool, Row};

#[allow(dead_code)]
pub(crate) enum RepositoryExecutor<'a> {
    Pool(&'a PgPool),
    Connection(&'a mut PgConnection),
}

macro_rules! repository {
    ($name:ident) => {
        /// Focused persistence handle; it has no policy and no public SQL escape hatch.
        pub struct $name<'a> {
            #[allow(dead_code)]
            pub(crate) executor: RepositoryExecutor<'a>,
        }
        impl<'a> $name<'a> {
            pub(crate) const fn from_pool(pool: &'a PgPool) -> Self {
                Self {
                    executor: RepositoryExecutor::Pool(pool),
                }
            }
            pub(crate) fn from_connection(connection: &'a mut PgConnection) -> Self {
                Self {
                    executor: RepositoryExecutor::Connection(connection),
                }
            }
        }
    };
}
repository!(UserRepository);
repository!(EmailRepository);
repository!(SessionRepository);
repository!(AuditEventRepository);
repository!(InternalEventRepository);
repository!(PasskeyRepository);
repository!(OidcRepository);
repository!(TokenRepository);
repository!(FederationRepository);
repository!(ServiceIdentityRepository);

macro_rules! fetch_optional {
    ($self:expr, $query:expr) => {{
        match &mut $self.executor {
            RepositoryExecutor::Pool(pool) => $query.fetch_optional(*pool).await,
            RepositoryExecutor::Connection(connection) => {
                $query.fetch_optional(&mut **connection).await
            }
        }
        .map_err(crate::error::map_error)
    }};
}
macro_rules! fetch_one {
    ($self:expr, $query:expr) => {{
        match &mut $self.executor {
            RepositoryExecutor::Pool(pool) => $query.fetch_one(*pool).await,
            RepositoryExecutor::Connection(connection) => $query.fetch_one(&mut **connection).await,
        }
        .map_err(crate::error::map_error)
    }};
}
macro_rules! execute {
    ($self:expr, $query:expr) => {{
        match &mut $self.executor {
            RepositoryExecutor::Pool(pool) => $query.execute(*pool).await,
            RepositoryExecutor::Connection(connection) => $query.execute(&mut **connection).await,
        }
        .map_err(crate::error::map_error)
    }};
}

fn stored_user(row: &sqlx::postgres::PgRow) -> Result<StoredUser, DatabaseError> {
    let status = match row
        .try_get::<String, _>("status")
        .map_err(|_| DatabaseError::InvalidStoredData)?
        .as_str()
    {
        "active" => AccountStatus::Active,
        "disabled" => AccountStatus::Disabled,
        _ => return Err(DatabaseError::InvalidStoredData),
    };
    let version = u64::try_from(
        row.try_get::<i64, _>("profile_version")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
    )
    .map_err(|_| DatabaseError::InvalidStoredData)?;
    Ok(StoredUser {
        id: UserId::from_uuid(
            row.try_get("id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        username: row
            .try_get("username")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        display_name: row
            .try_get("display_name")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        profile_version: version,
        status,
        created_at: row
            .try_get("created_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
    })
}

impl UserRepository<'_> {
    pub async fn insert(&mut self, input: &InsertUser) -> Result<StoredUser, DatabaseError> {
        let row = fetch_one!(self, sqlx::query("INSERT INTO users (id, username, display_name) VALUES ($1, $2, $3) RETURNING id, username, display_name, profile_version, status, created_at, updated_at").bind(input.id.as_uuid()).bind(&input.username).bind(&input.display_name))?;
        stored_user(&row)
    }
    pub async fn find_by_id(&mut self, id: UserId) -> Result<Option<StoredUser>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT id, username, display_name, profile_version, status, created_at, updated_at FROM users WHERE id = $1").bind(id.as_uuid()))?.map(|row| stored_user(&row)).transpose()
    }
    pub async fn find_active_by_id_for_update(
        &mut self,
        id: UserId,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT id, username, display_name, profile_version, status, created_at, updated_at FROM users WHERE id = $1 AND status='active' FOR UPDATE").bind(id.as_uuid()))?.map(|row| stored_user(&row)).transpose()
    }
    pub async fn find_active_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT id, username, display_name, profile_version, status, created_at, updated_at FROM users WHERE username = $1 AND status = 'active'").bind(username))?.map(|row| stored_user(&row)).transpose()
    }
    pub async fn update_profile(
        &mut self,
        input: &UpdateUserProfile,
    ) -> Result<StoredUser, DatabaseError> {
        let expected =
            i64::try_from(input.expected_version).map_err(|_| DatabaseError::Conflict)?;
        let row = fetch_optional!(self, sqlx::query("UPDATE users SET username = $1, display_name = $2, profile_version = profile_version + 1, updated_at = now() WHERE id = $3 AND profile_version = $4 RETURNING id, username, display_name, profile_version, status, created_at, updated_at").bind(&input.username).bind(&input.display_name).bind(input.id.as_uuid()).bind(expected))?.ok_or(DatabaseError::Conflict)?;
        stored_user(&row)
    }
    pub async fn set_status(
        &mut self,
        id: UserId,
        status: AccountStatus,
    ) -> Result<bool, DatabaseError> {
        let status = match status {
            AccountStatus::Active => "active",
            AccountStatus::Disabled => "disabled",
        };
        Ok(execute!(
            self,
            sqlx::query(
                "UPDATE users SET status = $1, updated_at = now() WHERE id = $2 AND status <> $1"
            )
            .bind(status)
            .bind(id.as_uuid())
        )?
        .rows_affected()
            == 1)
    }
}

impl EmailRepository<'_> {
    pub async fn insert_verified(
        &mut self,
        input: &InsertVerifiedEmail,
    ) -> Result<StoredEmail, DatabaseError> {
        let row = fetch_one!(self, sqlx::query("INSERT INTO user_emails (id, user_id, normalized_email, verified_at, is_primary) VALUES ($1, $2, $3, $4, $5) RETURNING id, user_id, normalized_email, verified_at, is_primary").bind(input.id.as_uuid()).bind(input.user_id.as_uuid()).bind(&input.normalized_email).bind(input.verified_at).bind(input.is_primary))?;
        Ok(StoredEmail {
            id: piquel_auth_protocol::TokenId::from_uuid(
                row.try_get("id")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            )
            .map_err(|_| DatabaseError::InvalidStoredData)?,
            user_id: UserId::from_uuid(
                row.try_get("user_id")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            )
            .map_err(|_| DatabaseError::InvalidStoredData)?,
            normalized_email: row
                .try_get("normalized_email")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            verified_at: row
                .try_get("verified_at")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            is_primary: row
                .try_get("is_primary")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        })
    }
    pub async fn find_active_verified(
        &mut self,
        normalized: &str,
    ) -> Result<Option<StoredEmail>, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("SELECT e.id, e.user_id, e.normalized_email, e.verified_at, e.is_primary FROM active_verified_email_ownership o JOIN user_emails e ON e.user_id = o.user_id AND e.normalized_email = o.normalized_email AND e.verified_at IS NOT NULL WHERE o.normalized_email = $1 ORDER BY e.is_primary DESC, e.created_at LIMIT 1").bind(normalized))?;
        row.map(|row| {
            Ok(StoredEmail {
                id: piquel_auth_protocol::TokenId::from_uuid(
                    row.try_get("id")
                        .map_err(|_| DatabaseError::InvalidStoredData)?,
                )
                .map_err(|_| DatabaseError::InvalidStoredData)?,
                user_id: UserId::from_uuid(
                    row.try_get("user_id")
                        .map_err(|_| DatabaseError::InvalidStoredData)?,
                )
                .map_err(|_| DatabaseError::InvalidStoredData)?,
                normalized_email: row
                    .try_get("normalized_email")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                verified_at: row
                    .try_get("verified_at")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                is_primary: row
                    .try_get("is_primary")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            })
        })
        .transpose()
    }

    pub async fn find_users_by_verified_email(
        &mut self,
        normalized: &str,
    ) -> Result<Vec<StoredUser>, DatabaseError> {
        let rows=match &mut self.executor{RepositoryExecutor::Pool(pool)=>sqlx::query("SELECT DISTINCT u.id,u.username,u.display_name,u.profile_version,u.status,u.created_at,u.updated_at FROM user_emails e JOIN users u ON u.id=e.user_id WHERE e.normalized_email=$1 AND e.verified_at IS NOT NULL ORDER BY u.id").bind(normalized).fetch_all(*pool).await,RepositoryExecutor::Connection(connection)=>sqlx::query("SELECT DISTINCT u.id,u.username,u.display_name,u.profile_version,u.status,u.created_at,u.updated_at FROM user_emails e JOIN users u ON u.id=e.user_id WHERE e.normalized_email=$1 AND e.verified_at IS NOT NULL ORDER BY u.id").bind(normalized).fetch_all(&mut **connection).await}.map_err(crate::error::map_error)?;
        rows.iter().map(stored_user).collect()
    }
}

impl SessionRepository<'_> {
    pub async fn insert(&mut self, input: &InsertSession) -> Result<StoredSession, DatabaseError> {
        let methods = serde_json::to_value(&input.authentication_methods)
            .map_err(|_| DatabaseError::Internal)?;
        // Lock the account row through insertion so disablement and session
        // creation have a single serialization point. A session can never be
        // committed for an account that was disabled first.
        let row = fetch_one!(self, sqlx::query("WITH active_user AS (SELECT id FROM users WHERE id=$2 AND status='active' FOR UPDATE) INSERT INTO sessions (id, user_id, authentication_methods, authenticated_at, expires_at, last_seen_at, user_agent_family) SELECT $1,id,$3,$4,$5,$4,$6 FROM active_user RETURNING id,user_id,authentication_methods,authenticated_at,expires_at,last_seen_at,revoked_at").bind(input.id.as_uuid()).bind(input.user_id.as_uuid()).bind(methods).bind(input.authenticated_at).bind(input.expires_at).bind(&input.user_agent_family))?;
        stored_session(&row)
    }
    pub async fn find_by_id(
        &mut self,
        id: SessionId,
    ) -> Result<Option<StoredSession>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT id,user_id,authentication_methods,authenticated_at,expires_at,last_seen_at,revoked_at FROM sessions WHERE id=$1").bind(id.as_uuid()))?.map(|row| stored_session(&row)).transpose()
    }
    pub async fn find_active_by_id(
        &mut self,
        id: SessionId,
    ) -> Result<Option<StoredSession>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT s.id,s.user_id,s.authentication_methods,s.authenticated_at,s.expires_at,s.last_seen_at,s.revoked_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'").bind(id.as_uuid()))?.map(|row| stored_session(&row)).transpose()
    }
    pub async fn touch(&mut self, id: SessionId) -> Result<bool, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE sessions SET last_seen_at=now() WHERE id=$1 AND revoked_at IS NULL AND expires_at>now()").bind(id.as_uuid()))?.rows_affected()==1)
    }
    pub async fn revoke(&mut self, id: SessionId) -> Result<bool, DatabaseError> {
        Ok(execute!(
            self,
            sqlx::query("UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL")
                .bind(id.as_uuid())
        )?
        .rows_affected()
            == 1)
    }
    pub async fn revoke_all_for_user(&mut self, user_id: UserId) -> Result<u64, DatabaseError> {
        Ok(execute!(
            self,
            sqlx::query(
                "UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL"
            )
            .bind(user_id.as_uuid())
        )?
        .rows_affected())
    }
}

impl OidcRepository<'_> {
    /// Idempotently provisions a statically reviewed public client and exact URI allowlists.
    pub async fn bootstrap_client(
        &mut self,
        input: &BootstrapOidcClient,
    ) -> Result<(), DatabaseError> {
        validate_bootstrap_client(input)?;
        let scopes =
            serde_json::to_value(&input.allowed_scopes).map_err(|_| DatabaseError::Internal)?;
        let audiences =
            serde_json::to_value(&input.allowed_audiences).map_err(|_| DatabaseError::Internal)?;
        execute!(self, sqlx::query("WITH upsert AS (INSERT INTO oidc_clients(id,display_name,allowed_scopes,allowed_audiences,allow_refresh) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET display_name=EXCLUDED.display_name,allowed_scopes=EXCLUDED.allowed_scopes,allowed_audiences=EXCLUDED.allowed_audiences,allow_refresh=EXCLUDED.allow_refresh RETURNING id), desired(uri,kind) AS (SELECT unnest($6::text[]),'authorization' UNION ALL SELECT unnest($7::text[]),'post_logout'), inserted AS (INSERT INTO oidc_redirect_uris(client_id,uri,kind) SELECT $1,d.uri,d.kind FROM desired d,upsert ON CONFLICT DO NOTHING RETURNING uri), removed AS (DELETE FROM oidc_redirect_uris r WHERE r.client_id=$1 AND NOT EXISTS (SELECT 1 FROM desired d WHERE d.uri=r.uri AND d.kind=r.kind) RETURNING uri) SELECT id FROM upsert")
            .bind(&input.id).bind(&input.display_name).bind(scopes).bind(audiences).bind(input.allow_refresh).bind(&input.redirect_uris).bind(&input.post_logout_uris))?;
        Ok(())
    }

    pub async fn find_client(
        &mut self,
        id: &str,
    ) -> Result<Option<StoredOidcClient>, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("SELECT c.id,c.display_name,c.enabled,c.allowed_scopes,c.allowed_audiences,c.allow_refresh,COALESCE(jsonb_agg(r.uri) FILTER (WHERE r.kind='authorization'),'[]'::jsonb) AS redirect_uris,COALESCE(jsonb_agg(r.uri) FILTER (WHERE r.kind='post_logout'),'[]'::jsonb) AS post_logout_uris FROM oidc_clients c LEFT JOIN oidc_redirect_uris r ON r.client_id=c.id WHERE c.id=$1 GROUP BY c.id").bind(id))?;
        row.map(|row| {
            let strings = |column| -> Result<Vec<String>, DatabaseError> {
                serde_json::from_value(
                    row.try_get(column)
                        .map_err(|_| DatabaseError::InvalidStoredData)?,
                )
                .map_err(|_| DatabaseError::InvalidStoredData)
            };
            Ok(StoredOidcClient {
                id: row
                    .try_get("id")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                display_name: row
                    .try_get("display_name")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                enabled: row
                    .try_get("enabled")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                redirect_uris: strings("redirect_uris")?,
                post_logout_uris: strings("post_logout_uris")?,
                allowed_scopes: strings("allowed_scopes")?,
                allowed_audiences: strings("allowed_audiences")?,
                allow_refresh: row
                    .try_get("allow_refresh")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            })
        })
        .transpose()
    }

    pub async fn insert_code(
        &mut self,
        input: &InsertAuthorizationCode,
    ) -> Result<(), DatabaseError> {
        let scopes = serde_json::to_value(&input.scopes).map_err(|_| DatabaseError::Internal)?;
        execute!(self, sqlx::query("INSERT INTO authorization_codes(id,secret_digest,client_id,user_id,session_id,redirect_uri,pkce_challenge,nonce,scopes,audience,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(input.id.as_uuid()).bind(&input.secret_digest).bind(&input.client_id)
            .bind(input.user_id.as_uuid()).bind(input.session_id.as_uuid()).bind(&input.redirect_uri)
            .bind(&input.pkce_challenge).bind(&input.nonce).bind(scopes).bind(&input.audience).bind(input.expires_at))?;
        Ok(())
    }

    pub async fn insert_authorization_request(
        &mut self,
        input: &InsertAuthorizationRequest,
    ) -> Result<(), DatabaseError> {
        let scopes = serde_json::to_value(&input.scopes).map_err(|_| DatabaseError::Internal)?;
        execute!(self, sqlx::query("INSERT INTO authorization_requests(id,secret_digest,client_id,redirect_uri,client_state,nonce,pkce_challenge,scopes,audience,force_login,max_age,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
            .bind(input.id.as_uuid()).bind(&input.secret_digest).bind(&input.client_id)
            .bind(&input.redirect_uri).bind(&input.client_state).bind(&input.nonce)
            .bind(&input.pkce_challenge).bind(scopes).bind(&input.audience)
            .bind(input.force_login).bind(input.max_age).bind(input.expires_at))?;
        Ok(())
    }

    pub async fn find_authorization_request(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<Option<StoredAuthorizationRequest>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT r.id,r.client_id,c.display_name AS client_display_name,r.redirect_uri,r.client_state,r.nonce,r.pkce_challenge,r.scopes,r.audience,r.force_login,r.max_age,r.created_at FROM authorization_requests r JOIN oidc_clients c ON c.id=r.client_id WHERE r.id=$1 AND r.secret_digest=$2 AND r.consumed_at IS NULL AND r.expires_at>now() AND c.enabled").bind(id.as_uuid()).bind(digest))?.map(|row| stored_authorization_request(&row)).transpose()
    }

    pub async fn consume_authorization_request(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<StoredAuthorizationRequest, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("UPDATE authorization_requests r SET consumed_at=now() FROM oidc_clients c WHERE r.id=$1 AND r.secret_digest=$2 AND r.consumed_at IS NULL AND r.expires_at>now() AND c.id=r.client_id AND c.enabled RETURNING r.id,r.client_id,c.display_name AS client_display_name,r.redirect_uri,r.client_state,r.nonce,r.pkce_challenge,r.scopes,r.audience,r.force_login,r.max_age,r.created_at").bind(id.as_uuid()).bind(digest))?.ok_or(DatabaseError::NotFound)?;
        stored_authorization_request(&row)
    }

    pub async fn consume_code(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<ConsumedAuthorizationCode, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("UPDATE authorization_codes c SET consumed_at=now() FROM oidc_clients cl,sessions s,users u WHERE c.id=$1 AND c.secret_digest=$2 AND c.consumed_at IS NULL AND c.expires_at>now() AND cl.id=c.client_id AND cl.enabled AND s.id=c.session_id AND s.revoked_at IS NULL AND s.expires_at>now() AND u.id=c.user_id AND u.status='active' RETURNING c.client_id,c.user_id,c.session_id,c.redirect_uri,c.pkce_challenge,c.nonce,c.scopes,c.audience").bind(id.as_uuid()).bind(digest))?.ok_or(DatabaseError::NotFound)?;
        Ok(ConsumedAuthorizationCode {
            client_id: row
                .try_get("client_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            user_id: UserId::from_uuid(
                row.try_get("user_id")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            )
            .map_err(|_| DatabaseError::InvalidStoredData)?,
            session_id: SessionId::from_uuid(
                row.try_get("session_id")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            )
            .map_err(|_| DatabaseError::InvalidStoredData)?,
            redirect_uri: row
                .try_get("redirect_uri")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            pkce_challenge: row
                .try_get("pkce_challenge")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            nonce: row
                .try_get("nonce")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            scopes: serde_json::from_value(
                row.try_get("scopes")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            )
            .map_err(|_| DatabaseError::InvalidStoredData)?,
            audience: row
                .try_get("audience")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        })
    }
}

fn validate_bootstrap_client(input: &BootstrapOidcClient) -> Result<(), DatabaseError> {
    let identifier = |value: &str| {
        (1..=64).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    let redirect = |value: &str| {
        url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
    };
    let valid = identifier(&input.id)
        && !input.display_name.trim().is_empty()
        && input.display_name.chars().count() <= 80
        && !input.redirect_uris.is_empty()
        && input.redirect_uris.len() <= 16
        && input.post_logout_uris.len() <= 16
        && input.redirect_uris.iter().all(|uri| redirect(uri))
        && input.post_logout_uris.iter().all(|uri| redirect(uri))
        && !input.allowed_scopes.is_empty()
        && input.allowed_scopes.len() <= 32
        && input.allowed_scopes.iter().all(|scope| identifier(scope))
        && !input.allowed_audiences.is_empty()
        && input.allowed_audiences.len() <= 16
        && input
            .allowed_audiences
            .iter()
            .all(|audience| identifier(audience));
    valid.then_some(()).ok_or(DatabaseError::Conflict)
}

fn stored_authorization_request(
    row: &sqlx::postgres::PgRow,
) -> Result<StoredAuthorizationRequest, DatabaseError> {
    Ok(StoredAuthorizationRequest {
        id: TokenId::from_uuid(
            row.try_get("id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        client_id: row
            .try_get("client_id")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        client_display_name: row
            .try_get("client_display_name")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        redirect_uri: row
            .try_get("redirect_uri")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        client_state: row
            .try_get("client_state")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        nonce: row
            .try_get("nonce")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        pkce_challenge: row
            .try_get("pkce_challenge")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        scopes: serde_json::from_value(
            row.try_get("scopes")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        audience: row
            .try_get("audience")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        force_login: row
            .try_get("force_login")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        max_age: row
            .try_get("max_age")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
    })
}

impl TokenRepository<'_> {
    pub async fn insert_family(
        &mut self,
        family: &InsertRefreshFamily,
        token: &InsertRefreshToken,
    ) -> Result<(), DatabaseError> {
        let scopes = serde_json::to_value(&family.scopes).map_err(|_| DatabaseError::Internal)?;
        execute!(self, sqlx::query("INSERT INTO refresh_token_families(id,user_id,client_id,session_id,audience,scopes) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(family.id.as_uuid()).bind(family.user_id.as_uuid()).bind(&family.client_id)
            .bind(family.session_id.as_uuid()).bind(&family.audience).bind(scopes))?;
        self.insert_token(token).await
    }

    pub async fn insert_token(&mut self, token: &InsertRefreshToken) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("INSERT INTO refresh_tokens(id,family_id,secret_digest,expires_at) VALUES($1,$2,$3,$4)")
            .bind(token.id.as_uuid()).bind(token.family_id.as_uuid()).bind(&token.secret_digest).bind(token.expires_at))?;
        Ok(())
    }

    pub async fn consume_for_rotation(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<RotatedRefreshToken, RefreshRotationError> {
        let row = fetch_optional!(self, sqlx::query("SELECT t.family_id,t.consumed_at,f.user_id,f.client_id,f.session_id,f.audience,f.scopes,c.allow_refresh,c.allowed_scopes,c.allowed_audiences FROM refresh_tokens t JOIN refresh_token_families f ON f.id=t.family_id JOIN oidc_clients c ON c.id=f.client_id JOIN sessions s ON s.id=f.session_id JOIN users u ON u.id=f.user_id WHERE t.id=$1 AND t.secret_digest=$2 AND t.expires_at>now() AND f.revoked_at IS NULL AND c.enabled AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active' FOR UPDATE OF t,f,c,s,u").bind(id.as_uuid()).bind(digest)).map_err(|_| RefreshRotationError::Invalid)?.ok_or(RefreshRotationError::Invalid)?;
        let family_uuid: uuid::Uuid = row
            .try_get("family_id")
            .map_err(|_| RefreshRotationError::Invalid)?;
        let user_id = UserId::from_uuid(
            row.try_get("user_id")
                .map_err(|_| RefreshRotationError::Invalid)?,
        )
        .map_err(|_| RefreshRotationError::Invalid)?;
        if row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("consumed_at")
            .map_err(|_| RefreshRotationError::Invalid)?
            .is_some()
        {
            execute!(self, sqlx::query("UPDATE refresh_token_families SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL").bind(family_uuid)).map_err(|_| RefreshRotationError::Invalid)?;
            return Err(RefreshRotationError::Replay { user_id });
        }
        let family_scopes: Vec<String> = serde_json::from_value(
            row.try_get("scopes")
                .map_err(|_| RefreshRotationError::Invalid)?,
        )
        .map_err(|_| RefreshRotationError::Invalid)?;
        let allowed_scopes: Vec<String> = serde_json::from_value(
            row.try_get("allowed_scopes")
                .map_err(|_| RefreshRotationError::Invalid)?,
        )
        .map_err(|_| RefreshRotationError::Invalid)?;
        let allowed_audiences: Vec<String> = serde_json::from_value(
            row.try_get("allowed_audiences")
                .map_err(|_| RefreshRotationError::Invalid)?,
        )
        .map_err(|_| RefreshRotationError::Invalid)?;
        let audience: String = row
            .try_get("audience")
            .map_err(|_| RefreshRotationError::Invalid)?;
        let policy_valid = row
            .try_get::<bool, _>("allow_refresh")
            .map_err(|_| RefreshRotationError::Invalid)?
            && allowed_audiences.contains(&audience)
            && family_scopes
                .iter()
                .all(|scope| allowed_scopes.contains(scope));
        if !policy_valid {
            execute!(self, sqlx::query("UPDATE refresh_token_families SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL").bind(family_uuid)).map_err(|_| RefreshRotationError::Invalid)?;
            return Err(RefreshRotationError::Policy { user_id });
        }
        if execute!(
            self,
            sqlx::query(
                "UPDATE refresh_tokens SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL"
            )
            .bind(id.as_uuid())
        )
        .map_err(|_| RefreshRotationError::Invalid)?
        .rows_affected()
            != 1
        {
            return Err(RefreshRotationError::Invalid);
        }
        Ok(RotatedRefreshToken {
            family_id: TokenId::from_uuid(family_uuid)
                .map_err(|_| RefreshRotationError::Invalid)?,
            user_id,
            client_id: row
                .try_get("client_id")
                .map_err(|_| RefreshRotationError::Invalid)?,
            session_id: SessionId::from_uuid(
                row.try_get("session_id")
                    .map_err(|_| RefreshRotationError::Invalid)?,
            )
            .map_err(|_| RefreshRotationError::Invalid)?,
            audience,
            scopes: family_scopes,
        })
    }

    pub async fn revoke_family_for_token(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("UPDATE refresh_token_families f SET revoked_at=COALESCE(revoked_at,now()) FROM refresh_tokens t WHERE t.id=$1 AND t.secret_digest=$2 AND t.family_id=f.id").bind(id.as_uuid()).bind(digest))?;
        Ok(())
    }

    pub async fn revoke_all_for_user(&mut self, user_id: UserId) -> Result<u64, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE refresh_token_families SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL").bind(user_id.as_uuid()))?.rows_affected())
    }
}

impl FederationRepository<'_> {
    pub async fn insert_transaction(
        &mut self,
        input: &InsertFederationTransaction,
    ) -> Result<(), DatabaseError> {
        execute!(self,sqlx::query("INSERT INTO federation_transactions(id,provider_name,state_digest,browser_digest,nonce,pkce_verifier,return_to,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(input.id.as_uuid()).bind(&input.provider).bind(&input.state_digest).bind(&input.browser_digest).bind(&input.nonce).bind(&input.pkce_verifier).bind(&input.return_to).bind(input.expires_at))?;
        Ok(())
    }
    pub async fn consume_transaction(
        &mut self,
        provider: &str,
        state_digest: &[u8],
        browser_digest: &[u8],
    ) -> Result<ConsumedFederationTransaction, DatabaseError> {
        let row=fetch_optional!(self,sqlx::query("UPDATE federation_transactions SET consumed_at=now() WHERE provider_name=$1 AND state_digest=$2 AND browser_digest=$3 AND consumed_at IS NULL AND expires_at>now() RETURNING nonce,pkce_verifier,return_to").bind(provider).bind(state_digest).bind(browser_digest))?.ok_or(DatabaseError::NotFound)?;
        Ok(ConsumedFederationTransaction {
            nonce: row
                .try_get("nonce")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            pkce_verifier: row
                .try_get("pkce_verifier")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            return_to: row
                .try_get("return_to")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        })
    }
    pub async fn find_active(
        &mut self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<StoredExternalIdentity>, DatabaseError> {
        fetch_optional!(self,sqlx::query("SELECT id,user_id,provider_name,issuer,subject,linked_email FROM external_login_identities WHERE issuer=$1 AND subject=$2 AND revoked_at IS NULL").bind(issuer).bind(subject))?.map(|row|stored_external_identity(&row)).transpose()
    }
    pub async fn insert_identity(
        &mut self,
        input: &InsertExternalIdentity,
    ) -> Result<StoredExternalIdentity, DatabaseError> {
        let row=fetch_one!(self,sqlx::query("INSERT INTO external_login_identities(id,user_id,provider_name,issuer,subject,linked_email) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,user_id,provider_name,issuer,subject,linked_email").bind(input.id.as_uuid()).bind(input.user_id.as_uuid()).bind(&input.provider).bind(&input.issuer).bind(&input.subject).bind(&input.linked_email))?;
        stored_external_identity(&row)
    }
    pub async fn record_login(&mut self, id: TokenId) -> Result<(), DatabaseError> {
        execute!(self,sqlx::query("UPDATE external_login_identities SET last_login_at=now() WHERE id=$1 AND revoked_at IS NULL").bind(id.as_uuid()))?;
        Ok(())
    }
    pub async fn list_active(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<StoredExternalIdentity>, DatabaseError> {
        let rows=match &mut self.executor{RepositoryExecutor::Pool(pool)=>sqlx::query("SELECT id,user_id,provider_name,issuer,subject,linked_email FROM external_login_identities WHERE user_id=$1 AND revoked_at IS NULL ORDER BY linked_at").bind(user_id.as_uuid()).fetch_all(*pool).await,RepositoryExecutor::Connection(connection)=>sqlx::query("SELECT id,user_id,provider_name,issuer,subject,linked_email FROM external_login_identities WHERE user_id=$1 AND revoked_at IS NULL ORDER BY linked_at").bind(user_id.as_uuid()).fetch_all(&mut **connection).await}.map_err(crate::error::map_error)?;
        rows.iter().map(stored_external_identity).collect()
    }
}
fn stored_external_identity(
    row: &sqlx::postgres::PgRow,
) -> Result<StoredExternalIdentity, DatabaseError> {
    Ok(StoredExternalIdentity {
        id: TokenId::from_uuid(
            row.try_get("id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        user_id: UserId::from_uuid(
            row.try_get("user_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        provider: row
            .try_get("provider_name")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        issuer: row
            .try_get("issuer")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        subject: row
            .try_get("subject")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        linked_email: row
            .try_get("linked_email")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
    })
}

impl ServiceIdentityRepository<'_> {
    /// Atomically provisions an administratively reviewed service key and permission set.
    pub async fn bootstrap(
        &mut self,
        input: &BootstrapServiceIdentity,
    ) -> Result<(), DatabaseError> {
        validate_service_identity(input)?;
        fetch_one!(self, sqlx::query("WITH service AS (INSERT INTO service_identities(id,display_name,enabled) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET display_name=EXCLUDED.display_name,enabled=EXCLUDED.enabled RETURNING id), key AS (INSERT INTO service_identity_keys(id,service_id,kid,algorithm,public_key,not_before,expires_at) SELECT $4,$1,$5,'ES256',$6,$7,$8 FROM service ON CONFLICT(service_id,kid) DO UPDATE SET public_key=EXCLUDED.public_key,not_before=EXCLUDED.not_before,expires_at=EXCLUDED.expires_at,revoked_at=NULL RETURNING service_id), desired(method) AS (SELECT unnest($9::text[])), removed AS (DELETE FROM service_rpc_permissions p WHERE p.service_id=$1 AND NOT EXISTS(SELECT 1 FROM desired d WHERE d.method=p.method) RETURNING method), inserted AS (INSERT INTO service_rpc_permissions(service_id,method) SELECT $1,d.method FROM desired d,key ON CONFLICT DO NOTHING RETURNING method) SELECT id FROM service")
            .bind(&input.id).bind(&input.display_name).bind(input.enabled)
            .bind(TokenId::new().as_uuid()).bind(&input.kid).bind(&input.public_key)
            .bind(input.not_before).bind(input.expires_at).bind(&input.permissions))?;
        Ok(())
    }

    pub async fn find_active_key(
        &mut self,
        service_id: &str,
        kid: &str,
    ) -> Result<Option<StoredServiceIdentity>, DatabaseError> {
        let row=fetch_optional!(self,sqlx::query("SELECT s.id,k.kid,k.public_key,COALESCE(jsonb_agg(p.method) FILTER(WHERE p.method IS NOT NULL),'[]'::jsonb) permissions FROM service_identities s JOIN service_identity_keys k ON k.service_id=s.id LEFT JOIN service_rpc_permissions p ON p.service_id=s.id WHERE s.id=$1 AND k.kid=$2 AND s.enabled AND k.algorithm='ES256' AND k.revoked_at IS NULL AND k.not_before<=now() AND k.expires_at>now() GROUP BY s.id,k.kid,k.public_key").bind(service_id).bind(kid))?;
        row.map(|row| {
            Ok(StoredServiceIdentity {
                id: row
                    .try_get("id")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                kid: row
                    .try_get("kid")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                public_key: row
                    .try_get("public_key")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                permissions: serde_json::from_value(
                    row.try_get("permissions")
                        .map_err(|_| DatabaseError::InvalidStoredData)?,
                )
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            })
        })
        .transpose()
    }
    pub async fn record_assertion(
        &mut self,
        jti: TokenId,
        service_id: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DatabaseError> {
        execute!(
            self,
            sqlx::query("DELETE FROM service_assertion_replays WHERE expires_at<=now()")
        )?;
        execute!(
            self,
            sqlx::query(
                "INSERT INTO service_assertion_replays(jti,service_id,expires_at) VALUES($1,$2,$3)"
            )
            .bind(jti.as_uuid())
            .bind(service_id)
            .bind(expires_at)
        )?;
        Ok(())
    }
}

fn validate_service_identity(input: &BootstrapServiceIdentity) -> Result<(), DatabaseError> {
    const METHODS: &[&str] = &[
        "GetUser",
        "BatchGetUsers",
        "GetSessionStatus",
        "RevokeSession",
        "RevokeAllUserSessions",
        "GetServiceConfiguration",
    ];
    let identifier = |value: &str| {
        (1..=64).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    let valid = identifier(&input.id)
        && identifier(&input.kid)
        && !input.display_name.trim().is_empty()
        && input.display_name.chars().count() <= 80
        && matches!(input.public_key.len(), 33 | 65)
        && input.not_before < input.expires_at
        && !input.permissions.is_empty()
        && input.permissions.len() <= METHODS.len()
        && input
            .permissions
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == input.permissions.len()
        && input
            .permissions
            .iter()
            .all(|method| METHODS.contains(&method.as_str()));
    if valid {
        Ok(())
    } else {
        Err(DatabaseError::Conflict)
    }
}
fn stored_session(row: &sqlx::postgres::PgRow) -> Result<StoredSession, DatabaseError> {
    let methods: serde_json::Value = row
        .try_get("authentication_methods")
        .map_err(|_| DatabaseError::InvalidStoredData)?;
    Ok(StoredSession {
        id: SessionId::from_uuid(
            row.try_get("id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        user_id: UserId::from_uuid(
            row.try_get("user_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        authentication_methods: serde_json::from_value(methods)
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        authenticated_at: row
            .try_get("authenticated_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        last_seen_at: row
            .try_get("last_seen_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        revoked_at: row
            .try_get("revoked_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
    })
}

impl AuditEventRepository<'_> {
    pub async fn append(&mut self, input: &AppendAuditEvent) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("INSERT INTO security_audit_log (id,user_id,action,outcome,request_metadata) VALUES ($1,$2,$3,$4,$5)").bind(input.id.as_uuid()).bind(input.user_id.map(UserId::as_uuid)).bind(&input.action).bind(&input.outcome).bind(&input.request_metadata))?;
        Ok(())
    }
}
impl InternalEventRepository<'_> {
    pub async fn append(&mut self, input: &AppendInternalEvent) -> Result<u64, DatabaseError> {
        let version = i32::try_from(input.schema_version).map_err(|_| DatabaseError::Internal)?;
        let row = fetch_one!(self, sqlx::query("WITH locked AS (SELECT pg_advisory_xact_lock(hashtextextended($1 || ':' || $2::text, 0))), next AS (SELECT COALESCE(MAX(aggregate_sequence),0)+1 AS sequence FROM internal_events, locked WHERE aggregate_type=$1 AND aggregate_id=$2) INSERT INTO internal_events (id,aggregate_type,aggregate_id,aggregate_sequence,event_type,schema_version,payload) SELECT $3,$1,$2,sequence,$4,$5,$6 FROM next RETURNING aggregate_sequence").bind(&input.aggregate_type).bind(input.aggregate_id.as_uuid()).bind(input.id.as_uuid()).bind(&input.event_type).bind(version).bind(&input.payload))?;
        u64::try_from(
            row.try_get::<i64, _>("aggregate_sequence")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)
    }
}

impl PasskeyRepository<'_> {
    pub async fn insert(&mut self, input: &InsertPasskey) -> Result<StoredPasskey, DatabaseError> {
        let row = fetch_one!(self, sqlx::query("INSERT INTO passkey_credentials (id,credential_id,user_id,credential,backup_eligible,backup_state,friendly_name) VALUES ($1,$2,$3,$4,false,false,$5) RETURNING id,credential_id,user_id,credential,friendly_name,revoked_at").bind(input.id.as_uuid()).bind(&input.credential_id).bind(input.user_id.as_uuid()).bind(&input.credential).bind(&input.friendly_name))?;
        stored_passkey(&row)
    }

    pub async fn list_active(
        &mut self,
        user_id: UserId,
        limit: u32,
    ) -> Result<Vec<StoredPasskey>, DatabaseError> {
        let limit = i64::from(limit.min(20));
        let rows = match &mut self.executor {
            RepositoryExecutor::Pool(pool) => sqlx::query("SELECT id,credential_id,user_id,credential,friendly_name,revoked_at FROM passkey_credentials WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at LIMIT $2").bind(user_id.as_uuid()).bind(limit).fetch_all(*pool).await,
            RepositoryExecutor::Connection(connection) => sqlx::query("SELECT id,credential_id,user_id,credential,friendly_name,revoked_at FROM passkey_credentials WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at LIMIT $2").bind(user_id.as_uuid()).bind(limit).fetch_all(&mut **connection).await,
        }.map_err(crate::error::map_error)?;
        rows.iter().map(stored_passkey).collect()
    }

    pub async fn find_active_by_credential_id(
        &mut self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT id,credential_id,user_id,credential,friendly_name,revoked_at FROM passkey_credentials WHERE credential_id=$1 AND revoked_at IS NULL").bind(credential_id))?.map(|row| stored_passkey(&row)).transpose()
    }

    pub async fn find_active_by_credential_id_for_update(
        &mut self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT id,credential_id,user_id,credential,friendly_name,revoked_at FROM passkey_credentials WHERE credential_id=$1 AND revoked_at IS NULL FOR UPDATE").bind(credential_id))?.map(|row| stored_passkey(&row)).transpose()
    }

    pub async fn update_after_authentication(
        &mut self,
        credential_id: &[u8],
        credential: &serde_json::Value,
    ) -> Result<bool, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE passkey_credentials SET credential=$1,last_used_at=now() WHERE credential_id=$2 AND revoked_at IS NULL").bind(credential).bind(credential_id))?.rows_affected()==1)
    }

    pub async fn rename(
        &mut self,
        id: TokenId,
        user_id: UserId,
        name: &str,
    ) -> Result<bool, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE passkey_credentials SET friendly_name=$1 WHERE id=$2 AND user_id=$3 AND revoked_at IS NULL").bind(name).bind(id.as_uuid()).bind(user_id.as_uuid()))?.rows_affected()==1)
    }

    /// Revokes a credential only while another active passkey remains.
    /// All of the user's credential rows are locked in one statement so two
    /// concurrent removals cannot both pass the last-factor check.
    pub async fn revoke_if_not_last(
        &mut self,
        id: TokenId,
        user_id: UserId,
    ) -> Result<bool, DatabaseError> {
        Ok(execute!(self, sqlx::query("WITH locked AS MATERIALIZED (SELECT id,revoked_at FROM passkey_credentials WHERE user_id=$2 FOR UPDATE), eligible AS (SELECT 1 FROM locked WHERE id=$1 AND revoked_at IS NULL AND (SELECT count(*) FROM locked WHERE revoked_at IS NULL)>1) UPDATE passkey_credentials SET revoked_at=now() FROM eligible WHERE passkey_credentials.id=$1 AND passkey_credentials.user_id=$2 AND passkey_credentials.revoked_at IS NULL").bind(id.as_uuid()).bind(user_id.as_uuid()))?.rows_affected()==1)
    }

    pub async fn revoke(&mut self, id: TokenId, user_id: UserId) -> Result<bool, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE passkey_credentials SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL").bind(id.as_uuid()).bind(user_id.as_uuid()))?.rows_affected()==1)
    }

    pub async fn insert_ceremony(&mut self, input: &InsertCeremony) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("INSERT INTO webauthn_ceremonies (id,user_id,session_id,ceremony_kind,challenge_digest,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)").bind(input.id.as_uuid()).bind(input.user_id.map(UserId::as_uuid)).bind(input.session_id.map(SessionId::as_uuid)).bind(&input.kind).bind(&input.challenge_digest).bind(&input.state).bind(input.expires_at))?;
        Ok(())
    }

    pub async fn consume_ceremony(
        &mut self,
        id: TokenId,
        kind: &str,
    ) -> Result<ConsumedCeremony, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("UPDATE webauthn_ceremonies SET consumed_at=now() WHERE id=$1 AND ceremony_kind=$2 AND consumed_at IS NULL AND expires_at>now() RETURNING user_id,session_id,state").bind(id.as_uuid()).bind(kind))?.ok_or(DatabaseError::NotFound)?;
        Ok(ConsumedCeremony {
            user_id: row
                .try_get::<Option<uuid::Uuid>, _>("user_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?
                .map(UserId::from_uuid)
                .transpose()
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            session_id: row
                .try_get::<Option<uuid::Uuid>, _>("session_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?
                .map(SessionId::from_uuid)
                .transpose()
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            state: row
                .try_get("state")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        })
    }
}

fn stored_passkey(row: &sqlx::postgres::PgRow) -> Result<StoredPasskey, DatabaseError> {
    Ok(StoredPasskey {
        id: TokenId::from_uuid(
            row.try_get("id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        credential_id: row
            .try_get("credential_id")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        user_id: UserId::from_uuid(
            row.try_get("user_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        credential: row
            .try_get("credential")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        friendly_name: row
            .try_get("friendly_name")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        revoked_at: row
            .try_get("revoked_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
    })
}

impl SessionRepository<'_> {
    pub async fn insert_browser_secret(
        &mut self,
        session_id: SessionId,
        digest: &[u8],
    ) -> Result<(), DatabaseError> {
        execute!(
            self,
            sqlx::query(
                "INSERT INTO browser_session_secrets(session_id,secret_digest) VALUES($1,$2)"
            )
            .bind(session_id.as_uuid())
            .bind(digest)
        )?;
        Ok(())
    }

    pub async fn find_active_by_browser_secret(
        &mut self,
        digest: &[u8],
    ) -> Result<Option<StoredSession>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT s.id,s.user_id,s.authentication_methods,s.authenticated_at,s.expires_at,s.last_seen_at,s.revoked_at FROM browser_session_secrets b JOIN sessions s ON s.id=b.session_id JOIN users u ON u.id=s.user_id WHERE b.secret_digest=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'").bind(digest))?.map(|row| stored_session(&row)).transpose()
    }
}
