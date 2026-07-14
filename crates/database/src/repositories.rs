//! Domain repository handles backed by a private pool or transaction connection.

use crate::{
    AppendAuditEvent, AppendInternalEvent, ConsumedCeremony, DatabaseError, InsertCeremony,
    InsertPasskey, InsertSession, InsertUser, InsertVerifiedEmail, StoredEmail, StoredPasskey,
    StoredSession, StoredUser, UpdateUserProfile,
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
        .map_err(Into::<DatabaseError>::into)
    }};
}
macro_rules! fetch_one {
    ($self:expr, $query:expr) => {{
        match &mut $self.executor {
            RepositoryExecutor::Pool(pool) => $query.fetch_one(*pool).await,
            RepositoryExecutor::Connection(connection) => $query.fetch_one(&mut **connection).await,
        }
        .map_err(Into::<DatabaseError>::into)
    }};
}
macro_rules! execute {
    ($self:expr, $query:expr) => {{
        match &mut $self.executor {
            RepositoryExecutor::Pool(pool) => $query.execute(*pool).await,
            RepositoryExecutor::Connection(connection) => $query.execute(&mut **connection).await,
        }
        .map_err(Into::<DatabaseError>::into)
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
        let row = fetch_optional!(self, sqlx::query("SELECT e.id, e.user_id, e.normalized_email, e.verified_at, e.is_primary FROM active_verified_email_ownership o JOIN users u ON u.id = o.user_id AND u.status = 'active' JOIN user_emails e ON e.user_id = o.user_id AND e.normalized_email = o.normalized_email AND e.verified_at IS NOT NULL WHERE o.normalized_email = $1 ORDER BY e.is_primary DESC, e.created_at LIMIT 1").bind(normalized))?;
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
        Ok(execute!(self, sqlx::query("UPDATE sessions s SET last_seen_at=now() FROM users u WHERE s.id=$1 AND s.user_id=u.id AND u.status='active' AND s.revoked_at IS NULL AND s.expires_at>now()").bind(id.as_uuid()))?.rows_affected()==1)
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
    ) -> Result<Vec<StoredPasskey>, DatabaseError> {
        let rows = match &mut self.executor {
            RepositoryExecutor::Pool(pool) => sqlx::query("SELECT id,credential_id,user_id,credential,friendly_name,revoked_at FROM passkey_credentials WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at").bind(user_id.as_uuid()).fetch_all(*pool).await,
            RepositoryExecutor::Connection(connection) => sqlx::query("SELECT id,credential_id,user_id,credential,friendly_name,revoked_at FROM passkey_credentials WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at").bind(user_id.as_uuid()).fetch_all(&mut **connection).await,
        }.map_err(Into::<DatabaseError>::into)?;
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
