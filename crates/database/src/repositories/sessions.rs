//! Active browser sessions, cookie digests and passkey confirmations.

use super::{JsonArray, RepositoryExecutor, SessionRepository};
use crate::{DatabaseError, DatabaseTransaction};
use chrono::{DateTime, TimeDelta, Utc};
use piquel_common::{
    AuthenticationMethod, PasskeyId, SessionId, UserId,
    admin::Session,
    events::{DomainEvent, EventContext, RevocationReason, UserAgentFamily},
    protocol::claims::{Acr, Amr},
};
use serde::{Deserialize, Serialize};
use sqlx::{
    Decode, Postgres, Type,
    error::BoxDynError,
    postgres::{PgTypeInfo, PgValueRef},
    types::Json,
};
use std::{collections::BTreeSet, net::IpAddr};

/// How often a session's `last_seen_at` and `last_seen_ip` are refreshed at most.
pub const LAST_SEEN_INTERVAL: TimeDelta = TimeDelta::minutes(5);

/// A new browser session.
#[derive(Clone, Debug)]
pub struct InsertSession {
    /// Session identifier.
    pub id: SessionId,
    /// Authenticated account; it must be active.
    pub user_id: UserId,
    /// Methods that authenticated this session.
    pub authentication_methods: Vec<AuthenticationMethod>,
    /// When authentication happened; also the initial `last_seen_at`.
    pub authenticated_at: DateTime<Utc>,
    /// Absolute expiry; must be after `authenticated_at`.
    pub expires_at: DateTime<Utc>,
    /// Coarse browser and platform of the signing-in request; never the raw header.
    pub user_agent_family: UserAgentFamily,
    /// IP address of the signing-in request; also the initial `last_seen_ip`.
    pub ip: IpAddr,
    /// When the session last proved possession of a passkey, if it did.
    pub passkey_confirmed_at: Option<DateTime<Utc>>,
    /// The passkey that signed it in, if one did. A later confirmation replaces
    /// it with the confirming passkey (see [`SessionRepository::confirm_passkey`]).
    pub passkey_id: Option<PasskeyId>,
}

/// A browser session row.
#[derive(Clone, Debug)]
pub struct StoredSession {
    /// Session identifier.
    pub id: SessionId,
    /// Authenticated account.
    pub user_id: UserId,
    /// Methods that authenticated this session.
    pub authentication_methods: Vec<AuthenticationMethod>,
    /// When authentication happened.
    pub authenticated_at: DateTime<Utc>,
    /// Absolute expiry.
    pub expires_at: DateTime<Utc>,
    /// Last recorded activity.
    pub last_seen_at: DateTime<Utc>,
    /// When the session was revoked; `None` while it is usable.
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the session last proved possession of a passkey. Social sign-in never sets it.
    pub passkey_confirmed_at: Option<DateTime<Utc>>,
    /// Coarse browser and platform it signed in with; `None` for sessions created
    /// before they were recorded.
    pub user_agent_family: Option<UserAgentFamily>,
    /// IP address of its last recorded activity; `None` for sessions created before
    /// it was recorded.
    pub last_seen_ip: Option<IpAddr>,
}

/// Which of an account's sessions [`DatabaseTransaction::revoke_sessions`] ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionScope {
    /// This session only.
    One(SessionId),
    /// Every session but this one.
    AllExcept(SessionId),
    /// Every session.
    All,
}

impl SessionScope {
    /// The `(only, except)` session binds of the revocation query.
    fn binds(self) -> (Option<SessionId>, Option<SessionId>) {
        match self {
            Self::One(id) => (Some(id), None),
            Self::AllExcept(id) => (None, Some(id)),
            Self::All => (None, None),
        }
    }
}

impl From<StoredSession> for Session {
    /// Keeps what the admin dashboard shows.
    fn from(session: StoredSession) -> Self {
        Self {
            id: session.id,
            methods: session.authentication_methods,
            authenticated_at: session.authenticated_at,
            passkey_confirmed_at: session.passkey_confirmed_at,
            last_seen_at: session.last_seen_at,
            expires_at: session.expires_at,
        }
    }
}

/// How and when a session authenticated, as tokens report it. Token issuance,
/// authorization requirements and passkey confirmation checks all read this.
/// Authorization codes and refresh families store it as JSON when the code is
/// issued, so a grant keeps reporting its original authentication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAuthentication {
    /// Phishing-resistant once a passkey confirmed the session, social before.
    pub acr: Acr,
    /// The latest authentication at `acr`: the passkey confirmation, or else the sign-in.
    pub auth_time: DateTime<Utc>,
    /// Union of the `amr` values of every method used in the session.
    pub amr: Vec<Amr>,
}

impl From<&StoredSession> for SessionAuthentication {
    /// Derives the claims from the session's methods and authentication times.
    fn from(session: &StoredSession) -> Self {
        Self {
            acr: if session.passkey_confirmed_at.is_some() {
                Acr::PhishingResistant
            } else {
                Acr::Social
            },
            auth_time: session
                .passkey_confirmed_at
                .unwrap_or(session.authenticated_at),
            amr: session
                .authentication_methods
                .iter()
                .flat_map(|method| method.amr())
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }
}

impl Type<Postgres> for SessionAuthentication {
    /// Stored as `JSONB`.
    fn type_info() -> PgTypeInfo {
        Json::<Self>::type_info()
    }
}

impl<'r> Decode<'r, Postgres> for SessionAuthentication {
    /// Deserializes the stored snapshot.
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        Json::<Self>::decode(value).map(|Json(value)| value)
    }
}

impl SessionRepository<'_> {
    /// Creates a session for an active account.
    ///
    /// The account row stays locked through insertion, so disablement and
    /// session creation share one serialization point: a session is never
    /// committed for an account that was disabled first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the account is not active, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn insert(&mut self, input: &InsertSession) -> Result<StoredSession, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                StoredSession,
                r#"WITH active_user AS (
                    SELECT id
                    FROM users
                    WHERE id = $2
                    AND status = 'active'
                    FOR NO KEY UPDATE
                )
                INSERT INTO sessions (
                    id, user_id, authentication_methods, authenticated_at, expires_at,
                    last_seen_at, user_agent_family, passkey_confirmed_at, created_ip,
                    last_seen_ip, passkey_id
                )
                SELECT $1, id, $3, $4, $5, $4, $6, $7, $8, $8, $9
                FROM active_user
                RETURNING
                    id AS "id: SessionId", user_id AS "user_id: UserId",
                    authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    authenticated_at, expires_at, last_seen_at, revoked_at, passkey_confirmed_at,
                    user_agent_family AS "user_agent_family: UserAgentFamily",
                    last_seen_ip AS "last_seen_ip: IpAddr""#,
                input.id.as_uuid(),
                input.user_id.as_uuid(),
                Json(&input.authentication_methods) as _,
                input.authenticated_at,
                input.expires_at,
                input.user_agent_family.to_string(),
                input.passkey_confirmed_at,
                input.ip as _,
                input.passkey_id.map(PasskeyId::as_uuid),
            )
        )
    }

    /// Finds a session in any state.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_by_id(
        &mut self,
        id: SessionId,
    ) -> Result<Option<StoredSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredSession,
                r#"SELECT
                    id AS "id: SessionId", user_id AS "user_id: UserId",
                    authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    authenticated_at, expires_at, last_seen_at, revoked_at, passkey_confirmed_at,
                    user_agent_family AS "user_agent_family: UserAgentFamily",
                    last_seen_ip AS "last_seen_ip: IpAddr"
                FROM sessions
                WHERE id = $1"#,
                id.as_uuid(),
            )
        )
    }

    /// Finds an unrevoked, unexpired session of an active account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_id(
        &mut self,
        id: SessionId,
    ) -> Result<Option<StoredSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredSession,
                r#"SELECT
                    s.id AS "id: SessionId", s.user_id AS "user_id: UserId",
                    s.authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    s.authenticated_at, s.expires_at, s.last_seen_at, s.revoked_at,
                    s.passkey_confirmed_at,
                    s.user_agent_family AS "user_agent_family: UserAgentFamily",
                    s.last_seen_ip AS "last_seen_ip: IpAddr"
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.id = $1
                AND s.revoked_at IS NULL
                AND s.expires_at > now()
                AND u.status = 'active'"#,
                id.as_uuid(),
            )
        )
    }

    /// Finds and locks an unrevoked, unexpired session of an active account, so a
    /// concurrent logout either commits first or waits until this transaction ends.
    /// Callers lock the account first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_id_for_update(
        &mut self,
        id: SessionId,
    ) -> Result<Option<StoredSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredSession,
                r#"SELECT
                    s.id AS "id: SessionId", s.user_id AS "user_id: UserId",
                    s.authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    s.authenticated_at, s.expires_at, s.last_seen_at, s.revoked_at,
                    s.passkey_confirmed_at,
                    s.user_agent_family AS "user_agent_family: UserAgentFamily",
                    s.last_seen_ip AS "last_seen_ip: IpAddr"
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.id = $1
                AND s.revoked_at IS NULL
                AND s.expires_at > now()
                AND u.status = 'active'
                FOR NO KEY UPDATE OF s"#,
                id.as_uuid(),
            )
        )
    }

    /// Revokes the active `scope` sessions of `user_id`, with the refresh token
    /// families issued from them, and returns the IDs of the sessions it revoked.
    /// Sessions of other accounts are never touched, whatever the scope names, and
    /// expired ones are already over: no refresh family of theirs rotates. Only
    /// [`DatabaseTransaction::revoke_sessions`] calls it outside tests, so every
    /// revocation is recorded.
    ///
    /// The families are revoked by a second statement: a code exchange that held a
    /// session's lock may have committed a family while the first one waited, and
    /// only a new statement's snapshot sees it. They are locked in ID order, like
    /// every statement that locks several families.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub(crate) async fn revoke(
        &mut self,
        user_id: UserId,
        scope: SessionScope,
    ) -> Result<Vec<SessionId>, DatabaseError> {
        let (only, except) = scope.binds();
        let revoked = run!(
            self,
            fetch_all,
            sqlx::query_scalar!(
                r#"UPDATE sessions
                SET revoked_at = now(), passkey_confirmed_at = NULL
                WHERE user_id = $1
                AND revoked_at IS NULL
                AND expires_at > now()
                AND ($2::uuid IS NULL OR id = $2)
                AND ($3::uuid IS NULL OR id <> $3)
                RETURNING id AS "id: SessionId""#,
                user_id.as_uuid(),
                only.map(SessionId::as_uuid),
                except.map(SessionId::as_uuid),
            )
        )?;
        let ids: Vec<_> = revoked.iter().copied().map(SessionId::as_uuid).collect();
        run!(
            self,
            execute,
            sqlx::query!(
                "WITH locked AS (
                    SELECT id FROM refresh_token_families
                    WHERE session_id = ANY($1)
                    ORDER BY id
                    FOR UPDATE
                )
                UPDATE refresh_token_families f
                SET revoked_at = COALESCE(f.revoked_at, now())
                FROM locked
                WHERE f.id = locked.id",
                &ids,
            )
        )?;
        Ok(revoked)
    }

    /// Lists the account's unrevoked, unexpired sessions, most recently active first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_active_for_user(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<StoredSession>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredSession,
                r#"SELECT
                    id AS "id: SessionId", user_id AS "user_id: UserId",
                    authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    authenticated_at, expires_at, last_seen_at, revoked_at, passkey_confirmed_at,
                    user_agent_family AS "user_agent_family: UserAgentFamily",
                    last_seen_ip AS "last_seen_ip: IpAddr"
                FROM sessions
                WHERE user_id = $1
                AND revoked_at IS NULL
                AND expires_at > now()
                ORDER BY last_seen_at DESC, id DESC"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Records activity of the session from `ip`, at most once every
    /// [`LAST_SEEN_INTERVAL`], so session reads rarely become writes.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn touch(&mut self, id: SessionId, ip: IpAddr) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE sessions SET last_seen_at = now(), last_seen_ip = $2
                WHERE id = $1 AND last_seen_at < $3",
                id.as_uuid(),
                ip as _,
                Utc::now() - LAST_SEEN_INTERVAL,
            )
        )?;
        Ok(())
    }

    /// Stores the digest of a session's browser cookie secret.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the session already has a secret
    /// or the digest is reused, or another [`DatabaseError`] if the query fails.
    pub async fn insert_browser_secret(
        &mut self,
        session_id: SessionId,
        digest: &[u8],
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO browser_session_secrets(session_id,secret_digest) VALUES($1,$2)",
                session_id.as_uuid(),
                digest,
            )
        )?;
        Ok(())
    }

    /// Finds the active session whose browser secret has this digest.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_browser_secret(
        &mut self,
        digest: &[u8],
    ) -> Result<Option<StoredSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredSession,
                r#"SELECT
                    s.id AS "id: SessionId", s.user_id AS "user_id: UserId",
                    s.authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    s.authenticated_at, s.expires_at, s.last_seen_at, s.revoked_at,
                    s.passkey_confirmed_at,
                    s.user_agent_family AS "user_agent_family: UserAgentFamily",
                    s.last_seen_ip AS "last_seen_ip: IpAddr"
                FROM browser_session_secrets b
                JOIN sessions s ON s.id = b.session_id
                JOIN users u ON u.id = s.user_id
                WHERE b.secret_digest = $1
                AND s.revoked_at IS NULL
                AND s.expires_at > now()
                AND u.status = 'active'"#,
                digest,
            )
        )
    }

    /// Records that the session proved possession of passkey `passkey_id` `at` this
    /// time, adding passkeys to its methods. Protected actions accept the
    /// confirmation for a fixed time after it, so using it never extends it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the session is revoked or expired, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn confirm_passkey(
        &mut self,
        id: SessionId,
        passkey_id: PasskeyId,
        at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        let passkey = Json([AuthenticationMethod::Passkey]);
        let updated = run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE sessions
                SET passkey_confirmed_at = $2,
                    passkey_id = $4,
                    authentication_methods = CASE
                        WHEN authentication_methods @> $3 THEN authentication_methods
                        ELSE authentication_methods || $3
                    END
                WHERE id = $1
                AND revoked_at IS NULL
                AND expires_at > now()",
                id.as_uuid(),
                at,
                passkey as _,
                passkey_id.as_uuid(),
            )
        )?
        .rows_affected();
        if updated == 0 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }

    /// The passkey that last proved possession for session `id`: the one that
    /// signed it in or confirmed it since, if any did.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn passkey(&mut self, id: SessionId) -> Result<Option<PasskeyId>, DatabaseError> {
        Ok(run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                r#"SELECT passkey_id AS "passkey_id: PasskeyId" FROM sessions WHERE id = $1"#,
                id.as_uuid(),
            )
        )?
        .flatten())
    }

    /// Records a re-authentication of a session `at` this time that does not
    /// confirm it: a social sign-in, or `passkey`, a recovery's passkey during its
    /// probation, which the session then records as its passkey. Only a session
    /// without a passkey confirmation qualifies: either would lower its `acr`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the session is revoked, expired or
    /// confirmed by a passkey, or another [`DatabaseError`] if the query fails.
    pub async fn reauthenticate_unconfirmed(
        &mut self,
        id: SessionId,
        passkey: Option<PasskeyId>,
        at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        let method = Json([AuthenticationMethod::Passkey]);
        let updated = run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE sessions
                SET authenticated_at = $2,
                    passkey_id = COALESCE($3, passkey_id),
                    authentication_methods = CASE
                        WHEN $3::uuid IS NULL OR authentication_methods @> $4
                            THEN authentication_methods
                        ELSE authentication_methods || $4
                    END
                WHERE id = $1
                AND passkey_confirmed_at IS NULL
                AND revoked_at IS NULL
                AND expires_at > $2",
                id.as_uuid(),
                at,
                passkey.map(PasskeyId::as_uuid),
                method as _,
            )
        )?
        .rows_affected();
        if updated == 0 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }

    /// Replaces the digest of a session's browser cookie secret, so the cookie from
    /// before a re-authentication stops working.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the session has no secret,
    /// [`DatabaseError::Conflict`] if the digest is reused, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn replace_browser_secret(
        &mut self,
        session_id: SessionId,
        digest: &[u8],
    ) -> Result<(), DatabaseError> {
        let updated = run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE browser_session_secrets SET secret_digest = $2 WHERE session_id = $1",
                session_id.as_uuid(),
                digest,
            )
        )?
        .rows_affected();
        if updated == 0 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }
}

impl DatabaseTransaction<'_> {
    /// Ends the `scope` sessions of `user_id` early, with the refresh token families
    /// issued from them, and records one [`DomainEvent::SessionRevoked`] each, caused
    /// as `context` says. Recording the event queues the logout tokens of the
    /// session's clients, so this is the only way sessions end early: none can end
    /// without its clients being told. Returns the revoked sessions.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a query fails or an event cannot be recorded.
    pub async fn revoke_sessions(
        &mut self,
        context: &EventContext,
        user_id: UserId,
        scope: SessionScope,
        reason: &RevocationReason,
    ) -> Result<Vec<SessionId>, DatabaseError> {
        let revoked = self.sessions().revoke(user_id, scope).await?;
        for &session_id in &revoked {
            let event = DomainEvent::SessionRevoked {
                session_id,
                reason: reason.clone(),
            };
            self.record(context, Some(user_id), event).await?;
        }
        Ok(revoked)
    }
}
