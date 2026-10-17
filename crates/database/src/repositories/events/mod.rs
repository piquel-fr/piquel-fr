//! Typed domain events: what changed, who changed it, and the personal data kept apart.
//!
//! An event row holds only non-identifying content, so it can be kept and later
//! hashed (#31). Personal data, the client IP, user agent family and every
//! [`Personal`] payload value, lives in a separate row that retention and account
//! purges delete; reads then return [`Personal::Erased`] in its place.

use super::{EventRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{
    AuthenticationMethod, ClientId, EventId, PasskeyId, Provider, SessionId, TokenId, UserId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::types::Json;
use std::net::IpAddr;

/// Payload version recorded with every event. A kind whose payload changes shape
/// gets a new version, and reads keep accepting the old one.
const EVENT_VERSION: i16 = 1;
/// Key under which a [`Personal`] value serializes; matches its serde rename.
const PERSONAL_KEY: &str = "$personal";
/// What a [`Personal`] value leaves in the stored payload; matches the serde
/// rename of [`Personal::Erased`].
const ERASED: &str = "$erased";

/// Something that happened to an account or its grants, recorded in the
/// transaction that made the change. Adding a variant makes every `match` handle it.
///
/// Outside [`Personal`], a variant holds only typed auth IDs, enums, scopes,
/// timestamps and counts, so a secret, token or raw header cannot end up in one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum DomainEvent {
    /// An account was created. Its first session follows as [`Self::SignedIn`].
    AccountCreated {
        /// How the person proved who they are: a passkey, or a provider for social signup.
        method: AuthenticationMethod,
        /// Whether an invitation was redeemed.
        invited: bool,
    },
    /// A browser signed in: it got a new session, or re-authenticated its current one.
    SignedIn {
        /// The new or re-authenticated session.
        session_id: SessionId,
        /// How the browser authenticated.
        method: AuthenticationMethod,
    },
    /// A passkey or provider authentication was rejected, whether signing in or
    /// confirming a session. Only the rejected attempt is recorded; nothing changed.
    SignInFailed {
        /// The method that was attempted.
        method: AuthenticationMethod,
        /// Why it was rejected.
        reason: SignInFailure,
    },
    /// A session ended early. Revoking several sessions records one event each.
    SessionRevoked {
        /// The revoked session.
        session_id: SessionId,
        /// Why it was revoked; the actor says who revoked it.
        reason: RevocationReason,
    },
    /// A session proved possession of a passkey for protected actions.
    PasskeyConfirmed {
        /// The confirmed session.
        session_id: SessionId,
    },
    /// A passkey was added to the account.
    PasskeyAdded {
        /// The new passkey.
        passkey_id: PasskeyId,
    },
    /// A passkey's label changed.
    PasskeyRenamed {
        /// The renamed passkey.
        passkey_id: PasskeyId,
    },
    /// A passkey was removed from the account.
    PasskeyRemoved {
        /// The removed passkey.
        passkey_id: PasskeyId,
    },
    /// A provider identity was linked to the account.
    IdentityLinked {
        /// The identity's provider.
        provider: Provider,
        /// The provider's subject identifier, which identifies the person there.
        subject: Personal<String>,
    },
    /// A provider identity was unlinked from the account.
    IdentityUnlinked {
        /// The identity's provider.
        provider: Provider,
    },
    /// The user approved a client's access, adding to any earlier consent.
    ConsentGranted {
        /// The approved client.
        client_id: ClientId,
        /// The approved scopes, drawn from the client's registered allowlist.
        scopes: Vec<String>,
    },
    /// A client exchanged an authorization code for tokens.
    GrantIssued {
        /// The client the tokens were issued to.
        client_id: ClientId,
        /// The refresh family created, when the grant includes refresh tokens.
        family_id: Option<TokenId>,
        /// The granted scopes.
        scopes: Vec<String>,
    },
    /// A refresh family was revoked. Rotations are not events; they are counted as metrics.
    GrantRevoked {
        /// The client the family was issued to.
        client_id: ClientId,
        /// The revoked family.
        family_id: TokenId,
        /// Why it was revoked.
        reason: GrantRevocation,
    },
    /// A client redeemed an authorization code a second time. Every refresh family
    /// issued from the code is revoked, each with its own [`Self::GrantRevoked`].
    CodeReplayed {
        /// The client that redeemed the code.
        client_id: ClientId,
    },
    /// A signup invitation was created.
    InvitationCreated {
        /// When the invitation stops being accepted.
        expires_at: DateTime<Utc>,
    },
    /// A row of the security audit log that preceded typed events. Only
    /// migrations write these, so this crate alone can construct one.
    Imported(ImportedAudit),
}

impl DomainEvent {
    /// The client the event concerns, stored in its own column for filtering.
    fn client_id(&self) -> Option<&ClientId> {
        match self {
            Self::ConsentGranted { client_id, .. }
            | Self::GrantIssued { client_id, .. }
            | Self::GrantRevoked { client_id, .. }
            | Self::CodeReplayed { client_id }
            | Self::SessionRevoked {
                reason: RevocationReason::RelyingPartyLogout { client_id },
                ..
            } => Some(client_id),
            Self::AccountCreated { .. }
            | Self::SignedIn { .. }
            | Self::SignInFailed { .. }
            | Self::SessionRevoked { .. }
            | Self::PasskeyConfirmed { .. }
            | Self::PasskeyAdded { .. }
            | Self::PasskeyRenamed { .. }
            | Self::PasskeyRemoved { .. }
            | Self::IdentityLinked { .. }
            | Self::IdentityUnlinked { .. }
            | Self::InvitationCreated { .. }
            | Self::Imported(_) => None,
        }
    }

    /// The session the event concerns, stored in its own column for filtering.
    const fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::SignedIn { session_id, .. }
            | Self::SessionRevoked { session_id, .. }
            | Self::PasskeyConfirmed { session_id } => Some(*session_id),
            Self::AccountCreated { .. }
            | Self::SignInFailed { .. }
            | Self::PasskeyAdded { .. }
            | Self::PasskeyRenamed { .. }
            | Self::PasskeyRemoved { .. }
            | Self::IdentityLinked { .. }
            | Self::IdentityUnlinked { .. }
            | Self::ConsentGranted { .. }
            | Self::GrantIssued { .. }
            | Self::GrantRevoked { .. }
            | Self::CodeReplayed { .. }
            | Self::InvitationCreated { .. }
            | Self::Imported(_) => None,
        }
    }
}

/// Why an authentication was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignInFailure {
    /// The assertion or provider evidence did not verify against the account.
    InvalidCredential,
    /// A passkey's signature counter did not increase, so it may have been copied.
    CounterRegression,
    /// No active account holds the credential or username.
    UnknownAccount,
    /// The account is disabled, or cannot sign in this way any more.
    AccountUnavailable,
}

/// Why a session was revoked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RevocationReason {
    /// The user signed out.
    Logout,
    /// The browser signed in to another account, which ends its previous session.
    AccountSwitched,
    /// The user signed out at a client's request (RP-initiated logout).
    RelyingPartyLogout {
        /// The client that asked, as named by a verified `id_token_hint` or a
        /// registered `post_logout_redirect_uri`.
        client_id: ClientId,
    },
    /// A passkey was removed, which ends the account's other sessions.
    CredentialRemoved,
    /// A provider identity was unlinked, which ends the account's other sessions.
    IdentityUnlinked,
    /// An administrator revoked it.
    Admin,
    /// The account was disabled.
    AccountDisabled,
    /// The account is being deleted.
    AccountDeletion,
    /// It expired.
    Expired,
}

/// Why a refresh family was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRevocation {
    /// The client revoked it (RFC 7009).
    ClientRevoked,
    /// One of its refresh tokens was used twice.
    RefreshReplay,
    /// The client's policy no longer allows it.
    PolicyRejected,
    /// The authorization code it came from was redeemed twice.
    CodeReplay,
}

/// Who caused an event. Every feature attributes events with this one type.
///
/// Operator attribution (`os_user`, `host`, an administrator's user ID) is
/// accountability data, so it stays in the event rather than in personal data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Actor {
    /// A signed-in user, or one signing in.
    User {
        /// The acting account.
        user_id: UserId,
        /// The session acting, once there is one.
        session_id: Option<SessionId>,
    },
    /// An administrator, through the admin API.
    Admin {
        /// The administrator's account.
        user_id: UserId,
        /// The administrator's session.
        session_id: SessionId,
    },
    /// An operator, through the service's command line.
    Cli {
        /// The operating system user, from `$USER`.
        os_user: String,
        /// The machine's host name.
        host: String,
    },
    /// A client calling a back-channel endpoint.
    Client {
        /// The authenticated client.
        client_id: ClientId,
    },
    /// A background job.
    System {
        /// The job.
        job: JobName,
    },
    /// An unauthenticated browser, e.g. one failing to sign in.
    Anonymous,
    /// Unknown: imported audit rows never recorded who acted.
    Unrecorded,
}

impl Actor {
    /// The client acting, if any.
    const fn client_id(&self) -> Option<&ClientId> {
        match self {
            Self::Client { client_id } => Some(client_id),
            Self::User { .. }
            | Self::Admin { .. }
            | Self::Cli { .. }
            | Self::System { .. }
            | Self::Anonymous
            | Self::Unrecorded => None,
        }
    }

    /// The session acting, if any.
    const fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::User { session_id, .. } => *session_id,
            Self::Admin { session_id, .. } => Some(*session_id),
            Self::Cli { .. }
            | Self::Client { .. }
            | Self::System { .. }
            | Self::Anonymous
            | Self::Unrecorded => None,
        }
    }
}

/// Background jobs that act on their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobName {
    /// The periodic expired-state cleanup.
    Cleanup,
}

/// A value that identifies a person outside auth. It is stored apart from its
/// event and reads back as [`Self::Erased`] once retention or a purge deleted it.
///
/// It serializes as `{"$personal": value}`, which the repository moves out of the
/// payload, leaving `"$erased"` in its place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Personal<T> {
    /// The value, while it is kept.
    #[serde(rename = "$personal")]
    Value(T),
    /// The value was deleted or never recorded.
    #[serde(rename = "$erased")]
    Erased,
}

/// A security audit log row, kept verbatim by the migrations to typed events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedAudit {
    /// The logged action, e.g. `passkey.login`.
    action: String,
    /// `success`, `failure` or `rejected`.
    outcome: String,
    /// The logged metadata, e.g. `{"provider": "github"}`.
    metadata: Value,
}

impl ImportedAudit {
    /// The logged action, e.g. `passkey.login`.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// `success`, `failure` or `rejected`.
    #[must_use]
    pub fn outcome(&self) -> &str {
        &self.outcome
    }

    /// The logged metadata, e.g. `{"provider": "github"}`.
    #[must_use]
    pub const fn metadata(&self) -> &Value {
        &self.metadata
    }
}

piquel_common::str_enum! {
    /// Coarse browser family derived from a `User-Agent` header, which is never stored.
    pub enum UserAgentFamily {
        /// Google Chrome and other Chromium browsers that announce no other name.
        Chrome = "chrome",
        /// Microsoft Edge.
        Edge = "edge",
        /// Mozilla Firefox.
        Firefox = "firefox",
        /// Opera.
        Opera = "opera",
        /// Apple Safari.
        Safari = "safari",
        /// Anything else, including back-channel HTTP clients.
        Other = "other",
    }
}

impl UserAgentFamily {
    /// Classifies a `User-Agent` header. Markers are checked in order, because Edge
    /// and Opera also announce Chrome, and Chrome announces Safari.
    #[must_use]
    pub fn classify(user_agent: &str) -> Self {
        [
            ("Edg/", Self::Edge),
            ("EdgA/", Self::Edge),
            ("EdgiOS/", Self::Edge),
            ("OPR/", Self::Opera),
            ("Firefox/", Self::Firefox),
            ("FxiOS/", Self::Firefox),
            ("Chrome/", Self::Chrome),
            ("CriOS/", Self::Chrome),
            ("Safari/", Self::Safari),
        ]
        .into_iter()
        .find(|(marker, _)| user_agent.contains(marker))
        .map_or(Self::Other, |(_, family)| family)
    }
}

/// Where a request came from. Both fields are personal data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestOrigin {
    /// The client's IP address, when the event came from a request.
    pub client_ip: Option<IpAddr>,
    /// The client's browser family, when the event came from a request.
    pub user_agent_family: Option<UserAgentFamily>,
}

/// Who caused an event and where their request came from, passed to
/// [`DatabaseTransaction::record`](crate::DatabaseTransaction::record).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventContext {
    /// Who caused the event.
    pub actor: Actor,
    /// Where the request came from; empty outside requests.
    pub origin: RequestOrigin,
}

/// A consumer's position in the event stream: everything up to and including the
/// event it was read from. See [`EventRepository::read_after`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventCursor {
    /// The writing transaction's ID.
    txid: i64,
    /// The event's position in insertion order.
    sequence: i64,
}

/// A recorded event with its personal data merged back in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    /// Event identifier.
    pub id: EventId,
    /// Position to pass to [`EventRepository::acknowledge`] once handled.
    pub cursor: EventCursor,
    /// When it was recorded.
    pub occurred_at: DateTime<Utc>,
    /// Who caused it.
    pub actor: Actor,
    /// The account it concerns, if any. The account may no longer exist.
    pub subject: Option<UserId>,
    /// What happened.
    pub event: DomainEvent,
    /// Where the request came from, until its personal data is deleted.
    pub origin: Personal<RequestOrigin>,
}

/// An event joined with its personal data, as the read queries return it.
struct EventRow {
    /// Event identifier.
    id: EventId,
    /// The writing transaction's ID.
    txid: i64,
    /// Insertion order.
    sequence: i64,
    /// When it was recorded.
    occurred_at: DateTime<Utc>,
    /// The serde tag of the [`DomainEvent`] variant.
    kind: String,
    /// The variant's data, with `"$erased"` where personal values were.
    payload: Value,
    /// Who caused it.
    actor: Json<Actor>,
    /// The account it concerns.
    subject_user_id: Option<UserId>,
    /// Whether the personal data row still exists.
    personal: bool,
    /// The client's IP address.
    client_ip: Option<IpAddr>,
    /// The client's browser family.
    user_agent_family: Option<UserAgentFamily>,
    /// Personal payload values by JSON pointer.
    details: Option<Value>,
}

impl TryFrom<EventRow> for StoredEvent {
    type Error = DatabaseError;

    /// Restores the event's personal values, if they are still stored, and decodes it.
    fn try_from(row: EventRow) -> Result<Self, DatabaseError> {
        let invalid = |column: &str, source: serde_json::Error| DatabaseError::InvalidStoredData {
            column: column.into(),
            source: source.into(),
        };
        let mut payload = row.payload;
        let origin = if row.personal {
            serde_json::from_value::<PersonalDetails>(row.details.unwrap_or_default())
                .map_err(|source| invalid("details", source))?
                .restore(&mut payload);
            Personal::Value(RequestOrigin {
                client_ip: row.client_ip,
                user_agent_family: row.user_agent_family,
            })
        } else {
            Personal::Erased
        };
        let event = serde_json::from_value(Value::Object(Map::from_iter([
            ("kind".to_owned(), Value::String(row.kind)),
            ("data".to_owned(), payload),
        ])))
        .map_err(|source| invalid("payload", source))?;
        Ok(Self {
            id: row.id,
            cursor: EventCursor {
                txid: row.txid,
                sequence: row.sequence,
            },
            occurred_at: row.occurred_at,
            actor: row.actor.0,
            subject: row.subject_user_id,
            event,
            origin,
        })
    }
}

/// A serialized [`DomainEvent`], split into its kind and data.
#[derive(Deserialize)]
struct TaggedEvent {
    /// The variant's serde tag.
    kind: String,
    /// The variant's data.
    data: Value,
}

/// The [`Personal`] values of one payload, keyed by their JSON pointer, as stored
/// in `event_personal_data.details`.
#[derive(Default, Serialize, Deserialize)]
struct PersonalDetails(Map<String, Value>);

impl PersonalDetails {
    /// Moves every `{"$personal": value}` out of `payload`, leaving `"$erased"`.
    fn extract(payload: &mut Value) -> Self {
        let mut details = Self::default();
        details.walk(payload, String::new());
        details
    }

    /// Extracts the personal values under `value`, found at `pointer`.
    fn walk(&mut self, value: &mut Value, pointer: String) {
        match value {
            Value::Object(object) if object.len() == 1 && object.contains_key(PERSONAL_KEY) => {
                let personal = object.remove(PERSONAL_KEY).unwrap_or_default();
                self.0.insert(pointer, personal);
                *value = Value::String(ERASED.to_owned());
            }
            Value::Object(object) => {
                for (key, child) in object {
                    // RFC 6901 escaping.
                    let key = key.replace('~', "~0").replace('/', "~1");
                    self.walk(child, format!("{pointer}/{key}"));
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter_mut().enumerate() {
                    self.walk(child, format!("{pointer}/{index}"));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    /// Puts each stored value back where [`Self::extract`] found it.
    fn restore(self, payload: &mut Value) {
        for (pointer, personal) in self.0 {
            if let Some(slot) = payload.pointer_mut(&pointer) {
                *slot = Value::Object(Map::from_iter([(PERSONAL_KEY.to_owned(), personal)]));
            }
        }
    }
}

impl EventRepository<'_> {
    /// Writes an event and its personal data. Only
    /// [`DatabaseTransaction::record`](crate::DatabaseTransaction::record) calls it,
    /// so both rows always commit or roll back with the change they describe.
    pub(crate) async fn insert(
        &mut self,
        context: &EventContext,
        subject: Option<UserId>,
        event: &DomainEvent,
    ) -> Result<(), DatabaseError> {
        let serialization = |error| DatabaseError::Operation(Box::new(error));
        let TaggedEvent { kind, mut data } =
            serde_json::from_value(serde_json::to_value(event).map_err(serialization)?)
                .map_err(serialization)?;
        let details = PersonalDetails::extract(&mut data);
        let id = EventId::new();
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO domain_events (
                    id, kind, version, payload, actor, subject_user_id, client_id, session_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                id.as_uuid(),
                kind,
                EVENT_VERSION,
                data,
                Json(&context.actor) as _,
                subject.map(UserId::as_uuid),
                event
                    .client_id()
                    .or(context.actor.client_id())
                    .map(ClientId::as_str),
                event
                    .session_id()
                    .or(context.actor.session_id())
                    .map(SessionId::as_uuid),
            )
        )?;
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO event_personal_data (event_id, client_ip, user_agent_family, details)
                VALUES ($1, $2, $3, $4)",
                id.as_uuid(),
                context.origin.client_ip as _,
                context
                    .origin
                    .user_agent_family
                    .map(UserAgentFamily::as_str),
                Json(&details) as _,
            )
        )?;
        Ok(())
    }

    /// Lists the events concerning an account, newest first, for its security history.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a stored event does not decode.
    pub async fn history_for_user(
        &mut self,
        user_id: UserId,
        limit: u32,
    ) -> Result<Vec<StoredEvent>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                EventRow,
                r#"SELECT
                    e.id AS "id: EventId", e.txid::text::bigint AS "txid!", e.sequence,
                    e.occurred_at, e.kind, e.payload, e.actor AS "actor: Json<Actor>",
                    e.subject_user_id AS "subject_user_id: UserId",
                    p.event_id IS NOT NULL AS "personal!", p.client_ip AS "client_ip?: IpAddr",
                    p.user_agent_family AS "user_agent_family?: UserAgentFamily",
                    p.details AS "details?"
                FROM domain_events e
                LEFT JOIN event_personal_data p ON p.event_id = e.id
                WHERE e.subject_user_id = $1
                ORDER BY e.sequence DESC
                LIMIT $2"#,
                user_id.as_uuid(),
                i64::from(limit),
            )
        )?
        .into_iter()
        .map(StoredEvent::try_from)
        .collect()
    }

    /// Returns up to `limit` events after `consumer`'s acknowledged cursor, in a
    /// safe order, for consumers such as the sealer (#31) or alerts (#83).
    ///
    /// Sequence order alone is not safe: a transaction can take sequence 10 and
    /// commit after another took 11, so a reader that saw 11 would skip 10. Events
    /// are read in `(txid, sequence)` order instead, and only from transactions
    /// older than every transaction still running. Those have all finished, so no
    /// event can later appear before the cursor. The cost is that a long-running
    /// transaction holds back every consumer until it ends.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a stored event does not decode.
    pub async fn read_after(
        &mut self,
        consumer: &'static str,
        limit: u32,
    ) -> Result<Vec<StoredEvent>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                EventRow,
                r#"SELECT
                    e.id AS "id: EventId", e.txid::text::bigint AS "txid!", e.sequence,
                    e.occurred_at, e.kind, e.payload, e.actor AS "actor: Json<Actor>",
                    e.subject_user_id AS "subject_user_id: UserId",
                    p.event_id IS NOT NULL AS "personal!", p.client_ip AS "client_ip?: IpAddr",
                    p.user_agent_family AS "user_agent_family?: UserAgentFamily",
                    p.details AS "details?"
                FROM domain_events e
                LEFT JOIN event_personal_data p ON p.event_id = e.id
                LEFT JOIN event_consumers c ON c.name = $1
                WHERE (e.txid, e.sequence) > (COALESCE(c.txid, '0'::xid8), COALESCE(c.sequence, 0))
                AND e.txid < pg_snapshot_xmin(pg_current_snapshot())
                ORDER BY e.txid, e.sequence
                LIMIT $2"#,
                consumer,
                i64::from(limit),
            )
        )?
        .into_iter()
        .map(StoredEvent::try_from)
        .collect()
    }

    /// Moves `consumer`'s cursor to `cursor`, so [`Self::read_after`] continues after
    /// it. Run it in the transaction that applies the consumer's effects. A cursor
    /// never moves backwards.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn acknowledge(
        &mut self,
        consumer: &'static str,
        cursor: EventCursor,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO event_consumers (name, txid, sequence)
                VALUES ($1, $2::bigint::text::xid8, $3)
                ON CONFLICT (name) DO UPDATE
                SET txid = EXCLUDED.txid, sequence = EXCLUDED.sequence
                WHERE (event_consumers.txid, event_consumers.sequence)
                    < (EXCLUDED.txid, EXCLUDED.sequence)",
                consumer,
                cursor.txid,
                cursor.sequence,
            )
        )?;
        Ok(())
    }
}

/// Database tests for recording, personal data, the consumer cursor and the migration.
#[cfg(test)]
mod tests;
