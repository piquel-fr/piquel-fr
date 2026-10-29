//! Every administrative operation, shared by the admin dashboard and the CLI.

use super::{AdminError, HandleProblem, InviteExpiry, Operator, Reason, UserRef};
use crate::{
    Applied, ClientDetails, ClientRegistry, ClientRegistryError, GracePeriod,
    account::AccountService,
    emails::EmailApplication,
    handles::{Handles, HandlesError},
    recovery::{LINK_LIFETIME, PROBATION, RecoveryLinks, Revoke},
    routes,
};
use chrono::Utc;
use piquel_common::{
    AccountStatus, ClientId, DeliveryId, Handle, Personal, RecoveryId, SessionId, TokenId, UserId,
    admin::{
        Administrator, Client, CreatedInvitation, Email, Event, EventPage, EventSearch, Invitation,
        UserDetail, UserPage,
    },
    clients::{ClientField, ClientOwner, ClientRegistration},
    config::Origin,
    email::NormalizedEmail,
    events::{DomainEvent, EventContext, RecoveryRevocation, RevocationReason},
};
use piquel_crypto::{ClientSecret, Secret};
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, DeliveryStatus, DeliverySummary, EventFilter,
    InsertRecovery, RecentRecovery, SessionScope, StoredOidcClient,
};
use piquel_ui::{LoginQuery, Query};
use url::Url;

/// Accounts per search page.
const USER_PAGE_SIZE: u16 = 50;
/// Events per page.
const EVENT_PAGE_SIZE: u16 = 100;

/// Owns each administrative operation. Dashboard pages and CLI commands are thin
/// adapters that say which [`Operator`] acts. Every mutation, and viewing an
/// account's details, records a domain event attributed to it in the same
/// transaction.
///
/// Every operation takes its [`Operator`] and checks it, so a caller in the same
/// process, such as the dashboard, needs no check of its own. Reads first require
/// an administrator to still hold their rights and session, signed in with a
/// passkey (`Operator::authorize_read`). Mutations recheck that an administrator
/// still holds their rights, session and recent confirmation after their last
/// write, just before committing. Those on accounts refuse
/// administrator accounts unless the CLI acts, so a stolen dashboard session
/// cannot lock other administrators out; revoking their rights comes first, and is itself
/// guarded.
#[derive(Clone)]
pub struct AdminService {
    /// Accounts, sessions, invitations, clients, events, deliveries and administrators.
    database: Database,
    /// Whether email is enabled, so a recovery link can be mailed.
    mails: bool,
}

impl AdminService {
    /// Operates on `database`, mailing recovery links if `mails`, as email is
    /// enabled.
    #[must_use]
    pub const fn new(database: Database, mails: bool) -> Self {
        Self { database, mails }
    }

    /// Ends every mutation: rechecks `operator`, records `events` about `subject`,
    /// then commits. The check runs after the mutation's last write, so it waits
    /// for nothing afterwards, and a failure rolls the writes back.
    async fn finish(
        mut tx: DatabaseTransaction<'_>,
        operator: &Operator,
        subject: Option<UserId>,
        events: Vec<DomainEvent>,
    ) -> Result<(), AdminError> {
        operator.authorize(&mut tx).await?;
        let context = operator.context();
        for event in events {
            tx.record(&context, subject, event).await?;
        }
        Ok(tx.commit().await?)
    }

    /// The ID of the account `user` names, in any status; an email names only the
    /// active account that verified it.
    pub(crate) async fn find_user(
        &self,
        operator: &Operator,
        user: &UserRef,
    ) -> Result<UserId, AdminError> {
        operator.authorize_read(&self.database).await?;
        let found = match user {
            UserRef::Id(id) => self
                .database
                .users()
                .find_by_id(*id)
                .await?
                .map(|user| user.id),
            // A name that is not a handle was never stored.
            UserRef::Handle(handle) => match Handle::parse(handle) {
                Ok(handle) => self
                    .database
                    .users()
                    .find_by_handle(&handle)
                    .await?
                    .map(|user| user.id),
                Err(_) => None,
            },
            // An address that cannot be normalized was never stored.
            UserRef::Email(address) => match NormalizedEmail::parse(address) {
                Ok(address) => self
                    .database
                    .emails()
                    .find_active_verified(address.as_str())
                    .await?
                    .map(|email| email.user_id),
                Err(_) => None,
            },
        };
        found.ok_or(AdminError::UserNotFound)
    }

    /// Lists accounts matching `query`, by ID, after the `cursor` of a previous page.
    pub(crate) async fn search_users(
        &self,
        operator: &Operator,
        query: &str,
        cursor: Option<UserId>,
    ) -> Result<UserPage, AdminError> {
        operator.authorize_read(&self.database).await?;
        let users = self
            .database
            .users()
            .search(query.trim(), cursor, USER_PAGE_SIZE)
            .await?;
        let next = (users.len() == usize::from(USER_PAGE_SIZE))
            .then(|| users.last().map(|user| user.id))
            .flatten();
        Ok(UserPage { users, next })
    }

    /// Returns an account's profile, emails, status, passkey labels, identities,
    /// sessions and consents. Recorded, since it shows personal data.
    pub(crate) async fn view_user(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<UserDetail, AdminError> {
        operator.authorize_read(&self.database).await?;
        let mut tx = self.database.begin().await?;
        let user = tx
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(AdminError::UserNotFound)?;
        let detail = UserDetail {
            administrator: tx.administrators().contains(user_id).await?,
            emails: tx
                .emails()
                .list(user_id)
                .await?
                .into_iter()
                .map(Email::from)
                .collect(),
            passkeys: Self::views(tx.passkeys().list_active(user_id).await?),
            identities: Self::views(tx.federation().list_active(user_id).await?),
            sessions: tx
                .sessions()
                .list_active_for_user(user_id)
                .await?
                .into_iter()
                .map(Into::into)
                .collect(),
            consents: tx.oidc().list_consents(user_id).await?,
            user: user.into(),
        };
        tx.record(
            &operator.context(),
            Some(user_id),
            DomainEvent::AccountViewed {},
        )
        .await?;
        tx.commit().await?;
        Ok(detail)
    }

    /// Shows each stored record without what the dashboard and CLI never show.
    fn views<S: Into<T>, T>(records: Vec<S>) -> Vec<T> {
        records.into_iter().map(Into::into).collect()
    }

    /// Disables an account and ends all its sessions and refresh grants in one
    /// transaction, so its next request and token refresh fail. A recovery link
    /// not used yet stops working, so re-enabling the account does not revive it.
    pub(crate) async fn disable_user(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        operator.lock(&mut tx, user_id).await?;
        if !tx
            .users()
            .set_status(user_id, AccountStatus::Disabled)
            .await?
        {
            return Err(AdminError::AlreadyDisabled);
        }
        let disabled = DomainEvent::AccountDisabled {
            reason: Personal::Value(reason.into_inner()),
        };
        tx.record(&operator.context(), Some(user_id), disabled)
            .await?;
        tx.recoveries().cancel_open(user_id).await?;
        Self::end_sessions(
            &mut tx,
            &operator.context(),
            user_id,
            RevocationReason::AccountDisabled,
        )
        .await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Reactivates a disabled account. Fails if another active account claimed one
    /// of its verified emails meanwhile.
    pub(crate) async fn enable_user(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        operator.lock(&mut tx, user_id).await?;
        let changed = tx
            .users()
            .set_status(user_id, AccountStatus::Active)
            .await
            .map_err(|error| match error {
                DatabaseError::Conflict(_) => AdminError::EmailClaimed(error),
                DatabaseError::NotFound
                | DatabaseError::Timeout(_)
                | DatabaseError::InvalidStoredData { .. }
                | DatabaseError::Operation(_) => error.into(),
            })?;
        if !changed {
            return Err(AdminError::AlreadyActive);
        }
        Self::finish(
            tx,
            operator,
            Some(user_id),
            vec![DomainEvent::AccountEnabled {}],
        )
        .await
    }

    /// Starts recovering the active account `user_id`, whose owner lost every
    /// passkey, for `reason`, in one transaction. It ends the account's sessions
    /// and refresh grants, removes its unverified addresses, so no verification
    /// link sent before can change it, and cancels an unused older link. Its
    /// current primary verified address is sent a link that enrolls one passkey,
    /// once, within a day. An operator at the terminal is also given the link,
    /// which also reaches an owner without an address. An administrator never
    /// sees it, so they may only start a recovery that mails it, which needs email
    /// enabled.
    ///
    /// With `revoke`, for an account that was in someone else's hands, it first
    /// takes back every way in but the passkeys the owner vouched for: every
    /// other passkey, the last included, every identity and every consent. Its
    /// link is then only printed, and every verified address is told at once.
    ///
    /// Refused for an administrator, whose rights must be revoked first, and while
    /// a recovery of the account is in probation, which support undoes first
    /// ([`Self::undo_recovery`]) once it knows who used it.
    pub(crate) async fn recover_account(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
        links: &RecoveryLinks,
        revoke: Option<Revoke>,
    ) -> Result<Option<Url>, AdminError> {
        let mut tx = self.database.begin().await?;
        let user = operator.lock(&mut tx, user_id).await?;
        if user.status != AccountStatus::Active {
            return Err(AdminError::RecoveryOfDisabledAccount);
        }
        if tx.administrators().contains(user_id).await? {
            return Err(AdminError::RecoveryOfAdministrator);
        }
        if AccountService::undoable(&mut tx, user_id)
            .await?
            .is_some_and(|undoable| undoable.is_probation())
        {
            return Err(AdminError::RecoveryInProbation);
        }
        let shown = matches!(operator, Operator::Cli { .. });
        let emails = tx.emails().list(user_id).await?;
        let mailed = self.mails
            && revoke.is_none()
            && emails
                .iter()
                .any(|email| email.is_primary && email.verified_at.is_some());
        if !mailed && !shown {
            return Err(AdminError::RecoveryNeedsEmail);
        }
        let context = EventContext {
            reason: Some(reason.into_inner()),
            ..operator.context()
        };
        // Cancelled before any revocation, which the database refuses while a
        // recovery's link works.
        tx.recoveries().cancel_open(user_id).await?;
        let revoke = match revoke {
            Some(revoke) => Some(Self::take_back(&mut tx, &context, user_id, revoke).await?),
            None => None,
        };
        for email in emails.iter().filter(|email| email.verified_at.is_none()) {
            EmailApplication::delete(&mut tx, &context, user_id, email.id).await?;
        }
        let id = RecoveryId::new();
        let token = links.token(id)?;
        let expires_at = Utc::now() + LINK_LIFETIME;
        tx.recoveries()
            .insert(&InsertRecovery {
                id,
                user_id,
                secret_digest: token.digest().as_bytes(),
                expires_at,
            })
            .await?;
        let started = DomainEvent::RecoveryStarted {
            recovery_id: id,
            expires_at,
            revoke,
        };
        tx.record(&context, Some(user_id), started).await?;
        Self::end_sessions(&mut tx, &context, user_id, RevocationReason::Admin).await?;
        let link = shown.then(|| links.url(&token));
        Self::finish(tx, operator, Some(user_id), vec![]).await?;
        Ok(link)
    }

    /// Takes back every way into `user_id`'s account but the passkeys `revoke`
    /// keeps, recording each change in `context`: every other passkey, the last
    /// included, every identity, and every refresh grant and consent. Fails if a
    /// kept passkey is not an active one of the account, so a typo cannot leave a
    /// stolen one active.
    async fn take_back(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user_id: UserId,
        revoke: Revoke,
    ) -> Result<RecoveryRevocation, AdminError> {
        let passkeys = tx.passkeys().list_active(user_id).await?;
        if let Some(unknown) = revoke
            .keep
            .iter()
            .find(|kept| !passkeys.iter().any(|passkey| passkey.id == **kept))
        {
            return Err(AdminError::UnknownPasskey(*unknown));
        }
        let mut revoked = Vec::new();
        for passkey in passkeys
            .iter()
            .filter(|passkey| !revoke.keep.contains(&passkey.id))
        {
            if AccountService::take_back_passkey(tx, context, user_id, passkey.id).await? {
                revoked.push(passkey.id);
            }
        }
        for identity in tx.federation().list_active(user_id).await? {
            let provider = identity.provider;
            if tx.federation().unlink(user_id, provider).await? {
                tx.record(
                    context,
                    Some(user_id),
                    DomainEvent::IdentityUnlinked { provider },
                )
                .await?;
            }
        }
        AccountService::withdraw_consents(tx, context, user_id).await?;
        Ok(RecoveryRevocation {
            revoked,
            kept: revoke.keep,
        })
    }

    /// The account's recoveries started or used within the last [`PROBATION`],
    /// newest first, with where each stands and the passkey each enrolled, those
    /// undone included, so support sees a repeated attempt before starting
    /// another. Recorded, as a view of the account.
    pub(crate) async fn recent_recoveries(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<Vec<RecentRecovery>, AdminError> {
        operator.authorize_read(&self.database).await?;
        let mut tx = self.database.begin().await?;
        let since = Utc::now() - PROBATION;
        let recent = tx.recoveries().recent(user_id, since).await?;
        tx.record(
            &operator.context(),
            Some(user_id),
            DomainEvent::AccountViewed {},
        )
        .await?;
        tx.commit().await?;
        Ok(recent)
    }

    /// Undoes the account's recovery that can still be undone, for `reason`, as
    /// support does once it has confirmed the owner, who may have no passkey left
    /// from before it, or whose account is disabled. In probation, it takes back
    /// the recovery's passkey, even the account's last, every consent, every
    /// session and every refresh grant, each change recording `reason`; support
    /// then starts a new recovery if the owner needs one. Its link unused, it
    /// only cancels the link.
    pub(crate) async fn undo_recovery(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        operator.lock(&mut tx, user_id).await?;
        let recovery = AccountService::undoable(&mut tx, user_id)
            .await?
            .ok_or(AdminError::NoRecoveryToUndo)?;
        let context = EventContext {
            reason: Some(reason.into_inner()),
            ..operator.context()
        };
        AccountService::revert(&mut tx, &context, &recovery, RevocationReason::Admin).await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Ends every session and refresh grant of an account.
    pub(crate) async fn revoke_user_sessions(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        operator.lock(&mut tx, user_id).await?;
        Self::end_sessions(
            &mut tx,
            &operator.context(),
            user_id,
            RevocationReason::Admin,
        )
        .await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Revokes the account's sessions, recording each in `context`, then its
    /// refresh grants. Callers hold the account lock.
    async fn end_sessions(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user_id: UserId,
        reason: RevocationReason,
    ) -> Result<(), AdminError> {
        tx.revoke_sessions(context, user_id, SessionScope::All, &reason)
            .await?;
        tx.tokens().revoke_for_user(user_id, None).await?;
        Ok(())
    }

    /// Ends one active session and the refresh grants issued from it.
    pub(crate) async fn revoke_session(
        &self,
        operator: &Operator,
        session_id: SessionId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        // The owner never changes, so it can be read before taking the account lock.
        let session = tx
            .sessions()
            .find_by_id(session_id)
            .await?
            .ok_or(AdminError::SessionNotFound)?;
        operator.lock(&mut tx, session.user_id).await?;
        if tx
            .revoke_sessions(
                &operator.context(),
                session.user_id,
                SessionScope::One(session_id),
                &RevocationReason::Admin,
            )
            .await?
            .is_empty()
        {
            return Err(AdminError::SessionNotFound);
        }
        Self::finish(tx, operator, Some(session.user_id), vec![]).await
    }

    /// Lists invitations that have not been purged yet, newest first.
    pub(crate) async fn list_invitations(
        &self,
        operator: &Operator,
    ) -> Result<Vec<Invitation>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self.database.security().list_invitations().await?)
    }

    /// Creates a single-use signup link to the registration page on `origin`, auth's
    /// own. Only the secret's digest is stored, so the link cannot be shown again.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, or secret generation or
    /// persistence fails.
    pub async fn create_invitation(
        &self,
        operator: &Operator,
        origin: &Origin,
        expires_in: InviteExpiry,
    ) -> Result<CreatedInvitation, AdminError> {
        let secret = Secret::generate()?;
        let id = TokenId::new();
        let expires_at = Utc::now() + expires_in.duration();
        let mut tx = self.database.begin().await?;
        tx.security()
            .create_invitation(id, secret.digest().as_bytes(), expires_at)
            .await?;
        let created = DomainEvent::InvitationCreated { expires_at };
        Self::finish(tx, operator, None, vec![created]).await?;
        let url = LoginQuery {
            invitation: Some(secret.encoded()),
            ..LoginQuery::default()
        }
        .url(origin.as_url(), routes::page::REGISTER)?;
        Ok(CreatedInvitation {
            id,
            url,
            expires_at,
        })
    }

    /// Revokes an unredeemed invitation.
    pub(crate) async fn revoke_invitation(
        &self,
        operator: &Operator,
        invitation_id: TokenId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        if !tx.security().revoke_invitation(invitation_id).await? {
            return Err(AdminError::InvitationNotFound);
        }
        let revoked = DomainEvent::InvitationRevoked { invitation_id };
        Self::finish(tx, operator, None, vec![revoked]).await
    }

    /// Lists every OIDC client, enabled or not.
    pub(crate) async fn list_clients(
        &self,
        operator: &Operator,
    ) -> Result<Vec<Client>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(Self::views(self.database.oidc().list_clients().await?))
    }

    /// Describes one OIDC client as stored, with the lifetimes of its secrets.
    pub(crate) async fn client_details(
        &self,
        operator: &Operator,
        id: &ClientId,
    ) -> Result<ClientDetails, AdminError> {
        operator.authorize_read(&self.database).await?;
        let mut tx = self.database.begin().await?;
        let client = tx
            .oidc()
            .find_client(id.as_str())
            .await?
            .ok_or(AdminError::ClientNotFound)?;
        let secrets = tx.oidc().client_secrets(id).await?;
        tx.commit().await?;
        Ok(ClientDetails { client, secrets })
    }

    /// Runs `change` on the client registry in one transaction, attributed to
    /// `operator`, and commits once the operator is authorized again. The
    /// registry records each change's event itself.
    async fn change_clients<T, E: From<AdminError>>(
        &self,
        operator: &Operator,
        change: impl AsyncFnOnce(&mut ClientRegistry<'_, '_>) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut tx = self.database.begin().await.map_err(AdminError::from)?;
        let value = change(&mut ClientRegistry::new(&mut tx, operator.context())).await?;
        Self::finish(tx, operator, None, Vec::new()).await?;
        Ok(value)
    }

    /// Registers a client operators manage, and returns a confidential client's
    /// first secret, which is shown only this once.
    pub(crate) async fn create_client(
        &self,
        operator: &Operator,
        registration: &ClientRegistration,
    ) -> Result<Option<ClientSecret>, AdminError> {
        self.change_clients(operator, async |clients| {
            Ok(clients
                .create(ClientOwner::Operator, registration, None)
                .await?)
        })
        .await
    }

    /// Registers a client a deployment manages, or updates it to match, with the
    /// secret its deployment generated. Earlier secrets keep working for `grace`.
    pub(crate) async fn apply_client(
        &self,
        operator: &Operator,
        registration: &ClientRegistration,
        secret: Option<ClientSecret>,
        grace: GracePeriod,
    ) -> Result<Applied, AdminError> {
        self.change_clients(operator, async |clients| {
            Ok(clients.apply(registration, secret, grace).await?)
        })
        .await
    }

    /// Replaces client `id`'s registration with what `edit` makes of the stored
    /// one, and returns the settings that changed.
    pub(crate) async fn update_client<E>(
        &self,
        operator: &Operator,
        id: &ClientId,
        edit: impl FnOnce(&StoredOidcClient) -> Result<ClientRegistration, E>,
    ) -> Result<Vec<ClientField>, E>
    where
        E: From<AdminError> + From<ClientRegistryError>,
    {
        self.change_clients(operator, async |clients| clients.update(id, edit).await)
            .await
    }

    /// Enables or disables client `id`. A suspended client cannot be enabled.
    pub(crate) async fn set_client_enabled(
        &self,
        operator: &Operator,
        id: &ClientId,
        enabled: bool,
    ) -> Result<(), AdminError> {
        self.change_clients(operator, async |clients| {
            Ok(clients.set_enabled(id, enabled).await?)
        })
        .await
    }

    /// Suspends client `id`, which disables it until the suspension is lifted, or
    /// lifts its suspension, which leaves it disabled.
    pub(crate) async fn set_client_suspended(
        &self,
        operator: &Operator,
        id: &ClientId,
        suspended: bool,
    ) -> Result<(), AdminError> {
        self.change_clients(operator, async |clients| {
            Ok(clients.set_suspended(id, suspended).await?)
        })
        .await
    }

    /// Deletes client `id`: it stops working at once, and its ID is never reused.
    pub(crate) async fn delete_client(
        &self,
        operator: &Operator,
        id: &ClientId,
    ) -> Result<(), AdminError> {
        self.change_clients(operator, async |clients| Ok(clients.delete(id).await?))
            .await
    }

    /// Gives confidential client `id` a new secret, shown only this once. Earlier
    /// secrets keep working for `grace`.
    pub(crate) async fn rotate_client_secret(
        &self,
        operator: &Operator,
        id: &ClientId,
        grace: GracePeriod,
    ) -> Result<ClientSecret, AdminError> {
        self.change_clients(operator, async |clients| {
            Ok(clients.rotate_secret(id, grace).await?)
        })
        .await
    }

    /// Returns a page of the events matching `search`, newest first.
    pub(crate) async fn events(
        &self,
        operator: &Operator,
        search: EventSearch,
    ) -> Result<EventPage, AdminError> {
        operator.authorize_read(&self.database).await?;
        let filter = EventFilter {
            subject: search.user,
            kind: search.kind,
            before: search.before,
            id: None,
        };
        let stored = self
            .database
            .events()
            .list(&filter, u32::from(EVENT_PAGE_SIZE))
            .await?;
        let next = (stored.len() == usize::from(EVENT_PAGE_SIZE))
            .then(|| stored.last().map(|event| event.id))
            .flatten();
        let events = stored
            .into_iter()
            .map(|stored| {
                Ok(Event {
                    id: stored.id,
                    occurred_at: stored.occurred_at,
                    actor: serde_json::to_value(stored.actor)?,
                    subject: stored.subject,
                    trace_id: stored.trace_id,
                    event: serde_json::to_value(stored.event)?,
                })
            })
            .collect::<Result<_, serde_json::Error>>()?;
        Ok(EventPage { events, next })
    }

    /// Lists the accounts whose current handle is reserved, by handle: ones an
    /// operator assigned on purpose, or that a later release reserved.
    ///
    /// # Errors
    /// Fails when the operator may not read, or the query fails.
    pub async fn check_handles(
        &self,
        operator: &Operator,
    ) -> Result<Vec<HandleProblem>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self
            .database
            .handles()
            .list_current()
            .await?
            .into_iter()
            .filter_map(|current| {
                let error = current.handle.ensure_unreserved().err()?;
                Some(HandleProblem {
                    user_id: current.user_id?,
                    handle: current.handle,
                    error,
                })
            })
            .collect())
    }

    /// Gives the account `user_id` the handle `handle`, for `reason`, as a settings
    /// rename does but without its cooldown. Reserved names are refused unless
    /// `allow_reserved`. The reason is recorded with the change, as personal data
    /// the owner sees in their history.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, the account is unknown, or
    /// the handle is reserved, taken, retired, a look-alike or already the
    /// account's.
    pub async fn rename_handle(
        &self,
        operator: &Operator,
        user_id: UserId,
        handle: Handle,
        reason: Reason,
        allow_reserved: bool,
    ) -> Result<(), AdminError> {
        if !allow_reserved {
            handle.ensure_unreserved().map_err(HandlesError::from)?;
        }
        let mut tx = self.database.begin().await?;
        let user = operator.lock(&mut tx, user_id).await?;
        let (mut tx, changed) = Handles::new(&self.database)
            .rename(tx, &user, handle)
            .await?;
        let context = EventContext {
            reason: Some(reason.into_inner()),
            ..operator.context()
        };
        tx.record(&context, Some(user_id), changed).await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Deletes the released handle `handle`, or a purged account's last one, so
    /// anyone may claim it again: the only way a handle returns to the pool, for
    /// cases such as a trademark dispute.
    ///
    /// # Errors
    /// Fails when no released handle, or purged account's, is `handle`.
    pub async fn release_handle(
        &self,
        operator: &Operator,
        handle: Handle,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        let released = tx
            .handles()
            .delete_released(&handle)
            .await?
            .ok_or(AdminError::HandleNotReleased)?;
        let event = DomainEvent::HandleReleased {
            handle: Personal::Value(handle),
        };
        Self::finish(tx, operator, released.user_id, vec![event]).await
    }

    /// Lists every administrator, oldest grant first.
    ///
    /// # Errors
    /// Fails when the operator may not read, or the query fails.
    pub async fn list_administrators(
        &self,
        operator: &Operator,
    ) -> Result<Vec<Administrator>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self.database.administrators().list().await?)
    }

    /// Makes the active account `user_id` an administrator. Administrators cannot
    /// grant themselves rights: one whose rights were revoked while the request
    /// waited would otherwise restore them. While a recovery of the account can
    /// still be undone, it is refused, by the CLI too: granted during a probation,
    /// the rights would go live for whoever used its link once it settles. The
    /// migration's `administrators_no_grant_mid_recovery` backs it for every
    /// writer.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, or the account is unknown,
    /// disabled, already an administrator, the caller's own, or has a recovery
    /// that can still be undone.
    pub(crate) async fn grant_administrator(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        operator.refuse_own_rights(user_id)?;
        let mut tx = self.database.begin().await?;
        tx.administrators().lock().await?;
        let user = tx
            .users()
            .find_by_id_for_update(user_id)
            .await?
            .ok_or(AdminError::UserNotFound)?;
        if user.status == AccountStatus::Disabled {
            return Err(AdminError::AccountDisabled);
        }
        if AccountService::undoable(&mut tx, user_id).await?.is_some() {
            return Err(AdminError::GrantDuringRecovery);
        }
        if !tx.administrators().grant(user_id).await? {
            return Err(AdminError::AlreadyAdministrator);
        }
        let granted = DomainEvent::AdministratorGranted {};
        Self::finish(tx, operator, Some(user_id), vec![granted]).await
    }

    /// Removes the administrator rights of `user_id`. Administrators cannot remove
    /// their own, and nobody can remove the last administrator's: someone must be
    /// left to administer.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, the account is not an
    /// administrator, or either rule forbids it.
    pub async fn revoke_administrator(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        operator.refuse_own_rights(user_id)?;
        let mut tx = self.database.begin().await?;
        tx.administrators().lock().await?;
        let administrators = tx.administrators().list().await?;
        if !administrators.iter().any(|admin| admin.user_id == user_id) {
            return Err(AdminError::NotAnAdministrator);
        }
        if administrators.len() == 1 {
            return Err(AdminError::LastAdministrator);
        }
        tx.administrators().revoke(user_id).await?;
        let revoked = DomainEvent::AdministratorRevoked {};
        Self::finish(tx, operator, Some(user_id), vec![revoked]).await
    }

    /// Lists outbound deliveries, newest first, with `status` and on `channel` when
    /// given, at most `limit`.
    pub(crate) async fn list_deliveries(
        &self,
        operator: &Operator,
        status: Option<DeliveryStatus>,
        channel: Option<&str>,
        limit: u32,
    ) -> Result<Vec<DeliverySummary>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self
            .database
            .deliveries()
            .list(status, channel, limit)
            .await?)
    }

    /// Attempts a failed delivery, or a cancelled unordered one, again now.
    pub(crate) async fn retry_delivery(
        &self,
        operator: &Operator,
        id: DeliveryId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        tx.deliveries()
            .retry(id)
            .await
            .map_err(AdminError::delivery(id, "failed or cancelled unordered"))?;
        let retried = DomainEvent::DeliveryRetried { delivery_id: id };
        Self::finish(tx, operator, None, vec![retried]).await
    }

    /// Cancels a pending or failed delivery, which unblocks the deliveries ordered
    /// after it.
    pub(crate) async fn cancel_delivery(
        &self,
        operator: &Operator,
        id: DeliveryId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        tx.deliveries()
            .cancel(id)
            .await
            .map_err(AdminError::delivery(id, "pending or failed"))?;
        let cancelled = DomainEvent::DeliveryCancelled { delivery_id: id };
        Self::finish(tx, operator, None, vec![cancelled]).await
    }
}
