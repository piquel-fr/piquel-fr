//! What can be done to an account, as [`AccountService`] operations on the
//! account and who acts on it: an [`Owner`], only for what the owner alone may
//! do; a [`Subject`], for changes any administrator may also make; or a
//! [`Viewer`], for reads. The owner's routes run them with the owner of their
//! session cookie, and the `account` command with the operator at the terminal.
//! The admin dashboard calls them in-process, as an administrator.
//!
//! The rule for sharing: administrators may view, edit and remove, but never add
//! a way to sign in or to receive the account's email, which would let them take
//! the account over. Adding a passkey, linking an identity, adding an address
//! and reporting a history entry take an [`Owner`], which only the session cookie
//! builds, so an administrator cannot call them. So does downloading the
//! account's data: the export copies every IP address and the whole history out
//! of auth, and only the owner's recently confirmed session may receive it.
//! Support recovers an owner who lost every passkey instead, who then downloads
//! it themselves. Verifying an address is
//! authorized by its link's token instead, and takes the signed-in owner only if
//! there is one, to refuse a browser signed in to another account. The owner's
//! clients, which administrators manage through `AdminService`, are the owner's
//! too.

/// Failures of the account operations.
mod error;
/// The account acted on, and who acts on it.
mod subject;

pub(crate) use error::AccountError;
pub(crate) use subject::{ConfirmedOwner, ConfirmedSubject, Owner, Subject, Viewer};

use crate::{
    emails::EmailView,
    federation::FederationError,
    grants::ConnectedApp,
    handles,
    history::{HistoryPage, HistoryQuery},
    notifications::{NotificationPage, NotificationQuery, NotificationView},
    operations::operations,
    passkey::{DisplayName, Rename},
    pictures::PictureView,
    routes::{
        apps, emails, federation, history, notifications, passkey, pictures, profile, sessions,
    },
    security::{RequestContext, SessionError},
    sessions::{Revoked, SessionItem},
};
use axum::{
    Json, Router,
    extract::{FromRef, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{MethodRouter, delete, get, patch, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sourceorigin_common::{
    ClientId, EmailId, Handle, NotificationId, PasskeyId, Personal, PictureId, SessionId,
    admin::KnownDevice,
    events::DomainEvent,
    notifications::NotificationPreference,
    protocol::api::{Identity, Passkey},
};
use sourceorigin_repository::{Database, StoredUser};

operations! {
    /// Every shared settings operation of the settings API. The owner's router
    /// maps each to its route, and the `account` command has a command for each,
    /// which a CLI test checks.
    pub(crate) enum AccountOperation {
        /// List the account's passkeys.
        ListPasskeys,
        /// Rename a passkey.
        RenamePasskey,
        /// Remove a passkey, keeping at least one, and sign the account out
        /// elsewhere.
        RevokePasskey,
        /// List the account's linked social identities.
        ListIdentities,
        /// Unlink a social identity, and sign the account out elsewhere.
        UnlinkIdentity,
        /// List the account's email addresses.
        ListEmails,
        /// Make a verified address the primary one.
        MakeEmailPrimary,
        /// Remove an email address.
        RemoveEmail,
        /// List the account's sessions.
        ListSessions,
        /// Sign one session out.
        RevokeSession,
        /// Sign every other session out.
        RevokeOtherSessions,
        /// List the browsers the account knows, whose sign-ins alert no one.
        ListKnownDevices,
        /// List the apps that keep access to the account.
        ListApps,
        /// Remove one app's access.
        RemoveApp,
        /// Page through the account's security history.
        ViewHistory,
        /// Change the display name.
        ChangeDisplayName,
        /// Show the account's profile picture.
        ViewPicture,
        /// Remove the account's profile picture.
        RemovePicture,
        /// Page through the account's notifications, without marking any read.
        ListNotifications,
        /// Read one notification, without marking it read.
        ViewNotification,
        /// Show which categories of notifications the account receives by
        /// email. Only the owner changes them.
        ViewNotificationPreferences,
    }
}

/// Every account settings operation, on any account. The owner's routes run them
/// all, and the `account` command the shared ones. An operation only the owner may
/// run takes the [`Owner`] it acts as, a shared change the [`Subject`] it acts on,
/// and a read the [`Viewer`] it shows. Each operation lives with its setting in the
/// passkey, federation, emails, sessions, history, grants, clients or pictures
/// module; the profile's live here.
#[derive(Clone)]
pub(crate) struct AccountService {
    /// Accounts, their settings and events.
    pub(crate) database: Database,
}

impl AccountService {
    /// Operates on `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// The owner of the browser session the request's `headers` carry, if any,
    /// acting from `context`: how a server-rendered page, which has no extractors,
    /// finds who acts. It records the session's activity, as the extractors do.
    pub(crate) async fn owner(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
    ) -> Result<Option<Owner>, AccountError> {
        Ok(Owner::resolve(&self.database, context, headers).await?)
    }

    /// The account's handle and display name. A session whose account is gone
    /// reads as signed out.
    pub(crate) async fn profile(&self, viewer: &Viewer) -> Result<Profile, AccountError> {
        viewer.authorize(&self.database).await?;
        Ok(self
            .database
            .users()
            .find_by_id(viewer.user())
            .await?
            .map(Profile::from)
            .ok_or(SessionError::Missing)?)
    }

    /// Changes the account's display name to `name`, trimmed, and bumps its profile version,
    /// so relying parties refresh `name`. A name grants nothing, so the owner's
    /// session is enough. The name the account already has changes nothing.
    pub(crate) async fn change_display_name(
        &self,
        subject: &Subject,
        name: String,
    ) -> Result<(), AccountError> {
        let name = DisplayName::parse(name.trim().to_owned())?;
        let mut tx = self.database.begin().await?;
        subject.lock(&mut tx).await?;
        if let Some(old) = tx.users().rename(subject.user(), name.as_str()).await? {
            tx.record(
                &subject.context(),
                Some(subject.user()),
                DomainEvent::DisplayNameChanged {
                    old: Personal::Value(old),
                    new: Personal::Value(name.into()),
                },
            )
            .await?;
        }
        subject.commit(tx).await
    }
}

/// The account as auth's pages show it to the browser signed in to it: in the
/// account's bar, on the sign-in and undo pages, and in its profile's settings.
pub(crate) struct Profile {
    /// Its handle, the login name.
    pub(crate) handle: Handle,
    /// When the owner may change the handle again, if not yet.
    pub(crate) handle_changeable_at: Option<DateTime<Utc>>,
    /// The name shown to the user and to relying parties.
    pub(crate) display_name: String,
    /// Its profile picture, if any.
    pub(crate) picture: Option<PictureId>,
}

impl From<StoredUser> for Profile {
    /// Keeps what the account's pages show.
    fn from(user: StoredUser) -> Self {
        Self {
            handle_changeable_at: handles::changeable_at(&user),
            handle: user.handle,
            display_name: user.display_name,
            picture: user.picture,
        }
    }
}

/// A change to the account's profile, as the owner's route takes it.
#[derive(Deserialize)]
struct ProfileChange {
    /// The new display name, validated by the operation.
    display_name: String,
}

/// The owner's routes for the shared settings, at `/account`.
#[derive(Clone)]
pub(crate) struct AccountApplication {
    /// The operations behind the routes.
    service: AccountService,
}

impl FromRef<AccountApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &AccountApplication) -> Self {
        application.service.database.clone()
    }
}

impl AccountApplication {
    /// Serves the shared settings of the signed-in owner from `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self {
            service: AccountService::new(database),
        }
    }

    /// Returns every shared route at its `/account/…` path, with this
    /// application as state.
    pub(crate) fn routes(self) -> Router {
        AccountOperation::ALL
            .iter()
            .map(|operation| Self::route(*operation))
            .fold(Router::new(), |router, (path, method)| {
                router.route(path, method)
            })
            .with_state(self)
    }

    /// The path and method serving `operation`. Methods on one path merge, here
    /// and with the owner-only methods of the same path.
    fn route(operation: AccountOperation) -> (&'static str, MethodRouter<Self>) {
        type Op = AccountOperation;
        match operation {
            Op::ListPasskeys => (passkey::LIST, get(Self::passkeys)),
            Op::RenamePasskey => (passkey::ITEM, patch(Self::rename_passkey)),
            Op::RevokePasskey => (passkey::ITEM, delete(Self::revoke_passkey)),
            Op::ListIdentities => (federation::IDENTITIES, get(Self::identities)),
            Op::UnlinkIdentity => (federation::IDENTITY, delete(Self::unlink_identity)),
            Op::ListEmails => (emails::LIST, get(Self::emails)),
            Op::MakeEmailPrimary => (emails::PRIMARY, post(Self::make_primary_email)),
            Op::RemoveEmail => (emails::ITEM, delete(Self::remove_email)),
            Op::ListSessions => (sessions::LIST, get(Self::sessions)),
            Op::RevokeSession => (sessions::ITEM, delete(Self::revoke_session)),
            Op::RevokeOtherSessions => (sessions::REVOKE_OTHERS, post(Self::revoke_other_sessions)),
            Op::ListKnownDevices => (sessions::DEVICES, get(Self::known_devices)),
            Op::ListApps => (apps::LIST, get(Self::apps)),
            Op::RemoveApp => (apps::ITEM, delete(Self::remove_app)),
            Op::ViewHistory => (history::LIST, get(Self::history)),
            Op::ChangeDisplayName => (profile::ITEM, patch(Self::change_display_name)),
            Op::ViewPicture => (pictures::OWN, get(Self::picture)),
            Op::RemovePicture => (pictures::OWN, delete(Self::remove_picture)),
            Op::ListNotifications => (notifications::LIST, get(Self::notifications)),
            Op::ViewNotification => (notifications::ITEM, get(Self::notification)),
            Op::ViewNotificationPreferences => (
                notifications::PREFERENCES,
                get(Self::notification_preferences),
            ),
        }
    }

    /// Lists the account's active passkeys.
    async fn passkeys(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<Passkey>>, AccountError> {
        Ok(Json(app.service.passkeys(&viewer).await?))
    }

    /// Renames a passkey. A name grants nothing, so the owner's session is enough.
    async fn rename_passkey(
        State(app): State<Self>,
        subject: Subject,
        Path(id): Path<PasskeyId>,
        Json(input): Json<Rename>,
    ) -> Result<StatusCode, AccountError> {
        app.service
            .rename_passkey(&subject, id, input.friendly_name)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Removes a passkey, keeping at least one.
    async fn revoke_passkey(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(id): Path<PasskeyId>,
    ) -> Result<StatusCode, AccountError> {
        app.service.revoke_passkey(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists the account's linked social identities.
    async fn identities(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<Identity>>, AccountError> {
        Ok(Json(app.service.identities(&viewer).await?))
    }

    /// Unlinks the provider the path names.
    async fn unlink_identity(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(provider): Path<String>,
    ) -> Result<StatusCode, AccountError> {
        let provider = provider
            .parse()
            .map_err(FederationError::UnsupportedProvider)?;
        app.service.unlink_identity(&subject, provider).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists the account's addresses, primary first.
    async fn emails(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<EmailView>>, AccountError> {
        Ok(Json(app.service.emails(&viewer).await?))
    }

    /// Makes a verified address the primary one.
    async fn make_primary_email(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(id): Path<EmailId>,
    ) -> Result<StatusCode, AccountError> {
        app.service.make_primary_email(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Removes an address.
    async fn remove_email(
        State(app): State<Self>,
        subject: ConfirmedSubject,
        Path(id): Path<EmailId>,
    ) -> Result<StatusCode, AccountError> {
        app.service.remove_email(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lists the account's active sessions, most recently active first.
    async fn sessions(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<SessionItem>>, AccountError> {
        Ok(Json(app.service.sessions(&viewer).await?))
    }

    /// Lists the browsers the account knows, most recently seen first.
    async fn known_devices(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<KnownDevice>>, AccountError> {
        Ok(Json(app.service.known_devices(&viewer).await?))
    }

    /// Signs one session out.
    async fn revoke_session(
        State(app): State<Self>,
        subject: Subject,
        Path(id): Path<SessionId>,
    ) -> Result<StatusCode, AccountError> {
        app.service.revoke_session(&subject, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Signs every other session out, and says how many there were.
    async fn revoke_other_sessions(
        State(app): State<Self>,
        subject: Subject,
    ) -> Result<Json<Revoked>, AccountError> {
        Ok(Json(app.service.revoke_other_sessions(&subject).await?))
    }

    /// Lists the apps that keep access to the account, by name.
    async fn apps(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<ConnectedApp>>, AccountError> {
        Ok(Json(app.service.apps(&viewer).await?))
    }

    /// Removes one app's access. It only takes access away, so the owner's session
    /// is enough.
    async fn remove_app(
        State(app): State<Self>,
        subject: Subject,
        Path(client): Path<ClientId>,
    ) -> Result<StatusCode, AccountError> {
        app.service.remove_app(&subject, &client).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Changes the display name. A name grants nothing, so the owner's session is
    /// enough.
    async fn change_display_name(
        State(app): State<Self>,
        subject: Subject,
        Json(input): Json<ProfileChange>,
    ) -> Result<StatusCode, AccountError> {
        app.service
            .change_display_name(&subject, input.display_name)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// The account's profile picture, or `null` without one.
    async fn picture(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Option<PictureView>>, AccountError> {
        Ok(Json(app.service.picture(&viewer).await?))
    }

    /// Removes the account's profile picture.
    async fn remove_picture(
        State(app): State<Self>,
        subject: Subject,
    ) -> Result<StatusCode, AccountError> {
        app.service.remove_picture(&subject).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Returns a page of the account's history, newest first.
    async fn history(
        State(app): State<Self>,
        viewer: Viewer,
        Query(query): Query<HistoryQuery>,
    ) -> Result<Json<HistoryPage>, AccountError> {
        Ok(Json(app.service.history(&viewer, query.before).await?))
    }

    /// Returns a page of the account's notifications, newest first.
    async fn notifications(
        State(app): State<Self>,
        viewer: Viewer,
        Query(query): Query<NotificationQuery>,
    ) -> Result<Json<NotificationPage>, AccountError> {
        Ok(Json(
            app.service.notifications(&viewer, query.before).await?,
        ))
    }

    /// Returns one notification. Reading it marks nothing read.
    async fn notification(
        State(app): State<Self>,
        viewer: Viewer,
        Path(id): Path<NotificationId>,
    ) -> Result<Json<NotificationView>, AccountError> {
        Ok(Json(app.service.notification(&viewer, id).await?))
    }

    /// Returns whether the account receives each category's email.
    async fn notification_preferences(
        State(app): State<Self>,
        viewer: Viewer,
    ) -> Result<Json<Vec<NotificationPreference>>, AccountError> {
        Ok(Json(app.service.notification_preferences(&viewer).await?))
    }
}

/// Database-backed scenarios of administrators acting on another account.
#[cfg(test)]
mod tests;
