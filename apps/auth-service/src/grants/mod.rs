//! The apps that keep access to the account, and removing that access: what
//! [`AccountService`] serves the settings' connected apps. Their scenarios run with
//! the OIDC flow tests, which issue the grants they remove.
use crate::account::{AccountError, AccountService, Owner, Viewer};
use piquel_common::{ClientId, events::DomainEvent, protocol::oauth::Scope};
use piquel_repository::StoredApp;

/// Removal failures and their browser response mapping.
mod error;
pub(crate) use error::GrantError;

/// An app that keeps access to the account: one it consented to, or one whose
/// refresh grant still works.
pub(crate) struct ConnectedApp {
    /// Its client ID, to remove it.
    pub(crate) client_id: ClientId,
    /// The name its consent screen shows.
    pub(crate) name: String,
    /// Whether it is first-party: it signs in without the consent screen, so
    /// its next sign-in grants it access again.
    pub(crate) first_party: bool,
    /// What it can read, `offline_access` aside.
    pub(crate) scopes: Vec<String>,
    /// Whether it holds a refresh grant, so it can act while the user is away.
    pub(crate) offline: bool,
}

impl From<StoredApp> for ConnectedApp {
    /// Says `offline_access` as whether the app holds a refresh grant, rather
    /// than among what it reads.
    fn from(app: StoredApp) -> Self {
        Self {
            client_id: app.client_id,
            name: app.name,
            first_party: app.trusted,
            scopes: app
                .scopes
                .into_iter()
                .filter(|scope| scope != Scope::OfflineAccess.as_str())
                .collect(),
            offline: app.offline,
        }
    }
}

impl AccountService {
    /// Lists the apps that keep access to the account, by name.
    pub(crate) async fn apps(&self, viewer: &Viewer) -> Result<Vec<ConnectedApp>, AccountError> {
        viewer.authorize(&self.database).await?;
        Ok(self
            .database
            .oidc()
            .list_apps(viewer.user())
            .await?
            .into_iter()
            .map(ConnectedApp::from)
            .collect())
    }

    /// Removes `client`'s access to the owner's account in one transaction,
    /// under the account lock: revokes its refresh grants, withdraws the
    /// consent, so it asks again before its next sign-in, and expires its
    /// outstanding codes. Recorded as one `ConsentRevoked`. Access tokens it
    /// already holds expire within minutes.
    ///
    /// Only the owner may: it needs no passkey confirmation, since it only takes
    /// access away. The owner's sessions stay signed in, since other apps share
    /// them. A code exchange locks the account first too, so it either finishes
    /// before this, and its refresh grant is revoked here, or finds its code
    /// expired.
    pub(crate) async fn remove_app(
        &self,
        owner: &Owner,
        client: &ClientId,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        owner.lock(&mut tx).await?;
        let user = owner.user();
        // Refresh grants before the consent, in the order a client's deletion
        // locks them, so neither waits for what the other holds.
        let revoked = tx.tokens().revoke_for_user(user, Some(client)).await?;
        let withdrawn = tx.oidc().revoke_consents(user, Some(client)).await?;
        tx.oidc().expire_codes(user, client).await?;
        if revoked == 0 && withdrawn.is_empty() {
            return Err(GrantError::NotFound.into());
        }
        let removed = DomainEvent::ConsentRevoked {
            client_id: client.clone(),
        };
        tx.record(&owner.context(), Some(user), removed).await?;
        tx.commit().await?;
        Ok(())
    }
}
