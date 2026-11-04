//! Client changes reach running replicas on their next request, and each records
//! its event as made by whoever made it. Owners find and change only their own
//! clients, confirming what needs it, and a deletion leaves a tombstone without
//! deadlocking the token grants it revokes.
use super::*;
use crate::{
    account::{AccountError, AccountService, Owner},
    security::Session,
    tests::{Browser, Replicas, change, register, registration, replace, until_blocked},
};
use piquel_common::{AuthenticationMethod, UserId, clients::RedirectUris};
use piquel_repository::Database;

mod deletion;
mod origins;
mod owners;
mod registry;

/// An account, and the owner's operations on its clients, over the test database.
struct Account {
    /// The scenario database.
    database: Database,
    /// The owner's operations.
    service: AccountService,
    /// A browser signed in to the account with a passkey, so confirmed.
    browser: Browser,
}

impl Account {
    /// Creates an account over a migrated test database.
    async fn new() -> Self {
        let database = Replicas::database().await;
        Self {
            service: AccountService::new(database.clone()),
            browser: Browser::new_account(&database).await,
            database,
        }
    }

    /// The owner, as the browser signed in with a passkey shows them.
    async fn owner(&self) -> Owner {
        self.browser.owner(&self.database).await
    }

    /// Signs another browser in to the account socially, which never confirms
    /// with a passkey.
    async fn social(&self) -> Browser {
        let federation = AuthenticationMethod::Federation;
        Browser::sign_in_with(&self.database, self.browser.user_id, federation).await
    }

    /// Registers a client of `kind` calling back to `https://notes.example` as the
    /// confirmed owner, and returns its ID.
    async fn create(&self, kind: ClientKind) -> ClientId {
        let origin = "https://notes.example";
        self.browser
            .register_app(&self.database, kind, origin)
            .await
    }

    /// The owner's client `id`, as `owner` finds it.
    async fn find(&self, owner: Owner, id: &ClientId) -> OwnedClient {
        let found = self.service.owned_client(owner, id.as_str()).await;
        found.expect("the owner's client")
    }

    /// Makes `change` to client `id` as the owner, from a social session that a
    /// passkey confirms while the change waits for the account lock, and returns
    /// its result.
    async fn confirmed_while_waiting(
        &self,
        id: &ClientId,
        change: impl AsyncFnOnce(&OwnedClient) -> Result<(), AccountError>,
    ) -> Result<(), AccountError> {
        let stale = self.social().await;
        let client = self.find(stale.owner(&self.database).await, id).await;
        let mut holder = self.database.begin().await.expect("transaction");
        holder
            .users()
            .find_active_by_id_for_update(stale.user_id)
            .await
            .expect("lock")
            .expect("account");
        let (result, ()) = tokio::join!(change(&client), async {
            until_blocked(&mut holder, 1).await;
            let session = holder.sessions().find_by_id(stale.session_id).await;
            let session = session.expect("lookup").expect("session");
            let passkey = AuthenticationMethod::Passkey.into();
            Session::reauthenticate(&mut holder, &session, passkey)
                .await
                .expect("confirm");
            holder.commit().await.expect("commit");
        });
        result
    }
}
