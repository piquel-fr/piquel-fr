//! The developer console, at `/developers`: the apps an account registers as
//! `OpenID` Connect clients, registering one, and each app's pages.
//!
//! Each page is an [`AccountPage`] of the developers section, serving only the
//! account's own apps: an app page whose path names another account's app, a
//! deleted one or none answers `404` ([`Failure::Missing`]) and changes nothing,
//! so probing IDs reveals nothing. A registration or a rotation shows the secret
//! it made in its own answer ([`Applied::Revealed`]).

/// An app's overview, settings and secrets.
mod app;
#[cfg(test)]
mod tests;

pub(super) use app::{AppSecrets, AppSettings, Overview};

use super::{
    Failure, WebApplication,
    account::{AccountPage, Applied, Framed, NoChange, Reader},
};
use crate::{
    DEFAULT_CLIENT_SCOPES, MAX_OWNED_CLIENTS,
    account::{AccountError, Owner},
    clients::{ClientDetails, ClientSettings, NewClient, OwnedClient},
    routes::page::developers::{self, APP, APP_SECRETS, APP_SETTINGS, HOME, NEW},
};
use piquel_common::clients::ClientKind;
use piquel_repository::StoredOidcClient;
use piquel_ui::{
    AppLink, AppTab, ClientDraft, ClientRow, ClientStatus, Messages, NewAppChange, NewAppState,
    Notice, Registered, Revealed, Section, Title,
};
use topcoat::{
    context::Cx,
    router::{StatusCode, path_param, response::Response},
    view::{Child, view},
};

// The client ID an app page's path names. Unparsed: an ID that is not one is not
// the account's either, and is missing like any other.
path_param!(id);

/// Each app tab and the route of the page it links.
const APP_TABS: [(AppTab, &str); 3] = [
    (AppTab::Overview, APP),
    (AppTab::Settings, APP_SETTINGS),
    (AppTab::Secrets, APP_SECRETS),
];

/// The account's apps.
pub(in crate::web) struct Apps;

impl AccountPage for Apps {
    const SECTION: Section = Section::Developers;
    const PATH: &'static str = HOME;
    const TITLE: &'static str = Title::Developers.as_str();
    type Change = NoChange;
    type Row = ();

    fn reopened(change: &NoChange) {
        match *change {}
    }

    fn apply(
        _: &WebApplication,
        _: &Cx,
        _: Owner,
        change: NoChange,
    ) -> impl Future<Output = Result<Applied<()>, AccountError>> + Send {
        std::future::ready(change.absurd())
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        (): (),
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let clients = web.account.clients(reader.owner()).await?;
        let links: Vec<_> = clients
            .iter()
            .map(|client| AppLink {
                client: client.row(),
                page: developers::of(APP, &client.id),
            })
            .collect();
        let page = view! { cx =>
            piquel_ui::apps(links: &links, limit: MAX_OWNED_CLIENTS, new: NEW)
        };
        let head = Child::default();
        web.console_page(cx, Self::TITLE, reader, outcome, head, Child::new(page))
            .await
    }
}

/// Registering an app.
pub(in crate::web) struct NewApp;

impl AccountPage for NewApp {
    const SECTION: Section = Section::Developers;
    const PATH: &'static str = NEW;
    const TITLE: &'static str = Title::NewApp.as_str();
    type Change = NewAppChange;
    type Row = NewAppState;

    fn reopened(NewAppChange::Register { kind, draft }: &NewAppChange) -> NewAppState {
        NewAppState {
            kind: *kind,
            draft: Some(draft.clone()),
            registered: None,
        }
    }

    /// A public app goes on to its overview. A confidential one shows its secret,
    /// which nothing shows again, in this answer.
    async fn apply(
        web: &WebApplication,
        _: &Cx,
        owner: Owner,
        NewAppChange::Register { kind, draft }: NewAppChange,
    ) -> Result<Applied<NewAppState>, AccountError> {
        let new = NewClient {
            kind: kind.unwrap_or(NewAppChange::DEFAULT_KIND),
            settings: draft.into(),
        };
        let (client, secret) = web.account.create_client(&owner, new).await?;
        let overview = developers::of(APP, &client.id);
        Ok(match secret {
            Some(secret) => Applied::Revealed(NewAppState {
                registered: Some(Registered {
                    overview,
                    secret: Revealed::new(secret.expose().to_owned()),
                }),
                ..NewAppState::default()
            }),
            None => Applied::Moved {
                to: overview,
                notice: Notice::ClientRegistered,
            },
        })
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        state: NewAppState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let draft = state.draft.clone().unwrap_or_else(|| ClientDraft {
            scopes: DEFAULT_CLIENT_SCOPES.into_iter().collect(),
            ..ClientDraft::default()
        });
        let page = view! { cx =>
            piquel_ui::new_app(
                page: NEW,
                home: HOME,
                state: &state,
                draft: &draft,
                confirmed: reader.is_recent(),
                error: outcome.1.field_error(),
            )
        };
        let head = Child::default();
        web.console_page(cx, Self::TITLE, reader, outcome, head, Child::new(page))
            .await
    }
}

/// A stored client as the console shows it.
trait AsRow {
    /// The client's row.
    fn row(&self) -> ClientRow<'_>;
}

impl AsRow for StoredOidcClient {
    /// Its settings, status and last use.
    fn row(&self) -> ClientRow<'_> {
        ClientRow {
            id: &self.id,
            name: &self.display_name,
            kind: self.kind,
            status: ClientStatus::of(self.enabled, self.suspended_at),
            redirect_uris: &self.redirect_uris,
            post_logout_uris: &self.post_logout_uris,
            allowed_scopes: &self.allowed_scopes,
            allow_refresh: self.allow_refresh,
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
            backchannel_logout_uri: self.backchannel_logout_uri.as_deref(),
            last_used_at: self.last_used_at,
        }
    }
}

impl From<ClientDraft> for ClientSettings {
    /// The settings as the form sent them, its name trimmed.
    fn from(draft: ClientDraft) -> Self {
        Self {
            display_name: draft.display_name.trim().to_owned(),
            redirect_uris: draft.redirect_uris.into(),
            post_logout_uris: draft.post_logout_uris.into(),
            allowed_scopes: draft.scopes.names(),
            allow_refresh: draft.allow_refresh.0,
            require_pushed_authorization_requests: draft.require_pushed_authorization_requests.0,
        }
    }
}

impl WebApplication {
    /// The app the page's path names, as `owner` owns it. Another account's, a
    /// deleted or an unknown one is not found.
    async fn app(&self, cx: &Cx, owner: Owner) -> Result<OwnedClient, AccountError> {
        self.account.owned_client(owner, path_param::<Id>(cx)).await
    }

    /// The app the page's path names, as `reader` owns it, with the lifetimes of
    /// its secrets.
    async fn app_details(&self, cx: &Cx, reader: &Reader) -> Result<ClientDetails, AccountError> {
        let app = self.app(cx, reader.owner().clone()).await?;
        self.account.client(app).await
    }

    /// Answers with the console page titled `title`, `head` then `page`, at the
    /// status and with the messages of `outcome`.
    async fn console_page(
        &self,
        cx: &Cx,
        title: &str,
        reader: &Reader,
        outcome: (StatusCode, Messages<'_>),
        head: Child<'_>,
        page: Child<'_>,
    ) -> Result<Response, Failure> {
        let framed = Framed {
            section: Section::Developers,
            title,
            head,
            page,
        };
        self.account_page(cx, reader, outcome, &[], framed).await
    }

    /// Answers with the page `tab` of the app `client`, `page`, below the app's
    /// header and tabs, at the status and with the messages of `outcome`. A public
    /// app has no secrets tab.
    async fn app_page(
        &self,
        cx: &Cx,
        tab: AppTab,
        reader: &Reader,
        client: &StoredOidcClient,
        outcome: (StatusCode, Messages<'_>),
        page: Child<'_>,
    ) -> Result<Response, Failure> {
        let tabs: Vec<_> = APP_TABS
            .into_iter()
            .filter(|(tab, _)| *tab != AppTab::Secrets || client.kind == ClientKind::Confidential)
            .map(|(tab, route)| (tab, developers::of(route, &client.id)))
            .collect();
        let head = view! { cx =>
            piquel_ui::app_header(home: HOME, client: client.row(), tabs: &tabs, current: tab)
        };
        let title = tab.title(&client.display_name);
        self.console_page(cx, &title, reader, outcome, Child::new(head), page)
            .await
    }
}
