//! `/settings/notifications`: the inbox, marking every notification read or one
//! unread; and `/settings/notifications/{id}`, one notification, which opening
//! marks read.

use crate::{
    account::{AccountError, Owner},
    routes::page::{self, settings},
    security::FETCH_SITE_HEADER,
    web::{
        Failure, WebApplication,
        account::{AccountPage, Applied, Framed, NoChange, Reader},
    },
};
use piquel_common::{NotificationId, notifications::Notification};
use piquel_ui::{
    Audience, Crumb, EmailRow, HistoryRow, Holdings, InboxChange, InboxPage, InboxRow, InboxState,
    Messages, NotificationState, Section, Tab,
};
use topcoat::{
    context::Cx,
    router::{
        Method, StatusCode, path_param,
        request::{headers, method, uri},
        response::Response,
    },
    view::{Child, view},
};

// The notification a notification's page names. Unparsed: an ID that is not
// one is not the account's either, and is missing like any other.
path_param!(id);

/// The inbox, a page at a time.
pub(in crate::web) struct Inbox;

/// One notification's page.
pub(in crate::web) struct NotificationPage;

impl AccountPage for Inbox {
    const SECTION: Section = Section::Account;
    const PATH: &'static str = settings::NOTIFICATIONS;
    const TITLE: &'static str = Tab::Notifications.label();
    type Change = InboxChange;
    type Row = InboxState;

    fn reopened(_: &InboxChange) -> InboxState {
        InboxState::default()
    }

    /// Marking read or unread goes back to the inbox's newest page, which shows
    /// the change.
    async fn apply(
        web: &WebApplication,
        _: &Cx,
        owner: Owner,
        change: InboxChange,
    ) -> Result<Applied<InboxState>, AccountError> {
        match change {
            InboxChange::ReadAll => web.account.read_all_notifications(&owner).await?,
            InboxChange::MarkUnread { id } => {
                web.account.mark_notification(&owner, id, false).await?;
            }
        }
        Ok(Applied::Opened(InboxState::default()))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        shown: InboxState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let viewer = reader.viewer();
        let notifications = web.account.notifications(&viewer, shown.before).await?;
        let unread = web.account.unread_notifications(&viewer).await?;
        let rows: Vec<_> = notifications
            .notifications
            .iter()
            .map(InboxRow::from)
            .collect();
        let page = InboxPage {
            page: settings::NOTIFICATIONS,
            item: Some(settings::NOTIFICATION),
            shown,
            next: notifications.next,
            unread,
            audience: Audience::Owner {
                confirmed: reader.is_recent(),
            },
        };
        let page = Child::new(view! { cx => piquel_ui::inbox(rows: &rows, page: page) });
        web.settings_page(cx, Tab::Notifications, reader, outcome, &[], page)
            .await
    }
}

impl NotificationPage {
    /// Whether the browser navigated here from auth's own pages, or by itself,
    /// as from a bookmark or the address bar (`Sec-Fetch-Site`): only then does
    /// opening the page mark it read, so a link on another site cannot dismiss a
    /// notification unseen. A browser that does not say marks nothing.
    fn opened_here(cx: &Cx) -> bool {
        method(cx) == Method::GET
            && matches!(
                headers(cx)
                    .get(FETCH_SITE_HEADER)
                    .and_then(|value| value.to_str().ok()),
                Some("same-origin" | "none")
            )
    }

    /// The notification the path names, which is missing if it is not an ID.
    fn id(cx: &Cx) -> Result<NotificationId, Failure> {
        path_param::<Id>(cx).parse().map_err(|_| Failure::Missing)
    }
}

impl AccountPage for NotificationPage {
    const SECTION: Section = Section::Account;
    const PATH: &'static str = settings::NOTIFICATION;
    const TITLE: &'static str = Tab::Notifications.label();
    type Change = NoChange;
    type Row = NotificationState;

    fn reopened(change: &NoChange) -> NotificationState {
        change.absurd()
    }

    fn apply(
        _: &WebApplication,
        _: &Cx,
        _: Owner,
        change: NoChange,
    ) -> impl Future<Output = Result<Applied<NotificationState>, AccountError>> + Send {
        std::future::ready(change.absurd())
    }

    /// Marks the notification read once opened from auth's own pages, then
    /// shows it, with its history entry and the recovery's undo page while it
    /// can still be undone.
    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        shown: NotificationState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let id = Self::id(cx)?;
        if Self::opened_here(cx) {
            web.account
                .mark_notification(reader.owner(), id, true)
                .await?;
        }
        let viewer = reader.viewer();
        let view = web.account.notification(&viewer, id).await?;
        let passkeys = web.account.passkeys(&viewer).await?;
        let emails = web.account.emails(&viewer).await?;
        let linked: Vec<_> = web
            .account
            .identities(&viewer)
            .await?
            .into_iter()
            .map(|identity| identity.provider)
            .collect();
        let email_rows: Vec<_> = emails.iter().map(EmailRow::from).collect();
        let entry = view.history.as_ref().map(HistoryRow::from);
        let about_recovery = matches!(
            view.item.notification,
            Notification::Recovered | Notification::AccountSecured { kept: true }
        );
        let here = uri(cx).path().to_owned();
        let page = piquel_ui::NotificationPage {
            here: &here,
            inbox: settings::NOTIFICATIONS,
            history: settings::HISTORY,
            undo: (about_recovery && reader.recovery().is_some()).then_some(page::RECOVER_UNDO),
            entry: entry.as_ref(),
            holds: Holdings {
                passkeys: &passkeys,
                emails: &email_rows,
                linked: &linked,
                recovery: reader.recovery(),
            },
            shown,
        };
        let row = InboxRow::from(&view.item);
        let page = Child::new(view! { cx => piquel_ui::notification(row: row, page: page) });
        // Under the inbox in the crumb, named by its subject.
        let framed = Framed {
            section: Section::Account,
            tab: Some(Tab::Notifications),
            trail: &[(
                Crumb::Label(Tab::Notifications.label()),
                settings::NOTIFICATIONS,
            )],
            title: Crumb::Name(view.item.subject),
            head: Child::default(),
            page,
        };
        web.account_page(cx, reader, outcome, &[], framed).await
    }
}
