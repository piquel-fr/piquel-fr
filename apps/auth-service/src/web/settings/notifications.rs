//! `/settings/notifications`: the inbox, marking every notification read or one
//! unread, recognizing one from the banner of unread security notifications, and
//! turning a category's email on or off; `/settings/notifications/{id}`, one
//! notification, which opening marks read; `/unsubscribe`, which an
//! announcement's email links to turn announcements' email off; and
//! `/sign-out-everywhere`, which a security notification's email links to sign
//! the account out everywhere.

use crate::{
    account::{AccountError, Owner},
    notifications::{Link, LinkTarget, Links},
    routes::{
        self,
        page::{self, settings},
    },
    security::FETCH_SITE_HEADER,
    web::{
        Failure, WebApplication,
        account::{AccountPage, Applied, Framed, NoChange, Reader},
        settings::TABS,
    },
};
use sourceorigin_common::{
    NotificationId,
    notifications::{Notification, NotificationPreference},
};
use sourceorigin_ui::{
    Audience, Crumb, EmailRow, HistoryRow, Holdings, InboxChange, InboxPage, InboxRow, InboxState,
    Messages, Notice, NotificationState, Section, SignOutStep, Tab, Title, UnsubscribeStep,
};
use topcoat::{
    Error,
    context::{Cx, app_context},
    router::{
        Body, Method, StatusCode, parse_query_params, path_param,
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

    /// A refused change to the email preferences shows their dialog again.
    fn reopened(change: &InboxChange) -> InboxState {
        InboxState {
            email: matches!(change, InboxChange::Email { .. }),
            ..InboxState::default()
        }
    }

    /// Marking read or unread goes back to the inbox's newest page, which shows
    /// the change; recognizing a notification from the banner goes back to the
    /// settings page it was on; turning a category's email on or off reopens the
    /// email preferences dialog, which shows it.
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
            InboxChange::Recognized { id, back } => {
                web.account.mark_notification(&owner, id, true).await?;
                let to = TABS
                    .iter()
                    .find(|(tab, _)| Some(*tab) == back)
                    .map_or(settings::NOTIFICATIONS, |(_, page)| *page);
                return Ok(Applied::Moved {
                    to: to.to_owned(),
                    notice: Notice::Recognized,
                });
            }
            InboxChange::Email { category, email } => {
                let preference = NotificationPreference {
                    category,
                    email: email.0,
                };
                web.account
                    .set_notification_preference(&owner, preference)
                    .await?;
                return Ok(Applied::Opened(InboxState {
                    email: true,
                    ..InboxState::default()
                }));
            }
        }
        Ok(Applied::Opened(InboxState::default()))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        shown: InboxState,
        (status, messages): (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        // A refused preference is said in the dialog shown again, not behind it.
        let (alert, messages) = messages.into_dialog(shown.email);
        let viewer = reader.viewer();
        let inbox = web.account.inbox(&viewer, shown.before).await?;
        let rows: Vec<_> = inbox
            .page
            .notifications
            .iter()
            .map(InboxRow::from)
            .collect();
        let page = InboxPage {
            page: settings::NOTIFICATIONS,
            item: Some(settings::NOTIFICATION),
            shown,
            next: inbox.page.next,
            unread: inbox.unread,
            audience: Audience::Owner {
                confirmed: reader.is_recent(),
            },
            preferences: &inbox.preferences,
            alert,
        };
        let page = Child::new(view! { cx => sourceorigin_ui::inbox(rows: &rows, page: page) });
        web.settings_page(
            cx,
            Tab::Notifications,
            reader,
            (status, messages),
            &[],
            page,
        )
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

    /// Marks the notification read once opened from auth's own pages, unless to
    /// report its event, which marks it read once made, then shows it, with its history entry, the recovery's undo page while it can
    /// still be undone, and the dashboard's alerts for an alert's.
    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        shown: NotificationState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let id = Self::id(cx)?;
        if Self::opened_here(cx) && !shown.reporting {
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
        let alerts = web
            .dashboard
            .as_ref()
            .filter(|_| view.item.notification.links_alerts())
            .map(|dashboard| dashboard.dashboard().join(routes::dashboard::ALERTS));
        let page = sourceorigin_ui::NotificationPage {
            here: &here,
            inbox: settings::NOTIFICATIONS,
            history: settings::HISTORY,
            undo: (about_recovery && reader.recovery().is_some()).then_some(page::RECOVER_UNDO),
            alerts: alerts.as_deref(),
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
        let page = Child::new(view! { cx => sourceorigin_ui::notification(row: row, page: page) });
        // Under the inbox in the crumb, named by its subject.
        let framed = Framed {
            section: Section::Account,
            tab: Some(Tab::Notifications),
            trail: &[(
                Crumb::Label(Tab::Notifications.label()),
                settings::NOTIFICATIONS,
            )],
            title: Crumb::Name(&view.item.subject),
            head: Child::default(),
            page,
        };
        web.account_page(cx, reader, outcome, &[], framed).await
    }
}

/// The links of notifications' emails, which need no session: the token of each,
/// derived from the ID it names, is its credential. The unsubscribe link of an
/// announcement's email turns announcements' email off; the sign-out link of a
/// security notification's signs its account out everywhere.
impl WebApplication {
    /// `GET /unsubscribe`: asks to turn announcements' email off, for the account
    /// the link names. Opening it changes nothing, so a mail scanner that follows
    /// links does not unsubscribe anyone.
    pub(in crate::web) async fn unsubscription(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let here = uri(cx).to_string();
        match Self::linked(cx, &web.email.unsubscribe_links)? {
            Some(_) => {
                let step = UnsubscribeStep::Confirm { action: &here };
                web.unsubscribe_page(cx, StatusCode::OK, step).await
            }
            None => {
                web.unsubscribe_page(cx, StatusCode::NOT_FOUND, UnsubscribeStep::Invalid)
                    .await
            }
        }
    }

    /// `POST /unsubscribe`: turns announcements' email off for the account the
    /// link names, from the page's button, or in one click from a mail client
    /// (RFC 8058). The body, `List-Unsubscribe=One-Click` from a client, is not
    /// read: the link is all it needs.
    pub(in crate::web) async fn unsubscribe(cx: &Cx, _: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let Some(user) = Self::linked(cx, &web.email.unsubscribe_links)? else {
            return web
                .unsubscribe_page(cx, StatusCode::NOT_FOUND, UnsubscribeStep::Invalid)
                .await;
        };
        web.account.unsubscribe(user, Self::context(cx)?).await?;
        let step = UnsubscribeStep::Done {
            notifications: settings::NOTIFICATIONS,
        };
        web.unsubscribe_page(cx, StatusCode::OK, step).await
    }

    /// `GET /sign-out-everywhere`: asks to sign the account out everywhere, for
    /// the notification the link names. Opening it changes nothing, so a mail
    /// scanner that follows links signs no one out.
    pub(in crate::web) async fn sign_out_confirmation(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let here = uri(cx).to_string();
        match Self::linked(cx, &web.email.sign_out_links)? {
            Some(_) => {
                let step = SignOutStep::Confirm { action: &here };
                web.sign_out_page(cx, StatusCode::OK, step).await
            }
            None => {
                web.sign_out_page(cx, StatusCode::NOT_FOUND, SignOutStep::Invalid)
                    .await
            }
        }
    }

    /// `POST /sign-out-everywhere`: signs the account of the notification the
    /// link names out everywhere, once, while the link works.
    pub(in crate::web) async fn sign_out_everywhere(cx: &Cx, _: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let signed_out = match Self::linked(cx, &web.email.sign_out_links)? {
            Some(id) => {
                web.account
                    .sign_out_everywhere(id, Self::context(cx)?)
                    .await?
            }
            None => false,
        };
        if signed_out {
            let step = SignOutStep::Done {
                history: settings::HISTORY,
            };
            web.sign_out_page(cx, StatusCode::OK, step).await
        } else {
            web.sign_out_page(cx, StatusCode::NOT_FOUND, SignOutStep::Invalid)
                .await
        }
    }

    /// What the page's link names, if its token is the one Origin Auth made for
    /// it with `links`.
    fn linked<T: LinkTarget>(cx: &Cx, links: &Links<T>) -> Result<Option<T>, Failure>
    where
        Link<T>: serde::de::DeserializeOwned,
    {
        let Ok(link) = parse_query_params::<Link<T>>(cx) else {
            return Ok(None);
        };
        Ok(links.check(&link).map_err(Error::from)?)
    }

    /// The sign-out page at `step`, at `status`.
    async fn sign_out_page(
        &self,
        cx: &Cx,
        status: StatusCode,
        step: SignOutStep<'_>,
    ) -> Result<Response, Failure> {
        let view = view! { cx => sourceorigin_ui::sign_out_everywhere(step: step) };
        let title = Title::SignOut.as_str();
        Ok(self.render(cx, status, title, &[], view).await?)
    }

    /// The unsubscribe page at `step`, at `status`.
    async fn unsubscribe_page(
        &self,
        cx: &Cx,
        status: StatusCode,
        step: UnsubscribeStep<'_>,
    ) -> Result<Response, Failure> {
        let view = view! { cx => sourceorigin_ui::unsubscribe(step: step) };
        let title = Title::Unsubscribe.as_str();
        Ok(self.render(cx, status, title, &[], view).await?)
    }
}
