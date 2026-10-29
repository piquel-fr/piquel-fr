//! The signed-in account's pages, its settings and its developer console alike:
//! the frame they share, and the one way each shows itself and makes its changes.
//!
//! Each is an [`AccountPage`]. Its `GET` finds who acts and renders the page with
//! the rows its query opens. Its `POST` decodes the change its form names and makes
//! it, then answers `303` to the page with a notice, or on to where the change
//! leads, so reloading it posts nothing again. A change that makes a secret renders
//! the page with it at `200` instead, so the secret is in no URL. A change that
//! fails renders the page again, with the change's row still open and why above
//! it, or beside the setting it refused.

use super::{Failure, WebApplication};
use crate::{
    account::{AccountError, Owner, Viewer},
    clients::OwnedClientError,
    deletion::{AccountDeleted, AccountExport},
    federation::FlowCookie,
    routes::page,
    security::{ApiError, BrowserCookie, SessionError},
};
use piquel_common::ErrorChain;
use piquel_ui::{Alert, Area, FieldError, LoginQuery, Messages, Notice, Query, Recovery, Section};
use serde::{Deserialize, de::DeserializeOwned};
use topcoat::{
    Error,
    context::{Cx, app_context},
    router::{
        Body, RouteHandlerFn, StatusCode,
        content::Form,
        error::see_other,
        parse_query_params,
        request::{FromRequest, headers, uri},
        response::{IntoResponse, Response},
    },
    view::{Child, view},
};
use url::Url;

/// Each section of the account's pages and the page the account's bar links.
const SECTIONS: [(Section, &str); 2] = [
    (Section::Account, page::settings::HOME),
    (Section::Developers, page::developers::HOME),
];

/// A page of the signed-in account: its section and path, the change its form
/// posts, its query, what a change does, and how the page renders.
/// [`WebApplication::show`] and [`WebApplication::submit`] serve it.
pub(super) trait AccountPage: 'static {
    /// Its section: its frame, and what it asks a browser that is not signed in.
    const SECTION: Section;
    /// Its route; `{id}` names an app.
    const PATH: &'static str;
    /// Its title in the browser when it cannot render, or the browser is not
    /// signed in.
    const TITLE: &'static str;
    /// What its form posts, named by the form's hidden `action` field.
    type Change: DeserializeOwned + Send;
    /// Its query: which of its rows is open, and what only the answer to a change
    /// shows, such as what was typed into a change that failed.
    type Row: Query + DeserializeOwned + Default + Send + Sync;

    /// The row a failed `change` shows open again, with what was typed into it.
    fn reopened(change: &Self::Change) -> Self::Row;

    /// Makes `change` as `owner`, on the page `cx` requests, whose path may name
    /// an app.
    fn apply(
        web: &WebApplication,
        cx: &Cx,
        owner: Owner,
        change: Self::Change,
    ) -> impl Future<Output = Result<Applied<Self::Row>, AccountError>> + Send;

    /// Renders the page for `reader`, with `row` open, at the status and with the
    /// messages of `outcome`.
    fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        row: Self::Row,
        outcome: (StatusCode, Messages<'_>),
    ) -> impl Future<Output = Result<Response, Failure>> + Send;
}

/// What a page without a form posts: nothing decodes as it, so a post says the page
/// was out of date.
#[derive(Deserialize)]
pub(super) enum NoChange {}

impl NoChange {
    /// Anything at all, since there is no change to make it of.
    pub(super) const fn absurd<T>(&self) -> T {
        match *self {}
    }
}

/// What a change did, which its page answers.
pub(super) enum Applied<R> {
    /// The page says the notice, which a cookie carries, so a link can never claim
    /// a change that was not made.
    Done(Notice),
    /// Another of the account's pages says the notice, such as the apps once one
    /// is deleted.
    Moved {
        /// The page.
        to: String,
        /// What it says.
        notice: Notice,
    },
    /// The page shows the query `R`, such as what a report left to undo.
    Opened(R),
    /// The page renders again with `R`, whose skipped fields hold what only this
    /// answer may show, such as a new client secret: with no redirect, it is in no
    /// URL, history entry or cookie.
    Revealed(R),
    /// The browser saves the account's records, as a file.
    Download(Box<AccountExport>),
    /// The account was scheduled for deletion, which signed the browser out: the
    /// answer says when it is purged, and deletes the session cookie.
    Deleted(AccountDeleted),
    /// The browser goes on to the provider at `to`, with the cookie binding the
    /// flow to it.
    Elsewhere {
        /// Where.
        to: Url,
        /// The cookie binding the flow to the browser.
        cookie: FlowCookie,
    },
}

impl<R: Query> Applied<R> {
    /// Answers the change `owner` made on the page `P`: a `303` to where it leads,
    /// or the page with what it revealed.
    async fn answer<P: AccountPage<Row = R>>(
        self,
        web: &WebApplication,
        cx: &Cx,
        owner: Owner,
    ) -> Result<Response, Failure> {
        // The page's own path, not its route's template.
        let here = uri(cx).path();
        match self {
            Self::Revealed(row) => {
                let outcome = (StatusCode::OK, Messages::default());
                let reader = Reader::new(web, owner).await?;
                web.rendered::<P>(cx, &reader, row, outcome).await
            }
            Self::Done(notice) => WebApplication::notify(cx, here, notice),
            Self::Moved { to, notice } => WebApplication::notify(cx, &to, notice),
            Self::Opened(row) => Ok(see_other(row.on(here)?).into_response(cx)?),
            Self::Download(export) => WebApplication::download(cx, &export),
            Self::Deleted(deleted) => web.deleted(cx, &deleted).await,
            Self::Elsewhere { to, cookie } => {
                let mut response = see_other(to).into_response(cx)?;
                cookie.set_on(&mut response).map_err(Error::from)?;
                Ok(response)
            }
        }
    }
}

/// Whether a session can make the changes that need a recent passkey confirmation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Confirmation {
    /// It confirmed with a passkey recently enough.
    Recent,
    /// It did not, or the change just posted was refused for want of one.
    Stale,
}

/// The account a page shows, whether its session can make the changes that need
/// a recent passkey confirmation, and the account's recovery that can still be
/// undone, which every page asks about.
pub(super) struct Reader {
    /// Who reads.
    owner: Owner,
    /// Whether their session was confirmed recently enough.
    confirmation: Confirmation,
    /// The account's recovery that can still be undone, if any.
    recovery: Option<Recovery>,
}

impl Reader {
    /// `owner`, as their session is now, with their account's recovery, as
    /// `web` reads it once for the whole page: only a page that renders reads it.
    async fn new(web: &WebApplication, owner: Owner) -> Result<Self, Failure> {
        Ok(Self {
            confirmation: if owner.is_confirmed() {
                Confirmation::Recent
            } else {
                Confirmation::Stale
            },
            recovery: web.recovery(&owner).await?,
            owner,
        })
    }

    /// The owner, for the reads only they may make, such as their apps'.
    pub(super) const fn owner(&self) -> &Owner {
        &self.owner
    }

    /// The owner as the settings' reads take them.
    pub(super) fn viewer(&self) -> Viewer {
        Viewer::from(&self.owner)
    }

    /// Whether the session needs no passkey confirmation now. A form whose change
    /// always needs one asks for one otherwise.
    pub(super) fn is_recent(&self) -> bool {
        self.confirmation == Confirmation::Recent
    }

    /// The account's recovery that can still be undone, if any: no passkey but
    /// its own can be removed meanwhile.
    pub(super) const fn recovery(&self) -> Option<&Recovery> {
        self.recovery.as_ref()
    }
}

/// An account page as [`WebApplication::account_page`] frames it. Its views are
/// boxed, as they are large, before any page awaits with them.
pub(super) struct Framed<'a> {
    /// The section it belongs to.
    pub(super) section: Section,
    /// Its title in the browser.
    pub(super) title: &'a str,
    /// What opens it, above its messages: the settings tabs, or an app's header.
    pub(super) head: Child<'a>,
    /// The page.
    pub(super) page: Child<'a>,
}

impl From<AccountError> for Failure {
    /// An app the account does not have is missing. Any other failure to read the
    /// account is internal.
    fn from(error: AccountError) -> Self {
        match error {
            AccountError::Client(OwnedClientError::NotFound) => Self::Missing,
            error => Self::Internal(Error::from(error)),
        }
    }
}

impl WebApplication {
    /// The account page `P`'s entry in [`WebApplication::pages`].
    pub(super) fn entry<P: AccountPage>() -> (&'static str, RouteHandlerFn, RouteHandlerFn) {
        page!(P::PATH, P::TITLE, Self::show::<P>, Self::submit::<P>)
    }

    /// `GET` of the account page `P`: the page with the rows its query opens and,
    /// once, the notice of the change just made, or sign-in. A query that does not
    /// parse, from an edited or old link, opens nothing.
    async fn show<P: AccountPage>(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let Some(owner) = web.owner(cx).await? else {
            return web
                .signed_out(cx, P::SECTION, P::TITLE, StatusCode::OK)
                .await;
        };
        let notice = BrowserCookie::read_notice(headers(cx));
        let messages = Messages {
            notice,
            alert: None,
        };
        let row = parse_query_params(cx).unwrap_or_default();
        let outcome = (StatusCode::OK, messages);
        let reader = Reader::new(web, owner).await?;
        let mut response = web.rendered::<P>(cx, &reader, row, outcome).await?;
        if notice.is_some() {
            BrowserCookie::Notice
                .clear_on(&mut response)
                .map_err(Error::from)?;
        }
        Ok(response)
    }

    /// `POST` of the account page `P`: makes the change its form names, then
    /// answers as [`Applied`] says, or renders the page again with why it failed.
    /// A form from an older page that does not decode changes nothing.
    async fn submit<P: AccountPage>(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let Some(owner) = web.owner(cx).await? else {
            return web
                .signed_out(cx, P::SECTION, P::TITLE, StatusCode::UNAUTHORIZED)
                .await;
        };
        let Some(change) = Self::change::<P::Change>(cx, body).await else {
            let outcome = (
                StatusCode::BAD_REQUEST,
                Messages::alert(Alert::Page(piquel_ui::OUT_OF_DATE)),
            );
            let reader = Reader::new(web, owner).await?;
            return web
                .rendered::<P>(cx, &reader, P::Row::default(), outcome)
                .await;
        };
        let row = P::reopened(&change);
        let error = match P::apply(web, cx, owner.clone(), change).await {
            Ok(applied) => return applied.answer::<P>(web, cx, owner).await,
            Err(error) => error,
        };
        // A confirmation asked for is asked for again, by the page's forms.
        let stale = matches!(
            error,
            AccountError::Owner(SessionError::StepUpRequired { .. })
        );
        let (status, message, field) = match error {
            // A setting refused is said beside its input.
            AccountError::Client(OwnedClientError::InvalidSetting(invalid)) => (
                StatusCode::BAD_REQUEST,
                invalid.reason().to_string(),
                Some(invalid.field().clone()),
            ),
            // Internal failures are logged here, once, as `ApiError` logs them.
            error => {
                let error = ApiError::from(error);
                let (status, message) = error.public();
                (status, message.to_owned(), None)
            }
        };
        // Read once the failure is logged, so a read that fails too hides nothing.
        let mut reader = Reader::new(web, owner).await?;
        if stale {
            reader.confirmation = Confirmation::Stale;
        }
        let alert = match &field {
            Some(field) => Alert::Field(FieldError {
                field,
                message: &message,
            }),
            None => Alert::Page(&message),
        };
        web.rendered::<P>(cx, &reader, row, (status, Messages::alert(alert)))
            .await
    }

    /// Renders the account page `P` for `reader`, with `row` open, at the status
    /// and with the messages of `outcome`. When the account has no app by the ID
    /// its path names, the page says so instead, at `404`.
    async fn rendered<P: AccountPage>(
        &self,
        cx: &Cx,
        reader: &Reader,
        row: P::Row,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        match P::render(self, cx, reader, row, outcome).await {
            Err(Failure::Missing) => {
                let head = view! { cx => piquel_ui::back_to_apps(home: page::developers::HOME) };
                let framed = Framed {
                    section: P::SECTION,
                    title: P::TITLE,
                    head: Child::new(head),
                    page: Child::default(),
                };
                let missing = Messages::alert(Alert::Page(piquel_ui::MISSING));
                self.account_page(cx, reader, (StatusCode::NOT_FOUND, missing), &[], framed)
                    .await
            }
            rendered => rendered,
        }
    }

    /// The change a page's form posted, as `T`, or `None` when it does not decode,
    /// as a form from an older page does. Why is logged at debug level, as the
    /// client caused it.
    pub(super) async fn change<T: DeserializeOwned + Send>(cx: &Cx, body: Body) -> Option<T> {
        Form::from_request(cx, body)
            .await
            .inspect_err(|error| {
                tracing::debug!(error = %ErrorChain(&**error), "page form rejected");
            })
            .ok()
            .map(|Form(change)| change)
    }

    /// The owner of the request's browser session, if it has one.
    pub(super) async fn owner(&self, cx: &Cx) -> Result<Option<Owner>, Failure> {
        Ok(self.account.owner(Self::context(cx)?, headers(cx)).await?)
    }

    /// Sends the browser to the page `to`, which says `notice` once. A cookie
    /// carries it, so a link can never claim a change that was not made.
    pub(super) fn notify(cx: &Cx, to: &str, notice: Notice) -> Result<Response, Failure> {
        let mut response = see_other(to).into_response(cx)?;
        BrowserCookie::set_notice_on(&mut response, notice).map_err(Error::from)?;
        Ok(response)
    }

    /// Answers with the account page `framed`, at the status and with the messages
    /// of `outcome`, in its section's frame, below the account's bar and what the
    /// account's recovery that can still be undone asks, if any. Its forms may
    /// redirect to `targets`.
    pub(super) async fn account_page(
        &self,
        cx: &Cx,
        reader: &Reader,
        (status, messages): (StatusCode, Messages<'_>),
        targets: &[Url],
        framed: Framed<'_>,
    ) -> Result<Response, Failure> {
        let Framed {
            section,
            title,
            head,
            page,
        } = framed;
        let profile = match self.account.profile(&reader.viewer()).await {
            Ok(profile) => profile,
            Err(AccountError::Owner(SessionError::Missing)) => {
                return self
                    .signed_out(cx, section, title, StatusCode::UNAUTHORIZED)
                    .await;
            }
            Err(error) => return Err(error.into()),
        };
        let session = reader.owner().session_id();
        let confirmed = reader.owner().was_passkey_confirmed();
        let page = view! { cx =>
            piquel_ui::account(
                section: section,
                user: reader.owner().user(),
                display_name: &profile.display_name,
                handle: profile.handle.as_str(),
                sections: &SECTIONS,
                sign_out: page::LOGOUT,
                recovery: view! {
                    if let Some(recovery) = reader.recovery() {
                        piquel_ui::recovery_banner(
                            recovery: recovery,
                            session: session,
                            confirmed: confirmed,
                            undo: page::RECOVER_UNDO,
                        )
                    }
                },
                head: head,
                messages: messages,
                (page)
            )
        };
        Ok(self
            .render(cx, status, title, Area::Section(section), targets, page)
            .await?)
    }

    /// Answers with the page titled `title` of `section` for a browser that is not
    /// signed in, at `status`: a link to sign in, which comes back to the page as
    /// requested.
    async fn signed_out(
        &self,
        cx: &Cx,
        section: Section,
        title: &str,
        status: StatusCode,
    ) -> Result<Response, Failure> {
        let here = uri(cx)
            .path_and_query()
            .map_or(page::settings::HOME, |path| path.as_str());
        let sign_in = LoginQuery {
            return_to: Some(here.to_owned()),
            ..LoginQuery::default()
        }
        .on(page::LOGIN)?;
        let page = view! { cx => piquel_ui::signed_out(section: section, sign_in: &sign_in) };
        Ok(self
            .render(cx, status, title, Area::Section(section), &[], page)
            .await?)
    }
}
