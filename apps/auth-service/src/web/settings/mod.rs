//! The account's settings, at `/settings`: the frame every settings page shares,
//! and the one way each page shows itself and makes its changes.
//!
//! Each tab is a [`SettingsPage`]. Its `GET` finds who acts and renders the page
//! with the rows its query opens. Its `POST` decodes the change its form names,
//! applies it, and answers `303` to the page with a notice, or on to where the
//! change leads, so reloading it posts nothing again; a change that fails renders
//! the page again, with the change's row still open and why above it. Confirming an
//! address, from its emailed link, is a page of its own.

/// Email addresses, and confirming one.
mod emails;
/// Security history.
mod history;
/// Signed-in devices.
mod sessions;
/// Passkeys and social sign-in.
mod sign_in;
#[cfg(test)]
mod tests;

pub(super) use emails::Addresses;
pub(super) use history::History;
pub(super) use sessions::Devices;
pub(super) use sign_in::SignInMethods;

use super::{Failure, WebApplication};
use crate::{
    account::{AccountError, Owner, Viewer},
    emails::EmailView,
    federation::FlowCookie,
    routes::page::{self, settings},
    security::{ApiError, BrowserCookie, SessionError},
};
use piquel_common::ErrorChain;
use piquel_ui::{Area, EmailRow, Messages, Notice, Query, Tab};
use serde::de::DeserializeOwned;
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
    view::{Child, View, view},
};
use url::{Url, form_urlencoded};

/// Each tab and the page it links.
const TABS: [(Tab, &str); 4] = [
    (Tab::SignIn, settings::HOME),
    (Tab::Emails, settings::EMAILS),
    (Tab::Devices, settings::SESSIONS),
    (Tab::History, settings::HISTORY),
];

/// One settings tab: its path, the change its form posts, its query, what a change
/// does, and how the page renders. [`WebApplication::show`] and
/// [`WebApplication::submit`] serve it.
pub(super) trait SettingsPage: 'static {
    /// Its tab.
    const TAB: Tab;
    /// Its path.
    const PATH: &'static str;
    /// What its form posts, named by the form's hidden `action` field.
    type Change: DeserializeOwned + Send;
    /// Its query: which of its rows is open, and anything typed into a change that
    /// failed.
    type Row: Query + DeserializeOwned + Default + Send + Sync;

    /// The row a failed `change` shows open again, with what was typed into it.
    fn reopened(change: &Self::Change) -> Self::Row;

    /// Makes `change` as `owner`.
    fn apply(
        web: &WebApplication,
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

/// What a change did, which its page answers with a `303`.
pub(super) enum Applied<R> {
    /// The page shows the notice, which a cookie carries, so a link can never claim
    /// a change that was not made.
    Done(Notice),
    /// The page shows the query `R`, such as what a report left to undo.
    Opened(R),
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
    /// The `303` answering the change, made on the page at `path`.
    fn response(self, cx: &Cx, path: &str) -> topcoat::Result<Response> {
        let (to, notice) = match self {
            Self::Done(notice) => (path.to_owned(), Some(notice)),
            Self::Opened(row) => (row.on(path)?, None),
            Self::Elsewhere { to, cookie } => {
                let mut response = see_other(to).into_response(cx)?;
                cookie.set_on(&mut response)?;
                return Ok(response);
            }
        };
        let mut response = see_other(to).into_response(cx)?;
        if let Some(notice) = notice {
            BrowserCookie::set_notice_on(&mut response, notice)?;
        }
        Ok(response)
    }
}

/// The account a settings page shows, and whether its session can make the changes
/// that need a recent passkey confirmation.
pub(super) struct Reader {
    /// Who reads.
    viewer: Viewer,
    /// Whether the session was confirmed recently enough.
    confirmed: bool,
}

impl From<&Owner> for Reader {
    /// The owner, as their session is now.
    fn from(owner: &Owner) -> Self {
        Self {
            viewer: Viewer::from(owner),
            confirmed: owner.is_confirmed(),
        }
    }
}

impl From<AccountError> for Failure {
    /// The account could not be read: an internal failure.
    fn from(error: AccountError) -> Self {
        Self::Internal(Error::from(error))
    }
}

impl<'a> From<&'a EmailView> for EmailRow<'a> {
    /// The address as a page shows it.
    fn from(email: &'a EmailView) -> Self {
        Self {
            id: email.id,
            address: &email.address,
            verified: email.verified,
            primary: email.primary,
        }
    }
}

impl WebApplication {
    /// The settings tab `P`'s entry in [`WebApplication::pages`].
    pub(super) fn settings<P: SettingsPage>() -> (&'static str, RouteHandlerFn, RouteHandlerFn) {
        page!(P::PATH, P::TAB.label(), Self::show::<P>, Self::submit::<P>,)
    }

    /// `GET` of the settings tab `P`: the account's page with the rows its query
    /// opens and, once, the notice of the change just made, or sign-in. A query that
    /// does not parse, from an edited or old link, opens nothing.
    async fn show<P: SettingsPage>(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let Some(owner) = web.owner(cx).await? else {
            return web.signed_out(cx, P::TAB, StatusCode::OK).await;
        };
        let notice = BrowserCookie::read_notice(headers(cx));
        let messages = Messages {
            notice,
            alert: None,
        };
        let row = parse_query_params(cx).unwrap_or_default();
        let outcome = (StatusCode::OK, messages);
        let mut response = P::render(web, cx, &Reader::from(&owner), row, outcome).await?;
        if notice.is_some() {
            BrowserCookie::Notice
                .clear_on(&mut response)
                .map_err(Error::from)?;
        }
        Ok(response)
    }

    /// `POST` of the settings tab `P`: makes the change its form names, then
    /// answers `303` to the page with what it did, or on to where it leads, or
    /// renders the page again with why it failed. A form from an older page that
    /// does not decode changes nothing.
    async fn submit<P: SettingsPage>(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let Some(owner) = web.owner(cx).await? else {
            return web.signed_out(cx, P::TAB, StatusCode::UNAUTHORIZED).await;
        };
        let mut reader = Reader::from(&owner);
        let Some(change) = Self::change::<P::Change>(cx, body).await else {
            let outcome = (
                StatusCode::BAD_REQUEST,
                Messages::alert(piquel_ui::OUT_OF_DATE),
            );
            return P::render(web, cx, &reader, P::Row::default(), outcome).await;
        };
        let row = P::reopened(&change);
        match P::apply(web, owner, change).await {
            Ok(applied) => Ok(applied.response(cx, P::PATH)?),
            Err(error) => {
                let step_up = matches!(
                    error,
                    AccountError::Owner(SessionError::StepUpRequired { .. })
                );
                // A confirmation asked for is asked for again, by the page's form.
                reader.confirmed &= !step_up;
                // Internal failures are logged here, once, as `ApiError` logs them.
                let error = ApiError::from(error);
                let (status, message) = error.public();
                P::render(web, cx, &reader, row, (status, Messages::alert(message))).await
            }
        }
    }

    /// The change a settings page's form posted, as `T`, or `None` when it does not
    /// decode, as a form from an older page does. Why is logged at debug level, as
    /// the client caused it.
    async fn change<T: DeserializeOwned + Send>(cx: &Cx, body: Body) -> Option<T> {
        Form::from_request(cx, body)
            .await
            .inspect_err(|error| {
                tracing::debug!(error = %ErrorChain(&**error), "settings form rejected");
            })
            .ok()
            .map(|Form(change)| change)
    }

    /// The owner of the request's browser session, if it has one.
    async fn owner(&self, cx: &Cx) -> Result<Option<Owner>, Failure> {
        Ok(self.account.owner(Self::context(cx)?, headers(cx)).await?)
    }

    /// Answers with the settings page `tab`, `page`, in the frame, with the
    /// account's bar, the tabs and the messages of `outcome`, at its status. Its
    /// forms may redirect to `targets`.
    async fn settings_page(
        &self,
        cx: &Cx,
        tab: Tab,
        reader: &Reader,
        (status, messages): (StatusCode, Messages<'_>),
        targets: &[Url],
        page: impl View,
    ) -> Result<Response, Failure> {
        let profile = match self.account.profile(&reader.viewer).await {
            Ok(profile) => profile,
            Err(AccountError::Owner(SessionError::Missing)) => {
                return self.signed_out(cx, tab, StatusCode::UNAUTHORIZED).await;
            }
            Err(error) => return Err(error.into()),
        };
        let page = Child::new(page);
        let page = view! { cx =>
            piquel_ui::settings_frame(
                piquel_ui::account(
                    display_name: &profile.display_name,
                    handle: &profile.handle,
                    sign_out: page::LOGOUT,
                    tabs: &TABS,
                    current: tab,
                    messages: messages,
                    (page)
                )
            )
        };
        Ok(self
            .render(cx, status, tab.label(), Area::Account, targets, page)
            .await?)
    }

    /// Answers with the settings page `tab` for a browser that is not signed in, at
    /// `status`: a link to sign in, which comes back to the page as requested.
    async fn signed_out(&self, cx: &Cx, tab: Tab, status: StatusCode) -> Result<Response, Failure> {
        let here = uri(cx)
            .path_and_query()
            .map_or(settings::HOME, |path| path.as_str());
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", here)
            .finish();
        let sign_in = format!("{}?{query}", page::LOGIN);
        let page =
            view! { cx => piquel_ui::settings_frame(piquel_ui::signed_out(sign_in: &sign_in)) };
        Ok(self
            .render(cx, status, tab.label(), Area::Account, &[], page)
            .await?)
    }
}
