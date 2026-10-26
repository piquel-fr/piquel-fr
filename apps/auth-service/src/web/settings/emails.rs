//! `/settings/emails`: the account's addresses, and confirming one from its link.

use crate::{
    account::{AccountError, Owner, Subject},
    routes::page::settings,
    security::ApiError,
    web::{
        Failure, WebApplication,
        account::{AccountPage, Applied, Reader},
    },
};
use piquel_ui::{Area, EmailChange, EmailRow, EmailsState, Messages, Notice, Section, Tab, Title};
use serde::Deserialize;
use topcoat::{
    context::{Cx, app_context},
    router::{Body, StatusCode, response::Response},
    view::{Child, View, view},
};

/// What the verification page posts.
#[derive(Deserialize)]
struct Verification {
    /// The link's token, which the passkey script copies from its fragment.
    token: String,
}

/// The addresses page.
pub(in crate::web) struct Addresses;

impl Addresses {
    /// Its tab.
    const TAB: Tab = Tab::Emails;
}

impl AccountPage for Addresses {
    const SECTION: Section = Section::Account;
    const PATH: &'static str = settings::EMAILS;
    const TITLE: &'static str = Self::TAB.label();
    type Change = EmailChange;
    type Row = EmailsState;

    fn reopened(change: &EmailChange) -> EmailsState {
        match change {
            EmailChange::Add { email } => EmailsState {
                removing: None,
                adding: Some(email.clone()),
            },
            EmailChange::Remove { id } => EmailsState {
                removing: Some(*id),
                adding: None,
            },
            EmailChange::Primary { .. } => EmailsState::default(),
        }
    }

    async fn apply(
        web: &WebApplication,
        _: &Cx,
        owner: Owner,
        change: EmailChange,
    ) -> Result<Applied<EmailsState>, AccountError> {
        let notice = match change {
            EmailChange::Add { email } => {
                web.account.add_email(&owner, &web.email, &email).await?;
                Notice::EmailAdded
            }
            EmailChange::Primary { id } => {
                web.account
                    .make_primary_email(&Subject::from(owner), id)
                    .await?;
                Notice::EmailPrimary
            }
            EmailChange::Remove { id } => {
                web.account.remove_email(&Subject::from(owner), id).await?;
                Notice::EmailRemoved
            }
        };
        Ok(Applied::Done(notice))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        state: EmailsState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let mut emails = web.account.emails(&reader.viewer()).await?;
        emails.sort_by_key(|email| !email.primary);
        let rows: Vec<_> = emails.iter().map(EmailRow::from).collect();
        let sends = web.email.smtp.is_some();
        let page = Child::new(view! { cx =>
            piquel_ui::addresses(
                page: settings::EMAILS,
                emails: &rows,
                state: &state,
                confirmed: reader.is_recent(),
                sends: sends,
            )
        });
        web.settings_page(cx, Self::TAB, reader, outcome, &[], page)
            .await
    }
}

impl WebApplication {
    /// `GET /settings/emails/verify`: the confirmation of an address, from its
    /// link. It never verifies: mail scanners open links.
    pub(in crate::web) async fn verify(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        web.verify_page(cx, StatusCode::OK, None).await
    }

    /// `POST /settings/emails/verify`: confirms the address the link's token names,
    /// signed in or not; an owner signed in to another account cannot.
    pub(in crate::web) async fn confirm_address(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let owner = web.owner(cx).await?;
        let Some(Verification { token }) = Self::change(cx, body).await else {
            return web
                .verify_page(cx, StatusCode::BAD_REQUEST, Some(piquel_ui::OUT_OF_DATE))
                .await;
        };
        match web
            .account
            .verify_email(&token, owner.as_ref(), Self::context(cx)?)
            .await
        {
            Ok(verified) => {
                let page = view! { cx =>
                    piquel_ui::verified(
                        address: &verified.address,
                        primary: verified.primary,
                        emails: settings::EMAILS,
                    )
                };
                web.verification(cx, StatusCode::OK, page).await
            }
            Err(error) => {
                let error = ApiError::from(error);
                let (status, message) = error.public();
                web.verify_page(cx, status, Some(message)).await
            }
        }
    }

    /// The confirmation page, with the `alert` of a failed confirmation, at
    /// `status`.
    async fn verify_page(
        &self,
        cx: &Cx,
        status: StatusCode,
        alert: Option<&str>,
    ) -> Result<Response, Failure> {
        let page = view! { cx =>
            piquel_ui::verify(action: settings::VERIFY, emails: settings::EMAILS, alert: alert)
        };
        self.verification(cx, status, page).await
    }

    /// Answers with `page`, the confirmation of an address or its outcome, at
    /// `status`.
    async fn verification(
        &self,
        cx: &Cx,
        status: StatusCode,
        page: impl View,
    ) -> Result<Response, Failure> {
        let title = Title::VerifyEmail.as_str();
        Ok(self
            .render(
                cx,
                status,
                title,
                Area::Section(Section::Account),
                &[],
                page,
            )
            .await?)
    }
}
