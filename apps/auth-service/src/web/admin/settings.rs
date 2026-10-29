//! An account's settings, which an administrator changes on its owner's behalf:
//! the owner's own sections and operations, for the changes administrators share
//! with owners, each with the reason they give, and the owner's handle.
//!
//! Reads take a [`Viewer`] and changes a [`Subject`] of the administrator, so the
//! service checks their rights, refuses an administrator's account, and records
//! the reason with each change, which the owner sees in their history. Nothing
//! here adds a way in or an address: those are the owner's alone.

use super::{AdminApplication as App, Refusal, Refused, users::Account};
use crate::{
    Reason,
    account::{Subject, Viewer},
    admin::SignedInAdmin,
    handles::HandlesError,
    security::ApiError,
    web::{
        account::AccountPage,
        settings::{Addresses, ConnectedApps, SignInMethods},
    },
};
use piquel_common::{Handle, UserId};
use piquel_ui::{
    Audience, ConnectedAppChange, ConnectedAppRow, EmailChange, EmailRow, ProviderRow, Recovery,
    SignInChange, Tab,
};
use serde::{Deserialize, de::DeserializeOwned};
use topcoat::{
    Result,
    context::Cx,
    router::{
        Body, Method, StatusCode,
        content::Form,
        href, parse_query_params, path_param,
        request::{FromRequest, method},
        response::Response,
        route,
    },
    view::{Child, View, view},
};

/// A settings change an administrator posts: the owner's change, and why.
#[derive(Clone, Deserialize)]
struct Administered<C> {
    /// The change, as the owner's form names it.
    #[serde(flatten)]
    change: C,
    /// Why, recorded with the change and shown to the owner in their history.
    reason: String,
}

/// The form giving an account a new handle.
#[derive(Clone, Deserialize)]
struct NewHandle {
    /// The handle.
    handle: String,
    /// Why, recorded with the change and shown to the owner in their history.
    reason: String,
}

/// `/users/{account}/sign-in`: the account's passkeys and linked identities, to
/// rename or remove a passkey, or unlink a provider.
#[route([GET, POST] "/users/{account}/sign-in")]
pub(super) async fn sign_in(cx: &Cx, body: Body) -> Result<Response> {
    let (admin, user) = App::settings(cx).await?;
    let form = App::posted::<Administered<SignInChange>>(cx, body).await?;
    let refused = App::submit(cx, form, App::here(cx), |posted| async move {
        let subject = App::subject(user, admin, posted.reason)?;
        let account = &App::of(cx).account;
        match posted.change {
            SignInChange::Rename { id, friendly_name } => {
                let name = friendly_name.trim().to_owned();
                Ok(account.rename_passkey(&subject, id, name).await?)
            }
            SignInChange::Remove { id } => Ok(account.revoke_passkey(&subject, id).await?),
            SignInChange::Unlink { provider } => {
                Ok(account.unlink_identity(&subject, provider).await?)
            }
            // The owner renames, with the cooldown; an administrator, on the handle
            // page.
            SignInChange::Handle { .. } | SignInChange::Link { .. } | SignInChange::Enrolled {} => {
                Err(App::owners())
            }
        }
    })
    .await?;
    let viewer = App::viewer(user, admin);
    let account = &App::of(cx).account;
    let passkeys = account.passkeys(&viewer).await?;
    let identities = account.identities(&viewer).await?;
    let recovery = account.recovery_notice(&viewer).await?.map(Recovery::from);
    // Only a linked provider is listed: an administrator links none.
    let providers: Vec<_> = identities
        .iter()
        .map(|identity| ProviderRow {
            provider: identity.provider,
            identity: Some(identity),
            enabled: true,
        })
        .collect();
    let (state, reason) = App::reopened::<SignInMethods>(cx, refused.as_ref());
    let (page, passkeys, providers, state, recovery) =
        (&App::here(cx), &passkeys, &providers, &state, &recovery);
    let section = view! { cx =>
        piquel_ui::sign_in_methods(
            page: page.as_str(),
            passkeys: passkeys,
            providers: providers,
            state: state,
            audience: Audience::Administrator { reason },
            android: false,
            recovery: recovery.as_ref(),
        )
    };
    App::settings_page(cx, user, Tab::SignIn, refused.as_deref(), section).await
}

/// `/users/{account}/emails`: the account's addresses, to make a verified one
/// primary, or remove one.
#[route([GET, POST] "/users/{account}/emails")]
pub(super) async fn emails(cx: &Cx, body: Body) -> Result<Response> {
    let (admin, user) = App::settings(cx).await?;
    let form = App::posted::<Administered<EmailChange>>(cx, body).await?;
    let refused = App::submit(cx, form, App::here(cx), |posted| async move {
        let subject = App::subject(user, admin, posted.reason)?;
        let account = &App::of(cx).account;
        match posted.change {
            EmailChange::Primary { id } => Ok(account.make_primary_email(&subject, id).await?),
            EmailChange::Remove { id } => Ok(account.remove_email(&subject, id).await?),
            EmailChange::Add { .. } => Err(App::owners()),
        }
    })
    .await?;
    let emails = App::of(cx)
        .account
        .emails(&App::viewer(user, admin))
        .await?;
    let rows: Vec<_> = emails.iter().map(EmailRow::from).collect();
    let (state, reason) = App::reopened::<Addresses>(cx, refused.as_ref());
    let (page, rows, state) = (&App::here(cx), &rows, &state);
    let section = view! { cx =>
        piquel_ui::addresses(
            page: page.as_str(),
            emails: rows,
            state: state,
            audience: Audience::Administrator { reason },
            sends: false,
        )
    };
    App::settings_page(cx, user, Tab::Emails, refused.as_deref(), section).await
}

/// `/users/{account}/apps`: the apps that keep access to the account, to remove
/// one's access.
#[route([GET, POST] "/users/{account}/apps")]
pub(super) async fn apps(cx: &Cx, body: Body) -> Result<Response> {
    let (admin, user) = App::settings(cx).await?;
    let form = App::posted::<Administered<ConnectedAppChange>>(cx, body).await?;
    let refused = App::submit(cx, form, App::here(cx), |posted| async move {
        let subject = App::subject(user, admin, posted.reason)?;
        let ConnectedAppChange::Remove { client_id } = posted.change;
        let account = &App::of(cx).account;
        account
            .remove_app(&subject, &client_id)
            .await
            .map_err(Refusal::from)
    })
    .await?;
    let apps = App::of(cx).account.apps(&App::viewer(user, admin)).await?;
    let rows: Vec<_> = apps.iter().map(ConnectedAppRow::from).collect();
    let (state, reason) = App::reopened::<ConnectedApps>(cx, refused.as_ref());
    let (page, rows, state) = (&App::here(cx), &rows, &state);
    let section = view! { cx =>
        piquel_ui::connected_apps(
            page: page.as_str(),
            rows: rows,
            state: state,
            audience: Audience::Administrator { reason },
        )
    };
    App::settings_page(cx, user, Tab::Apps, refused.as_deref(), section).await
}

/// `/users/{account}/handle`: gives the account a new handle, such as one that
/// impersonates another account, without the settings' cooldown. A reserved
/// handle is refused here: only the terminal may assign one.
#[route([GET, POST] "/users/{account}/handle")]
pub(super) async fn handle(cx: &Cx, form: Option<Form<NewHandle>>) -> Result<Response> {
    let (admin, user) = App::settings(cx).await?;
    let back = App::account(cx, user);
    let refused = App::submit(cx, form, back.clone(), |input: NewHandle| async move {
        let handle = Handle::parse(input.handle.trim()).map_err(HandlesError::from)?;
        let reason = Reason::parse(input.reason)?;
        App::of(cx)
            .service
            .rename_handle(&admin.operator, user, handle, reason, false)
            .await
    })
    .await?;
    let (typed, reason) = refused.as_ref().map_or(("", ""), |refused| {
        (refused.form.handle.as_str(), refused.form.reason.as_str())
    });
    let refused = refused.as_deref();
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Rename this account's handle",
            description: "The account signs in and is shown under the new handle at once. Its old handle stays reserved for it: no other account can take it unless it is released from the terminal, and the account can take it back.",
            button: "Rename",
            back: back.as_str(),
            refusal: refused,
            <label>
                "New handle"
                <input name="handle" required="" maxlength="32" autocomplete="off" value=(typed)>
            </label>
            <label>
                "Reason, shown to the owner in their history"
                <input name="reason" required="" maxlength="500" value=(reason)>
            </label>
        )
    };
    App::render(cx, StatusCode::OK, page).await
}

impl App {
    /// The administrator and the account a settings page shows, once the
    /// dashboard's passkey confirmation is recent enough for its changes.
    async fn settings(cx: &Cx) -> Result<(&SignedInAdmin, UserId)> {
        let user = *path_param::<Account>(cx)?;
        let admin = Self::admin(cx).await?;
        Self::confirm(cx, admin)?;
        Ok((admin, user))
    }

    /// The form a `POST` sends, or none for a `GET`, whose query only opens a row:
    /// a link never changes anything.
    async fn posted<T: DeserializeOwned + Send>(cx: &Cx, body: Body) -> Result<Option<Form<T>>> {
        if method(cx) == Method::POST {
            Ok(Some(Form::from_request(cx, body).await?))
        } else {
            Ok(None)
        }
    }

    /// The page's own path, which its forms post to and its changes go back to.
    fn here(cx: &Cx) -> String {
        topcoat::router::request::uri(cx).path().to_owned()
    }

    /// The row `P`'s section opens, and the reason its form shows: after a
    /// refusal, the refused change's own row, as posted, so nothing typed is lost;
    /// otherwise the row the page's query opens, if it parses, and no reason yet.
    fn reopened<'a, P: AccountPage>(
        cx: &Cx,
        refused: Option<&'a Refused<Administered<P::Change>>>,
    ) -> (P::Row, &'a str) {
        match refused {
            Some(refused) => (
                P::reopened(&refused.form.change),
                refused.form.reason.as_str(),
            ),
            None => (parse_query_params(cx).unwrap_or_default(), ""),
        }
    }

    /// `admin` reading `user`'s settings.
    fn viewer(user: UserId, admin: &SignedInAdmin) -> Viewer {
        Viewer::operator(user, admin.operator.clone())
    }

    /// `admin` changing `user`'s settings, for `reason`.
    fn subject(user: UserId, admin: &SignedInAdmin, reason: String) -> Result<Subject, Refusal> {
        let reason = Reason::parse(reason)?;
        Ok(Subject::operator(user, admin.operator.clone(), reason))
    }

    /// Why a change only the owner makes, such as adding a way in, is refused.
    fn owners() -> Refusal {
        Refusal::Form(ApiError::bad_request(
            "Only the account's owner can make this change.",
        ))
    }

    /// Answers with `user`'s settings tab `tab`, its `section`, under the tabs and
    /// why the change just posted was `refused`, if it was.
    async fn settings_page(
        cx: &Cx,
        user: UserId,
        tab: Tab,
        refused: Option<&str>,
        section: impl View,
    ) -> Result<Response> {
        let links = [
            (Tab::SignIn, href!(sign_in, Account(user)).resolve(cx)),
            (Tab::Emails, href!(emails, Account(user)).resolve(cx)),
            (Tab::Apps, href!(apps, Account(user)).resolve(cx)),
        ];
        let tabs: &Vec<_> = &links
            .iter()
            .map(|(tab, link)| (*tab, link.as_str()))
            .collect();
        let back = &Self::account(cx, user);
        let section = Child::new(section);
        let page = view! { cx =>
            piquel_ui::account_settings(
                back: back.as_str(),
                tabs: tabs,
                current: tab,
                refusal: refused,
                (section)
            )
        };
        let status = if refused.is_some() {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::OK
        };
        Self::render(cx, status, page).await
    }
}
