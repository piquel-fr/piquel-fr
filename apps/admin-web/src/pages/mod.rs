//! The dashboard's pages. Each reads or changes auth through the admin API as the
//! signed-in administrator ([`Admin`](crate::admin::Admin)); none keeps state of its own.

use crate::{
    admin::{Admin, sdk_responses},
    config::AUTH_MOUNT,
};
use chrono::{DateTime, Utc};
use piquel_admin_api::{AdminClient, ApiError};
use piquel_common::ErrorChain;
use std::sync::LazyLock;
use topcoat::{
    Error, Result,
    context::Cx,
    router::{
        Router, Slot, StatusCode,
        content::Css,
        error::{SeeOther, see_other},
        href, layout,
        request::uri,
        route,
    },
    view::{Child, View, class, component, error_boundary, view},
};

/// Account search and detail, and the changes made to one account.
mod users;

/// The administrator list.
mod administrators;
/// The OIDC clients.
mod clients;
/// Domain events.
mod events;
/// Signup invitations.
mod invitations;

/// The shared piquel.fr styles, `piquel-ui`'s, then the dashboard's own.
static STYLE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    [
        piquel_ui::STYLESHEET.bytes(),
        include_bytes!("../style.css"),
    ]
    .concat()
});

/// Every page, calling the admin API through `api`.
pub fn router(api: AdminClient) -> Router {
    Router::builder()
        .app_context(api)
        .layer(sdk_responses)
        .layout(root)
        .route(home)
        .route(style)
        .page(users::search)
        .page(users::detail)
        .page(users::disable)
        .page(users::enable)
        .page(users::revoke_sessions)
        .page(users::revoke_session)
        .page(administrators::list)
        .page(administrators::grant)
        .page(administrators::revoke)
        .page(invitations::list)
        .page(invitations::create)
        .page(invitations::revoke)
        .page(clients::list)
        .page(events::list)
        .build()
}

/// `/`: the account search.
#[route(GET "/")]
async fn home(cx: &Cx) -> Result<SeeOther> {
    Ok(see_other(href!(users::search).resolve(cx)))
}

/// `/style.css`.
#[route(GET "/style.css")]
async fn style() -> Result<Css<&'static [u8]>> {
    Ok(Css(STYLE.as_slice()))
}

/// The document around every page: navigation, the administrator's name and
/// sign-out, and the page, or what went wrong calling the API instead.
#[layout("/")]
async fn root(cx: &Cx, slot: Slot<'_>) -> Result<impl View> {
    // A browser that is not signed in yet is redirected by the page itself.
    let admin = Admin::of(cx).await.ok();
    let sections = [
        ("Users", href!(users::search).resolve(cx)),
        ("Administrators", href!(administrators::list).resolve(cx)),
        ("Invitations", href!(invitations::list).resolve(cx)),
        ("Clients", href!(clients::list).resolve(cx)),
        ("Events", href!(events::list).resolve(cx)),
    ];
    let path = uri(cx).path();
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta name="referrer" content="no-referrer">
                <title>"Piquel admin"</title>
                <link rel="stylesheet" href=(href!(style))>
            </head>
            <body>
                <header class="topbar">
                    <div class="shell row between">
                        <a class="brand" href=(href!(users::search))>
                            <span class="mark">"P"</span>
                            "Piquel admin"
                        </a>
                        if let Some(admin) = admin {
                            <form method="post" action=(format!("{AUTH_MOUNT}/logout")) class="row signed-in">
                                <span class="muted">(admin.name())</span>
                                <button class="secondary small">"Sign out"</button>
                            </form>
                        }
                    </div>
                    <nav class="shell row">
                        for (label, link) in sections {
                            let current = path.starts_with(&link);
                            <a
                                href=(link)
                                aria-current=(current.then_some("page"))
                                class=(class!("tab", "active" if current))
                            >
                                (label)
                            </a>
                        }
                    </nav>
                </header>
                <main class="shell stack">
                    error_boundary(
                        fallback: |error: Error| {
                            if error.is::<ApiError>() {
                                Ok(view! { failure(error: error) })
                            } else {
                                Err(error)
                            }
                        },
                        (slot)
                    )
                </main>
            </body>
        </html>
    })
}

/// What a failed admin API read means for the administrator, in place of the page.
#[component]
async fn failure(error: Error) -> Result<impl View> {
    let Some(error) = error.downcast_ref::<ApiError>() else {
        return Err(error);
    };
    let (status, title, detail) = match error {
        ApiError::Refused { status, .. } if *status == StatusCode::FORBIDDEN => (
            *status,
            "This account has no access",
            "Only administrators can use this dashboard.".to_owned(),
        ),
        ApiError::Refused { status, body } => {
            (*status, "The admin API refused", body.error.clone())
        }
        ApiError::SignIn(_) | ApiError::Unreachable(_) | ApiError::InvalidResponse { .. } => {
            tracing::error!(error = %ErrorChain(error), "admin API call failed");
            (
                StatusCode::BAD_GATEWAY,
                "Auth is unavailable",
                "The admin API could not be reached. Try again shortly.".to_owned(),
            )
        }
    };
    Ok(view! {
        (status)
        <section class="card">
            <h1>(title)</h1>
            <p>(detail)</p>
        </section>
    })
}

/// A page heading, with an optional line under it.
#[component]
async fn heading(title: &str, #[default] lead: Option<String>) -> Result<impl View> {
    Ok(view! {
        <div>
            <h1>(title)</h1>
            if let Some(lead) = lead {
                <p>(lead)</p>
            }
        </div>
    })
}

/// A moment, in UTC.
#[component]
async fn time(at: DateTime<Utc>) -> Result<impl View> {
    Ok(view! {
        <time datetime=(at.to_rfc3339())>(at.format("%Y-%m-%d %H:%M UTC").to_string())</time>
    })
}

/// The form of one change: what it does, its inputs as `child`, the API's refusal
/// of the last attempt, and the button. Changing pages confirm a recent passkey
/// before rendering it ([`Admin::confirm`]).
#[component]
async fn change_form(
    title: &str,
    description: &str,
    button: &str,
    /// Where cancelling goes.
    back: String,
    #[default] refusal: Option<String>,
    #[default] danger: bool,
    #[default] child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <section class="card narrow">
            <h1>(title)</h1>
            <p>(description)</p>
            if let Some(refusal) = refusal {
                <p class="notice error" role="alert">(refusal)</p>
            }
            <form method="post">
                (child)
                <div class="row">
                    <button class=(class!("danger" if danger))>(button)</button>
                    <a class="button secondary" href=(back)>"Cancel"</a>
                </div>
            </form>
        </section>
    })
}

/// A change that the API would refuse, shown disabled with the reason.
#[component]
async fn refused_action(label: &str, reason: &str) -> Result<impl View> {
    Ok(view! {
        <span class="row">
            <button class="secondary" disabled="" title=(reason)>(label)</button>
            <small>(reason)</small>
        </span>
    })
}
