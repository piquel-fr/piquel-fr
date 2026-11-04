//! The OIDC clients, as the `client` command manages them: the list, one
//! client's page, registering and changing one, enabling, disabling,
//! suspending and deleting it, and rotating a confidential client's secret. The
//! origins approved for a client's pages have their own pages, in [`origins`].
//! Applying a client a deployment manages stays the CLI's: see
//! [`AdminApplication::page`](super::AdminApplication::page).
//!
//! The registration page sits beside the clients' own, at `/clients/new`, so a
//! client with that ID has no overview here; the rest of its pages, and the
//! CLI, still reach it.

use super::{
    AdminApplication as App, Refusal,
    origins::{self, OriginQuery},
};
use crate::{
    AdminError, AdminService, Operator,
    clients::{ClientSettings, InvalidSetting, OperatorSettings},
    security::ApiError,
};
use chrono::Utc;
use piquel_common::{
    ClientId,
    clients::{ClientKind, ClientRegistration},
};
use piquel_repository::StoredOidcClient;
use piquel_ui::{
    Action, AdminClientRow, Change, ClientChanges, ClientPage, ClientRow, ClientStatus,
    NewClientForm, OperatorDraft, Query, Registration, Revealed, SecretRow, SecretsChange,
    SecretsState,
};
use serde::de::IgnoredAny;
use topcoat::{
    Result,
    context::Cx,
    router::{
        StatusCode, content::Form, error::see_other, href, path_param, request::uri,
        response::Response, route,
    },
    view::view,
};

path_param!(pub client: ClientId, error = not_found);

/// `/clients`: every OIDC client, deleted ones included, each linking its page.
#[route(GET "/clients")]
pub(super) async fn list(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let clients = App::of(cx).service.list_clients(&admin.operator).await?;
    let rows: Vec<_> = clients
        .iter()
        .map(|client| AdminClientRow {
            client,
            href: href!(detail, Client(client.id.clone())).resolve(cx),
        })
        .collect();
    let (rows, new) = (&rows, &href!(create).resolve(cx));
    let page = view! { cx => piquel_ui::client_list(rows: rows, new: new) };
    App::render(cx, StatusCode::OK, "Clients", page).await
}

/// `/clients/{client}`: everything about one client, its secrets' lifetimes and
/// approved origins, and the changes the dashboard may make to it.
#[route(GET "/clients/{client}")]
pub(super) async fn detail(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let service = &App::of(cx).service;
    let id = path_param::<Client>(cx)?.clone();
    let details = service.client_details(&admin.operator, &id).await?;
    let approved = service.list_related_origins(&admin.operator).await?;
    let stored = &details.client;
    let client = App::client_row(stored);
    let page = || Client(id.clone());
    let secrets: Vec<_> = details
        .secrets
        .iter()
        .map(|secret| SecretRow {
            created_at: secret.created_at,
            expires_at: secret.expires_at,
        })
        .collect();
    let origins = approved
        .iter()
        .filter(|approved| approved.client_id == id)
        .map(|approved| {
            let query = OriginQuery {
                origin: approved.origin.clone(),
            };
            let remove = query.on(&href!(origins::remove, page()).resolve(cx))?;
            Ok((approved.origin.as_str(), remove))
        })
        .collect::<Result<_>>()?;
    let approve = if stored.deleted_at.is_some() {
        Err("Deleted clients sign nobody in.")
    } else if stored.trusted {
        Ok(href!(origins::approve, page()).resolve(cx))
    } else {
        Err("Only trusted clients' pages sign users in themselves.")
    };
    // A confirmed dashboard shows each change's form on the page itself; one that
    // is not links the change's page, which confirms first.
    let inline = admin.operator.is_confirmed(super::FORM_TIME);
    let action = |href: String| Action { href, inline };
    let changes = stored.deleted_at.is_none().then(|| ClientChanges {
        settings: href!(edit, page()).resolve(cx),
        status: match client.status {
            ClientStatus::Suspended { .. } => None,
            ClientStatus::Enabled => Some(action(href!(disable, page()).resolve(cx))),
            ClientStatus::Disabled => Some(action(href!(enable, page()).resolve(cx))),
        },
        suspension: action(match client.status {
            ClientStatus::Suspended { .. } => href!(unsuspend, page()).resolve(cx),
            ClientStatus::Enabled | ClientStatus::Disabled => href!(suspend, page()).resolve(cx),
        }),
        delete: action(href!(delete, page()).resolve(cx)),
        secret: (stored.kind == ClientKind::Confidential)
            .then(|| href!(rotate, page()).resolve(cx)),
    });
    let shown = ClientPage {
        client,
        trusted: stored.trusted,
        audiences: &stored.allowed_audiences,
        owner: stored
            .owner_id
            .map(|owner| (owner, App::account(cx, owner))),
        created_at: stored.created_at,
        updated_at: stored.updated_at,
        deleted_at: stored.deleted_at,
        secrets: &secrets,
        origins,
        approve,
        changes,
    };
    let (shown, back) = (&shown, &href!(list).resolve(cx));
    let page = view! { cx =>
        piquel_ui::client_page(page: shown, back: back.as_str(), now: Utc::now())
    };
    // A large page: its future is boxed, off the handler's stack.
    Box::pin(App::render(cx, StatusCode::OK, App::title(stored), page)).await
}

/// `/clients/new`: registers a client operators manage. A confidential one shows
/// its first secret, which nothing shows again, in this answer; a public one goes
/// on to its page.
#[route([GET, POST] "/clients/new")]
pub(super) async fn create(cx: &Cx, form: Option<Form<NewClientForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let created = App::change(cx, form, async |new: NewClientForm| {
        let registration = App::registration(new)?;
        let secret = service
            .create_client(&admin.operator, &registration)
            .await?;
        Ok::<_, Refusal>((registration.id, secret))
    })
    .await?;
    let (shown, refusal) = match created {
        Some(Ok((id, None))) => return Err(see_other(href!(detail, Client(id)).resolve(cx)).into()),
        Some(Ok((id, Some(secret)))) => {
            let page = &href!(detail, Client(id)).resolve(cx);
            let secret = &Revealed::new(secret.expose().to_owned());
            let page = view! { cx =>
                piquel_ui::client_created(secret: secret, page: page.as_str())
            };
            return App::render(cx, StatusCode::OK, "Client registered", page).await;
        }
        Some(Err(refused)) => (refused.form.clone(), Some(refused.message)),
        None => (App::new_client(), None),
    };
    let registration = Registration::New {
        id: &shown.id,
        kind: shown.kind(),
    };
    App::registration_page(cx, registration, &shown.settings, refusal.as_deref()).await
}

/// `/clients/{client}/settings`: changes a client's registration, every setting
/// but its ID and kind, then goes back to its page.
#[route([GET, POST] "/clients/{client}/settings")]
pub(super) async fn edit(cx: &Cx, form: Option<Form<OperatorDraft>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = path_param::<Client>(cx)?.clone();
    let back = href!(detail, Client(id.clone())).resolve(cx);
    let refusal = App::submit(cx, form, back.clone(), async |draft: OperatorDraft| {
        service
            .update_client(&admin.operator, &id, |stored| {
                OperatorSettings::from(draft)
                    .registration(stored.id.clone(), stored.kind)
                    .map_err(Refusal::from)
            })
            .await
            .map(drop)
    })
    .await?;
    let stored = service.client_details(&admin.operator, &id).await?.client;
    let shown = match &refusal {
        Some(refused) => refused.form.clone(),
        None => OperatorDraft::of(&App::client_row(&stored), stored.trusted),
    };
    let registration = Registration::Edit {
        name: App::title(&stored),
    };
    App::registration_page(cx, registration, &shown, refusal.as_deref()).await
}

/// `/clients/{client}/secret`: a confidential client's secrets, and rotating
/// them. The new secret, which nothing shows again, shows in this answer.
#[route([GET, POST] "/clients/{client}/secret")]
pub(super) async fn rotate(cx: &Cx, form: Option<Form<SecretsChange>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = path_param::<Client>(cx)?.clone();
    let rotated = App::change(cx, form, async |SecretsChange::Rotate { grace }| {
        let grace = grace.unwrap_or_default().into();
        service
            .rotate_client_secret(&admin.operator, &id, grace)
            .await
    })
    .await?;
    let (state, refusal) = match rotated {
        Some(Ok(secret)) => (
            SecretsState {
                grace: None,
                rotated: Some(Revealed::new(secret.expose().to_owned())),
            },
            None,
        ),
        Some(Err(refused)) => {
            let SecretsChange::Rotate { grace } = refused.form;
            (
                SecretsState {
                    grace,
                    rotated: None,
                },
                Some(refused.message),
            )
        }
        None => (SecretsState::default(), None),
    };
    let details = service.client_details(&admin.operator, &id).await?;
    let secrets: Vec<_> = details
        .secrets
        .iter()
        .map(|secret| SecretRow {
            created_at: secret.created_at,
            expires_at: secret.expires_at,
        })
        .collect();
    let (here, back, name, secrets, state, refusal) = (
        &href!(rotate, Client(id.clone())).resolve(cx),
        &href!(detail, Client(id.clone())).resolve(cx),
        App::title(&details.client),
        &secrets,
        &state,
        refusal.as_deref(),
    );
    let page = view! { cx =>
        piquel_ui::client_secrets(
            page: here.as_str(),
            back: back.as_str(),
            name: name,
            secrets: secrets,
            now: Utc::now(),
            state: state,
            refusal: refusal,
        )
    };
    App::render(cx, StatusCode::OK, "Client secrets", page).await
}

/// A change to a client that only needs confirming, as its `client` command
/// makes it, each on its own page.
#[derive(Clone, Copy)]
enum Toggle {
    /// `client enable`.
    Enable,
    /// `client disable`.
    Disable,
    /// `client suspend`.
    Suspend,
    /// `client unsuspend`.
    Unsuspend,
    /// `client delete`.
    Delete,
}

impl Toggle {
    /// What it does, in the dashboard's words.
    const fn change(self) -> Change {
        match self {
            Self::Enable => Change::EnableClient,
            Self::Disable => Change::DisableClient,
            Self::Suspend => Change::SuspendClient,
            Self::Unsuspend => Change::UnsuspendClient,
            Self::Delete => Change::DeleteClient,
        }
    }

    /// Makes it to client `id`, as `operator`.
    async fn make(
        self,
        service: &AdminService,
        operator: &Operator,
        id: &ClientId,
    ) -> Result<(), AdminError> {
        match self {
            Self::Enable => service.set_client_enabled(operator, id, true).await,
            Self::Disable => service.set_client_enabled(operator, id, false).await,
            Self::Suspend => service.set_client_suspended(operator, id, true).await,
            Self::Unsuspend => service.set_client_suspended(operator, id, false).await,
            Self::Delete => service.delete_client(operator, id).await,
        }
    }

    /// Its page, for the client the path names: a `GET` asks to confirm it, and a
    /// `POST` makes it, then goes back to the client's page, or to the clients
    /// once the client is deleted.
    async fn page(self, cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
        let admin = App::admin(cx).await?;
        App::confirm(cx, admin)?;
        let service = &App::of(cx).service;
        let id = path_param::<Client>(cx)?.clone();
        let back = href!(detail, Client(id.clone())).resolve(cx);
        let done = match self {
            Self::Delete => href!(list).resolve(cx),
            Self::Enable | Self::Disable | Self::Suspend | Self::Unsuspend => back.clone(),
        };
        let refusal =
            App::submit(cx, form, done, |_| self.make(service, &admin.operator, &id)).await?;
        let change = self.change();
        let which = format!("Client {id}.");
        let page = view! { cx =>
            piquel_ui::dashboard_change(
                change: change,
                back: back.as_str(),
                refusal: refusal.as_deref(),
                <p class="help">(which.as_str())</p>
            )
        };
        App::render(cx, StatusCode::OK, change.title(), page).await
    }
}

/// `/clients/{client}/enable`: lets a disabled client sign users in again.
#[route([GET, POST] "/clients/{client}/enable")]
pub(super) async fn enable(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    Toggle::Enable.page(cx, form).await
}

/// `/clients/{client}/disable`: stops a client signing users in.
#[route([GET, POST] "/clients/{client}/disable")]
pub(super) async fn disable(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    Toggle::Disable.page(cx, form).await
}

/// `/clients/{client}/suspend`: blocks a client, so that its owner cannot enable
/// it again.
#[route([GET, POST] "/clients/{client}/suspend")]
pub(super) async fn suspend(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    Toggle::Suspend.page(cx, form).await
}

/// `/clients/{client}/unsuspend`: lifts a client's suspension; it stays disabled.
#[route([GET, POST] "/clients/{client}/unsuspend")]
pub(super) async fn unsuspend(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    Toggle::Unsuspend.page(cx, form).await
}

/// `/clients/{client}/delete`: deletes a client for good.
#[route([GET, POST] "/clients/{client}/delete")]
pub(super) async fn delete(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    Toggle::Delete.page(cx, form).await
}

impl From<OperatorDraft> for OperatorSettings {
    /// The settings as the form sent them, with every scope chosen.
    fn from(operator: OperatorDraft) -> Self {
        let allowed_scopes = operator.scopes();
        Self {
            settings: ClientSettings {
                allowed_scopes,
                ..ClientSettings::from(operator.draft)
            },
            trusted: operator.trusted.0,
        }
    }
}

impl From<InvalidSetting> for Refusal {
    /// The form says which setting is invalid, and why.
    fn from(invalid: InvalidSetting) -> Self {
        Self::Form(ApiError::bad_request(invalid.to_string()))
    }
}

impl From<crate::ClientRegistryError> for Refusal {
    /// What the dashboard does about the registry refusing a change.
    fn from(error: crate::ClientRegistryError) -> Self {
        AdminError::from(error).into()
    }
}

impl App {
    /// The client `stored`, as the console's pieces show it.
    fn client_row(stored: &StoredOidcClient) -> ClientRow<'_> {
        ClientRow {
            id: &stored.id,
            name: &stored.display_name,
            kind: stored.kind,
            status: ClientStatus::of(stored.enabled, stored.suspended_at),
            redirect_uris: &stored.redirect_uris,
            post_logout_uris: &stored.post_logout_uris,
            allowed_scopes: &stored.allowed_scopes,
            allow_refresh: stored.allow_refresh,
            require_pushed_authorization_requests: stored.require_pushed_authorization_requests,
            backchannel_logout_uri: stored.backchannel_logout_uri.as_deref(),
            last_used_at: stored.last_used_at,
        }
    }

    /// The name of client `stored`'s pages: its own, or its ID once deleted, which
    /// erases its name.
    fn title(stored: &StoredOidcClient) -> &str {
        if stored.display_name.is_empty() {
            stored.id.as_str()
        } else {
            &stored.display_name
        }
    }

    /// A new client's form, as it starts: the default scopes chosen.
    fn new_client() -> NewClientForm {
        let mut new = NewClientForm::default();
        new.settings.draft.scopes = crate::DEFAULT_CLIENT_SCOPES.into_iter().collect();
        new
    }

    /// The registration `new` asks for, its ID and every setting validated.
    fn registration(new: NewClientForm) -> Result<ClientRegistration, Refusal> {
        let kind = new.kind();
        let id: ClientId =
            new.id.trim().parse().map_err(|error| {
                Refusal::Form(ApiError::bad_request(format!("client ID: {error}")))
            })?;
        Ok(OperatorSettings::from(new.settings).registration(id, kind)?)
    }

    /// Answers with the page of `registration`, its form showing `settings`, and
    /// why the last attempt was refused, if it was.
    async fn registration_page(
        cx: &Cx,
        registration: Registration<'_>,
        settings: &OperatorDraft,
        refusal: Option<&str>,
    ) -> Result<Response> {
        let back = match registration {
            Registration::New { .. } => href!(list).resolve(cx),
            Registration::Edit { .. } => {
                href!(detail, Client(path_param::<Client>(cx)?.clone())).resolve(cx)
            }
        };
        let here = uri(cx).path().to_owned();
        let (title, back, here) = (registration.title(), &back, &here);
        let page = view! { cx =>
            piquel_ui::client_registration(
                registration: registration,
                settings: settings,
                action: here.as_str(),
                back: back.as_str(),
                refusal: refusal,
            )
        };
        App::render(cx, StatusCode::OK, title, page).await
    }
}
