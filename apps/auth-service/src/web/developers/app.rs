//! `/developers/clients/{id}`: one of the account's apps, its overview, settings
//! and secrets. Each page reads the app first, so another account's or an unknown
//! one is missing before anything else happens.

use super::AsRow;
use crate::{
    account::{AccountError, Owner},
    clients::{ClientDetails, ClientPatch, ClientSettings},
    routes::{
        oidc::DISCOVERY,
        page::developers::{self, APP, APP_SECRETS, APP_SETTINGS, HOME},
    },
    web::{
        Failure, WebApplication,
        account::{AccountPage, Applied, NoChange, Reader},
    },
};
use chrono::Utc;
use piquel_common::clients::ClientKind;
use piquel_ui::{
    AppChange, AppSettingsState, AppTab, Checkbox, Connection, Messages, Notice, Revealed,
    SecretRow, SecretsChange, SecretsState, Section, Title,
};
use topcoat::{
    context::Cx,
    router::{StatusCode, response::Response},
    view::{Child, view},
};

/// An app's overview: what its `OpenID` Connect library needs.
pub(in crate::web) struct Overview;

impl AccountPage for Overview {
    const SECTION: Section = Section::Developers;
    const PATH: &'static str = APP;
    const TITLE: &'static str = Title::App.as_str();
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
        let ClientDetails { client, .. } = web.app_details(cx, reader).await?;
        let secrets = (client.kind == ClientKind::Confidential)
            .then(|| developers::of(APP_SECRETS, &client.id));
        let issuer = web.issuer.serialized();
        let discovery = web.issuer.join(DISCOVERY);
        let connection = Connection {
            issuer: &issuer,
            discovery: &discovery,
        };
        let row = client.row();
        let page = view! { cx =>
            piquel_ui::overview(client: row, connection: connection, secrets: secrets.as_deref())
        };
        web.app_page(
            cx,
            AppTab::Overview,
            reader,
            &client,
            outcome,
            Child::new(page),
        )
        .await
    }
}

/// An app's settings, disabling and deleting it.
pub(in crate::web) struct AppSettings;

impl AccountPage for AppSettings {
    const SECTION: Section = Section::Developers;
    const PATH: &'static str = APP_SETTINGS;
    const TITLE: &'static str = Title::App.as_str();
    type Change = AppChange;
    type Row = AppSettingsState;

    fn reopened(change: &AppChange) -> AppSettingsState {
        match change {
            AppChange::Save { draft } => AppSettingsState {
                draft: Some(draft.clone()),
                ..AppSettingsState::default()
            },
            AppChange::Delete {} => AppSettingsState {
                deleting: Checkbox(true),
                draft: None,
            },
            AppChange::Disable {} | AppChange::Enable {} => AppSettingsState::default(),
        }
    }

    /// Saving asks for a passkey confirmation only when it changes the URIs, which
    /// the service checks before committing. A deleted app goes back to the apps.
    async fn apply(
        web: &WebApplication,
        cx: &Cx,
        owner: Owner,
        change: AppChange,
    ) -> Result<Applied<AppSettingsState>, AccountError> {
        let app = web.app(cx, owner).await?;
        let notice = match change {
            AppChange::Save { draft } => {
                let patch = ClientPatch::from(ClientSettings::from(draft));
                web.account.update_client(&app, patch).await?;
                Notice::ClientSaved
            }
            AppChange::Disable {} => {
                web.account.set_client_enabled(&app, false).await?;
                Notice::ClientDisabled
            }
            AppChange::Enable {} => {
                web.account.set_client_enabled(&app, true).await?;
                Notice::ClientEnabled
            }
            AppChange::Delete {} => {
                web.account.delete_client(&app).await?;
                return Ok(Applied::Moved {
                    to: HOME.to_owned(),
                    notice: Notice::ClientDeleted,
                });
            }
        };
        Ok(Applied::Done(notice))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        state: AppSettingsState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let ClientDetails { client, .. } = web.app_details(cx, reader).await?;
        let page = developers::of(APP_SETTINGS, &client.id);
        let row = client.row();
        let view = view! { cx =>
            piquel_ui::app_settings(
                page: &page,
                client: row,
                state: &state,
                confirmed: reader.is_recent(),
                asked: reader.asked(),
                error: outcome.1.field_error(),
            )
        };
        web.app_page(
            cx,
            AppTab::Settings,
            reader,
            &client,
            outcome,
            Child::new(view),
        )
        .await
    }
}

/// A confidential app's secrets, and rotating them. A public app has none, so
/// its page is missing.
pub(in crate::web) struct AppSecrets;

impl AccountPage for AppSecrets {
    const SECTION: Section = Section::Developers;
    const PATH: &'static str = APP_SECRETS;
    const TITLE: &'static str = Title::App.as_str();
    type Change = SecretsChange;
    type Row = SecretsState;

    fn reopened(&SecretsChange::Rotate { grace }: &SecretsChange) -> SecretsState {
        SecretsState {
            grace,
            rotated: None,
        }
    }

    /// The new secret, which nothing shows again, shows in this answer.
    async fn apply(
        web: &WebApplication,
        cx: &Cx,
        owner: Owner,
        SecretsChange::Rotate { grace }: SecretsChange,
    ) -> Result<Applied<SecretsState>, AccountError> {
        let app = web.app(cx, owner).await?;
        let grace = grace.unwrap_or_default().into();
        let secret = web.account.rotate_client_secret(&app, grace).await?;
        Ok(Applied::Revealed(SecretsState {
            grace: None,
            rotated: Some(Revealed::new(secret.expose().to_owned())),
        }))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        state: SecretsState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let ClientDetails { client, secrets } = web.app_details(cx, reader).await?;
        if client.kind == ClientKind::Public {
            return Err(Failure::Missing);
        }
        let rows: Vec<_> = secrets
            .iter()
            .map(|secret| SecretRow {
                created_at: secret.created_at,
                expires_at: secret.expires_at,
            })
            .collect();
        let page = developers::of(APP_SECRETS, &client.id);
        let view = view! { cx =>
            piquel_ui::app_secrets(
                page: &page,
                secrets: &rows,
                now: Utc::now(),
                state: &state,
                confirmed: reader.is_recent(),
            )
        };
        web.app_page(
            cx,
            AppTab::Secrets,
            reader,
            &client,
            outcome,
            Child::new(view),
        )
        .await
    }
}
