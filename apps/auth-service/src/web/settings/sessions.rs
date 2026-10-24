//! `/settings/sessions`: the browsers signed in to the account.

use super::{Applied, Reader, SettingsPage};
use crate::{
    account::{AccountError, Owner, Subject},
    routes::page::settings,
    web::{Failure, WebApplication},
};
use chrono::Utc;
use piquel_ui::{DeviceChange, DeviceRow, Messages, Notice, Tab};
use topcoat::{
    context::Cx,
    router::{StatusCode, response::Response},
    view::view,
};

/// The devices page, which opens no rows.
pub(in crate::web) struct Devices;

impl SettingsPage for Devices {
    const TAB: Tab = Tab::Devices;
    const PATH: &'static str = settings::SESSIONS;
    type Change = DeviceChange;
    type Row = ();

    fn reopened(_: &DeviceChange) {}

    async fn apply(
        web: &WebApplication,
        owner: Owner,
        change: DeviceChange,
    ) -> Result<Applied<()>, AccountError> {
        let subject = Subject::from(owner);
        let notice = match change {
            DeviceChange::SignOut { id } => {
                web.account.revoke_session(&subject, id).await?;
                Notice::DeviceSignedOut
            }
            DeviceChange::SignOutOthers => {
                web.account.revoke_other_sessions(&subject).await?;
                Notice::OthersSignedOut
            }
        };
        Ok(Applied::Done(notice))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        (): (),
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let sessions = web.account.sessions(&reader.viewer).await?;
        let rows: Vec<_> = sessions
            .iter()
            .map(|session| DeviceRow {
                id: session.id,
                current: session.current,
                device: session.device,
                ip: session.ip,
                methods: &session.methods,
                authenticated_at: session.authenticated_at,
                last_seen_at: session.last_seen_at,
            })
            .collect();
        let page = view! { cx =>
            piquel_ui::devices(page: settings::SESSIONS, rows: &rows, now: Utc::now())
        };
        web.settings_page(cx, Self::TAB, reader, outcome, &[], page)
            .await
    }
}
