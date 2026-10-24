//! `/settings/history`: the account's security history, and reporting an entry.

use super::{Applied, Reader, SettingsPage};
use crate::{
    account::{AccountError, Owner},
    routes::page::settings,
    web::{Failure, WebApplication},
};
use piquel_ui::{
    EmailRow, HistoryChange, HistoryPage, HistoryRow, HistoryState, Holdings, Messages, Tab,
};
use topcoat::{
    context::Cx,
    router::{StatusCode, response::Response},
    view::view,
};

/// The history page, a page at a time, with the report its query opens, or the
/// one just made.
pub(in crate::web) struct History;

impl SettingsPage for History {
    const TAB: Tab = Tab::History;
    const PATH: &'static str = settings::HISTORY;
    type Change = HistoryChange;
    type Row = HistoryState;

    fn reopened(&HistoryChange::Report { event_id, before }: &HistoryChange) -> HistoryState {
        HistoryState {
            before,
            reporting: Some(event_id),
            reported: None,
        }
    }

    /// A report goes on to what is left to undo, on the page it was made on.
    async fn apply(
        web: &WebApplication,
        owner: Owner,
        HistoryChange::Report { event_id, before }: HistoryChange,
    ) -> Result<Applied<HistoryState>, AccountError> {
        web.account.report(&owner, event_id).await?;
        Ok(Applied::Opened(HistoryState {
            before,
            reporting: None,
            reported: Some(event_id),
        }))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        shown: HistoryState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let history = web.account.history(&reader.viewer, shown.before).await?;
        let passkeys = web.account.passkeys(&reader.viewer).await?;
        let emails = web.account.emails(&reader.viewer).await?;
        let linked: Vec<_> = web
            .account
            .identities(&reader.viewer)
            .await?
            .into_iter()
            .map(|identity| identity.provider)
            .collect();
        let reported = match shown.reported {
            Some(event_id) => web.account.reported(&reader.viewer, event_id).await?,
            None => None,
        };
        let email_rows: Vec<_> = emails.iter().map(EmailRow::from).collect();
        let rows: Vec<_> = history
            .entries
            .iter()
            .map(|item| HistoryRow {
                id: item.id,
                occurred_at: item.occurred_at,
                entry: &item.entry,
                actor: item.actor,
                reason: item.reason.as_deref(),
                client: item
                    .client
                    .as_ref()
                    .map(|client| (client.id.as_str(), client.name.as_deref())),
                ip: item.ip,
                device: item.device,
                erased: item.erased,
            })
            .collect();
        let holds = Holdings {
            passkeys: &passkeys,
            emails: &email_rows,
            linked: &linked,
        };
        let page = HistoryPage {
            page: settings::HISTORY,
            sign_in: settings::HOME,
            emails: settings::EMAILS,
            shown,
            next: history.next,
            reported,
            confirmed: reader.confirmed,
        };
        let page = view! { cx => piquel_ui::history(rows: &rows, holds: holds, page: page) };
        web.settings_page(cx, Self::TAB, reader, outcome, &[], page)
            .await
    }
}
