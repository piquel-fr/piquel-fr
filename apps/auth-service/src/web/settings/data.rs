//! `/settings/data`: downloading the account's data, and deleting the account.

use crate::{
    account::{AccountError, Owner},
    deletion::{AccountDeleted, AccountExport, GRACE_PERIOD_DAYS},
    routes::page::{self, settings},
    web::{
        Failure, WebApplication,
        account::{AccountPage, Applied, Reader},
    },
};
use piquel_ui::{Area, DataChange, DataState, Messages, Section, Tab, Title};
use topcoat::{
    Error,
    context::Cx,
    router::{
        StatusCode,
        header::{self, HeaderValue},
        response::{IntoResponse, Response},
    },
    view::{Child, view},
};

/// The data page.
pub(in crate::web) struct AccountData;

impl AccountData {
    /// Its tab.
    const TAB: Tab = Tab::Data;
}

impl AccountPage for AccountData {
    const SECTION: Section = Section::Account;
    const PATH: &'static str = settings::DATA;
    const TITLE: &'static str = Self::TAB.label();
    type Change = DataChange;
    type Row = DataState;

    fn reopened(change: &DataChange) -> DataState {
        DataState {
            deleting: matches!(change, DataChange::Delete { .. }),
        }
    }

    async fn apply(
        web: &WebApplication,
        _: &Cx,
        owner: Owner,
        change: DataChange,
    ) -> Result<Applied<DataState>, AccountError> {
        Ok(match change {
            DataChange::Export => Applied::Download(Box::new(web.account.export(&owner).await?)),
            DataChange::Delete { handle } => {
                Applied::Deleted(web.account.delete_account(&owner, handle.trim()).await?)
            }
        })
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        state: DataState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let profile = web.account.profile(&reader.viewer()).await?;
        let page = Child::new(view! { cx =>
            piquel_ui::account_data(
                page: settings::DATA,
                handle: profile.handle.as_str(),
                grace_days: GRACE_PERIOD_DAYS,
                state: state,
                confirmed: reader.is_recent(),
            )
        });
        web.settings_page(cx, Self::TAB, reader, outcome, &[], page)
            .await
    }
}

impl WebApplication {
    /// Answers with `export` as a JSON file the browser saves. It holds personal
    /// data, and like every page's answer, the security layer marks it
    /// `no-store, no-transform`.
    pub(in crate::web) fn download(cx: &Cx, export: &AccountExport) -> Result<Response, Failure> {
        let body = serde_json::to_string_pretty(export).map_err(Error::from)?;
        let disposition = format!("attachment; filename=\"{}\"", export.file_name());
        Ok((
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    HeaderValue::try_from(disposition).map_err(Error::from)?,
                ),
            ],
            body,
        )
            .into_response(cx)?)
    }

    /// Answers the deletion just scheduled: says when the account is purged, and
    /// how to restore it, and deletes the session cookie it ended.
    pub(in crate::web) async fn deleted(
        &self,
        cx: &Cx,
        deleted: &AccountDeleted,
    ) -> Result<Response, Failure> {
        let page = view! { cx =>
            piquel_ui::account_deleted(purge_after: deleted.purge_after, sign_in: page::LOGIN)
        };
        let title = Title::AccountDeleted.as_str();
        let area = Area::Section(Section::Account);
        let mut response = self
            .render(cx, StatusCode::OK, title, area, &[], page)
            .await?;
        deleted.clear_on(&mut response).map_err(Error::from)?;
        Ok(response)
    }
}
