//! The dashboard's overview, at `/`: what needs attention, the last hour's
//! numbers against the week's, the newest events and the newest accounts.

use super::{AdminApplication as App, lists, users};
use crate::admin::Problem;
use piquel_common::admin::EventSearch;
use piquel_ui::{AdminOverview, Measure, Query, UserRow};
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, href, response::Response, route},
    view::view,
};

/// `/`: the overview.
#[route(GET "/")]
pub(super) async fn overview(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let service = &App::of(cx).service;
    let overview = service.overview(&admin.operator).await?;
    let administrators: Vec<_> = service
        .list_administrators(&admin.operator)
        .await?
        .into_iter()
        .map(|administrator| administrator.user_id)
        .collect();
    let events_page = href!(lists::events).resolve(cx);
    let failures = EventSearch {
        kind: Some("sign_in_failed".to_owned()),
        ..EventSearch::default()
    }
    .on(&events_page)?;
    let problems: Vec<_> = overview
        .problems()
        .into_iter()
        .map(|problem| match problem {
            Problem::FailedSignIns(rate) => piquel_ui::Problem::FailedSignIns {
                count: rate.last_hour,
                usual: rate.usual,
                events: &failures,
            },
            Problem::DeliveriesWaiting { pending, oldest } => {
                piquel_ui::Problem::DeliveriesWaiting { pending, oldest }
            }
        })
        .collect();
    let measures = [
        Measure::FailedSignIns {
            count: overview.failed_sign_ins.last_hour,
            usual: overview.failed_sign_ins.usual,
        },
        Measure::SignIns {
            count: overview.sign_ins.last_hour,
            usual: overview.sign_ins.usual,
        },
        Measure::ActiveSessions(overview.active_sessions),
        Measure::AppSignIns {
            count: overview.app_sign_ins.last_hour,
            usual: overview.app_sign_ins.usual,
        },
    ];
    let events = App::event_rows(cx, &overview.events);
    let newest: Vec<_> = overview
        .newest
        .iter()
        .map(|user| UserRow {
            user,
            administrator: administrators.contains(&user.id),
            href: App::account(cx, user.id),
        })
        .collect();
    let all_users = href!(users::search).resolve(cx);
    let page = AdminOverview {
        problems: &problems,
        measures: &measures,
        accounts: overview.accounts,
        administrators: overview.administrators,
        events: &events,
        newest: &newest,
        all_events: &events_page,
        all_users: &all_users,
    };
    let view = view! { cx => piquel_ui::admin_overview(overview: page) };
    App::render(cx, StatusCode::OK, "Overview", view).await
}
