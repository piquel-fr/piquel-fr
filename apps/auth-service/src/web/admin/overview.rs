//! The dashboard's overview, at `/`: what needs attention, the last hour's
//! numbers against the week's, the newest events and the newest accounts.

use super::{AdminApplication as App, alerts, deliveries, lists, users};
use crate::admin::{Kinds, Problem};
use sourceorigin_common::admin::EventSearch;
use sourceorigin_ui::{AdminOverview, Measure, Query};
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
    let generation = App::attention_generation(cx);
    let overview = service.overview(&admin.operator).await?;
    App::remember_attention(cx, generation, &overview);
    let administrators: Vec<_> = service
        .list_administrators(&admin.operator)
        .await?
        .into_iter()
        .map(|administrator| administrator.user_id)
        .collect();
    let events_page = href!(lists::events).resolve(cx);
    let failures = EventSearch {
        kind: Some(Kinds::FAILED.to_owned()),
        ..EventSearch::default()
    }
    .on(&events_page)?;
    let queue = href!(deliveries::list).resolve(cx);
    let alerts = href!(alerts::list).resolve(cx);
    let problems: Vec<_> = overview
        .problems()
        .into_iter()
        .map(|problem| match problem {
            Problem::OpenAlerts(count) => sourceorigin_ui::Problem::OpenAlerts {
                count,
                alerts: &alerts,
            },
            Problem::FailedSignIns(rate) => sourceorigin_ui::Problem::FailedSignIns {
                count: rate.last_hour,
                usual: rate.usual,
                events: &failures,
            },
            Problem::DeliveriesWaiting { pending, oldest } => {
                sourceorigin_ui::Problem::DeliveriesWaiting {
                    pending,
                    oldest,
                    deliveries: &queue,
                }
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
    let newest = App::user_rows(cx, &overview.newest, &administrators);
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
    let view = view! { cx => sourceorigin_ui::admin_overview(overview: page) };
    App::render(cx, StatusCode::OK, "Overview", view).await
}
