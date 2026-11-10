//! What the top bar's search finds beyond the page's own results: accounts and
//! clients, which the search script fetches as the administrator types.

use super::{AdminApplication as App, clients};
use sourceorigin_common::admin::Client;
use sourceorigin_ui::{AdminClientRow, Destination};
use topcoat::{
    Result,
    context::Cx,
    router::{
        HeaderValue, StatusCode, header, href, query_params,
        response::{IntoResponse, Response},
        route,
    },
    view::{ViewExt, view},
};

/// How many accounts, and how many clients, the top bar lists.
const SUGGESTED: usize = 6;

/// The query of [`suggest`].
#[query_params(error = bad_request)]
struct SuggestQuery {
    /// What the administrator typed.
    q: Option<String>,
}

/// `/search`: the accounts and the clients matching `q`, the closest first, as
/// the top bar's groups of results; nothing for an empty query. Accounts match
/// as the users page finds them, and clients by name or ID.
#[route(GET "/search")]
pub(super) async fn suggest(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let app = App::of(cx);
    let query = query_params::<SuggestQuery>(cx)?;
    let q = query.q.as_deref().unwrap_or_default().trim();
    let (users, clients) = if q.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let mut users = app
            .service
            .search_users(&admin.operator, q, None)
            .await?
            .users;
        users.truncate(SUGGESTED);
        let clients = app.service.list_clients(&admin.operator).await?;
        (users, App::closest_clients(clients, q))
    };
    let accounts = App::user_rows(cx, &users, &[]);
    let clients: Vec<_> = clients
        .iter()
        .map(|client| AdminClientRow {
            client,
            href: href!(clients::detail, clients::Client(client.id.clone())).resolve(cx),
        })
        .collect();
    let found: Vec<Destination<'_>> = accounts
        .iter()
        .map(Destination::from)
        .chain(clients.iter().map(Destination::from))
        .collect();
    let html = view! { cx => sourceorigin_ui::search_results(found: &found) }
        .single()
        .await?
        .render(cx);
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        html,
    )
        .into_response(cx)
}

impl App {
    /// The [`SUGGESTED`] clients of `clients` whose name or ID contains `q`,
    /// ignoring case, the closest first: the one named or identified by it,
    /// then those starting with it, then those with a word starting with it.
    fn closest_clients(clients: Vec<Client>, q: &str) -> Vec<Client> {
        let q = q.to_lowercase();
        let closeness = |text: &str| {
            let text = text.to_lowercase();
            if text == q {
                Some(0)
            } else if text.starts_with(&q) {
                Some(1)
            } else if text
                .split(|c: char| !c.is_alphanumeric())
                .any(|word| word.starts_with(&q))
            {
                Some(2)
            } else {
                text.contains(&q).then_some(3)
            }
        };
        let mut found: Vec<_> = clients
            .into_iter()
            .filter_map(|client| {
                let rank = [client.display_name.as_str(), client.id.as_str()]
                    .into_iter()
                    .filter_map(closeness)
                    .min()?;
                Some((rank, client))
            })
            .collect();
        found.sort_by(|(a, first), (b, second)| {
            a.cmp(b)
                .then_with(|| first.display_name.cmp(&second.display_name))
        });
        found
            .into_iter()
            .take(SUGGESTED)
            .map(|(_, client)| client)
            .collect()
    }
}
