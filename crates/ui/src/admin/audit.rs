//! The audit chain's state and its checkpoints.

use super::moment;
use crate::{form::post_form, layout::page_head};
use sourceorigin_common::admin::{AuditPage, ChainPoint, Pruning, VerificationKeys};
use topcoat::{
    Result,
    context::Cx,
    view::{View, class, component, view},
};

/// The audit chain, as stored and as last verified, why the last attempt to
/// verify it was refused, if it was, then a `page` of its checkpoints, each with
/// whether the chain may be pruned through it and the command that would, and the
/// link to `later` checkpoints, if there are more. `keys` are those a
/// verification from here checks against.
#[component]
pub async fn audit_page<'a>(
    cx: &Cx,
    page: &'a AuditPage,
    keys: VerificationKeys,
    #[into]
    #[default]
    refusal: Option<&'a str>,
    #[into]
    #[default]
    later: Option<String>,
) -> Result<impl View> {
    // Without a committed key, the CLI checks against the one the notice saves.
    let uncommitted = keys == VerificationKeys::Uncommitted;
    let key = if uncommitted {
        " --key audit-key.pub"
    } else {
        ""
    };
    Ok(view! {
        page_head(
            title: "Audit history",
            lead: "Every event is hash-chained, and checkpoints of the chain are signed. \
                   Run auth-service audit verify from a trusted build for the authoritative check."
                .to_owned(),
        )
        if let Some(refusal) = refusal {
            <p class="notice error" role="alert">(refusal)</p>
        }
        chain_card(page: page, uncommitted: uncommitted)
        <section class="card">
            <header><h2>"Checkpoints"</h2></header>
            <p class="help">
                "Pruning deletes every event up to a checkpoint. It needs the database owner, \
                 which auth never holds, so run the command shown as the owner. It verifies the \
                 chain again first, and refuses if it breaks at or before that checkpoint."
            </p>
            if page.checkpoints.is_empty() {
                <p class="empty">"No checkpoint to show."</p>
            } else {
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr><th>"position"</th><th>"signed"</th><th>"pruning"</th></tr>
                        </thead>
                        <tbody>
                            #[key(position)]
                            for (position, checkpoint) in page.checkpoints.iter().enumerate() {
                                <tr>
                                    <td><code title=(checkpoint.point.hash.as_str())>(checkpoint.point.position.to_string())</code></td>
                                    <td>moment(at: checkpoint.signed_at)</td>
                                    <td>
                                        match &checkpoint.pruning {
                                            Pruning::Prunable => {
                                                <code>(format!("auth-service audit prune --through {}{key}", checkpoint.point.position))</code>
                                            },
                                            Pruning::Pruned { .. } => {
                                                <span class="muted">"Already pruned"</span>
                                            },
                                            Pruning::Broken(broken) => {
                                                <span class="muted">(format!("Not prunable: the chain breaks at {}", broken.position))</span>
                                            },
                                        }
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        </section>
        if let Some(later) = later {
            <div class="row"><a class="button secondary" href=(later)>"Later checkpoints"</a></div>
        }
    })
}

/// The chain as stored and as the `page`'s newest recorded verification found it,
/// with the form that verifies it again, warning of keys a compromised server
/// could hold if they are `uncommitted`.
#[component]
async fn chain_card<'a>(cx: &Cx, page: &'a AuditPage, uncommitted: bool) -> Result<impl View> {
    let chain = &page.chain;
    let point = |point: &Option<ChainPoint>| {
        point
            .as_ref()
            .map_or_else(|| "None".to_owned(), ChainPoint::to_string)
    };
    let position = |point: &Option<ChainPoint>| point.as_ref().map_or(0, |point| point.position);
    let verification = page
        .verified
        .as_ref()
        .map(|verified| &verified.verification);
    let broken = verification.and_then(|verification| verification.broken.as_ref());
    // Events sealed since an intact verification, which it could not check. A
    // broken one stopped before the newest events, so none of those count.
    let since = verification
        .filter(|verification| verification.broken.is_none())
        .map(|verification| position(&chain.newest).saturating_sub(position(&verification.newest)));
    let (badge, status) = match (verification, broken) {
        (None, _) => ("warning", "Not verified"),
        (Some(_), Some(_)) => ("danger", "Broken at last check"),
        (Some(_), None) => ("ok", "Intact at last check"),
    };
    Ok(view! {
        <section class="card">
            <header>
                <h2>"Chain"</h2>
                <span class=(class!("badge", badge))>(status)</span>
            </header>
            <div class="body">
                if let Some(broken) = broken {
                    <p class="notice error" role="alert">
                        (format!("The last check found the chain broken at position {}: {}.", broken.position, broken.problem))
                        " The change may also be a removal or insertion just before it."
                    </p>
                }
                if uncommitted {
                    <p class="notice warning">
                        "No audit key is committed for this environment, so checkpoints are checked \
                         against this server's own key, which a compromised server could have used. \
                         To prune, first save it with auth-service keys audit > audit-key.pub."
                    </p>
                }
                <dl class="facts">
                    <dt>"Last verified"</dt>
                    <dd>
                        if let Some(verified) = &page.verified {
                            moment(at: verified.at)
                        } else {
                            "Never"
                        }
                    </dd>
                    if let Some(verification) = verification {
                        <dt>"Events checked"</dt><dd>(verification.events_checked.to_string())</dd>
                        <dt>"Checkpoints checked"</dt><dd>(verification.checkpoints_checked.to_string())</dd>
                        <dt>"Keys"</dt><dd>(verification.keys.to_string())</dd>
                    }
                    if let Some(since) = since {
                        <dt>"Sealed since"</dt><dd>(since.to_string())</dd>
                    }
                    <dt>"Unsealed"</dt><dd>(chain.unsealed.to_string())</dd>
                    <dt>"Pruned through"</dt><dd><code>(point(&chain.anchor))</code></dd>
                    <dt>"Newest"</dt><dd><code>(point(&chain.newest))</code></dd>
                </dl>
                post_form(class: "stack",
                    <p class="help">
                        "This is the newest verification the audit log records, not a check made now: \
                         events sealed since were not checked, and someone with auth's database role could \
                         record a forged result. Auth verifies on its own once no one has for six hours. Verifying \
                         recomputes the whole history, as auth-service audit verify does, and records \
                         what it finds."
                    </p>
                    <div class="row actions"><button class="secondary">"Verify now"</button></div>
                )
            </div>
        </section>
    })
}
