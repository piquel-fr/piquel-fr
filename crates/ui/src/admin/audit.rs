//! The audit chain's state and its checkpoints.

use super::{heading, moment};
use piquel_common::admin::{AuditPage, ChainPoint, Pruning, VerificationKeys};
use topcoat::{
    Result,
    view::{View, class, component, view},
};

/// The audit chain as `auth-service audit verify` reports it, then a `page` of its
/// checkpoints, each with whether the chain may be pruned through it and the
/// command that would, and the link to `later` checkpoints, if there are more.
#[component]
pub async fn audit_page<'a>(
    page: &'a AuditPage,
    #[into]
    #[default]
    later: Option<String>,
) -> Result<impl View> {
    let verification = &page.verification;
    // Without a committed key, the CLI checks against the one the notice saves.
    let uncommitted = verification.keys == VerificationKeys::Uncommitted;
    let key = if uncommitted {
        " --key audit-key.pub"
    } else {
        ""
    };
    let point = |point: &Option<ChainPoint>| {
        point
            .as_ref()
            .map_or_else(|| "None".to_owned(), ChainPoint::to_string)
    };
    Ok(view! {
        heading(
            title: "Audit history",
            lead: "Every event is hash-chained, and checkpoints of the chain are signed. \
                   Run auth-service audit verify from a trusted build for the authoritative check."
                .to_owned(),
        )
        <section class="card stack">
            <div class="row between">
                <h2>"Chain"</h2>
                <span class=(class!("badge", "warning" if verification.broken.is_some()))>
                    (if verification.broken.is_some() { "Broken" } else { "Intact" })
                </span>
            </div>
            if let Some(broken) = &verification.broken {
                <p class="notice error" role="alert">
                    (format!("Broken at position {}: {}.", broken.position, broken.problem))
                    " The change may also be a removal or insertion just before it."
                </p>
            }
            if uncommitted {
                <p class="notice">
                    "No audit key is committed for this environment, so checkpoints were checked \
                     against this server's own key, which a compromised server could have used. \
                     To prune, first save it with auth-service keys audit > audit-key.pub."
                </p>
            }
            <dl class="facts">
                <dt>"Events checked"</dt><dd>(verification.events_checked.to_string())</dd>
                <dt>"Checkpoints checked"</dt><dd>(verification.checkpoints_checked.to_string())</dd>
                <dt>"Unsealed"</dt><dd>(verification.unsealed.to_string())</dd>
                <dt>"Pruned through"</dt><dd><code>(point(&verification.anchor))</code></dd>
                <dt>"Newest"</dt><dd><code>(point(&verification.newest))</code></dd>
                <dt>"Latest checkpoint"</dt><dd><code>(point(&verification.latest_checkpoint))</code></dd>
                <dt>"Keys"</dt><dd>(verification.keys.to_string())</dd>
            </dl>
        </section>
        <section class="card stack">
            <h2>"Checkpoints"</h2>
            <p class="help">
                "Pruning deletes every event up to a checkpoint. It needs the database owner, \
                 which auth never holds, so run the command shown as the owner."
            </p>
            if page.checkpoints.is_empty() {
                <p class="empty">"No checkpoint to show."</p>
            } else {
                <table>
                    <thead>
                        <tr><th>"Position"</th><th>"Signed"</th><th>"Pruning"</th></tr>
                    </thead>
                    <tbody>
                        for checkpoint in &page.checkpoints {
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
            }
        </section>
        if let Some(later) = later {
            <a class="button secondary" href=(later)>"Later checkpoints"</a>
        }
    })
}
