use super::heading;
use crate::admin::Admin;
use piquel_admin_api::{AdminClient, ChainPoint, VerificationKeys};
use topcoat::{
    Result,
    context::Cx,
    router::page,
    view::{View, view},
};

/// `/audit`: verifies the audit history each time it opens, as
/// `auth-service audit verify` does.
#[page("/audit")]
pub async fn verify(cx: &Cx) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    let verification = admin.read(AdminClient::audit_verification).await?;
    let point = |point: &Option<ChainPoint>| {
        point
            .as_ref()
            .map_or_else(|| "None".to_owned(), ChainPoint::to_string)
    };
    Ok(view! {
        heading(
            title: "Audit history",
            lead: Some("Auth recomputes the hash chain over every sealed event and checks each signed checkpoint against it.".to_owned()),
        )
        <section class="card">
            <div class="row between">
                <h2>"Chain"</h2>
                if verification.broken.is_none() {
                    <span class="badge">"Intact"</span>
                } else {
                    <span class="badge disabled">"Broken"</span>
                }
            </div>
            if let Some(broken) = &verification.broken {
                <p class="notice error" role="alert">
                    "Broken at position " (broken.position.to_string()) ": " (broken.problem.to_string()) "."
                </p>
            }
            if verification.keys == VerificationKeys::Uncommitted {
                <p class="notice">
                    "This server signs checkpoints with a key that is not committed to the repository, so checkpoints were also checked against it. Run "
                    <code>"auth-service audit verify"</code>
                    " from a trusted build for an independent check."
                </p>
            }
            <dl class="facts">
                <dt>"Events checked"</dt><dd>(verification.events_checked.to_string())</dd>
                <dt>"Checkpoints checked"</dt><dd>(verification.checkpoints_checked.to_string())</dd>
                <dt>"Not sealed yet"</dt><dd>(verification.unsealed.to_string())</dd>
                if verification.anchor.is_some() {
                    <dt>"Pruned through"</dt><dd><code>(point(&verification.anchor))</code></dd>
                }
                <dt>"Newest event"</dt><dd><code>(point(&verification.newest))</code></dd>
                <dt>"Latest checkpoint"</dt><dd><code>(point(&verification.latest_checkpoint))</code></dd>
                <dt>"Keys"</dt><dd>(verification.keys.to_string())</dd>
            </dl>
        </section>
    })
}
