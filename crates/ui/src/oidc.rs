//! The pages of OAuth and `OpenID` Connect flows: consent, logout, and why one
//! cannot go on.

use crate::intro;
use piquel_common::{
    Provider,
    protocol::oauth::{ErrorCode, Scope},
};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// The consent page: what the application named `client` asks to receive through
/// `scopes`, and the decision on the pending `transaction`, posted to `action` as
/// `decision=approve` or `decision=deny`. The form posts once: a second decision
/// would find the authorization already used.
#[component]
pub async fn consent(
    client: &str,
    scopes: &[String],
    action: &str,
    transaction: &str,
) -> Result<impl View> {
    Ok(view! {
        <section class="auth-shell stack">
            intro(
                eyebrow: "Application access",
                title: format!("Continue to {client}."),
                lead: "Review what this application will receive from your Piquel account.",
            )
            <div class="card">
                <h2>(client)</h2>
                <ul>
                    for scope in scopes {
                        <li>(scope_label(scope))</li>
                    }
                </ul>
            </div>
            <form method="post" action=(action) data-submit-once="">
                <input type="hidden" name="transaction" value=(transaction)>
                <button name="decision" value="approve">"Continue"</button>
                <button class="secondary" name="decision" value="deny">"Cancel"</button>
            </form>
        </section>
    })
}

/// What a scope gives the application, in the user's words. A scope Piquel does
/// not describe, such as an application's own, is shown as it is.
fn scope_label(scope: &str) -> &str {
    match scope.parse() {
        Ok(Scope::OpenId) => "Your account identifier",
        Ok(Scope::Profile) => "Your username and display name",
        Ok(Scope::Email) => "Your verified email address",
        Ok(Scope::OfflineAccess) => "Stay signed in",
        Err(_) => scope,
    }
}

/// The confirmation of an application's logout request: a form posting `fields`,
/// the request's parameters, back to `action`, and a link to `keep` the session.
#[component]
pub async fn logout<'a>(
    action: &'a str,
    fields: &'a [(&'a str, &'a str)],
    keep: &'a str,
) -> Result<impl View> {
    Ok(view! {
        <section class="auth-shell stack">
            intro(
                eyebrow: "Your Piquel account",
                title: "Ready to sign out?",
                lead: "This will end your Piquel sign-in session in this browser.",
            )
            <form method="post" action=(action)>
                for (name, value) in fields {
                    <input type="hidden" name=(*name) value=(*value)>
                }
                <button>"Sign out"</button>
            </form>
            <a href=(keep)>"Keep my session"</a>
        </section>
    })
}

/// Why an OAuth page cannot go on: what `code` means for the user, the
/// `description` of what the request got wrong when they may see it, and a `link`
/// onwards as its label and URL.
#[component]
pub async fn failure<'a>(
    code: &'a ErrorCode,
    #[default] description: Option<&'a str>,
    #[default] link: Option<(&'a str, &'a str)>,
) -> Result<impl View> {
    let message = match code {
        ErrorCode::InvalidRequest => {
            "This sign-in request is invalid or expired. Start again from the application."
        }
        ErrorCode::InvalidToken | ErrorCode::LoginRequired => "Please sign in again.",
        ErrorCode::AccessDenied => "Sign-in was cancelled or access was declined.",
        ErrorCode::ConsentRequired => "Review the application’s requested access to continue.",
        ErrorCode::UnmetAuthenticationRequirements => {
            "This application needs a stronger sign-in than your account can give right now."
        }
        ErrorCode::ServerError => "Sign-in is temporarily unavailable. Please try again.",
        ErrorCode::InvalidClient
        | ErrorCode::InvalidGrant
        | ErrorCode::InvalidScope
        | ErrorCode::InvalidTarget
        | ErrorCode::UnsupportedGrantType
        | ErrorCode::RequestNotSupported
        | ErrorCode::InvalidRequestUri
        | ErrorCode::Other(_) => {
            "This request could not be completed. Start again from the application."
        }
    };
    Ok(view! {
        <section class="auth-shell stack">
            intro(eyebrow: "Your Piquel account", title: message)
            if let Some(description) = description {
                <p class="notice error" role="alert">(description)</p>
            }
            if let Some((label, href)) = link {
                <a href=(href)>(label)</a>
            }
        </section>
    })
}

/// Where an [`onward`] link leads.
#[derive(Clone, Copy, Debug)]
pub enum Onward {
    /// Back to the application the flow is for.
    Application,
    /// To the provider, which signs the user in on the way to the application.
    Provider(Provider),
}

/// A step of a flow whose redirects a form may not lead through, because they end
/// at a destination no Content-Security-Policy can name, such as a native
/// application's loopback address: a link to `href`, which leads `to` there, that
/// the user follows instead.
#[component]
pub async fn onward(href: &str, to: Onward) -> Result<impl View> {
    let (title, lead) = match to {
        Onward::Application => (
            "Return to the application".to_owned(),
            "Continue to finish in the application.",
        ),
        Onward::Provider(provider) => (
            format!("Continue with {}", provider.name()),
            "Sign in there, then you return to the application.",
        ),
    };
    Ok(view! {
        <section class="auth-shell stack">
            intro(eyebrow: "Your Piquel account", title: title, lead: lead)
            <a class="button" href=(href)>"Continue"</a>
        </section>
    })
}
