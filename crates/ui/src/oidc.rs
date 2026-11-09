//! The pages of OAuth and `OpenID` Connect flows: consent, logout, and why one
//! cannot go on.

use crate::{
    icons::{Icon, icon},
    login::switch_account,
};
use sourceorigin_common::{
    Provider,
    protocol::oauth::{ErrorCode, Scope},
};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// The consent page: what the application named `client`, which sends the browser
/// back to `host`, asks to receive through `scopes`, and the decision on the
/// pending `transaction`, posted to `action` as `decision=approve` or
/// `decision=deny`. An application an account registered, `registered_by` by its
/// handle, is labelled unverified. The page names the signed-in `account`, and
/// offers to switch accounts by posting to `sign_in`, the sign-in page continuing
/// the transaction. The form posts once: a second decision would find the
/// authorization already used.
#[component]
pub async fn consent<'a>(
    client: &'a str,
    host: &'a str,
    #[default] registered_by: Option<&'a str>,
    account: &'a str,
    scopes: &'a [String],
    action: &'a str,
    sign_in: &'a str,
    transaction: &'a str,
) -> Result<impl View> {
    Ok(view! {
        <div>
            <h1>(format!("Continue to {client}?"))</h1>
            <p class="lead">"You’ll be sent to " <strong>(host)</strong> " after you decide."</p>
        </div>
        if let Some(owner) = registered_by {
            <p class="notice warning">
                icon(kind: Icon::Warning)
                <span class="text">
                    (format!("Unverified app, registered by @{owner}"))
                    <small>"SourceOrigin hasn’t checked who runs it. Continue only if you trust it."</small>
                </span>
            </p>
        }
        <section class="card" aria-labelledby="access-heading">
            <header><h2 id="access-heading">(format!("{client} will receive"))</h2></header>
            <ul class="list">
                for scope in scopes {
                    <li>icon(kind: Icon::Check)<span class="text">(scope_label(scope))</span></li>
                }
            </ul>
        </section>
        <p class="help">
            (format!("{client} cannot see your passkeys or change your account. You can remove its access at any time from your connected apps."))
        </p>
        <form method="post" action=(action) data-submit-once="">
            <input type="hidden" name="transaction" value=(transaction)>
            <button name="decision" value="approve">"Continue"</button>
            <button class="secondary" name="decision" value="deny">"Cancel"</button>
        </form>
        <footer>
            <p class="help">(format!("Signed in as @{account}."))</p>
            switch_account(action: sign_in, label: "Not you? Switch account", class: "text-button")
        </footer>
    })
}

/// What a scope gives the application, in the user’s words, on the consent page
/// and among the connected apps. A scope SourceOrigin does not describe, such as an
/// application's own, is shown as it is.
pub(crate) fn scope_label(scope: &str) -> &str {
    match scope.parse() {
        Ok(Scope::OpenId) => "Your account identifier",
        Ok(Scope::Profile) => "Your username, display name and profile picture",
        Ok(Scope::Email) => "Your verified email address",
        Ok(Scope::OfflineAccess) => "Access your account while you’re away",
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
        <div>
            <h1>"Ready to sign out?"</h1>
            <p class="lead">"This will end your Origin Account session in this browser."</p>
        </div>
        <form method="post" action=(action)>
            for (name, value) in fields {
                <input type="hidden" name=(*name) value=(*value)>
            }
            <button>"Sign out"</button>
            <a class="button secondary" href=(keep)>"Keep my session"</a>
        </form>
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
        ErrorCode::ServerError => "Something went wrong on our side. Please try again.",
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
        <h1>(message)</h1>
        if let Some(description) = description {
            <p class="notice error" role="alert">(description)</p>
        }
        if let Some((label, href)) = link {
            <a class="button" href=(href)>(label)</a>
        }
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
        <div>
            <h1>(title)</h1>
            <p class="lead">(lead)</p>
        </div>
        <a class="button" href=(href)>"Continue"</a>
    })
}
