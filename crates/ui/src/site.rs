//! piquel.fr's own pages: the homepage, which says what Piquel's sign-in is, and
//! Piquel's policies, which every page's footer links.

use crate::intro;
use topcoat::{
    Result,
    view::{View, ViewHandle, component, view},
};

/// Where Piquel's users and developers write to.
pub const SUPPORT_ADDRESS: &str = "support@piquel.fr";

/// One of Piquel's policies. Its text is a fragment of trusted HTML, embedded at
/// compile time, so it reads and diffs as a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// What Piquel collects, why, for how long, and who else sees it.
    Privacy,
    /// The terms of using Piquel's accounts, sign-in and developer console.
    Terms,
}

impl Policy {
    /// Every policy.
    pub const ALL: [Self; 2] = [Self::Privacy, Self::Terms];

    /// Its title.
    #[must_use]
    pub const fn title(self) -> crate::Title {
        match self {
            Self::Privacy => crate::Title::Privacy,
            Self::Terms => crate::Title::Terms,
        }
    }

    /// Its text, as HTML.
    const fn text(self) -> &'static str {
        match self {
            Self::Privacy => include_str!("../assets/policies/privacy.html"),
            Self::Terms => include_str!("../assets/policies/terms.html"),
        }
    }
}

/// Where the homepage links: auth's pages, and the developer documentation.
#[derive(Clone, Copy, Debug)]
pub struct HomeLinks<'a> {
    /// Signing in.
    pub sign_in: &'a str,
    /// Creating an account.
    pub register: &'a str,
    /// The account's settings.
    pub settings: &'a str,
    /// The developer console.
    pub developers: &'a str,
    /// The developer documentation and the SDKs' source.
    pub documentation: &'a str,
}

/// piquel.fr's homepage: what Piquel's sign-in is, and each part of it, linking to
/// auth's pages at `links`.
#[component]
pub async fn home(links: HomeLinks<'_>) -> Result<impl View> {
    Ok(view! {
        <section class="site stack">
            <div class="site-hero">
                intro(
                    eyebrow: "Piquel",
                    title: "One passkey for every Piquel app.",
                    lead: "Piquel is a passkey-first sign-in service. Your Piquel account signs you in to Piquel's apps, and to other apps that use Piquel, with a passkey instead of a password.",
                )
                <div class="row">
                    <a class="button" href=(links.register)>"Create an account"</a>
                    <a class="button secondary" href=(links.sign_in)>"Sign in"</a>
                </div>
            </div>
            <div class="site-grid">
                <article class="card stack">
                    <h2>"Sign in with a passkey"</h2>
                    <p>"Your passkey stays on your device or in your password manager. There is no password to steal or reuse. You can also link GitHub or Google to sign in."</p>
                    <a href=(links.sign_in)>"Sign in"</a>
                </article>
                <article class="card stack">
                    <h2>"Your account, in your hands"</h2>
                    <p>"See and remove your passkeys, linked providers, email addresses, signed-in devices and the apps you allowed. Review your security history, download your data, or delete your account."</p>
                    <a href=(links.settings)>"Account settings"</a>
                </article>
                <article class="card stack">
                    <h2>"For developers"</h2>
                    <p>"Register your app as an OpenID Connect client, so its users sign in with their Piquel account. Apps only get what their users approve."</p>
                    <a href=(links.developers)>"Developer console"</a>
                </article>
                <article class="card stack">
                    <h2>"Open standards and SDKs"</h2>
                    <p>"Piquel speaks OpenID Connect and OAuth 2.0, so any standard library works. The Rust SDK, piquel-auth, validates tokens and signs users in for you."</p>
                    <a href=(links.documentation)>"Documentation"</a>
                </article>
            </div>
        </section>
    })
}

/// The page of the policy `of`.
#[component]
pub async fn policy(of: Policy) -> Result<impl View> {
    Ok(view! {
        <article class="site policy">
            (ViewHandle::unescaped_unchecked(of.text()))
        </article>
    })
}
