//! piquel.fr's pages: the homepage, which says what Piquel is, and Piquel's
//! policies, which every Piquel page's footer links.

use piquel_ui::{Policies, intro};
use topcoat::{
    Result,
    view::{View, ViewHandle, component, view},
};

/// One of piquel.fr's pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Page {
    /// The homepage.
    Home,
    /// What Piquel collects, why, for how long, and who else sees it.
    Privacy,
    /// The terms of using Piquel's accounts, sign-in and developer console.
    Terms,
}

impl Page {
    /// Every page.
    pub(crate) const ALL: [Self; 3] = [Self::Home, Self::Privacy, Self::Terms];

    /// Its path. The policies' are a contract with auth, which links them.
    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::Home => "/",
            Self::Privacy => Policies::PATHS.privacy,
            Self::Terms => Policies::PATHS.terms,
        }
    }

    /// Its title in the browser, before "· Piquel".
    pub(crate) const fn title(self) -> &'static str {
        match self {
            Self::Home => "Passkey sign-in",
            Self::Privacy => "Privacy policy",
            Self::Terms => "Terms of service",
        }
    }

    /// A policy's text: a fragment of trusted HTML, embedded at compile time, so it
    /// reads and diffs as a document.
    const fn text(self) -> &'static str {
        match self {
            Self::Home => "",
            Self::Privacy => include_str!("../assets/policies/privacy.html"),
            Self::Terms => include_str!("../assets/policies/terms.html"),
        }
    }
}

/// Where the homepage links: auth's pages, and the developer documentation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HomeLinks<'a> {
    /// Signing in.
    pub sign_in: &'a str,
    /// Creating an account.
    pub register: &'a str,
    /// The account's settings.
    pub settings: &'a str,
    /// The developer console.
    pub developers: &'a str,
}

/// Piquel's source code.
const SOURCE: &str = "https://github.com/piquel-fr/piquel-fr";
/// The developer documentation.
const DOCUMENTATION: &str = "https://github.com/piquel-fr/piquel-fr#oidc-clients";

/// The body of `page`; the homepage links auth's pages at `links`.
#[component]
pub(crate) async fn page_body(page: Page, links: HomeLinks<'_>) -> Result<impl View> {
    Ok(view! {
        match page {
            Page::Home => home(links: links),
            Page::Privacy | Page::Terms => {
                <article class="site policy">
                    (ViewHandle::unescaped_unchecked(page.text()))
                </article>
            }
        }
    })
}

/// The homepage: what Piquel's sign-in is, and each part of it.
#[component]
async fn home(links: HomeLinks<'_>) -> Result<impl View> {
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
                    <a href=(DOCUMENTATION)>"Documentation"</a>
                </article>
                <article class="card stack wide">
                    <h2>"Open source"</h2>
                    <p>"All of Piquel's code is public, under the Apache 2.0 license. Read exactly how your data is handled, report a problem, or contribute."</p>
                    <a href=(SOURCE)>"Source code"</a>
                </article>
            </div>
        </section>
    })
}
