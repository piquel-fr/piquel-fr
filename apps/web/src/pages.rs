//! piquel.fr's pages: the homepage, which says what Piquel is, and Piquel's
//! policies, which every Piquel page's footer links.

use piquel_ui::{Policies, SOURCE};
use topcoat::{
    Result,
    view::{View, ViewHandle, class, component, view},
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

/// The developer documentation.
const DOCUMENTATION: &str = "https://github.com/piquel-fr/piquel-fr#oidc-clients";

/// The body of `page`; the homepage links auth's pages at `links`.
#[component]
pub(crate) async fn page_body(page: Page, links: HomeLinks<'_>) -> Result<impl View> {
    Ok(view! {
        match page {
            Page::Home => home(links: links),
            Page::Privacy => policy(text: include_str!("../assets/policies/privacy.html")),
            Page::Terms => policy(text: include_str!("../assets/policies/terms.html")),
        }
    })
}

/// A policy, whose `text` is a fragment of trusted HTML, embedded at compile time
/// so it reads and diffs as a document.
#[component]
async fn policy(text: &'static str) -> Result<impl View> {
    Ok(view! {
        <article class="policy">
            (ViewHandle::unescaped_unchecked(text))
        </article>
    })
}

/// The homepage: what Piquel's sign-in is, and each part of it.
#[component]
async fn home(links: HomeLinks<'_>) -> Result<impl View> {
    Ok(view! {
        <section class="hero">
            <p class="eyebrow">"Piquel"</p>
            <h1>"One passkey for every Piquel app."</h1>
            <p class="lead">"Piquel is a passkey-first sign-in service. Your Piquel account signs you in to Piquel's apps, and to other apps that use Piquel, with a passkey instead of a password."</p>
            <div class="row">
                <a class="button" href=(links.register)>"Create an account"</a>
                <a class="button secondary" href=(links.sign_in)>"Sign in"</a>
            </div>
        </section>
        <div class="site-grid">
            feature(title: "Sign in with a passkey", text: "Your passkey stays on your device or in your password manager. There is no password to steal or reuse. You can also link GitHub or Google to sign in.", label: "Sign in", href: links.sign_in)
            feature(title: "Your account, in your hands", text: "See and remove your passkeys, linked providers, email addresses, signed-in devices and the apps you allowed. Review your security history, download your data, or delete your account.", label: "Account settings", href: links.settings)
            feature(title: "For developers", text: "Register your app as an OpenID Connect client, so its users sign in with their Piquel account. Apps only get what their users approve.", label: "Developer console", href: links.developers)
            feature(title: "Open standards and SDKs", text: "Piquel speaks OpenID Connect and OAuth 2.0, so any standard library works. The Rust SDK, piquel-auth, validates tokens and signs users in for you.", label: "Documentation", href: DOCUMENTATION)
            feature(title: "Public source", text: "All of Piquel's code is public. Read exactly how your data is handled, report a problem, or contribute. You may use it for anything but commercial purposes, and the SDKs are free for any app under Apache 2.0.", label: "Source code", href: SOURCE, wide: true)
        </div>
    })
}

/// One part of Piquel on the homepage: its `title`, what it does as `text`, and
/// its link, labelled `label`, to `href`. A `wide` card spans the grid.
#[component]
async fn feature<'a>(
    title: &'a str,
    text: &'a str,
    label: &'a str,
    href: &'a str,
    #[default] wide: bool,
) -> Result<impl View> {
    Ok(view! {
        <article class=(class!("card", "wide" if wide))>
            <div class="body">
                <h2>(title)</h2>
                <p>(text)</p>
                <a href=(href)>(label)</a>
            </div>
        </article>
    })
}
