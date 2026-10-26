//! The document around every page, and the parts pages share: the frame of each
//! section of the account's pages, the account's bar and the navigations.

use crate::{Alert, Messages};
use topcoat::{
    Result,
    view::{Child, View, component, view},
};

/// Which part of Piquel a page belongs to, named after the brand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Area {
    /// Signing in, creating an account, consent and logout.
    #[default]
    SignIn,
    /// A section of the account's pages.
    Section(Section),
}

impl Area {
    /// The name shown after the brand.
    const fn label(self) -> &'static str {
        match self {
            Self::SignIn => " / sign in",
            Self::Section(Section::Account) => " / account",
            Self::Section(Section::Developers) => " / developers",
        }
    }
}

/// A section of the account's pages. Its pages share a frame, and the account's
/// bar links each section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// The account's settings.
    Account,
    /// The developer console: the apps the account registers.
    Developers,
}

/// What a section's pages say in their frame.
struct Wording {
    /// Above the heading.
    eyebrow: &'static str,
    /// The heading.
    title: &'static str,
    /// Below the heading.
    lead: &'static str,
    /// What its pages ask a browser that is not signed in.
    sign_in: &'static str,
    /// Why it should.
    why: &'static str,
}

impl Section {
    /// What its pages say in their frame.
    const fn wording(self) -> Wording {
        match self {
            Self::Account => Wording {
                eyebrow: "Your account",
                title: "Security, made personal.",
                lead: "Manage how you sign in to Piquel and keep your account in your hands.",
                sign_in: "Sign in to see your settings",
                why: "Use your Piquel account to manage your passkeys, devices and linked providers.",
            },
            Self::Developers => Wording {
                eyebrow: "Developers",
                title: "Sign users in with Piquel.",
                lead: "Register your apps as OpenID Connect clients, so their users sign in with their Piquel account and passkeys.",
                sign_in: "Sign in to manage your apps",
                why: "Use your Piquel account to register and manage the apps that sign users in with it.",
            },
        }
    }
}

impl Label for Section {
    /// A section's link opens its home, not each of its pages, so it marks the
    /// section the page belongs to.
    const CURRENT: &'static str = "true";

    /// Its name in the account's bar.
    fn label(self) -> &'static str {
        match self {
            Self::Account => "Account",
            Self::Developers => "Developers",
        }
    }
}

/// A page's title in the browser, for pages that are not tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Title {
    /// Signing in.
    SignIn,
    /// Creating an account.
    SignUp,
    /// Linking a provider's sign-in to an existing account.
    Link,
    /// OAuth consent.
    Consent,
    /// Confirming an application's logout request.
    Logout,
    /// Confirming an email address.
    VerifyEmail,
    /// The account's apps.
    Developers,
    /// Registering an app.
    NewApp,
    /// One of the account's apps, when its name is unknown.
    App,
}

impl Title {
    /// The title.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "Sign in",
            Self::SignUp => "Create your account",
            Self::Link => "Link social sign-in",
            Self::Consent => "Authorize application",
            Self::Logout => "Sign out",
            Self::VerifyEmail => "Confirm your email address",
            Self::Developers => "Developers",
            Self::NewApp => "New app",
            Self::App => "App",
        }
    }
}

/// Something a navigation links, by its label.
pub(crate) trait Label: Copy + PartialEq + Send + Sync + 'static {
    /// The `aria-current` of the current one's link: `page` when the link opens
    /// the page shown, as a tab's does.
    const CURRENT: &'static str = "page";

    /// The link's text.
    fn label(self) -> &'static str;
}

/// The document around every page: the head, which links `stylesheet` and loads
/// the SDK's `script`, if any, Piquel's header, whose brand links `home` and names
/// the page's `area`, and the page as `child`. `title` names the page in the
/// browser, before "· Piquel".
#[component]
pub async fn document<'a>(
    title: &'a str,
    stylesheet: &'a str,
    #[default] script: Option<&'a str>,
    home: &'a str,
    #[default] area: Area,
    child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta name="robots" content="noindex">
                <title>(format!("{title} · Piquel"))</title>
                <link rel="stylesheet" href=(stylesheet)>
                if let Some(script) = script {
                    <script type="module" src=(script)></script>
                }
            </head>
            <body>
                <div class="shell">
                    <header>
                        <a class="brand" href=(home) aria-label="Piquel home">
                            <span class="mark">"p"</span>
                            "piquel"
                            <span class="muted">(area.label())</span>
                        </a>
                    </header>
                    <main>(child)</main>
                </div>
            </body>
        </html>
    })
}

/// A page's opening: a small `eyebrow` above its `title`, then a `lead` paragraph,
/// if any.
#[component]
pub async fn intro<'a>(
    eyebrow: &'a str,
    #[into] title: String,
    #[into]
    #[default]
    lead: Option<&'a str>,
) -> Result<impl View> {
    Ok(view! {
        <div>
            <p class="eyebrow">(eyebrow)</p>
            <h1>(title)</h1>
            if let Some(lead) = lead {
                <p>(lead)</p>
            }
        </div>
    })
}

/// The navigation named `label`, of `class`, linking each of `links` to its URL,
/// `current` among them, whose link is marked [`Label::CURRENT`].
#[component]
pub(crate) async fn navigation<'a, T: Label>(
    label: &'a str,
    class: &'a str,
    links: &'a [(T, &'a str)],
    current: T,
) -> Result<impl View> {
    Ok(view! {
        <nav class=(class) aria-label=(label)>
            for (link, href) in links {
                <a href=(*href) aria-current=((*link == current).then_some(T::CURRENT))>(link.label())</a>
            }
        </nav>
    })
}

/// The frame of `section`'s pages: its heading, or `title` for a page outside its
/// navigation, then the page as `child`.
#[component]
pub(crate) async fn frame<'a>(
    section: Section,
    #[into]
    #[default]
    title: Option<&'a str>,
    child: Child<'_>,
) -> Result<impl View> {
    let wording = section.wording();
    Ok(view! {
        <section class="settings">
            <div class="settings-header">
                intro(
                    eyebrow: wording.eyebrow,
                    title: title.unwrap_or(wording.title),
                    lead: title.is_none().then_some(wording.lead),
                )
            </div>
            (child)
        </section>
    })
}

/// A signed-in page of `section`, in its frame: the bar of the account, named
/// `display_name` and `handle`, linking each section's page in `sections` and
/// signing out by posting to `sign_out`; then the page's `head`, such as its tabs,
/// its `messages`, and the page as `child`.
#[component]
pub async fn account<'a>(
    section: Section,
    display_name: &'a str,
    handle: &'a str,
    sections: &'a [(Section, &'a str)],
    sign_out: &'a str,
    #[into]
    #[default]
    head: Child<'_>,
    #[default] messages: Messages<'a>,
    child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        frame(
            section: section,
            <div class="row between">
                <div>
                    <strong>(display_name)</strong>
                    <p class="help">(format!("@{handle}"))</p>
                </div>
                <div class="row">
                    navigation(label: "Piquel", class: "site-nav", links: sections, current: section)
                    <form method="post" action=(sign_out) data-submit-once="">
                        <button class="text-button">"Sign out"</button>
                    </form>
                </div>
            </div>
            (head)
            // A refused setting is said beside its input instead.
            if let Some(Alert::Page(alert)) = messages.alert {
                <p class="notice error" role="alert">(alert)</p>
            }
            if let Some(notice) = messages.notice {
                <p class="notice" role="status">(notice.message())</p>
            }
            (child)
        )
    })
}

/// What `section`'s pages show a browser that is not signed in, in their frame: a
/// link to sign in, at `sign_in`, which comes back to the page.
#[component]
pub async fn signed_out(section: Section, sign_in: &str) -> Result<impl View> {
    let wording = section.wording();
    Ok(view! {
        frame(
            section: section,
            <div class="card stack">
                <h2>(wording.sign_in)</h2>
                <p>(wording.why)</p>
                <a class="button" href=(sign_in)>"Sign in"</a>
            </div>
        )
    })
}
