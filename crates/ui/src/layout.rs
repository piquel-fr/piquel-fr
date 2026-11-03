//! The document around every page, and the frames pages share: the shell of the
//! signed-in pages, a sidebar beside the page and a status bar below it, which
//! the account's pages and the admin dashboard both use, and the narrow column
//! of the pages a signed-out browser sees.
//!
//! Everything works without scripts, since the dashboard loads none: the theme
//! and the sidebar's width are preferences a form posts and a cookie keeps, and
//! on phones a checkbox the shell reads opens the sidebar as a drawer.

use crate::{
    Alert, Messages,
    clients::copyable,
    form::Fields,
    icons::{Icon, icon},
    settings::Tab,
};
use piquel_common::{TraceId, UserId, admin::Paging};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{Child, View, class, component, view},
};

/// The repository every page links in its status bar.
const SOURCE: &str = "https://github.com/piquel-fr/piquel-fr";

/// A section of the account's pages, which the sidebar groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// The account's settings.
    Account,
    /// The developer console: the apps the account registers.
    Developers,
}

impl Section {
    /// Its name, in the sidebar and the crumb.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Account => "Account",
            Self::Developers => "Developers",
        }
    }

    /// What its pages ask a browser that is not signed in, and why.
    const fn sign_in(self) -> (&'static str, &'static str) {
        match self {
            Self::Account => (
                "Sign in to see your settings",
                "Use your Piquel account to manage your passkeys, devices and linked providers.",
            ),
            Self::Developers => (
                "Sign in to manage your apps",
                "Use your Piquel account to register and manage the apps that sign users in with it.",
            ),
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
    /// Adding a passkey with a recovery link.
    Recover,
    /// Undoing or cancelling a recovery.
    UndoRecovery,
    /// Going on to the admin dashboard.
    Dashboard,
    /// The account, just scheduled for deletion.
    AccountDeleted,
    /// Restoring an account scheduled for deletion.
    Restore,
    /// The theme and sidebar preferences.
    Preferences,
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
            Self::Recover => "Recover your account",
            Self::UndoRecovery => "Undo a recovery",
            Self::Dashboard => "Admin dashboard",
            Self::AccountDeleted => "Your account is scheduled for deletion",
            Self::Restore => "Restore your account",
            Self::Preferences => "Preferences",
        }
    }
}

piquel_common::str_enum! {
    /// A theme the browser chose, over the one it prefers.
    pub enum Theme {
        /// Light.
        Light = "light",
        /// Dark.
        Dark = "dark",
    }
}

piquel_common::str_enum! {
    /// How wide the sidebar is, on windows wide enough to show it beside the page.
    pub enum Sidebar {
        /// Icons and their labels.
        Expanded = "expanded",
        /// Icons alone, titled.
        Collapsed = "collapsed",
    }
}

/// What the browser chose for every page, as its cookies carry it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Preferences {
    /// The theme, if chosen; otherwise the one the browser prefers.
    pub theme: Option<Theme>,
    /// The sidebar's width, if chosen; expanded otherwise.
    pub sidebar: Option<Sidebar>,
}

/// What a preference form posts: the theme or the sidebar's width, and the page
/// to come back to. A value a form got wrong reads as absent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferenceChange {
    /// The theme to keep.
    #[serde(
        default,
        deserialize_with = "Fields::lenient",
        skip_serializing_if = "Option::is_none"
    )]
    pub theme: Option<Theme>,
    /// The sidebar's width to keep.
    #[serde(
        default,
        deserialize_with = "Fields::lenient",
        skip_serializing_if = "Option::is_none"
    )]
    pub sidebar: Option<Sidebar>,
    /// The page the form was on, as a path on the same origin.
    #[serde(default)]
    pub return_to: String,
}

/// Something a navigation links, by its label.
pub(crate) trait Label: Copy + PartialEq + Send + Sync + 'static {
    /// The `aria-current` of the current one's link: `page` when the link opens
    /// the page shown, as a tab's does.
    const CURRENT: &'static str = "page";

    /// The link's text.
    fn label(self) -> &'static str;
}

/// Where Piquel's users and developers write to.
pub const SUPPORT_ADDRESS: &str = "support@piquel.fr";

/// Where every page's footer links Piquel's policies, which piquel.fr serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policies<'a> {
    /// The privacy policy.
    pub privacy: &'a str,
    /// The terms of service.
    pub terms: &'a str,
}

impl Policies<'static> {
    /// The policies' paths on piquel.fr: piquel.fr routes them, and auth links
    /// them on its origin.
    pub const PATHS: Self = Self {
        privacy: "/privacy",
        terms: "/terms",
    };
}

/// The document around every page: the head, which links `stylesheet` and loads
/// the passkey `script`, if the page has one, and the page as `child`. `title`
/// names the page in the browser, before "· Piquel". The browser's `preferences`
/// set the theme and the sidebar's width on the root, where the stylesheet reads
/// them, and an `admin` page is marked so the stylesheet colours it as the
/// dashboard. Only an `indexable` page, such as piquel.fr's own, may be indexed
/// by search engines.
#[component]
pub async fn document<'a>(
    title: &'a str,
    stylesheet: &'a str,
    #[into]
    #[default]
    script: Option<&'a str>,
    #[default] preferences: Preferences,
    #[default] admin: bool,
    #[default] indexable: bool,
    child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html
            lang="en"
            data-theme=(preferences.theme.map(Theme::as_str))
            data-sidebar=(preferences.sidebar.map(Sidebar::as_str))
        >
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
                if !indexable {
                    <meta name="robots" content="noindex">
                }
                <meta name="color-scheme" content="light dark">
                <title>(format!("{title} · Piquel"))</title>
                <link rel="stylesheet" href=(stylesheet)>
                if let Some(script) = script {
                    <script type="module" src=(script)></script>
                }
            </head>
            <body class=(admin.then_some("admin"))>
                (child)
            </body>
        </html>
    })
}

/// A link of the sidebar.
#[derive(Clone, Copy, Debug)]
pub struct NavItem<'a> {
    /// Its icon.
    pub icon: Icon,
    /// Its label, also its title once the sidebar is collapsed to icons.
    pub label: &'a str,
    /// Where it goes.
    pub href: &'a str,
    /// Whether it is the page shown, or the part the page belongs to.
    pub current: bool,
    /// Whether something there needs attention, which a dot shows.
    pub warning: bool,
}

/// A group of the sidebar's links, under its label, if any.
#[derive(Clone, Copy, Debug)]
pub struct NavGroup<'a> {
    /// Its label, in the sidebar's small type.
    pub label: Option<&'a str>,
    /// Its links.
    pub items: &'a [NavItem<'a>],
}

/// Who is signed in, as the sidebar and top bar show them.
#[derive(Clone, Copy, Debug)]
pub struct Who<'a> {
    /// Their account, which the passkey script tells the password manager.
    pub user: Option<UserId>,
    /// The name shown.
    pub name: &'a str,
    /// Their handle.
    pub handle: &'a str,
    /// Whether they administer Piquel, which rings their avatar in red.
    pub administrator: bool,
}

impl Who<'_> {
    /// Up to two initials of the name, for the avatar.
    fn initials(&self) -> String {
        let mut initials: String = self
            .name
            .split_whitespace()
            .filter_map(|word| word.chars().next())
            .take(2)
            .flat_map(char::to_uppercase)
            .collect();
        if initials.is_empty() {
            initials = self
                .handle
                .chars()
                .take(2)
                .flat_map(char::to_uppercase)
                .collect();
        }
        initials
    }
}

/// Whether the service needs attention, as the status bar says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Health {
    /// Nothing needs attention.
    #[default]
    Normal,
    /// This many things do, on the dashboard's overview.
    Warnings(u32),
}

/// A search form the top bar shows, posting `name` to `action` by `GET`.
#[derive(Clone, Copy, Debug)]
pub struct Search<'a> {
    /// Where it searches.
    pub action: &'a str,
    /// Its input's name.
    pub name: &'a str,
    /// What it searches, as the input's placeholder and label.
    pub placeholder: &'a str,
    /// What was searched, if anything.
    pub value: &'a str,
}

/// The frame of a signed-in page: what every part of the shell shows.
#[derive(Clone, Copy, Debug)]
pub struct Shell<'a> {
    /// Where the brand links.
    pub home: &'a str,
    /// The part of Piquel the page belongs to, after the brand.
    pub area: &'a str,
    /// The sidebar's links.
    pub groups: &'a [NavGroup<'a>],
    /// Who is signed in, if the sidebar shows them.
    pub who: Option<Who<'a>>,
    /// Their own page, which the top bar's avatar links.
    pub me: Option<&'a str>,
    /// The page's name in the crumb, after the area's link.
    pub page: &'a str,
    /// A search form in the top bar, if the area has one.
    pub search: Option<Search<'a>>,
    /// What the browser chose, which the toggles reverse.
    pub preferences: Preferences,
    /// Where the preference forms post.
    pub preferences_action: &'a str,
    /// The page's own path and query, which the preference forms come back to.
    pub here: &'a str,
    /// Where signing out posts, if the sidebar offers it.
    pub sign_out: Option<&'a str>,
    /// What the status bar says of the service.
    pub health: Health,
    /// The deployment the status bar names, if it names one.
    pub environment: Option<&'a str>,
    /// Piquel's policies, which the status bar links.
    pub policies: Policies<'a>,
    /// The `reference` of a server error's trace, for the user to quote.
    pub reference: Option<TraceId>,
}

/// The shell of a signed-in page: the sidebar, the top bar with its crumb, the
/// page as `child`, and the status bar. The browser's `preferences` pick the
/// theme switch shown.
#[component]
pub async fn shell<'a>(frame: &'a Shell<'a>, child: Child<'_>) -> Result<impl View> {
    let reference = frame.reference.map(|reference| reference.to_string());
    Ok(view! {
        <div class="shell">
            <a class="skip" href="#content">"Skip to content"</a>
            sidebar(frame: frame)
            <label class="scrim" for="menu" aria-hidden="true"></label>
            <div class="main">
                topbar(frame: frame)
                <main id="content" class="content" tabindex="-1">
                    (child)
                    if let Some(reference) = &reference {
                        <footer class="reference stack">
                            <p class="help">"If you report this error, include this reference."</p>
                            copyable(id: "reference", label: "reference", value: reference.as_str())
                        </footer>
                    }
                </main>
                status_bar(health: Some(frame.health), environment: frame.environment, policies: frame.policies)
            </div>
        </div>
    })
}

/// The sidebar of [`shell`]: the brand and the width toggle, the groups of
/// links, then the theme switch, signing out and who is signed in.
#[component]
async fn sidebar<'a>(frame: &'a Shell<'a>) -> Result<impl View> {
    Ok(view! {
        <aside class="sidebar">
            <div class="top">
                <a class="brand" href=(frame.home) aria-label="Piquel home">
                    <span class="mark">"p"</span>
                    <span class="name">"piquel"</span>
                    <span class="area">(frame.area)</span>
                </a>
                sidebar_toggle(
                    action: frame.preferences_action,
                    here: frame.here,
                    collapsed: frame.preferences.sidebar == Some(Sidebar::Collapsed),
                )
                <label class="collapse close" for="menu" aria-label="Close the menu">
                    icon(kind: Icon::Close)
                </label>
            </div>
            for group in frame.groups {
                if let Some(label) = group.label {
                    <div class="group">(label)</div>
                }
                <nav aria-label=(group.label.unwrap_or(frame.area))>
                    for item in group.items {
                        <a
                            href=(item.href)
                            title=(item.label)
                            aria-current=(item.current.then_some("page"))
                        >
                            icon(kind: item.icon)
                            <span class="label">(item.label)</span>
                            if item.warning {
                                <span class="count warning" title="Needs attention"></span>
                            }
                        </a>
                    }
                </nav>
            }
            <div class="end">
                theme_toggle(action: frame.preferences_action, here: frame.here)
                if let Some(sign_out) = frame.sign_out {
                    <form method="post" action=(sign_out) data-submit-once="">
                        <button type="submit" title="Sign out">
                            icon(kind: Icon::SignOut)
                            <span class="label">"Sign out"</span>
                        </button>
                    </form>
                }
                if let Some(who) = frame.who {
                    <div
                        class="who"
                        data-passkey-user=(who.user.map(|user| user.to_string()))
                        data-passkey-name=(who.user.map(|_| who.handle))
                        data-passkey-display-name=(who.user.map(|_| who.name))
                    >
                        avatar(who: who)
                        <div>
                            (who.name)
                            <small>(format!("@{}", who.handle))</small>
                        </div>
                    </div>
                }
            </div>
        </aside>
    })
}

/// The top bar of [`shell`]: the menu button of the drawer, the crumb, the search
/// form, if the area has one, and the avatar.
#[component]
async fn topbar<'a>(frame: &'a Shell<'a>) -> Result<impl View> {
    Ok(view! {
        <header class="topbar">
            <label class="menu-button" for="menu">
                <input type="checkbox" id="menu" aria-label="Menu">
                icon(kind: Icon::Menu)
            </label>
            <div class="crumb">
                <a href=(frame.home)>(frame.area.to_lowercase())</a>
                <span aria-hidden="true">"/"</span>
                <b>(frame.page.to_lowercase())</b>
            </div>
            <div class="right">
                if let Some(search) = frame.search {
                    <form class="search" method="get" action=(search.action) role="search">
                        <label class="search-box">
                            icon(kind: Icon::Search)
                            <input
                                name=(search.name)
                                value=(search.value)
                                placeholder=(search.placeholder)
                                aria-label=(search.placeholder)
                                autocomplete="off"
                            >
                        </label>
                    </form>
                }
                if let Some(who) = frame.who {
                    <a class="me" href=(frame.me.unwrap_or(frame.home)) title="Your account" aria-label="Your account">
                        avatar(who: who)
                    </a>
                }
            </div>
        </header>
    })
}

/// The form collapsing the sidebar, or expanding it once `collapsed`, posting
/// to `action` and coming back to `here`. The stylesheet turns its chevron
/// around once collapsed, and hides it on phones, where the sidebar is a drawer.
#[component]
async fn sidebar_toggle<'a>(action: &'a str, here: &'a str, collapsed: bool) -> Result<impl View> {
    let (value, title) = if collapsed {
        (Sidebar::Expanded, "Expand the sidebar")
    } else {
        (Sidebar::Collapsed, "Collapse the sidebar")
    };
    Ok(view! {
        <form class="sidebar-toggle" method="post" action=(action)>
            <input type="hidden" name="return_to" value=(here)>
            <button class="collapse" name="sidebar" value=(value.as_str()) title=(title) aria-label=(title)>
                icon(kind: Icon::Chevron)
            </button>
        </form>
    })
}

/// The form choosing the theme, posting to `action` and coming back to `here`:
/// a button for each theme, of which the stylesheet shows the one not in use.
#[component]
async fn theme_toggle<'a>(action: &'a str, here: &'a str) -> Result<impl View> {
    Ok(view! {
        <form class="theme-toggle" method="post" action=(action)>
            <input type="hidden" name="return_to" value=(here)>
            <button name="theme" value="dark" title="Dark theme">
                icon(kind: Icon::Moon)
                <span class="label">"Dark theme"</span>
            </button>
            <button name="theme" value="light" title="Light theme">
                icon(kind: Icon::Sun)
                <span class="label">"Light theme"</span>
            </button>
        </form>
    })
}

/// `who`'s initials, ringed in red for an administrator.
#[component]
pub(crate) async fn avatar<'a>(who: Who<'a>, #[default] small: bool) -> Result<impl View> {
    Ok(view! {
        <span
            class=(class!("avatar", "admin" if who.administrator, "small" if small))
            title=(if who.administrator { "Administrator" } else { who.name })
            aria-hidden="true"
        >
            (who.initials())
        </span>
    })
}

/// The status bar below every page: whether the service needs attention, when a
/// page knows, the `environment` it runs in, if named, that Piquel is open
/// source, and the links: the source, Piquel's `policies` and support.
#[component]
pub(crate) async fn status_bar<'a>(
    #[default] health: Option<Health>,
    #[default] environment: Option<&'a str>,
    policies: Policies<'a>,
) -> Result<impl View> {
    Ok(view! {
        <footer class="status">
            match health {
                Some(Health::Normal) => {
                    <span class="health"><span class="dot ok"></span>"All systems normal"</span>
                }
                Some(Health::Warnings(count)) => {
                    <span class="health">
                        <span class="dot warning"></span>
                        (format!("{count} warning{}", if count == 1 { "" } else { "s" }))
                    </span>
                }
                None => {}
            }
            if let Some(environment) = environment {
                <span class="mono">(environment)</span>
            }
            <span>"Piquel is open source"</span>
            <span class="right">
                <a href=(SOURCE)>"Source"</a>
                <a href=(policies.privacy)>"Privacy"</a>
                <a href=(policies.terms)>"Terms"</a>
                <a href=(format!("mailto:{SUPPORT_ADDRESS}"))>"Support"</a>
            </span>
        </footer>
    })
}

/// The frame of a page a signed-out browser sees, or one outside the account's
/// shell: the brand above, the page as `child` in one narrow column, and the
/// status bar below. The brand links `home`. A page answering a server error
/// shows the `reference` of its trace, for the user to quote in a report. A page
/// on the way to the `admin` dashboard says so beside the brand. The status bar
/// links Piquel's `policies`.
#[component]
pub async fn auth_shell<'a>(
    home: &'a str,
    #[default] reference: Option<TraceId>,
    #[default] admin: bool,
    policies: Policies<'a>,
    child: Child<'_>,
) -> Result<impl View> {
    let reference = reference.map(|reference| reference.to_string());
    Ok(view! {
        <div class="auth">
            <header>
                <a class="brand" href=(home) aria-label="Piquel home">
                    <span class="mark">"p"</span>
                    "piquel"
                    if admin {
                        <span class="area">"Admin"</span>
                    }
                </a>
            </header>
            <main>
                (child)
                if let Some(reference) = &reference {
                    <footer class="reference stack">
                        <p class="help">"If you report this error, include this reference."</p>
                        copyable(id: "reference", label: "reference", value: reference.as_str())
                    </footer>
                }
            </main>
            status_bar(policies: policies)
        </div>
    })
}

/// The frame of piquel.fr's own pages: the brand, the `links` beside it, the
/// page as `child` in a wide column, and the status bar linking the `policies`.
/// Its pages have no forms, so the theme follows the browser alone.
#[component]
pub async fn site_shell<'a>(
    home: &'a str,
    links: &'a [(&'a str, &'a str)],
    policies: Policies<'a>,
    child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <div class="auth site">
            <header>
                <a class="brand" href=(home) aria-label="Piquel home">
                    <span class="mark">"p"</span>
                    "piquel"
                </a>
                <nav class="site-links" aria-label="Piquel">
                    for (label, href) in links {
                        <a href=(*href)>(*label)</a>
                    }
                </nav>
            </header>
            <main>
                (child)
            </main>
            status_bar(policies: policies)
        </div>
    })
}

/// Where a list's page stands, and the links to the pages before and after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pager {
    /// Where the page stands.
    pub paging: Paging,
    /// The previous page, if there is one.
    pub previous: Option<String>,
    /// The next page, if there is one.
    pub next: Option<String>,
}

impl Pager {
    /// The pager of `paging`, linking each page `link` names.
    ///
    /// # Errors
    ///
    /// Fails as `link` does.
    pub fn of<E>(
        paging: Paging,
        mut link: impl FnMut(u32) -> Result<String, E>,
    ) -> Result<Self, E> {
        Ok(Self {
            previous: paging.previous().map(&mut link).transpose()?,
            next: paging.next().map(&mut link).transpose()?,
            paging,
        })
    }
}

/// The pager below a list of `what`: which items the page shows of how many, and
/// the previous and next pages. A list that fits one page shows only its count.
#[component]
pub(crate) async fn pager<'a>(pages: &'a Pager, what: &'a str) -> Result<impl View> {
    let paging = pages.paging;
    let shown = match paging.range() {
        Some((first, last)) => format!("{first}–{last} of {} {what}", paging.total),
        None => format!("No {what}"),
    };
    Ok(view! {
        <nav class="pager" aria-label="Pages">
            <span class="muted">(shown.as_str())</span>
            if paging.pages > 1 {
                <span class="row">
                    match &pages.previous {
                        Some(href) => <a class="button secondary small" href=(href.as_str()) rel="prev">"Previous"</a>,
                        None => <span class="button secondary small" aria-disabled="true">"Previous"</span>,
                    }
                    <span class="mono muted">(format!("page {} of {}", paging.page, paging.pages))</span>
                    match &pages.next {
                        Some(href) => <a class="button secondary small" href=(href.as_str()) rel="next">"Next"</a>,
                        None => <span class="button secondary small" aria-disabled="true">"Next"</span>,
                    }
                </span>
            }
        </nav>
    })
}

/// A page's opening: its `title`, a `lead` paragraph, if any, and what acts on
/// the whole page as `actions`, beside them.
#[component]
pub async fn page_head(
    #[into] title: String,
    #[into]
    #[default]
    lead: Option<String>,
    #[into]
    #[default]
    actions: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <div class="page-head">
            <div>
                <h1>(title)</h1>
                if let Some(lead) = &lead {
                    <p class="lead">(lead.as_str())</p>
                }
            </div>
            <div class="row">(actions)</div>
        </div>
    })
}

/// What a page says: the `alert` of a change that failed, and the `notice` of
/// the one just made.
#[component]
pub(crate) async fn page_messages<'a>(messages: Messages<'a>) -> Result<impl View> {
    Ok(view! {
        // A refused setting is said beside its input instead.
        if let Some(Alert::Page(alert)) = messages.alert {
            <p class="notice error" role="alert">icon(kind: Icon::Warning)<span class="text">(alert)</span></p>
        }
        if let Some(notice) = messages.notice {
            <p class="notice" role="status">icon(kind: Icon::Check)<span class="text">(notice.message())</span></p>
        }
    })
}

/// An email `address`, blurred until clicked so a shared screen does not show it;
/// clicking again blurs it. A checkbox, visually hidden, holds whether it shows:
/// the admin dashboard allows no script.
#[component]
pub(crate) async fn private_address<'a>(address: &'a str) -> Result<impl View> {
    Ok(view! {
        <label class="private-address">
            <input type="checkbox" aria-label="Show address">
            <span>(address)</span>
        </label>
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

/// The account's sidebar: each settings tab's page in `tabs`, `current` among
/// them, if a tab is shown, and the developer console's home at `developers`,
/// which is current when `section` is it.
#[derive(Clone, Copy, Debug)]
pub struct AccountNav<'a> {
    /// The section shown.
    pub section: Section,
    /// Each settings tab's page.
    pub tabs: &'a [(Tab, &'a str)],
    /// The settings tab shown, if the page is one.
    pub current: Option<Tab>,
    /// The developer console's home.
    pub developers: &'a str,
}

/// A signed-in page of `section`, in the account's shell: the sidebar of `nav`
/// for `who`, signing out by posting to `sign_out`, the preference forms posting
/// to `preferences_action`, reversing `preferences`, and coming back to `here`,
/// the page named `title` in the crumb, and the status bar linking Piquel's
/// `policies`; then what the account's `recovery` that can still be undone asks,
/// if any, such as a [`crate::recovery_banner`]; the page's `head`, such as an
/// app's tabs, its `messages`, and the page as `child`.
#[component]
pub async fn account<'a>(
    nav: AccountNav<'a>,
    who: Who<'a>,
    title: &'a str,
    home: &'a str,
    sign_out: &'a str,
    preferences: Preferences,
    preferences_action: &'a str,
    here: &'a str,
    policies: Policies<'a>,
    #[default] reference: Option<TraceId>,
    #[into]
    #[default]
    recovery: Child<'_>,
    #[into]
    #[default]
    head: Child<'_>,
    #[default] messages: Messages<'a>,
    child: Child<'_>,
) -> Result<impl View> {
    let tabs: Vec<_> = nav
        .tabs
        .iter()
        .map(|(tab, href)| NavItem {
            icon: tab.icon(),
            label: tab.label(),
            href,
            current: nav.current == Some(*tab),
            warning: false,
        })
        .collect();
    let console = [NavItem {
        icon: Icon::Code,
        label: "Your apps",
        href: nav.developers,
        current: nav.section == Section::Developers,
        warning: false,
    }];
    Ok(view! {
        let groups = [
            NavGroup {
                label: Some("account"),
                items: &tabs,
            },
            NavGroup {
                label: Some("developers"),
                items: &console,
            },
        ];
        let frame = Shell {
            home,
            area: nav.section.label(),
            groups: &groups,
            who: Some(who),
            me: Some(home),
            page: title,
            search: None,
            preferences,
            preferences_action,
            here,
            sign_out: Some(sign_out),
            health: Health::Normal,
            environment: None,
            policies,
            reference,
        };
        shell(
            frame: &frame,
            (recovery)
            (head)
            page_messages(messages: messages)
            (child)
        )
    })
}

/// What `section`'s pages show a browser that is not signed in: a link to sign
/// in, at `sign_in`, which comes back to the page.
#[component]
pub async fn signed_out(section: Section, sign_in: &str) -> Result<impl View> {
    let (title, why) = section.sign_in();
    Ok(view! {
        <h1>(title)</h1>
        <p class="lead">(why)</p>
        <a class="button" href=(sign_in)>"Sign in"</a>
    })
}
