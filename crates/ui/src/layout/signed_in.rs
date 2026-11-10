//! The shell of the signed-in pages: the sidebar beside the page, with its
//! links, its width and theme toggles and who is signed in, and the top bar
//! with its crumb and search.

use super::{
    Health, Policies, Preferences, Sidebar,
    frames::status_bar,
    search::{Search, search_box},
};
use crate::{
    clients::copyable,
    icons::{Icon, icon},
};
use sourceorigin_common::{TraceId, UserId};
use topcoat::{
    Result,
    view::{Child, View, class, component, view},
};

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
    /// How many things there are new, such as unread notifications, if any.
    pub count: Option<u64>,
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
    /// The name shown.
    pub name: &'a str,
    /// Their handle.
    pub handle: &'a str,
    /// Where their profile picture is served, which their avatar shows instead of
    /// their initials.
    pub picture: Option<&'a str>,
    /// Whether they administer Origin Auth, which rings their avatar in red.
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

/// What the passkey script tells the browser's password manager of the
/// signed-in account (the `WebAuthn` Signal API): its current handle and name,
/// from [`Who`], so its passkeys show them after a change, and which of its
/// passkeys still exist.
#[derive(Clone, Copy, Debug)]
pub struct PasskeySignal<'a> {
    /// The account, the user handle its passkeys carry.
    pub user: UserId,
    /// The credential ID of every passkey of the account that still signs in, in
    /// unpadded base64url. The password manager forgets the account's passkeys
    /// this does not list, so it must never miss one.
    pub credentials: &'a [String],
}

/// A page's name in the crumb.
#[derive(Clone, Copy, Debug)]
pub enum Crumb<'a> {
    /// A menu's label, which the crumb shows in lowercase like the rest of
    /// the bar.
    Label(&'a str),
    /// A name someone chose, such as a handle or an app's, shown as it is.
    Name(&'a str),
}

impl<'a> Crumb<'a> {
    /// The name as written, for the browser's title.
    #[must_use]
    pub fn as_str(self) -> &'a str {
        match self {
            Self::Label(name) | Self::Name(name) => name,
        }
    }

    /// The name as the crumb shows it.
    fn text(self) -> String {
        match self {
            Self::Label(label) => label.to_lowercase(),
            Self::Name(name) => name.to_owned(),
        }
    }
}

impl<'a> From<&'a str> for Crumb<'a> {
    /// A plain string names a page from a menu.
    fn from(label: &'a str) -> Self {
        Self::Label(label)
    }
}

/// What a [`Shortcut`] of the top bar leads to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortcutKind {
    /// The signed-in account's inbox, counting its unread notifications.
    Inbox,
    /// The dashboard's alerts, counting the open ones.
    Alerts,
}

impl ShortcutKind {
    /// Its icon.
    const fn icon(self) -> Icon {
        match self {
            Self::Inbox => Icon::Bell,
            Self::Alerts => Icon::Warning,
        }
    }

    /// Its name, as its title and label.
    const fn label(self) -> &'static str {
        match self {
            Self::Inbox => "Notifications",
            Self::Alerts => "Alerts",
        }
    }

    /// What its count counts, after the number in its label.
    const fn counted(self) -> &'static str {
        match self {
            Self::Inbox => "unread",
            Self::Alerts => "open",
        }
    }

    /// Its class, which the stylesheet colors its count by.
    const fn class(self) -> &'static str {
        match self {
            Self::Inbox => "shortcut inbox",
            Self::Alerts => "shortcut alerts",
        }
    }
}

/// An icon link of the top bar, before the avatar, with a count at its corner
/// once there is something to count: the inbox's bell, on the account's pages
/// and the dashboard, and the dashboard's alerts.
#[derive(Clone, Copy, Debug)]
pub struct Shortcut<'a> {
    /// What it leads to.
    pub kind: ShortcutKind,
    /// Where it goes.
    pub href: &'a str,
    /// How many there are: unread notifications, or open alerts.
    pub count: u64,
}

impl Shortcut<'_> {
    /// Its label, with the count when there is one, as screen readers say it.
    fn aria_label(&self) -> String {
        match self.count {
            0 => self.kind.label().to_owned(),
            count => format!("{}, {count} {}", self.kind.label(), self.kind.counted()),
        }
    }
}

/// The frame of a signed-in page: what every part of the shell shows.
#[derive(Clone, Copy, Debug)]
pub struct Shell<'a> {
    /// Where the brand links.
    pub home: &'a str,
    /// The part of SourceOrigin the page belongs to, after the brand.
    pub area: &'a str,
    /// Where the crumb's area links: the part's own home.
    pub area_home: &'a str,
    /// The sidebar's links.
    pub groups: &'a [NavGroup<'a>],
    /// Who is signed in, if the sidebar shows them.
    pub who: Option<Who<'a>>,
    /// What the password manager is told of the account signed in, on its own
    /// pages only.
    pub signal: Option<PasskeySignal<'a>>,
    /// Their own page, which the top bar's avatar links.
    pub me: Option<&'a str>,
    /// The top bar's shortcuts, before the avatar.
    pub shortcuts: &'a [Shortcut<'a>],
    /// The pages between the area and the page in the crumb, each named and
    /// linked: the tab the page belongs to, then the page it is under, if any.
    pub trail: &'a [(Crumb<'a>, &'a str)],
    /// The page's name in the crumb, after the area's link.
    pub page: Crumb<'a>,
    /// The search in the top bar, if the area has one.
    pub search: Option<Search<'a>>,
    /// What the browser chose, which the toggles reverse.
    pub preferences: Preferences,
    /// Where the preference forms post.
    pub preferences_action: &'a str,
    /// The page's own path and query, which the preference forms come back to.
    pub here: &'a str,
    /// Where signing out posts, if the sidebar offers it.
    pub sign_out: Option<&'a str>,
    /// What the status bar says of the service, if the page checked.
    pub health: Option<Health>,
    /// The deployment the status bar names, if it names one.
    pub environment: Option<&'a str>,
    /// SourceOrigin's policies, which the status bar links.
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
            // The drawer's state, ahead of the drawer so the keyboard goes on
            // into it once opened; the top bar's button is its label.
            <input type="checkbox" id="menu" class="menu-state" aria-label="Menu">
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
                status_bar(health: frame.health, environment: frame.environment, policies: frame.policies)
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
                <a class="brand" href=(frame.home) aria-label="Origin Auth home">
                    <span class="mark">"o"</span>
                    <span class="name">"Origin Auth"</span>
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
                            } else if let Some(count) = item.count {
                                <span class="count new" title=(format!("{count} new"))>(count.to_string())</span>
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
                        data-passkey-user=(frame.signal.map(|signal| signal.user.to_string()))
                        data-passkey-name=(frame.signal.map(|_| who.handle))
                        data-passkey-display-name=(frame.signal.map(|_| who.name))
                        data-passkey-credentials=(frame.signal.map(|signal| signal.credentials.join(" ")))
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

/// The top bar of [`shell`]: the menu button of the drawer, the crumb, the search,
/// if the area has one, the shortcuts, and the avatar.
#[component]
async fn topbar<'a>(frame: &'a Shell<'a>) -> Result<impl View> {
    Ok(view! {
        // Boxed, so the page's type stops at the search: its results nest deeper
        // than the compiler follows a page's type.
        let search = frame
            .search
            .map(|search| Child::new(view! { search_box(search: search) }));
        <header class="topbar">
            <label class="menu-button" for="menu" aria-hidden="true">
                icon(kind: Icon::Menu)
            </label>
            <div class="crumb">
                <a href=(frame.area_home)>(frame.area.to_lowercase())</a>
                <span aria-hidden="true">"/"</span>
                for (name, href) in frame.trail {
                    <a href=(*href)>(name.text())</a>
                    <span aria-hidden="true">"/"</span>
                }
                <b>(frame.page.text())</b>
            </div>
            <div class="right">
                if let Some(search) = search {
                    (search)
                }
                // One group, so phones keep the shortcuts and the avatar together.
                <div class="links">
                    for shortcut in frame.shortcuts {
                        <a
                            class=(shortcut.kind.class())
                            href=(shortcut.href)
                            title=(shortcut.kind.label())
                            aria-label=(shortcut.aria_label())
                        >
                            icon(kind: shortcut.kind.icon())
                            if shortcut.count > 0 {
                                <span class="count" aria-hidden="true">(shortcut.count.to_string())</span>
                            }
                        </a>
                    }
                    if let Some(who) = frame.who {
                        <a class="me" href=(frame.me.unwrap_or(frame.home)) title="Your account" aria-label="Your account">
                            avatar(who: who)
                        </a>
                    }
                </div>
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

/// How large an [`avatar`] is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum AvatarSize {
    /// In a list's dense rows.
    Small,
    /// Beside a name.
    #[default]
    Normal,
    /// On the profile page, where the picture is what the page is about.
    Large,
}

/// `who`'s profile picture, or their initials when they have none, ringed in red
/// for an administrator. It is decorative beside their name, so it has no text of
/// its own.
#[component]
pub(crate) async fn avatar<'a>(who: Who<'a>, #[default] size: AvatarSize) -> Result<impl View> {
    let class = class!(
        "avatar",
        "admin" if who.administrator,
        "small" if size == AvatarSize::Small,
        "large" if size == AvatarSize::Large,
    );
    let title = if who.administrator {
        "Administrator"
    } else {
        who.name
    };
    Ok(view! {
        if let Some(picture) = who.picture {
            <img class=(class) src=(picture) title=(title) alt="" width="96" height="96">
        } else {
            <span class=(class) title=(title) aria-hidden="true">(who.initials())</span>
        }
    })
}
