//! The account's sections, its settings and the developer console, and their
//! pages in the shell: its sidebar, and what they show a browser that is not
//! signed in.

use super::{
    Crumb, Destination, Group, NavGroup, NavItem, PasskeySignal, Policies, Preferences, Search,
    Shell, Shortcut, ShortcutKind, Spot, Who, page_messages, shell,
};
use crate::{AppLink, Messages, icons::Icon, settings::Tab};
use sourceorigin_common::TraceId;
use topcoat::{
    Result,
    view::{Child, View, component, view},
};

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
                "Use your Origin Account to manage your passkeys, devices and linked providers.",
            ),
            Self::Developers => (
                "Sign in to manage your apps",
                "Use your Origin Account to register and manage the apps that sign users in with it.",
            ),
        }
    }
}

/// The account's sidebar: each settings tab's page in `tabs`, `current` among
/// them, if a tab is shown, and the developer console's home at `developers`,
/// which is current when `section` is it. The top bar's search finds those, the
/// settings on them and the account's `apps`.
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
    /// Registering an app, in the developer console.
    pub register: &'a str,
    /// The account's apps, in the developer console.
    pub apps: &'a [AppLink<'a>],
    /// The admin dashboard, for an account that administers Origin Auth; a section of
    /// its own in the sidebar, which nobody else sees.
    pub dashboard: Option<&'a str>,
    /// How many notifications are unread, which the inbox's tab counts.
    pub unread: u64,
}

impl AccountNav<'_> {
    /// The top bar's search, finding `destinations`, which the page holds: it
    /// asks the server nothing, and has no page of its own.
    const fn search<'b>(destinations: &'b [Destination<'b>]) -> Search<'b> {
        Search {
            placeholder: "Search settings and apps",
            destinations,
            suggest: None,
            page: None,
        }
    }

    /// What the top bar's search finds: every settings tab and what is on it,
    /// the developer console and each of the account's apps, and the dashboard
    /// for an administrator.
    fn destinations(&self) -> Vec<Destination<'_>> {
        let mut found: Vec<_> = Destination::tabs("Account settings", self.tabs).collect();
        found.extend(Tab::spots(self.tabs));
        found.push(Destination {
            group: Group::Pages,
            icon: Icon::Code,
            title: "Your apps".into(),
            trail: Section::Developers.label().into(),
            terms: "developer console oidc oauth clients applications".into(),
            href: self.developers.into(),
            confirms: false,
        });
        found.push(Destination::spot(
            "Your apps",
            Icon::Code,
            self.register.to_owned(),
            Spot::action(
                "Register an app",
                "new app create client oauth oidc application",
                false,
            ),
        ));
        found.extend(self.apps.iter().flat_map(AppLink::destinations));
        found.extend(self.dashboard.map(|href| Destination {
            group: Group::Pages,
            icon: Icon::Shield,
            title: "Admin dashboard".into(),
            trail: "Admin".into(),
            terms: "administrator administration operators".into(),
            href: href.into(),
            confirms: false,
        }));
        found
    }
}

/// A signed-in page of `section`, in the account's shell: the sidebar of `nav`
/// for `who`, whose passkey script tells the password manager `signal`, signing
/// out by posting to `sign_out`, the preference forms posting to
/// `preferences_action`, reversing `preferences`, and coming back to `here`,
/// the page named `title` in the crumb after `trail`, the pages it is under,
/// and the status bar linking SourceOrigin's `policies`; an administrator's sidebar
/// also links the dashboard. Then what the account's `recovery` that can still
/// be undone asks, if any, such as a [`crate::recovery_banner`]; the page's
/// `head`, such as an app's tabs, its `messages`, and the page as `child`.
#[component]
pub async fn account<'a>(
    nav: AccountNav<'a>,
    who: Who<'a>,
    signal: PasskeySignal<'a>,
    #[default] trail: &'a [(Crumb<'a>, &'a str)],
    title: Crumb<'a>,
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
            count: (*tab == Tab::Notifications && nav.unread > 0).then_some(nav.unread),
        })
        .collect();
    let shortcuts: Vec<_> = nav
        .tabs
        .iter()
        .find(|(tab, _)| *tab == Tab::Notifications)
        .map(|(_, href)| Shortcut {
            kind: ShortcutKind::Inbox,
            href,
            count: nav.unread,
        })
        .into_iter()
        .collect();
    let console = [NavItem {
        icon: Icon::Code,
        label: "Your apps",
        href: nav.developers,
        current: nav.section == Section::Developers,
        warning: false,
        count: None,
    }];
    let dashboard: Vec<_> = nav
        .dashboard
        .map(|href| NavItem {
            icon: Icon::Shield,
            label: "Admin dashboard",
            href,
            current: false,
            warning: false,
            count: None,
        })
        .into_iter()
        .collect();
    Ok(view! {
        let destinations = nav.destinations();
        let search = AccountNav::search(&destinations);
        let groups: Vec<_> = [
            Some(NavGroup {
                label: Some("account"),
                items: &tabs,
            }),
            Some(NavGroup {
                label: Some("developers"),
                items: &console,
            }),
            (!dashboard.is_empty()).then_some(NavGroup {
                label: Some("admin"),
                items: &dashboard,
            }),
        ]
        .into_iter()
        .flatten()
        .collect();
        let frame = Shell {
            home,
            area: nav.section.label(),
            area_home: match nav.section {
                Section::Account => home,
                Section::Developers => nav.developers,
            },
            groups: &groups,
            who: Some(who),
            signal: Some(signal),
            me: Some(home),
            shortcuts: &shortcuts,
            trail,
            page: title,
            search: Some(search),
            preferences,
            preferences_action,
            here,
            sign_out: Some(sign_out),
            health: None,
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
