//! The account's sections, its settings and the developer console, and their
//! pages in the shell: its sidebar, and what they show a browser that is not
//! signed in.

use super::{NavGroup, NavItem, Policies, Preferences, Shell, Who, page_messages, shell};
use crate::{Messages, icons::Icon, settings::Tab};
use piquel_common::TraceId;
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
                "Use your Piquel account to manage your passkeys, devices and linked providers.",
            ),
            Self::Developers => (
                "Sign in to manage your apps",
                "Use your Piquel account to register and manage the apps that sign users in with it.",
            ),
        }
    }
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
    /// The admin dashboard, for an account that administers Piquel; a section of
    /// its own in the sidebar, which nobody else sees.
    pub dashboard: Option<&'a str>,
}

/// A signed-in page of `section`, in the account's shell: the sidebar of `nav`
/// for `who`, signing out by posting to `sign_out`, the preference forms posting
/// to `preferences_action`, reversing `preferences`, and coming back to `here`,
/// the page named `title` in the crumb, and the status bar linking Piquel's
/// `policies`; an administrator's sidebar also links the dashboard. Then what
/// the account's `recovery` that can still be undone asks,
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
    let dashboard: Vec<_> = nav
        .dashboard
        .map(|href| NavItem {
            icon: Icon::Shield,
            label: "Admin dashboard",
            href,
            current: false,
            warning: false,
        })
        .into_iter()
        .collect();
    Ok(view! {
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
            me: Some(home),
            page: title,
            search: None,
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
