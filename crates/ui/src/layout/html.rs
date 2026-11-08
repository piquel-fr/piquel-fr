//! The document around every page, and what the browser chose for it: the
//! theme and the sidebar's width, which a form posts and a cookie keeps.

use crate::form::Fields;
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{Child, View, component, view},
};

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
    /// Turning announcements' email off from an email's link.
    Unsubscribe,
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
            Self::Unsubscribe => "Announcement emails",
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

/// The document around every page: the head, which links `stylesheet` and loads
/// the page's `scripts`, if it has any, and the page as `child`. `title`
/// names the page in the browser, before "· Piquel". The browser's `preferences`
/// set the theme and the sidebar's width on the root, where the stylesheet reads
/// them, and an `admin` page is marked so the stylesheet colours it as the
/// dashboard. Only an `indexable` page, such as piquel.fr's own, may be indexed
/// by search engines.
#[component]
pub async fn document<'a>(
    title: &'a str,
    stylesheet: &'a str,
    #[default] scripts: &'a [&'a str],
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
                for script in scripts {
                    <script type="module" src=(*script)></script>
                }
            </head>
            <body class=(admin.then_some("admin"))>
                (child)
            </body>
        </html>
    })
}
