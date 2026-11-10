//! The document around every page, and the frames pages share: the shell of the
//! signed-in pages, a sidebar beside the page and a status bar below it, which
//! the account's pages and the admin dashboard both use, and the narrow column
//! of the pages a signed-out browser sees.
//!
//! Everything works without scripts, which the dashboard's pages may lack: the theme
//! and the sidebar's width are preferences a form posts and a cookie keeps, and
//! on phones a checkbox the shell reads opens the sidebar as a drawer.

/// The frames outside the shell, and the status bar.
mod frames;
/// The document around every page, and the browser's preferences.
mod html;
/// The parts of a page within its frame.
mod parts;
/// The top bar's search.
mod search;
/// The account's sections, and their pages in the shell.
mod sections;
/// The shell of the signed-in pages.
mod signed_in;

pub use frames::{Health, Policies, SOURCE, auth_shell, site_shell};
pub use html::{PreferenceChange, Preferences, Sidebar, Theme, Title, document};
pub use parts::{Pager, page_head};
pub use search::{Destination, Group, Search, SearchPage, search_results};
pub use sections::{AccountNav, Section, account, signed_out};
pub use signed_in::{
    Crumb, NavGroup, NavItem, PasskeySignal, Shell, Shortcut, ShortcutKind, Who, shell,
};

pub(crate) use parts::{
    Label, alert_notice, announcement_text, dialog, navigation, page_messages, pager,
    private_address,
};
pub(crate) use search::{Searchable, Spot};
pub(crate) use signed_in::{AvatarSize, avatar};
