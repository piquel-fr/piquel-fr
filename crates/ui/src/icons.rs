//! The icons the pages draw inline, as 16-pixel line glyphs: the navigation's,
//! the controls' and the marks of a message's kind.

use topcoat::{
    Result,
    context::Cx,
    view::{View, component, view},
};

/// An icon, by what it stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    /// An overview.
    Home,
    /// Passkeys and sign-in methods.
    Key,
    /// The profile.
    Profile,
    /// Email addresses.
    Mail,
    /// Notifications.
    Bell,
    /// Devices.
    Device,
    /// Connected apps.
    Grid,
    /// History.
    Clock,
    /// Data.
    Database,
    /// The developer console.
    Code,
    /// Users.
    Users,
    /// Administrators.
    Shield,
    /// Invitations.
    Invitation,
    /// OIDC clients.
    Client,
    /// Events.
    Events,
    /// The audit chain.
    Audit,
    /// Searching.
    Search,
    /// A chevron pointing left, which collapsing the sidebar turns around.
    Chevron,
    /// The light theme.
    Sun,
    /// The dark theme.
    Moon,
    /// The menu, on phones.
    Menu,
    /// Closing.
    Close,
    /// Signing out.
    SignOut,
    /// Done.
    Check,
    /// A warning.
    Warning,
    /// Linking.
    Link,
    /// Outbound deliveries.
    Send,
    /// Handles.
    At,
    /// Announcements.
    Megaphone,
}

impl Icon {
    /// The glyph's paths, in a 16-pixel box, stroked.
    const fn paths(self) -> &'static [&'static str] {
        match self {
            Self::Home => &["M2 7.5L8 2.5l6 5V13a1 1 0 01-1 1H3a1 1 0 01-1-1z"],
            Self::Key => &["M8.5 10.5a3 3 0 11-3-3 3 3 0 013 3z", "M8 8l6-6M11 5l2 2"],
            Self::Mail => &["M2 3.5h12v9H2z", "M2 5l6 4 6-4"],
            Self::Bell => &[
                "M4 11.5V7a4 4 0 018 0v4.5l1.5 1.5h-11z",
                "M6.5 14a1.5 1.5 0 003 0",
            ],
            Self::Device => &["M2 2.5h12v8H2z", "M5.5 13.5h5"],
            Self::Grid => &["M2 2h5v5H2zM9 2h5v5H9zM2 9h5v5H2zM9 9h5v5H9z"],
            Self::Clock => &["M14 8A6 6 0 112 8a6 6 0 0112 0z", "M8 4.5V8l2.5 1.5"],
            Self::Database => &[
                "M13.5 4c0 1.1-2.5 2-5.5 2S2.5 5.1 2.5 4s2.5-2 5.5-2 5.5.9 5.5 2z",
                "M2.5 4v8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V4M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2",
            ],
            Self::Code => &["M5.5 4.5L2 8l3.5 3.5M10.5 4.5L14 8l-3.5 3.5"],
            Self::Profile => &[
                "M10.5 5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z",
                "M3 14c0-2.8 2.2-4.5 5-4.5s5 1.7 5 4.5",
            ],
            Self::Users => &[
                "M8.5 5.5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z",
                "M1.5 13.5c0-2.5 2-4 4.5-4s4.5 1.5 4.5 4M11 3.5a2.5 2.5 0 010 4.5M14.5 13.5c0-2-1.2-3.3-3-3.8",
            ],
            Self::Shield => &["M8 1.5l5.5 2v4.5c0 3-2.3 5.5-5.5 6.5-3.2-1-5.5-3.5-5.5-6.5V3.5z"],
            Self::Invitation => &["M14 8A6 6 0 112 8a6 6 0 0112 0z", "M8 5v6M5 8h6"],
            Self::Client => &["M2 3h12v10H2z", "M5 7l2 1.5L5 10M8.5 10h3"],
            Self::Events => &["M2 8h3l2-4 2 8 2-4h3"],
            Self::Audit => &["M4 2h6l3 3v9H4zM10 2v3h3M6.5 8.5h4M6.5 11h4"],
            Self::Search => &[
                "M11.5 7a4.5 4.5 0 11-9 0 4.5 4.5 0 019 0z",
                "M10.5 10.5L14 14",
            ],
            Self::Chevron => &["M10 3L5 8l5 5"],
            Self::Sun => &[
                "M11 8a3 3 0 11-6 0 3 3 0 016 0z",
                "M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4",
            ],
            Self::Moon => &["M13.5 9.5A6 6 0 016.5 2.5a6 6 0 107 7z"],
            Self::Menu => &["M2 4h12M2 8h12M2 12h12"],
            Self::Close => &["M4 4l8 8M12 4l-8 8"],
            Self::SignOut => &["M6 2H3v12h3M10 11l3-3-3-3M13 8H6"],
            Self::Check => &["M3 8.5l3 3 7-7"],
            Self::Warning => &["M8 2l6.5 11.5h-13zM8 6.5v3.5M8 12.2v.3"],
            Self::Megaphone => &[
                "M2 6.5h2.5L11 3v10L4.5 9.5H2z",
                "M4.5 9.5l1 4h2L7 10.2M13.5 6.5v3",
            ],
            Self::Link => &[
                "M6.5 9.5a3 3 0 004.2 0l2-2a3 3 0 00-4.2-4.2l-1 1M9.5 6.5a3 3 0 00-4.2 0l-2 2a3 3 0 004.2 4.2l1-1",
            ],
            Self::Send => &["M14 2L7 9", "M14 2l-4.5 12L7 9 2 6.5z"],
            Self::At => &[
                "M10.5 8a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z",
                "M10.5 8v1a2 2 0 004 0V8a6.5 6.5 0 10-2.5 5.1",
            ],
        }
    }
}

/// The icon `kind`, decorative: the text beside it names what it stands for.
#[component]
pub(crate) async fn icon(cx: &Cx, kind: Icon) -> Result<impl View> {
    Ok(view! {
        <svg class="icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
            for path in kind.paths() {
                <path d=(*path)></path>
            }
        </svg>
    })
}
