//! The frames of the pages outside the shell: the narrow column a signed-out
//! browser sees and piquel.fr's wide one, and the status bar below every page.

use crate::clients::copyable;
use piquel_common::TraceId;
use topcoat::{
    Result,
    context::Cx,
    view::{Child, View, component, view},
};

/// The repository every page links in its status bar.
pub const SOURCE: &str = "https://github.com/piquel-fr/piquel-fr";

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

/// Whether the service needs attention, as the status bar says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Health {
    /// Nothing needs attention.
    #[default]
    Normal,
    /// This many things do, on the dashboard's overview.
    Warnings(u32),
}

/// The status bar below every page: whether the service needs attention, when a
/// page knows, the `environment` it runs in, if named, that Piquel is open
/// source, and the links: the source, Piquel's `policies` and support.
#[component]
pub(crate) async fn status_bar<'a>(
    cx: &Cx,
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
            <span>"Piquel's code is public"</span>
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
    cx: &Cx,
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
    cx: &Cx,
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
                    #[key(position)]
                    for (position, (label, href)) in links.into_iter().enumerate() {
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
