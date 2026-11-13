//! The frames of the pages outside the shell: the narrow column a signed-out
//! browser sees and sourceorigin.dev's wide one, and the status bar below every page.

use crate::clients::copyable;
use sourceorigin_common::TraceId;
use topcoat::{
    Result,
    view::{Child, View, component, view},
};

/// The repository every page links in its status bar.
pub const SOURCE: &str = "https://github.com/sourceorigin-dev/sourceorigin";

/// Where SourceOrigin's users and developers write to.
pub const SUPPORT_ADDRESS: &str = "support@sourceorigin.dev";

/// Where every page's footer links SourceOrigin's policies, which sourceorigin.dev serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policies<'a> {
    /// The privacy policy.
    pub privacy: &'a str,
    /// The terms of service.
    pub terms: &'a str,
}

impl Policies<'static> {
    /// The policies' paths on sourceorigin.dev: sourceorigin.dev routes them, and auth links
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
/// page knows, the `environment` it runs in, if named, that SourceOrigin is open
/// source, and the links: the source, SourceOrigin's `policies` and support.
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
            <span>"SourceOrigin's code is public"</span>
            <span class="right">
                <a href=(SOURCE)>"Source"</a>
                <a href=(policies.privacy)>"Privacy"</a>
                <a href=(policies.terms)>"Terms"</a>
                <a href=(format!("mailto:{SUPPORT_ADDRESS}"))>"Support"</a>
            </span>
        </footer>
    })
}

/// The page of a browser's request that failed before a page of its own could
/// explain it, such as one refused for its rate, or an address with no page:
/// what failed, as `title`, why, as `message`, and the way back to the area's
/// `home`, labelled `back`. It goes in an [`auth_shell`].
#[component]
pub async fn error_page<'a>(
    title: &'a str,
    message: &'a str,
    home: &'a str,
    back: &'a str,
) -> Result<impl View> {
    Ok(view! {
        <h1>(title)</h1>
        <p class="lead">(message)</p>
        <a class="button" href=(home)>(back)</a>
    })
}

/// The frame of a page a signed-out browser sees, or one outside the account's
/// shell: the brand above, the page as `child` in one narrow column, and the
/// status bar below. The brand links `home`. A page answering a server error
/// shows the `reference` of its trace, for the user to quote in a report. A page
/// on the way to the `admin` dashboard says so beside the brand. The status bar
/// links SourceOrigin's `policies`.
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
                <a class="brand" href=(home) aria-label="Origin Auth home">
                    <span class="mark">"o"</span>
                    "Origin Auth"
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

/// The frame of sourceorigin.dev's own pages: the brand, the `links` beside it, the
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
                <a class="brand" href=(home) aria-label="SourceOrigin home">
                    <span class="mark">"s"</span>
                    "SourceOrigin"
                </a>
                <nav class="site-links" aria-label="SourceOrigin">
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
