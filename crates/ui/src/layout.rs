//! The document around every page, and the parts pages share.

use topcoat::{
    Result,
    view::{Child, View, component, view},
};

/// The document around every page: the head, which links `stylesheet` and loads
/// the SDK's `script`, if any, Piquel's header, whose brand links `home`, and the
/// page as `child`. `title` names the page in the browser, before "· Piquel".
#[component]
pub async fn document<'a>(
    title: &'a str,
    stylesheet: &'a str,
    #[default] script: Option<&'a str>,
    home: &'a str,
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
                            <span class="muted">" / sign in"</span>
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
