//! The parts of a page within its frame: its opening and messages, its
//! navigations, the pager below a list, and a private address.

use crate::{
    Alert, Messages,
    icons::{Icon, icon},
};
use piquel_common::admin::Paging;
use topcoat::{
    Result,
    view::{Child, View, component, view},
};

/// Something a navigation links, by its label.
pub(crate) trait Label: Copy + PartialEq + Send + Sync + 'static {
    /// The `aria-current` of the current one's link: `page` when the link opens
    /// the page shown, as a tab's does.
    const CURRENT: &'static str = "page";

    /// The link's text.
    fn label(self) -> &'static str;
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
