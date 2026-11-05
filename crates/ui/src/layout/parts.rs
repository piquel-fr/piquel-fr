//! The parts of a page within its frame: its opening and messages, its
//! navigations, the pager below a list, and a private address.

use crate::{
    Alert, Messages,
    browser::Browser,
    icons::{Icon, icon},
};
use piquel_common::admin::Paging;
use topcoat::{
    Result,
    context::Cx,
    runtime::{Event, Expr, Signal, expr, signal},
    view::{Child, View, component, view},
};

/// Something a page offers until this browser dismisses it, by its key: it starts
/// hidden, and shows unless dismissed. Where the browser keeps no local storage,
/// it shows on every page, and dismissing it hides it on that page only.
pub(crate) struct Dismissal {
    /// The key this browser keeps it dismissed under.
    key: String,
    /// Whether it shows.
    shown: Signal<bool>,
}

impl Dismissal {
    /// The one dismissed under `key`.
    pub(crate) fn new(cx: &Cx, key: String) -> Self {
        Self {
            key,
            shown: signal(cx, || false),
        }
    }

    /// Its `@mount` handler, which shows it unless this browser dismissed it.
    pub(crate) fn mount(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let (shown, dismissed) = (self.shown.clone(), Browser::dismissed(&self.key));
        expr!(|_e: Event| shown.set(!dismissed))
    }

    /// Whether it is hidden.
    pub(crate) fn hidden(&self) -> Expr<bool> {
        let shown = self.shown.clone();
        expr!(!shown.get())
    }

    /// The `@click` handler of the button dismissing it, which hides it from then
    /// on. Hiding it takes the focus from the button, so the page's heading gets it.
    pub(crate) fn dismiss(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let shown = self.shown.clone();
        let (focus, dismiss) = (Browser::focus_heading(), Browser::dismiss(&self.key));
        expr!(|_e: Event| {
            let _focused = focus;
            shown.set(false);
            let _dismissed = dismiss;
        })
    }
}

/// Something a navigation links, by its label.
pub(crate) trait Label: Copy + PartialEq + Send + Sync + 'static {
    /// The `aria-current` of the current one's link: `page` when the link opens
    /// the page shown, as a tab's does.
    const CURRENT: &'static str = "page";

    /// The link's text.
    fn label(self) -> &'static str;

    /// Whether its page needs the dashboard's passkey confirmation, so the
    /// dashboard confirms before following its link.
    fn confirms_first(self) -> bool {
        false
    }
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
pub(crate) async fn pager<'a>(cx: &Cx, pages: &'a Pager, what: &'a str) -> Result<impl View> {
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
    cx: &Cx,
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
pub(crate) async fn page_messages<'a>(cx: &Cx, messages: Messages<'a>) -> Result<impl View> {
    Ok(view! {
        // A refused setting is said beside its input instead.
        if let Some(Alert::Page(alert)) = messages.alert {
            alert_notice(message: alert)
        }
        if let Some(notice) = messages.notice {
            // A checkbox, visually hidden, dismisses it, so it needs no script.
            <p class="notice" role="status">
                icon(kind: Icon::Check)
                <span class="text">(notice.message())</span>
                <label class="dismiss" title="Dismiss">
                    <input type="checkbox" aria-label="Dismiss">
                    icon(kind: Icon::Close)
                </label>
            </p>
        }
    })
}

/// Why a change failed, as `message` says it.
#[component]
pub(crate) async fn alert_notice<'a>(cx: &Cx, message: &'a str) -> Result<impl View> {
    Ok(view! {
        <p class="notice error" role="alert">icon(kind: Icon::Warning)<span class="text">(message)</span></p>
    })
}

/// A dialog titled `title`, its element `id`, holding `child`. A button naming
/// `id` as its `popovertarget` opens it, and the browser closes it on Escape or a
/// click outside, with no script. Once `shown`, as when a change it holds was
/// refused, it is open as the page loads, saying the refusal's `alert` above its
/// form, over a scrim, and closing it, by its Close or a click outside, goes
/// `back`. A dialog that asks no input says to `focus_close`, so the focus moves
/// into it as it opens; one that does autofocuses its input.
#[component]
pub(crate) async fn dialog<'a>(
    cx: &Cx,
    id: &'a str,
    title: &'a str,
    shown: bool,
    back: &'a str,
    #[default] alert: Option<&'a str>,
    #[default] focus_close: bool,
    child: Child<'_>,
) -> Result<impl View> {
    let heading = format!("{id}-title");
    Ok(view! {
        if shown {
            <a class="dialog-scrim" href=(back) tabindex="-1" aria-hidden="true"></a>
        }
        <div
            class=(if shown { "dialog shown" } else { "dialog" })
            id=(id)
            popover=((!shown).then_some(""))
            role="dialog"
            aria-labelledby=(heading.as_str())
        >
            <header>
                <h2 id=(heading.as_str())>(title)</h2>
                if shown {
                    <a class="close" href=(back) aria-label="Close" autofocus=(focus_close)>icon(kind: Icon::Close)</a>
                } else {
                    <button type="button" class="close" popovertarget=(id) popovertargetaction="hide" aria-label="Close" autofocus=(focus_close)>
                        icon(kind: Icon::Close)
                    </button>
                }
            </header>
            if let Some(alert) = alert.filter(|_| shown) {
                alert_notice(message: alert)
            }
            (child)
        </div>
    })
}

/// An email `address`, blurred until clicked so a shared screen does not show it;
/// clicking again blurs it. A checkbox, visually hidden, holds whether it shows,
/// so it needs no script.
#[component]
pub(crate) async fn private_address<'a>(cx: &Cx, address: &'a str) -> Result<impl View> {
    Ok(view! {
        <label class="private-address">
            <input type="checkbox" aria-label="Show address">
            <span>(address)</span>
        </label>
    })
}

/// The navigation named `label`, of `class`, linking each of `links` to its URL,
/// `current` among them, whose link is marked [`Label::CURRENT`], and marked
/// `data-confirm-first` when [`Label::confirms_first`].
#[component]
pub(crate) async fn navigation<'a, T: Label>(
    cx: &Cx,
    label: &'a str,
    class: &'a str,
    links: &'a [(T, &'a str)],
    current: T,
) -> Result<impl View> {
    Ok(view! {
        <nav class=(class) aria-label=(label)>
            #[key(position)]
            for (position, (link, href)) in links.iter().enumerate() {
                <a href=(*href) aria-current=((*link == current).then_some(T::CURRENT)) data-confirm-first=(link.confirms_first())>(link.label())</a>
            }
        </nav>
    })
}
