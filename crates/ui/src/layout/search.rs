//! The top bar's search: the area's pages, the settings and actions on them, and
//! what the server finds for the query, such as accounts.
//!
//! The page holds every page and setting of its area as a result, which the
//! search script ranks as the user types, with no request; it fetches the rest
//! from the search's `suggest` URL, per keystroke, as groups of results that
//! [`search_results`] renders on both sides. Without the script, the form goes to
//! its `action` by `GET`, if it has one, and is hidden otherwise: the sidebar
//! still reaches every page.

use super::Label;
use crate::icons::{Icon, icon};
use std::borrow::Cow;
use topcoat::{
    Result,
    view::{View, component, view},
};

/// What a result is, which groups it in the list. Each group is listed in the
/// order of its best result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// A page of the sidebar.
    Pages,
    /// A setting or a part of a page.
    Settings,
    /// A change with a page of its own.
    Actions,
    /// One of the account's apps, in the developer console.
    Apps,
    /// An account, which the dashboard finds.
    Accounts,
    /// An OIDC client, which the dashboard finds.
    Clients,
}

impl Group {
    /// Its heading in the list.
    const fn label(self) -> &'static str {
        match self {
            Self::Pages => "Pages",
            Self::Settings => "Settings",
            Self::Actions => "Actions",
            Self::Apps => "Your apps",
            Self::Accounts => "Accounts",
            Self::Clients => "Clients",
        }
    }

    /// The `data-group` the script tells groups apart by.
    const fn key(self) -> &'static str {
        match self {
            Self::Pages => "pages",
            Self::Settings => "settings",
            Self::Actions => "actions",
            Self::Apps => "apps",
            Self::Accounts => "accounts",
            Self::Clients => "clients",
        }
    }
}

/// A setting, or an action, as search finds it: what it is called, and the
/// other words it answers to. Where it goes comes from its page: the ID its
/// heading takes, the query opening its dialog, or its route.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Spot {
    /// Its name.
    pub title: &'static str,
    /// The words it also answers to, such as what other sites call it.
    pub terms: &'static str,
    /// Whether it is a change with a page of its own, rather than a setting.
    pub action: bool,
    /// Whether its page needs the dashboard's passkey confirmation, which the
    /// dashboard's script asks for before following the link.
    pub confirms: bool,
}

impl Spot {
    /// A setting, on its tab's page.
    pub(crate) const fn setting(title: &'static str, terms: &'static str) -> Self {
        Self {
            title,
            terms,
            action: false,
            confirms: false,
        }
    }

    /// A change with a page of its own, which `confirms` first or not.
    pub(crate) const fn action(title: &'static str, terms: &'static str, confirms: bool) -> Self {
        Self {
            title,
            terms,
            action: true,
            confirms,
        }
    }
}

/// A tab search finds by its label and `terms`, which link its page.
pub(crate) trait Searchable: Label {
    /// Its icon, beside each of its results.
    fn icon(self) -> Icon;

    /// The words its page also answers to.
    fn terms(self) -> &'static str;
}

/// Something search finds, and where it goes.
#[derive(Clone, Debug)]
pub struct Destination<'a> {
    /// What it is.
    pub group: Group,
    /// Its icon.
    pub icon: Icon,
    /// Its name.
    pub title: Cow<'a, str>,
    /// What it belongs to, beside its name: the page a setting is on, or an
    /// account's display name.
    pub trail: Cow<'a, str>,
    /// The other words it answers to.
    pub terms: Cow<'a, str>,
    /// Where it goes.
    pub href: Cow<'a, str>,
    /// Whether its page needs the dashboard's passkey confirmation first.
    pub confirms: bool,
}

impl<'a> Destination<'a> {
    /// Each tab of `tabs` linking its page, in `area`.
    pub(crate) fn tabs<T: Searchable>(
        area: &'a str,
        tabs: &[(T, &'a str)],
    ) -> impl Iterator<Item = Self> {
        tabs.iter().map(move |&(tab, href)| Self {
            group: Group::Pages,
            icon: tab.icon(),
            title: tab.label().into(),
            trail: area.into(),
            terms: tab.terms().into(),
            href: href.into(),
            confirms: false,
        })
    }

    /// `spot`, at `href`, on the page named `page`, beside `glyph`.
    pub(crate) fn spot(page: &'a str, glyph: Icon, href: String, spot: Spot) -> Self {
        Self {
            group: if spot.action {
                Group::Actions
            } else {
                Group::Settings
            },
            icon: glyph,
            title: spot.title.into(),
            trail: page.into(),
            terms: spot.terms.into(),
            href: href.into(),
            confirms: spot.confirms,
        }
    }
}

/// The top bar's search, and where it searches.
#[derive(Clone, Copy, Debug)]
pub struct Search<'a> {
    /// What it searches, as the input's placeholder and label.
    pub placeholder: &'a str,
    /// The pages, settings and actions it finds, which the script ranks.
    pub destinations: &'a [Destination<'a>],
    /// Where the script asks what else the query finds, with `?q=` appended,
    /// which answers with [`search_results`]; nowhere when the page holds
    /// everything.
    pub suggest: Option<&'a str>,
    /// The page searching by itself, where the form goes without the script,
    /// or when Enter picks no result. Without one, the form shows only with the
    /// script.
    pub page: Option<SearchPage<'a>>,
}

/// A page searching by itself, such as the dashboard's users, which the top
/// bar's search goes to by `GET`, posting `q`.
#[derive(Clone, Copy, Debug)]
pub struct SearchPage<'a> {
    /// Where it is.
    pub href: &'a str,
    /// What it lists, as the last result names it before the query, e.g.
    /// "Every account matching".
    pub label: &'a str,
    /// What it searched, if it is the page shown.
    pub value: &'a str,
}

/// The ID of the top bar's list of results.
const RESULTS: &str = "search-results";

/// The top bar's `search` form: its input, and the list of its results, which
/// the script fills from its `<template>` and shows as the user types, ending
/// with its page's, if it has one.
#[component]
pub(crate) async fn search_box<'a>(search: Search<'a>) -> Result<impl View> {
    let page = search.page;
    Ok(view! {
        <form
            class="search"
            method="get"
            action=(page.map(|page| page.href))
            role="search"
            data-search=""
            data-suggest=(search.suggest)
            hidden=(page.is_none().then_some(""))
        >
            <label class="search-box">
                icon(kind: Icon::Search)
                <input
                    type="search"
                    name="q"
                    value=(page.map(|page| page.value))
                    placeholder=(search.placeholder)
                    aria-label=(search.placeholder)
                    role="combobox"
                    aria-autocomplete="list"
                    aria-expanded="false"
                    aria-controls=(RESULTS)
                    autocomplete="off"
                    spellcheck="false"
                >
                <kbd class="search-key" title="Press / to search" aria-hidden="true">"/"</kbd>
            </label>
            <div class="results" hidden="">
                <div id=(RESULTS) role="listbox" aria-label="Results"></div>
                <p class="results-empty" role="status" hidden="">"Nothing matches."</p>
            </div>
            // Outside the document until the script lists them, so hidden results
            // never stand beside the page's own text.
            <template class="search-source">
                search_results(found: search.destinations)
                if let Some(page) = page {
                    <div class="result-group" role="group" aria-label=(page.label) data-group="all">
                        <a class="result" role="option" tabindex="-1" href=(page.href) data-all="">
                            icon(kind: Icon::Search)
                            <span class="result-text">
                                <span class="result-title">(page.label) " " <q></q></span>
                            </span>
                        </a>
                    </div>
                }
            </template>
        </form>
    })
}

/// The results `found`, under a heading for each group, in the order each group
/// first appears. The top bar lists the page's own; the `suggest` URL of a
/// [`Search`] answers with the rest, in this same markup.
#[component]
pub async fn search_results<'a>(found: &'a [Destination<'a>]) -> Result<impl View> {
    let mut groups: Vec<Group> = Vec::new();
    for destination in found {
        if !groups.contains(&destination.group) {
            groups.push(destination.group);
        }
    }
    Ok(view! {
        for group in groups {
            <div class="result-group" role="group" aria-label=(group.label()) data-group=(group.key())>
                <div class="result-heading" aria-hidden="true">(group.label())</div>
                for destination in found.iter().filter(|destination| destination.group == group) {
                    <a
                        class="result"
                        role="option"
                        tabindex="-1"
                        href=(destination.href.as_ref())
                        data-terms=(destination.terms.as_ref())
                        data-confirm-first=(destination.confirms.then_some(""))
                    >
                        icon(kind: destination.icon)
                        <span class="result-text">
                            <span class="result-title">(destination.title.as_ref())</span>
                            <small>(destination.trail.as_ref())</small>
                        </span>
                    </a>
                }
            </div>
        }
    })
}
