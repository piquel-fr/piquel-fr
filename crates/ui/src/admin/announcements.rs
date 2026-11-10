//! Announcements to accounts: the list, one announcement with its email as its
//! recipients read it, and the form drafting one.

use super::{Action, Change, confirm, moment};
use crate::icons::{Icon, icon};
use crate::{
    clients::choice,
    email::{Mail, email_preview},
    layout::page_head,
};
use sourceorigin_common::admin::{
    Announcement, AnnouncementAudience, AnnouncementDetail, DraftAnnouncement, User,
};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// An announcement in the list, and its page.
#[derive(Clone, Debug)]
pub struct AdminAnnouncementRow<'a> {
    /// The announcement.
    pub announcement: &'a Announcement,
    /// Its page.
    pub page: String,
}

/// What may be done to a draft: changing it on its page at `edit`, and sending
/// and discarding it, each from a dialog on the draft's page or a page of its
/// own.
#[derive(Clone, Debug)]
pub struct DraftActions<'a> {
    /// Changing its text or recipients.
    pub edit: &'a str,
    /// Sending it, which needs the dashboard's passkey confirmation.
    pub send: Action,
    /// Deleting it, which needs none.
    pub discard: Action,
}

/// Whom `announcement` goes to, in words; how many, while auth knows.
fn audience(announcement: &Announcement) -> String {
    if !announcement.recipients_kept {
        return if announcement.everyone {
            "Everyone".to_owned()
        } else {
            "Chosen accounts".to_owned()
        };
    }
    let accounts = match announcement.recipients {
        1 => "1 account".to_owned(),
        count => format!("{count} accounts"),
    };
    if announcement.everyone {
        format!("Everyone, {accounts}")
    } else {
        accounts
    }
}

/// The announcements in `rows`, newest first, with the page drafting one at
/// `create`.
#[component]
pub async fn announcement_list<'a>(
    rows: &'a [AdminAnnouncementRow<'a>],
    create: &'a str,
) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Announcements",
            lead: "Emails to every account, or to chosen ones, such as a security incident or a change to the privacy policy. Recipients also find them in their inbox.".to_owned(),
            actions: view! { <a class="button" href=(create)>"New announcement"</a> },
        )
        <section class="card">
            if rows.is_empty() {
                <p class="empty">"No announcement yet."</p>
            } else {
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr><th>"subject"</th><th>"to"</th><th>"sent"</th></tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                <tr>
                                    <td><a href=(row.page.as_str())>(row.announcement.subject.as_str())</a></td>
                                    <td>(audience(row.announcement))</td>
                                    <td>
                                        match row.announcement.sent_at {
                                            Some(at) => moment(at: at),
                                            None => <span class="badge warning">"Draft"</span>,
                                        }
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        </section>
    })
}

/// One announcement, `detail`, the chosen `accounts` it goes to, linking their
/// pages, and its email, `preview`, as it will be sent; the crumb
/// leads back to the list. A draft has its `drafts` actions; a sent one says how
/// its emails fared and how many recipients read it.
#[component]
pub async fn announcement_page<'a>(
    detail: &'a AnnouncementDetail,
    accounts: &'a [(&'a User, String)],
    preview: &'a Mail,
    #[into]
    #[default]
    drafts: Option<DraftActions<'a>>,
) -> Result<impl View> {
    let announcement = &detail.announcement;
    let unmailed = announcement.recipients.saturating_sub(detail.mailed);
    let emails = detail.emails;
    let revision = announcement.revision.to_string();
    // The announcement, as the passkey dialog names it.
    let named = format!("{} ({})", announcement.subject, announcement.id);
    Ok(view! {
        page_head(
            title: announcement.subject.as_str(),
            actions: view! {
                match announcement.sent_at {
                    Some(_) => <span class="badge ok">"Sent"</span>,
                    None => <span class="badge warning">"Draft"</span>,
                }
            },
        )
        <section class="card">
            <div class="body">
                <dl class="facts">
                    <dt>"To"</dt><dd>(audience(announcement))</dd>
                    <dt>"Essential"</dt><dd>(announcement.essentiality())</dd>
                    if announcement.recipients_kept {
                        <dt>"Emailed to"</dt>
                        <dd>
                            (format!("{} {}", detail.mailed, announcement.emailed()))
                            if unmailed > 0 {
                                <small>(format!(" · the other {unmailed} only find it in their inbox"))</small>
                            }
                        </dd>
                    }
                    <dt>"Drafted"</dt><dd>moment(at: announcement.created_at)</dd>
                    match announcement.sent_at {
                        Some(at) => {
                            <dt>"Sent"</dt><dd>moment(at: at)</dd>
                            <dt>"Read"</dt>
                            if announcement.recipients_kept {
                                <dd>(format!("by {} of {} recipients, in their inbox", detail.read, announcement.recipients))</dd>
                            } else {
                                <dd>"Unknown: whom it went to, and who read it, are deleted a year after it is sent."</dd>
                            }
                            <dt>"Emails"</dt>
                            <dd>
                                (format!(
                                    "{} sent, {} waiting, {} failed, {} cancelled",
                                    emails.succeeded, emails.pending, emails.failed, emails.cancelled,
                                ))
                                <small>" · The queue keeps sent emails 7 days, failed ones 30."</small>
                            </dd>
                        },
                        None => {
                            <dt>"Last changed"</dt><dd>moment(at: announcement.updated_at)</dd>
                        },
                    }
                </dl>
                if let Some(actions) = &drafts {
                    <p class="help">
                        (if announcement.everyone {
                            "Nothing is sent until you send it. It then goes to every account at that moment, and nobody can change it."
                        } else {
                            "Nothing is sent until you send it, and nobody can change it once it is."
                        })
                    </p>
                    <div class="row actions">
                        confirm(
                            action: &actions.send,
                            change: Change::SendAnnouncement,
                            target: named.as_str(),
                            <input type="hidden" name="revision" value=(revision.as_str())>
                        )
                        <a class="button secondary small" href=(actions.edit)>"Edit"</a>
                        confirm(action: &actions.discard, change: Change::DiscardAnnouncement, target: named.as_str())
                    </div>
                }
            </div>
        </section>
        if !accounts.is_empty() {
            <section class="card">
                <header><h2>"Chosen accounts " <span class="count">(accounts.len().to_string())</span></h2></header>
                <ul class="list">
                    for (user, page) in accounts {
                        <li>
                            <div class="text">
                                <a href=(page.as_str())>(format!("@{}", user.handle))</a>
                                <small>(user.display_name.as_str())</small>
                            </div>
                        </li>
                    }
                </ul>
            </section>
        }
        <section class="card">
            <header><h2>"The email"</h2></header>
            <div class="body stack">
                email_preview(mail: preview)
            </div>
        </section>
    })
}

/// An account the draft form's search found, and whether its accounts already
/// list it.
#[derive(Clone, Copy, Debug)]
pub struct FoundAccount<'a> {
    /// The account.
    pub user: &'a User,
    /// Whether the form's accounts list it already.
    pub added: bool,
}

/// The form drafting an announcement, or changing a draft, as `change` says,
/// with a link `back`, filled in with `form`, the accounts its search `found`,
/// and why the last attempt was refused, if it was.
///
/// Its accounts take a pasted list, one per line, and a search whose results each
/// add themselves to it; a search saves nothing. Its first button, which Enter
/// presses, searches, so Enter never sends. "Send" saves the draft and sends it
/// as saved, after the dashboard's passkey confirmation; "Save draft" needs none.
#[component]
pub async fn announcement_form<'a>(
    change: Change,
    back: &'a str,
    form: &'a DraftAnnouncement,
    found: &'a [FoundAccount<'a>],
    #[into]
    #[default]
    refusal: Option<&'a str>,
) -> Result<impl View> {
    let chosen = form.audience == AnnouncementAudience::Accounts;
    // What its Send asks a passkey for: the announcement, by the subject it
    // was shown with, if it has one yet.
    let subject = Some(form.subject.trim()).filter(|subject| !subject.is_empty());
    let sending = Change::SendAnnouncement.confirming(subject);
    Ok(view! {
        page_head(title: change.title(), lead: change.description().to_owned())
        if let Some(refusal) = refusal {
            <p class="notice error" role="alert">(refusal)</p>
        }
        <section class="card">
            <form class="stack" method="post" data-submit-once="" data-unconfirmed="" data-confirming=(sending.as_str())>
                <label>
                    "Subject"
                    <input name="subject" required="" maxlength="150" value=(form.subject.as_str())>
                </label>
                <label>
                    "Text"
                    <textarea name="body" required="" rows="14" maxlength="20000">(form.body.as_str())</textarea>
                    <small>"The email starts with “Hello,” and ends with “SourceOrigin”. Separate paragraphs with a blank line. Links are written out in full: mail apps make them clickable."</small>
                </label>
                <fieldset>
                    <legend>"Send it to"</legend>
                    choice(
                        name: "audience",
                        value: Some("everyone"),
                        checked: !chosen,
                        label: view! { "Everyone" },
                        detail: view! {
                            "Every account when it is sent, disabled ones and ones being deleted included: SourceOrigin still holds their data."
                        },
                    )
                    choice(
                        name: "audience",
                        value: Some("accounts"),
                        checked: chosen,
                        label: view! { "These accounts" },
                        detail: view! { "Up to 1,000, found below or pasted into the list." },
                    )
                </fieldset>
                chosen_accounts(form: form, found: found)
                choice(
                    name: "essential",
                    checked: form.essential.0,
                    label: view! { "Essential" },
                    detail: view! {
                        "Emailed even to recipients who turned announcement emails off, without a link to unsubscribe. Only for a security incident, or a change to the privacy policy or terms."
                    },
                )
                <p class="help">"Send emails it at once, to every account when “Everyone” is chosen, and nobody can take it back. Save it as a draft to check its email first."</p>
                <div class="row actions">
                    <button name="intent" value="send" data-confirms="">"Send"</button>
                    <button class="secondary" name="intent" value="save">"Save draft"</button>
                    <a class="button secondary" href=(back)>"Cancel"</a>
                </div>
            </form>
        </section>
    })
}

/// The chosen accounts of `form`: a search, the accounts it `found`, each adding
/// itself, and the list, which also takes pasted accounts. Hidden while the form
/// chooses everyone.
#[component]
async fn chosen_accounts<'a>(
    form: &'a DraftAnnouncement,
    found: &'a [FoundAccount<'a>],
) -> Result<impl View> {
    let find = form.find.trim();
    Ok(view! {
        <div class="stack chosen-accounts">
            <div class="row search">
                <label class="search-box grow">
                    icon(kind: Icon::Search)
                    <input
                        type="search"
                        name="find"
                        value=(find)
                        placeholder="Handle, name, email or account ID"
                        aria-label="Find accounts"
                        autocomplete="off"
                        autofocus=(!find.is_empty())
                        data-live="found-accounts"
                    >
                </label>
                <button class="secondary" name="intent" value="find" formnovalidate="" data-live-submit="">"Find"</button>
            </div>
            // What the search script swaps in as the administrator types, finding
            // as the Find button does.
            <div class="live-results" id="found-accounts">
                if !find.is_empty() {
                    if found.is_empty() {
                        <p class="empty">(format!("No account matches “{find}”."))</p>
                    } else {
                        <ul class="list">
                            for account in found {
                                let handle = format!("@{}", account.user.handle);
                                <li>
                                    <div class="text">
                                        <strong>(handle.as_str())</strong>
                                        <small>(account.user.display_name.as_str())</small>
                                    </div>
                                    if account.added {
                                        <span class="badge ok">"Added"</span>
                                    } else {
                                        <button
                                            class="secondary small"
                                            name="add"
                                            value=(account.user.handle.as_str())
                                            formnovalidate=""
                                            aria-label=(format!("Add {handle}"))
                                        >"Add"</button>
                                    }
                                </li>
                            }
                        </ul>
                    }
                }
            </div>
            <label>
                "Accounts"
                <textarea name="accounts" rows="5">(form.accounts.as_str())</textarea>
                <small>"One per line: a handle, a verified email or an account ID, as added above or pasted. Only used for “These accounts”."</small>
            </label>
        </div>
    })
}
