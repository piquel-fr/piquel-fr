//! Announcements to accounts: drafting one, checking its email, and sending it.
//!
//! A draft has a page of its own, so a passkey confirmation that ran out while
//! the text was written sends the browser to confirm and back to the draft, with
//! nothing lost. Drafting, editing and discarding need no confirmation; sending
//! does.

use super::AdminApplication as App;
use crate::{AdminError, AnnouncementDraft, admin::SignedInAdmin, deliveries::AnnouncementSender};
use chrono::Duration;
use sourceorigin_common::{
    AnnouncementId,
    admin::{
        AnnouncementAudience, AnnouncementDetail, DraftAnnouncement, DraftIntent, SendAnnouncement,
    },
};
use sourceorigin_ui::{
    Action, AdminAnnouncementRow, Change, Checkbox, Crumb, DraftActions, FoundAccount, Query,
};
use serde::de::IgnoredAny;
use topcoat::{
    Error, Result,
    context::Cx,
    router::{
        Method, StatusCode,
        content::Form,
        error::{bad_request, see_other},
        href, parse_query_params, path_param,
        request::method,
        response::Response,
        route,
    },
    view::view,
};

path_param!(pub announcement: AnnouncementId else not_found);

/// `/announcements`: the latest announcements, drafts and sent ones.
#[route(GET "/announcements")]
pub(super) async fn list(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let announcements = App::of(cx)
        .service
        .list_announcements(&admin.operator)
        .await?;
    let rows: Vec<_> = announcements
        .iter()
        .map(|announcement| AdminAnnouncementRow {
            announcement,
            page: href!(show, Announcement(announcement.id)).resolve(cx),
        })
        .collect();
    let create = &href!(draft).resolve(cx);
    let page = view! {
        sourceorigin_ui::announcement_list(rows: &rows, create: create.as_str())
    };
    App::render(cx, StatusCode::OK, "Announcements", page).await
}

/// `/announcements/{announcement}`: one announcement, whom it goes to, and its
/// email; a draft's page links editing, sending and discarding it.
#[route(GET "/announcements/{announcement}")]
pub(super) async fn show(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let app = App::of(cx);
    let id = *path_param::<Announcement>(cx)?;
    let viewed = app.service.view_announcement(&admin.operator, id).await?;
    let detail = &viewed;
    let preview = AnnouncementSender::preview(&detail.announcement, &app.auth)
        .map_err(|error| Error::msg(format!("could not render an announcement: {error}")))?;
    let accounts: Vec<_> = detail
        .accounts
        .iter()
        .map(|user| (user, App::account(cx, user.id)))
        .collect();
    let editing = &href!(edit, Announcement(id)).resolve(cx);
    // Sending needs the dashboard's confirmation, which a dialog on this page
    // cannot ask for; discarding a draft needs none.
    let drafts = match detail.announcement.sent_at {
        Some(_) => None,
        None => Some(DraftActions {
            edit: editing,
            send: Action {
                href: SendAnnouncement {
                    revision: detail.announcement.revision,
                }
                .on(&href!(send, Announcement(id)).resolve(cx))?,
                inline: admin.operator.is_confirmed(super::FORM_TIME),
            },
            discard: Action {
                href: href!(discard, Announcement(id)).resolve(cx),
                inline: true,
            },
        }),
    };
    let page = view! {
        sourceorigin_ui::announcement_page(
            detail: detail,
            accounts: &accounts,
            preview: preview.as_str(),
            drafts: drafts,
        )
    };
    // The page, with its email and accounts, makes a large future.
    let title = Crumb::Name(&detail.announcement.subject);
    Box::pin(App::render(cx, StatusCode::OK, title, page)).await
}

/// `/announcements/new`: drafts an announcement, then shows its page, or sends
/// it.
#[route([GET, POST] "/announcements/new")]
pub(super) async fn draft(cx: &Cx, form: Option<Form<DraftAnnouncement>>) -> Result<Response> {
    App::compose(cx, form, None).await
}

/// `/announcements/{announcement}/edit`: changes a draft's text or recipients,
/// or sends it.
#[route([GET, POST] "/announcements/{announcement}/edit")]
pub(super) async fn edit(cx: &Cx, form: Option<Form<DraftAnnouncement>>) -> Result<Response> {
    let id = *path_param::<Announcement>(cx)?;
    App::compose(cx, form, Some(id)).await
}

/// Where a draft's form goes once it is saved.
enum Saved {
    /// The announcement's page: saved as a draft, or sent.
    Page(AnnouncementId),
    /// The send page, at the revision saved, which confirms the dashboard first.
    Send(AnnouncementId, u64),
}

/// `/announcements/{announcement}/send?revision=N`: sends the draft at the
/// revision its page showed, after a recent passkey confirmation. The query
/// carries that revision through auth's handoff, so a draft changed since its
/// page was read is refused, never sent unseen.
#[route([GET, POST] "/announcements/{announcement}/send")]
pub(super) async fn send(cx: &Cx, form: Option<Form<SendAnnouncement>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Announcement>(cx)?;
    let checked: SendAnnouncement = parse_query_params(cx)
        .map_err(|_| Error::from(bad_request("name the revision the draft's page showed")))?;
    let back = href!(show, Announcement(id)).resolve(cx);
    let refusal = App::submit(
        cx,
        form,
        back.clone(),
        |checked: SendAnnouncement| async move {
            service
                .send_announcement(&admin.operator, id, checked.revision)
                .await
                .map(drop)
        },
    )
    .await?;
    let detail = service.view_announcement(&admin.operator, id).await?;
    let announcement = &detail.announcement;
    // One already sent is not sent again: its page shows it.
    if refusal.is_none() && announcement.sent_at.is_some() {
        return Err(see_other(back).into());
    }
    let to = &if announcement.everyone {
        format!("Every account, {} now", announcement.recipients)
    } else {
        format!("{} chosen accounts", announcement.recipients)
    };
    let mailed = &format!("{} {}", detail.mailed, announcement.emailed());
    let revision = &checked.revision.to_string();
    let page = view! {
        sourceorigin_ui::dashboard_change(
            change: Change::SendAnnouncement,
            back: back.as_str(),
            refusal: refusal.as_deref(),
            <dl class="facts">
                <dt>"Subject"</dt><dd>(announcement.subject.as_str())</dd>
                <dt>"To"</dt><dd>(to.as_str())</dd>
                <dt>"Essential"</dt><dd>(announcement.essentiality())</dd>
                <dt>"Emailed to"</dt><dd>(mailed.as_str())</dd>
            </dl>
            <input type="hidden" name="revision" value=(revision.as_str())>
        )
    };
    App::render(cx, StatusCode::OK, "Send an announcement", page).await
}

/// `/announcements/{announcement}/discard`: deletes a draft.
#[route([GET, POST] "/announcements/{announcement}/discard")]
pub(super) async fn discard(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let service = &App::of(cx).service;
    let id = *path_param::<Announcement>(cx)?;
    let refusal = App::submit(cx, form, href!(list).resolve(cx), |_| {
        service.discard_announcement(&admin.operator, id)
    })
    .await?;
    let back = &href!(show, Announcement(id)).resolve(cx);
    let page = view! {
        sourceorigin_ui::dashboard_change(
            change: Change::DiscardAnnouncement,
            back: back.as_str(),
            refusal: refusal.as_deref(),
        )
    };
    App::render(cx, StatusCode::OK, "Discard a draft", page).await
}

impl App {
    /// The draft form of a new announcement, or of the draft `id`. Its accounts
    /// search, and its results' Add buttons, only fill the form in again, saving
    /// nothing. Saving keeps the draft and shows its page. Sending saves it, then
    /// sends it as saved once the dashboard is confirmed, or goes on to the send
    /// page, which confirms first: nothing typed is lost either way.
    async fn compose(
        cx: &Cx,
        form: Option<Form<DraftAnnouncement>>,
        id: Option<AnnouncementId>,
    ) -> Result<Response> {
        let admin = Self::admin(cx).await?;
        let service = &Self::of(cx).service;
        let back = match id {
            Some(id) => href!(show, Announcement(id)).resolve(cx),
            None => href!(list).resolve(cx),
        };
        let form = match form {
            Some(Form(mut input)) if method(cx) == Method::POST && input.composes() => {
                input.add_chosen();
                return Self::draft_form(cx, admin, id, &back, &input, None).await;
            }
            form => form,
        };
        let saved = Self::change(cx, form, |input: DraftAnnouncement| async move {
            let checked = AnnouncementDraft::try_from(&input)?;
            let (id, revision) = match id {
                Some(id) => (
                    id,
                    service
                        .edit_announcement(&admin.operator, id, &checked)
                        .await?,
                ),
                None => (
                    service
                        .draft_announcement(&admin.operator, &checked)
                        .await?,
                    1,
                ),
            };
            if input.intent != DraftIntent::Send {
                return Ok::<_, AdminError>(Saved::Page(id));
            }
            if !admin.operator.is_confirmed(Duration::zero()) {
                return Ok(Saved::Send(id, revision));
            }
            // The draft is saved: a send refused because it changed or was sent
            // meanwhile, or because the dashboard must confirm first, goes on to
            // the send page, rather than leave the form to save it again.
            match service
                .send_announcement(&admin.operator, id, revision)
                .await
            {
                Ok(_) => Ok(Saved::Page(id)),
                Err(
                    refused @ (AdminError::AnnouncementChanged
                    | AdminError::AnnouncementSent
                    | AdminError::StepUpRequired(_)
                    | AdminError::SessionEnded),
                ) => {
                    refused.log_refusal();
                    Ok(Saved::Send(id, revision))
                }
                Err(error) => Err(error),
            }
        })
        .await?;
        let (typed, refused) = match saved {
            Some(Ok(Saved::Page(id))) => {
                return Err(see_other(href!(show, Announcement(id)).resolve(cx)).into());
            }
            Some(Ok(Saved::Send(id, revision))) => {
                let sending = href!(send, Announcement(id)).resolve(cx);
                return Err(see_other(format!("{sending}?revision={revision}")).into());
            }
            Some(Err(refused)) => (refused.form.clone(), Some(refused)),
            None => match id {
                Some(id) => {
                    let detail = service.view_announcement(&admin.operator, id).await?;
                    // A sent announcement no longer changes: its page shows it.
                    if detail.announcement.sent_at.is_some() {
                        return Err(see_other(back).into());
                    }
                    (Self::form(&detail), None)
                }
                None => (DraftAnnouncement::default(), None),
            },
        };
        Self::draft_form(cx, admin, id, &back, &typed, refused.as_deref()).await
    }

    /// Answers with the draft form, `typed`, of a new announcement or of the
    /// draft `id`, with the accounts its search finds and why it was `refused`,
    /// if it was.
    async fn draft_form(
        cx: &Cx,
        admin: &SignedInAdmin,
        id: Option<AnnouncementId>,
        back: &str,
        typed: &DraftAnnouncement,
        refused: Option<&str>,
    ) -> Result<Response> {
        let find = typed.find.trim();
        let found = if find.is_empty() {
            Vec::new()
        } else {
            let service = &Self::of(cx).service;
            service
                .search_users(&admin.operator, find, None)
                .await?
                .users
        };
        let results: Vec<_> = found
            .iter()
            .map(|user| FoundAccount {
                user,
                added: typed.lists(user.handle.as_str()),
            })
            .collect();
        let (change, title) = match id {
            Some(_) => (Change::EditAnnouncement, "Edit the draft"),
            None => (Change::DraftAnnouncement, "New announcement"),
        };
        let page = view! {
            sourceorigin_ui::announcement_form(
                change: change,
                back: back,
                form: typed,
                found: &results,
                refusal: refused,
            )
        };
        Box::pin(Self::render(cx, StatusCode::OK, title, page)).await
    }

    /// The form showing the draft `detail` as it is, its chosen accounts by
    /// handle.
    fn form(detail: &AnnouncementDetail) -> DraftAnnouncement {
        let announcement = &detail.announcement;
        DraftAnnouncement {
            subject: announcement.subject.clone(),
            body: announcement.body.clone(),
            audience: if announcement.everyone {
                AnnouncementAudience::Everyone
            } else {
                AnnouncementAudience::Accounts
            },
            accounts: detail
                .accounts
                .iter()
                .map(|user| user.handle.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            essential: Checkbox(announcement.essential),
            ..DraftAnnouncement::default()
        }
    }
}
