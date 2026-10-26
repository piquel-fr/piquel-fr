//! The recovery pages, `/recover` and `/recover/undo`: adding a passkey with a
//! recovery link, and undoing or cancelling a recovery, signed in or not.
//!
//! Neither is an [`AccountPage`](super::account::AccountPage): whoever opens a
//! recovery's links may have no session. Each link carries what it names in its
//! fragment, which never reaches a server, so a page's `GET` only offers the form
//! posting it, and changes nothing: mail scanners open links. The passkey script
//! runs the passkey ceremony against the recovery's JSON routes, then posts that it
//! is done, and the page sends the browser on.

use super::{Failure, WebApplication};
use crate::{
    account::Owner,
    passkey::PasskeyApplication,
    recovery::{self, RecoveryNotice, RecoveryStage},
    routes::page::{self, settings},
    security::ApiError,
};
use piquel_ui::{
    Area, Notice, RecoverChange, RecoverStep, Recovery, RecoveryPasskey, Title, UndoChange,
    UndoStep,
};
use topcoat::{
    context::{Cx, app_context},
    router::{
        Body, StatusCode,
        error::see_other,
        request::headers,
        response::{IntoResponse, Response},
    },
    view::view,
};

#[cfg(test)]
mod tests;

impl From<RecoveryNotice> for Recovery {
    /// The recovery, as its pages show it.
    fn from(notice: RecoveryNotice) -> Self {
        let stage = match notice.stage {
            RecoveryStage::Open { expires_at } => piquel_ui::RecoveryStage::Open { expires_at },
            RecoveryStage::Probation {
                completed_at,
                settles_at,
                passkey,
            } => piquel_ui::RecoveryStage::Probation {
                completed_at,
                settles_at,
                passkey: passkey.map(|passkey| RecoveryPasskey {
                    id: passkey.id,
                    created_at: passkey.created_at,
                }),
            },
        };
        Self {
            id: notice.id,
            started_at: notice.started_at,
            stage,
            undoable: notice.undoable,
        }
    }
}

impl WebApplication {
    /// The recovery of `owner`'s account that can still be undone, if any, which
    /// the account's pages and its sign-ins ask about.
    pub(super) async fn recovery(&self, owner: &Owner) -> Result<Option<Recovery>, Failure> {
        Ok(self
            .account
            .recovery_notice(owner)
            .await?
            .map(Recovery::from))
    }

    /// `GET /recover`: the recovery link's form, which posts its token.
    pub(super) async fn recover(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        web.recover_page(cx, StatusCode::OK, RecoverStep::Open, None)
            .await
    }

    /// `POST /recover`: opens the link whose token the form posts, asking for a
    /// passkey for its account, or says why the link no longer works. Once the
    /// passkey script added the passkey, which signed the browser in, it goes on to
    /// the settings. A form from an older page that does not decode changes
    /// nothing.
    pub(super) async fn recover_change(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let refused = match Self::change(cx, body).await {
            Some(RecoverChange::Open { token }) => match web.account.open_recovery(&token).await {
                Ok(opened) => {
                    let account = opened.account();
                    let step = RecoverStep::Enroll {
                        username: &account.username,
                        display_name: &account.display_name,
                        expires_at: account.expires_at,
                        token: &token,
                        probation_days: recovery::PROBATION.num_days(),
                        android: PasskeyApplication::offers_google_password_manager(headers(cx)),
                    };
                    return web.recover_page(cx, StatusCode::OK, step, None).await;
                }
                Err(error) => ApiError::from(error),
            },
            Some(RecoverChange::Recovered {}) => {
                return match web.owner(cx).await? {
                    Some(_) => Self::notify(cx, settings::HOME, Notice::Recovered),
                    None => Ok(see_other(page::LOGIN).into_response(cx)?),
                };
            }
            None => ApiError::bad_request(piquel_ui::OUT_OF_DATE),
        };
        let (status, message) = refused.public();
        web.recover_page(cx, status, RecoverStep::Open, Some(message))
            .await
    }

    /// `GET /recover/undo`: the undo link's form, which posts the recovery's ID. A
    /// browser signed in to an account with a recovery that can still be undone is
    /// offered that one instead, should the link name none.
    pub(super) async fn undo_recovery(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let mut signed_in = None;
        if let Some(owner) = web.owner(cx).await?
            && let Some(recovery) = web.recovery(&owner).await?
            && let Some(account) = web.signed_in(&owner).await?
        {
            signed_in = Some((recovery, account.handle));
        }
        let signed_in = signed_in
            .as_ref()
            .map(|(recovery, handle)| (recovery, handle.as_str()));
        web.undo_page(cx, StatusCode::OK, UndoStep::Open { signed_in }, None)
            .await
    }

    /// `POST /recover/undo`: says what undoing the recovery the form names takes
    /// back, offering to undo it with a passkey from before it, or that there is
    /// nothing to undo. Once the passkey script undid it, says so: on the settings
    /// of the browser the undo signed in, or here when it signed nobody in, as on a
    /// disabled account. It needs no session and works on a disabled account, as
    /// the undo does. A form from an older page that does not decode changes
    /// nothing.
    pub(super) async fn undo_recovery_change(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let Some(change) = Self::change(cx, body).await else {
            let step = UndoStep::Open { signed_in: None };
            let alert = Some(piquel_ui::OUT_OF_DATE);
            return web
                .undo_page(cx, StatusCode::BAD_REQUEST, step, alert)
                .await;
        };
        match change {
            UndoChange::Open { recovery } => {
                let recovery = match recovery {
                    Some(id) => web.account.undoable_recovery(id).await?,
                    None => None,
                };
                match recovery.map(Recovery::from) {
                    Some(recovery) => {
                        let step = UndoStep::Undo {
                            recovery: &recovery,
                            handle: None,
                        };
                        web.undo_page(cx, StatusCode::OK, step, None).await
                    }
                    None => {
                        web.undo_page(cx, StatusCode::NOT_FOUND, UndoStep::Nothing, None)
                            .await
                    }
                }
            }
            // The finish says whether it signed the browser in; one it did not has a
            // disabled account, whatever session the browser holds.
            UndoChange::Undone { signed_in } => {
                if signed_in && web.owner(cx).await?.is_some() {
                    Self::notify(cx, settings::HOME, Notice::RecoveryUndone)
                } else {
                    web.undo_page(cx, StatusCode::OK, UndoStep::Done, None)
                        .await
                }
            }
        }
    }

    /// The recovery link's page at `step`, at `status`, saying why its form was
    /// refused in `alert`, if it was.
    async fn recover_page(
        &self,
        cx: &Cx,
        status: StatusCode,
        step: RecoverStep<'_>,
        alert: Option<&str>,
    ) -> Result<Response, Failure> {
        let view =
            view! { cx => piquel_ui::recover(action: page::RECOVER, step: step, alert: alert) };
        let title = Title::Recover.as_str();
        Ok(self
            .render(cx, status, title, Area::SignIn, &[], view)
            .await?)
    }

    /// The undo page at `step`, at `status`, saying why its form was refused in
    /// `alert`, if it was.
    async fn undo_page(
        &self,
        cx: &Cx,
        status: StatusCode,
        step: UndoStep<'_>,
        alert: Option<&str>,
    ) -> Result<Response, Failure> {
        let view = view! { cx =>
            piquel_ui::undo_recovery(action: page::RECOVER_UNDO, step: step, alert: alert)
        };
        let title = Title::UndoRecovery.as_str();
        Ok(self
            .render(cx, status, title, Area::SignIn, &[], view)
            .await?)
    }
}
