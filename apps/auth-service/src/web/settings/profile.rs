//! `/settings/profile`: the account's handle, display name and picture.

use crate::{
    account::{AccountError, Owner, Subject},
    pictures::{CropFields, PictureError},
    routes::{page::settings, pictures},
    web::{
        Failure, WebApplication,
        account::{AccountPage, Applied, Reader},
    },
};
use piquel_ui::{
    Alert, Audience, CROP_SIZE, CROP_X, CROP_Y, Messages, Notice, PICTURE_FIELD, ProfileChange,
    ProfileDialog, ProfileState, Section, Tab, Who,
};
use serde::Deserialize;
use topcoat::{
    context::Cx,
    router::{
        Body, StatusCode,
        content::multipart::Multipart,
        error::ContentTooLargeError,
        request::{FromRequest, content_type},
        response::Response,
    },
    view::{Child, view},
};

/// The profile page, whose dialogs open as its query says.
pub(in crate::web) struct Profile;

impl Profile {
    /// Its tab.
    const TAB: Tab = Tab::Profile;
}

/// A change the profile page makes. A text form names it as a [`ProfileChange`];
/// an upload posts `multipart/form-data`, which [`Profile::decode`] reads.
#[derive(Deserialize)]
#[serde(from = "ProfileChange")]
pub(in crate::web) enum ProfileEdit {
    /// Makes the image the account's picture, keeping the square chosen, or its
    /// centred one. Empty when a text form named it, which chose no image.
    Upload(Vec<u8>, CropFields),
    /// The upload was over the page's body limit.
    Oversize,
    /// Removes the account's picture.
    Remove,
    /// Changes the display name to the one typed.
    DisplayName(String),
    /// Changes the handle to the one typed.
    Handle(String),
}

impl From<ProfileChange> for ProfileEdit {
    /// The change a text form names: an upload in one carries no image.
    fn from(change: ProfileChange) -> Self {
        match change {
            ProfileChange::Upload => Self::Upload(Vec::new(), CropFields::default()),
            ProfileChange::Remove => Self::Remove,
            ProfileChange::DisplayName { display_name } => Self::DisplayName(display_name),
            ProfileChange::Handle { handle } => Self::Handle(handle),
        }
    }
}

impl Profile {
    /// The change `multipart` sends: its action and, for an upload, its picture's
    /// bytes, in any order. An upload over the body limit is
    /// [`ProfileEdit::Oversize`], so the page says how large an image may be; one
    /// that does not read changes nothing.
    async fn upload(mut multipart: Multipart) -> Option<ProfileEdit> {
        let (mut action, mut picture) = (None, None);
        let mut crop = CropFields::default();
        loop {
            let field = match multipart.next_field().await {
                Ok(Some(field)) => field,
                Ok(None) => break,
                Err(error) if error.is::<ContentTooLargeError>() => {
                    return Some(ProfileEdit::Oversize);
                }
                Err(error) => {
                    tracing::debug!(%error, "picture upload rejected");
                    return None;
                }
            };
            let read = match field.name() {
                Some("action") => field.text().await.map(|text| action = Some(text)),
                Some(PICTURE_FIELD) => field.bytes().await.map(|bytes| picture = Some(bytes)),
                Some(CROP_X) => field.text().await.map(|text| crop.x = text.parse().ok()),
                Some(CROP_Y) => field.text().await.map(|text| crop.y = text.parse().ok()),
                Some(CROP_SIZE) => field.text().await.map(|text| crop.size = text.parse().ok()),
                _ => Ok(()),
            };
            match read {
                Ok(()) => {}
                Err(error) if error.is::<ContentTooLargeError>() => {
                    return Some(ProfileEdit::Oversize);
                }
                Err(error) => {
                    tracing::debug!(%error, "picture upload rejected");
                    return None;
                }
            }
        }
        // The action is the text form's tag, so its name is written once.
        let action = serde_json::json!({ "action": action? });
        Some(match serde_json::from_value(action).ok()? {
            ProfileChange::Upload => {
                ProfileEdit::Upload(picture.map(Vec::from).unwrap_or_default(), crop)
            }
            change => change.into(),
        })
    }
}

impl AccountPage for Profile {
    const SECTION: Section = Section::Account;
    const PATH: &'static str = settings::PROFILE;
    const TITLE: &'static str = Self::TAB.label();
    type Change = ProfileEdit;
    type Row = ProfileState;

    /// A refused change shows its dialog again, holding what was typed.
    fn reopened(change: &ProfileEdit) -> ProfileState {
        let (open, display_name, handle) = match change {
            ProfileEdit::Upload(..) | ProfileEdit::Oversize => (ProfileDialog::Picture, None, None),
            ProfileEdit::Remove => (ProfileDialog::Remove, None, None),
            ProfileEdit::DisplayName(name) => (ProfileDialog::Name, Some(name.clone()), None),
            ProfileEdit::Handle(handle) => (ProfileDialog::Handle, None, Some(handle.clone())),
        };
        ProfileState {
            open: Some(open),
            display_name,
            handle,
        }
    }

    /// An upload is read here; the remove form posts text, as every other form.
    async fn decode(cx: &Cx, body: Body) -> Option<ProfileEdit> {
        if content_type(cx).is_some_and(|value| value.starts_with("multipart/form-data")) {
            let multipart = Multipart::from_request(cx, body).await.ok()?;
            return Self::upload(multipart).await;
        }
        WebApplication::change(cx, body).await
    }

    async fn apply(
        web: &WebApplication,
        _: &Cx,
        owner: Owner,
        change: ProfileEdit,
    ) -> Result<Applied<ProfileState>, AccountError> {
        let notice = match change {
            ProfileEdit::Upload(image, crop) => {
                web.account.set_picture(&owner, image, crop.crop()?).await?;
                Notice::PictureChanged
            }
            ProfileEdit::Oversize => return Err(PictureError::TooLarge.into()),
            ProfileEdit::Remove => {
                web.account.remove_picture(&Subject::from(owner)).await?;
                Notice::PictureRemoved
            }
            ProfileEdit::DisplayName(name) => {
                web.account
                    .change_display_name(&Subject::from(owner), name)
                    .await?;
                Notice::DisplayNameChanged
            }
            ProfileEdit::Handle(handle) => {
                web.account.rename_handle(&owner, &handle).await?;
                Notice::HandleChanged
            }
        };
        Ok(Applied::Done(notice))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        state: ProfileState,
        (status, messages): (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        // A refusal is said in the dialog shown again, not behind it, or above the
        // profile when the page no longer has that dialog.
        let (alert, messages) = match messages.alert {
            Some(Alert::Page(alert)) if state.open.is_some() => (
                Some(alert),
                Messages {
                    alert: None,
                    ..messages
                },
            ),
            _ => (None, messages),
        };
        let viewer = reader.viewer();
        let profile = web.account.profile(&viewer).await?;
        let administrator = web.account.is_administrator(&viewer).await?;
        let picture = profile.picture.map(pictures::of);
        let who = Who {
            user: None,
            name: &profile.display_name,
            handle: profile.handle.as_str(),
            picture: picture.as_deref(),
            administrator,
        };
        let state = &state;
        let page = Child::new(view! {
            piquel_ui::profile_settings(
                page: settings::PROFILE,
                who: who,
                // The owner's account is active, so it shows what it stored.
                stored: who.picture.is_some(),
                changeable_at: profile.handle_changeable_at,
                state: &state,
                audience: Audience::Owner { confirmed: reader.is_recent() },
                alert: alert,
            )
        });
        web.settings_page(cx, Self::TAB, reader, (status, messages), &[], page)
            .await
    }
}
