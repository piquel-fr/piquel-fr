//! The profile: what apps see of the account, its handle, display name and
//! picture, each changed in a dialog of its own.

use super::Audience;
use crate::{
    form::{Precision, Query, change_form, handle_input, hidden, post_form, time},
    layout::{AvatarSize, Who, alert_notice, avatar, dialog, page_head},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    context::Cx,
    view::{View, component, view},
};

/// The file input an upload sends its picture in.
pub const PICTURE_FIELD: &str = "picture";

/// The media types auth reads a picture from, as an upload's file input and a
/// fetch's `Accept` header name them; auth recognises the format by content.
pub const PICTURE_TYPES: &str = "image/png,image/jpeg,image/gif";

/// The hidden inputs an upload sends the square to keep in, in the picture's
/// pixels once upright: its left edge, its top edge and its side. The picture
/// script fills them as the owner moves and zooms the picture; without a script
/// they stay empty, and auth keeps the centred square.
pub const CROP_X: &str = "crop_x";
/// See [`CROP_X`].
pub const CROP_Y: &str = "crop_y";
/// See [`CROP_X`].
pub const CROP_SIZE: &str = "crop_size";

/// A change the profile page posts, named by its `action` field. A field the user
/// types is left empty here, and the form renders its input instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ProfileChange {
    /// Makes the image in the [`PICTURE_FIELD`] file the account's picture. Its
    /// form posts `multipart/form-data`, which the page reads itself; only the
    /// owner sets a picture.
    Upload,
    /// Removes the account's picture.
    Remove,
    /// Changes the account's display name. A name grants nothing, so it needs no
    /// passkey confirmation.
    DisplayName {
        /// The new name, which the user types.
        #[serde(skip_serializing_if = "String::is_empty")]
        display_name: String,
    },
    /// Changes the account's handle, once confirmed with a passkey.
    Handle {
        /// The new handle, which the user types.
        #[serde(skip_serializing_if = "String::is_empty")]
        handle: String,
    },
}

/// A dialog of the profile page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileDialog {
    /// Choosing a new picture.
    Picture,
    /// Removing the picture.
    Remove,
    /// Changing the display name.
    Name,
    /// Changing the handle.
    Handle,
}

impl ProfileDialog {
    /// Whether the page has this dialog, for `audience`: the owner's alone choose a
    /// picture and change the name, the handle once its cooldown is over, and either
    /// removes a picture the account `stored`.
    fn available(
        self,
        audience: Audience<'_>,
        stored: bool,
        changeable_at: Option<DateTime<Utc>>,
    ) -> bool {
        match self {
            Self::Picture | Self::Name => audience.owns(),
            Self::Handle => audience.owns() && changeable_at.is_none(),
            Self::Remove => stored,
        }
    }

    /// Its element's ID, which its button opens.
    const fn id(self) -> &'static str {
        match self {
            Self::Picture => "dialog-picture",
            Self::Remove => "dialog-remove-picture",
            Self::Name => "dialog-name",
            Self::Handle => "dialog-handle",
        }
    }
}

/// Which dialog of the profile page shows open as it loads, as the page's query
/// names it: one whose change was refused, holding what was typed, or one a link
/// opens.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProfileState {
    /// The dialog shown open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<ProfileDialog>,
    /// The display name a change that failed asked for, to ask for it again.
    #[serde(skip)]
    pub display_name: Option<String>,
    /// The handle a change that failed asked for, to ask for it again.
    #[serde(skip)]
    pub handle: Option<String>,
}

impl Query for ProfileState {}

/// The administrator's pages changing the display name and the handle, which ask
/// for a reason and take no cooldown; the owner changes them in dialogs instead.
#[derive(Clone, Copy, Debug)]
pub struct ProfilePages<'a> {
    /// Changing the display name.
    pub display_name: &'a str,
    /// Changing the handle.
    pub handle: &'a str,
}

/// The profile page: `who` as apps see them, with their picture, or their initials
/// while none shows, and a row for each of the handle, the display name and the
/// picture. The account `stored` a picture, which may be removed even while the
/// account is not active and so shows none; the handle may change again from
/// `changeable_at`, if not yet. Its changes post to `page`, the dialog `state`
/// names showing open, for `audience`: the owner changes each in a dialog, and an
/// administrator removes the picture, with a reason, and changes the rest on the
/// `pages` of the dashboard. Why the change just posted was refused, its `alert`,
/// shows in its dialog, or above the profile when the page no longer has it, as
/// when another tab removed the picture.
#[component]
pub async fn profile_settings<'a>(
    cx: &Cx,
    page: &'a str,
    who: Who<'a>,
    stored: bool,
    changeable_at: Option<DateTime<Utc>>,
    state: &'a ProfileState,
    audience: Audience<'a>,
    #[default] pages: Option<ProfilePages<'a>>,
    #[default] alert: Option<&'a str>,
) -> Result<impl View> {
    let handle = format!("@{}", who.handle);
    let shown = state
        .open
        .filter(|which| which.available(audience, stored, changeable_at));
    Ok(view! {
        if audience.owns() {
            page_head(
                title: "Profile",
                lead: "What apps you sign in to with Piquel see of you.".to_owned(),
            )
        }
        if let Some(alert) = alert.filter(|_| shown.is_none()) {
            alert_notice(message: alert)
        }
        <section class="card profile" aria-labelledby="profile-name">
            <div class="identity">
                avatar(who: who, size: AvatarSize::Large)
                <div class="names">
                    <h2 id="profile-name">(who.name)</h2>
                    <p class="handle">(handle.as_str())</p>
                </div>
            </div>
            <dl class="fields">
                <div class="field">
                    <dt>"Handle"</dt>
                    <dd>
                        <span class="mono">(handle.as_str())</span>
                        if let Some(at) = changeable_at.filter(|_| audience.owns()) {
                            <small>"You can change it again on " time(at: at, precision: Precision::Day) "."</small>
                        }
                    </dd>
                    <dd class="actions">
                        if let Some(pages) = pages {
                            <a data-confirm-first="" class="button secondary small" href=(pages.handle) aria-label="Change handle">"Change"</a>
                        } else {
                            <button
                                type="button"
                                class="secondary small"
                                popovertarget=(ProfileDialog::Handle.id())
                                aria-label="Change handle"
                                disabled=(changeable_at.is_some())
                            >"Change"</button>
                        }
                    </dd>
                </div>
                <div class="field">
                    <dt>"Display name"</dt>
                    <dd>(who.name)</dd>
                    <dd class="actions">
                        if let Some(pages) = pages {
                            <a data-confirm-first="" class="button secondary small" href=(pages.display_name) aria-label="Change display name">"Change"</a>
                        } else {
                            <button type="button" class="secondary small" popovertarget=(ProfileDialog::Name.id()) aria-label="Change display name">"Change"</button>
                        }
                    </dd>
                </div>
                <div class="field">
                    <dt>"Picture"</dt>
                    <dd>
                        (if !stored {
                            "None yet. Apps show initials instead."
                        } else if who.picture.is_some() {
                            "Apps show it beside the name."
                        } else {
                            "Shown nowhere while the account is not active."
                        })
                    </dd>
                    <dd class="actions">
                        if audience.owns() {
                            <button type="button" class="secondary small" popovertarget=(ProfileDialog::Picture.id())>
                                if stored { "Change" } else { "Add a picture" }
                            </button>
                        }
                        if stored {
                            <button type="button" class="danger small" popovertarget=(ProfileDialog::Remove.id())>"Remove"</button>
                        }
                    </dd>
                </div>
            </dl>
        </section>
        profile_dialogs(
            page: page,
            who: who,
            stored: stored,
            changeable_at: changeable_at,
            state: state,
            shown: shown,
            audience: audience,
            alert: alert.filter(|_| shown.is_some()),
        )
    })
}

/// The dialogs of [`profile_settings`], each changing what its row shows: for the
/// owner, unless `changeable_at` is still to come, the handle, the display name
/// and choosing a picture; and removing the picture the account `stored`, for
/// either audience. The one `shown` is open, holding what `state` says was typed,
/// with the `alert` saying why its change was refused.
#[component]
async fn profile_dialogs<'a>(
    cx: &Cx,
    page: &'a str,
    who: Who<'a>,
    stored: bool,
    changeable_at: Option<DateTime<Utc>>,
    state: &'a ProfileState,
    shown: Option<ProfileDialog>,
    audience: Audience<'a>,
    alert: Option<&'a str>,
) -> Result<impl View> {
    let available = move |which: ProfileDialog| which.available(audience, stored, changeable_at);
    let shown = move |which: ProfileDialog| shown == Some(which);
    let handle = format!("@{}", who.handle);
    Ok(view! {
        if available(ProfileDialog::Handle) {
            dialog(id: ProfileDialog::Handle.id(), title: "Change your handle", shown: shown(ProfileDialog::Handle), back: page, alert: alert,
                change_form(
                    action: page,
                    change: ProfileChange::Handle { handle: String::new() },
                    label: "Change handle",
                    confirm: audience.confirms(),
                    handle_input(new: true, value: state.handle.as_deref().or(Some(who.handle)), focus: true)
                    <div class="notice warning stack">
                        <p>
                            <strong>(format!("{handle} stops working right away."))</strong>
                            " Links to it, and apps that look you up by it, stop finding you."
                        </p>
                        <p>"It stays reserved for you, so nobody else can take it, and you can take it back later. You can change your handle once every 30 days."</p>
                    </div>
                )
            )
        }
        if available(ProfileDialog::Name) {
            dialog(id: ProfileDialog::Name.id(), title: "Change your display name", shown: shown(ProfileDialog::Name), back: page, alert: alert,
                <p class="help">"Apps show it as your name. It needs no passkey: a name grants nothing."</p>
                change_form(
                    action: page,
                    change: ProfileChange::DisplayName { display_name: String::new() },
                    label: "Save name",
                    <label>
                        "Display name"
                        <input
                            name="display_name"
                            value=(state.display_name.as_deref().unwrap_or(who.name))
                            maxlength="80"
                            required=""
                            autofocus=""
                        >
                    </label>
                )
            )
        }
        if available(ProfileDialog::Picture) {
            dialog(id: ProfileDialog::Picture.id(), title: "Choose a picture", shown: shown(ProfileDialog::Picture), back: page, alert: alert,
                <p class="help">"A PNG, JPEG or GIF of up to 10 MB, cropped to a square. Nothing but the image is kept, so not where a photo was taken."</p>
                post_form(action: page, multipart: true,
                    hidden(fields: ProfileChange::Upload)
                    <label>
                        "Picture"
                        <input type="file" name=(PICTURE_FIELD) accept=(PICTURE_TYPES) required="" autofocus="">
                    </label>
                    // The picture script shows the image chosen here, to move and
                    // zoom it; without a script it stays hidden and auth keeps the
                    // centred square.
                    <div class="cropper" data-cropper="" hidden="">
                        <div
                            class="crop-stage"
                            data-crop-stage=""
                            tabindex="0"
                            role="application"
                            aria-label="The part of the picture apps show. Drag it, or use the arrow keys, to move it."
                        >
                            <img alt="" data-crop-image="">
                        </div>
                        <label>
                            "Zoom"
                            <input type="range" min="1" max="4" step="0.01" value="1" data-crop-zoom="">
                        </label>
                    </div>
                    <input type="hidden" name=(CROP_X) data-crop="x">
                    <input type="hidden" name=(CROP_Y) data-crop="y">
                    <input type="hidden" name=(CROP_SIZE) data-crop="size">
                    <div class="row actions">
                        <button>"Upload picture"</button>
                    </div>
                )
            )
        }
        if available(ProfileDialog::Remove) {
            // It asks no input, so its Close takes the focus.
            dialog(id: ProfileDialog::Remove.id(), title: "Remove the picture?", shown: shown(ProfileDialog::Remove), back: page, alert: alert, focus_close: true,
                <p class="help">
                    if audience.owns() {
                        "Apps show your initials instead."
                    } else {
                        "Apps show the owner's initials instead, and their history says why."
                    }
                </p>
                change_form(
                    action: page,
                    change: ProfileChange::Remove,
                    label: "Remove picture",
                    class: "danger",
                    reason: audience.asks_reason(),
                )
            )
        }
    })
}
