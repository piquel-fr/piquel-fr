//! `/settings`: the handle, display name, passkeys and social sign-in.

use crate::{
    account::{AccountError, Owner, Subject},
    passkey::PasskeyApplication,
    routes::page::settings,
    web::{
        Failure, WebApplication,
        account::{AccountPage, Applied, Reader},
    },
};
use piquel_ui::{
    Audience, Checkbox, Messages, Notice, ProfileRow, Section, SignInChange, SignInState, Tab,
};
use topcoat::{
    Error,
    context::Cx,
    router::{StatusCode, request::headers, response::Response},
    view::{Child, view},
};

/// The sign-in methods page.
pub(in crate::web) struct SignInMethods;

impl SignInMethods {
    /// Its tab.
    const TAB: Tab = Tab::SignIn;
}

impl AccountPage for SignInMethods {
    const SECTION: Section = Section::Account;
    const PATH: &'static str = settings::SIGN_IN;
    const TITLE: &'static str = Self::TAB.label();
    type Change = SignInChange;
    type Row = SignInState;

    fn reopened(change: &SignInChange) -> SignInState {
        let closed = SignInState::default();
        match change {
            SignInChange::Handle { handle } => SignInState {
                changing_handle: Checkbox(true),
                handle: Some(handle.clone()),
                ..closed
            },
            SignInChange::DisplayName { display_name } => SignInState {
                changing_display_name: Checkbox(true),
                display_name: Some(display_name.clone()),
                ..closed
            },
            SignInChange::Rename { id, friendly_name } => SignInState {
                renaming: Some(*id),
                name: Some(friendly_name.clone()),
                ..closed
            },
            SignInChange::Remove { id } => SignInState {
                removing: Some(*id),
                ..closed
            },
            SignInChange::Unlink { provider } => SignInState {
                unlinking: Some(*provider),
                ..closed
            },
            SignInChange::Link { .. } | SignInChange::Enrolled {} => closed,
        }
    }

    /// Linking goes on at the provider, which returns to these settings once the
    /// link is confirmed.
    async fn apply(
        web: &WebApplication,
        _: &Cx,
        owner: Owner,
        change: SignInChange,
    ) -> Result<Applied<SignInState>, AccountError> {
        let notice = match change {
            SignInChange::Handle { handle } => {
                web.account.rename_handle(&owner, &handle).await?;
                Notice::HandleChanged
            }
            SignInChange::DisplayName { display_name } => {
                web.account
                    .change_display_name(&Subject::from(owner), display_name)
                    .await?;
                Notice::DisplayNameChanged
            }
            SignInChange::Link { provider } => {
                let (to, cookie) = web
                    .federation
                    .start_link(&owner, provider, settings::SIGN_IN)
                    .await?;
                return Ok(Applied::Elsewhere { to, cookie });
            }
            SignInChange::Rename { id, friendly_name } => {
                let name = friendly_name.trim().to_owned();
                web.account
                    .rename_passkey(&Subject::from(owner), id, name)
                    .await?;
                Notice::PasskeyRenamed
            }
            SignInChange::Remove { id } => {
                web.account
                    .revoke_passkey(&Subject::from(owner), id)
                    .await?;
                Notice::PasskeyRemoved
            }
            SignInChange::Unlink { provider } => {
                web.account
                    .unlink_identity(&Subject::from(owner), provider)
                    .await?;
                Notice::IdentityUnlinked
            }
            SignInChange::Enrolled {} => Notice::PasskeyAdded,
        };
        Ok(Applied::Done(notice))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        state: SignInState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let viewer = reader.viewer();
        let profile = web.account.profile(&viewer).await?;
        let passkeys = web.account.passkeys(&viewer).await?;
        let identities = web.account.identities(&viewer).await?;
        let providers = web.federation.provider_rows(&identities);
        let targets = web
            .federation
            .authorization_endpoints()
            .map_err(Error::from)?;
        let android = PasskeyApplication::offers_google_password_manager(headers(cx));
        let page = Child::new(view! { cx =>
            piquel_ui::sign_in_methods(
                page: settings::SIGN_IN,
                profile: Some(ProfileRow {
                    handle: profile.handle.as_str(),
                    changeable_at: profile.handle_changeable_at,
                    display_name: profile.display_name.as_str(),
                }),
                passkeys: &passkeys,
                providers: &providers,
                state: &state,
                audience: Audience::Owner { confirmed: reader.is_recent() },
                android: android,
                recovery: reader.recovery(),
            )
        });
        web.settings_page(cx, Self::TAB, reader, outcome, &targets, page)
            .await
    }
}
