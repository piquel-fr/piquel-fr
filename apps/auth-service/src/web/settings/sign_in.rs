//! `/settings`: passkeys and social sign-in.

use super::{Applied, Reader, SettingsPage};
use crate::{
    account::{AccountError, Owner, Subject},
    passkey::PasskeyKind,
    routes::page::settings,
    security::BrowserCookie,
    web::{Failure, WebApplication},
};
use piquel_ui::{Messages, Notice, ProviderRow, SignInChange, SignInState, Tab};
use topcoat::{
    Error,
    context::Cx,
    router::{StatusCode, request::headers, response::Response},
    view::view,
};

/// The sign-in methods page.
pub(in crate::web) struct SignInMethods;

impl SettingsPage for SignInMethods {
    const TAB: Tab = Tab::SignIn;
    const PATH: &'static str = settings::HOME;
    type Change = SignInChange;
    type Row = SignInState;

    fn reopened(change: &SignInChange) -> SignInState {
        let closed = SignInState::default();
        match change {
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
        owner: Owner,
        change: SignInChange,
    ) -> Result<Applied<SignInState>, AccountError> {
        let notice = match change {
            SignInChange::Link { provider } => {
                let (to, secret) = web
                    .federation
                    .start_link(&owner, provider, settings::HOME)
                    .await?;
                return Ok(Applied::Elsewhere {
                    to,
                    cookie: (BrowserCookie::Federation, secret),
                });
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
        let passkeys = web.account.passkeys(&reader.viewer).await?;
        let identities = web.account.identities(&reader.viewer).await?;
        // Enabled providers, then any linked one since disabled, so it can still be
        // unlinked.
        let enabled: Vec<_> = web.federation.enabled().collect();
        let mut providers: Vec<_> = enabled
            .iter()
            .map(|&provider| ProviderRow {
                provider,
                identity: identities
                    .iter()
                    .find(|identity| identity.provider == provider),
                enabled: true,
            })
            .collect();
        providers.extend(
            identities
                .iter()
                .filter(|identity| !enabled.contains(&identity.provider))
                .map(|identity| ProviderRow {
                    provider: identity.provider,
                    identity: Some(identity),
                    enabled: false,
                }),
        );
        let targets = web
            .federation
            .authorization_endpoints()
            .map_err(Error::from)?;
        let android = PasskeyKind::offers_google(headers(cx));
        let page = view! { cx =>
            piquel_ui::sign_in_methods(
                page: settings::HOME,
                passkeys: &passkeys,
                providers: &providers,
                state: &state,
                confirmed: reader.confirmed,
                android: android,
            )
        };
        web.settings_page(cx, Self::TAB, reader, outcome, &targets, page)
            .await
    }
}
