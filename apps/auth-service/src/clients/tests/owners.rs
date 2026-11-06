//! Owners finding and changing only their own clients, with a passkey
//! confirmation, valid settings, and never past an operator's suspension.
use super::*;
use crate::security::SessionError;

/// An account lists and finds only its own live clients: another account's, an
/// operator's, an unknown ID and a malformed one are not found. Every operation
/// on one client takes what [`AccountService::owned_client`] found, so none
/// reaches them either.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owners_find_only_their_own_clients() {
    let account = Account::new().await;
    let (alice, service) = (account.owner().await, &account.service);
    let bob = Browser::new_account(&account.database).await;
    let bob = bob.owner(&account.database).await;
    let operated = registration(ClientKind::Public, "https://operated.example");
    register(&account.database, &operated)
        .await
        .expect("operator client");

    let id = account.create(ClientKind::Confidential).await;
    assert!(id.as_str().starts_with("c_"), "{id}");
    let listed = service.clients(&alice).await.expect("list");
    assert_eq!(
        listed.iter().map(|client| &client.id).collect::<Vec<_>>(),
        [&id]
    );
    let app = account.find(alice.clone(), &id).await;
    let secrets = service.client_secrets(&app).await.expect("secrets");
    assert_eq!(secrets.len(), 1);

    assert_eq!(service.clients(&bob).await.expect("list"), []);
    for (owner, id) in [
        (&bob, id.as_str()),
        (&alice, operated.id.as_str()),
        (&alice, "c_unknown"),
        (&alice, "%FF"),
    ] {
        let found = service.owned_client(owner.clone(), id).await;
        assert!(
            matches!(found, Err(AccountError::Client(OwnedClientError::NotFound))),
            "{id}"
        );
    }
}

/// Every change to a client needs a recent passkey confirmation: changing any
/// setting, pausing or resuming it. A refused change leaves the client as it was.
/// A confirmed owner rotates its secret and changes its settings.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_change_needs_a_confirmation() {
    let account = Account::new().await;
    let service = &account.service;
    let id = account.create(ClientKind::Confidential).await;
    let social = account.social().await.owner(&account.database).await;
    let client = account.find(social, &id).await;
    let logout = ClientPatch {
        post_logout_uris: Some(vec!["https://attacker.example/".into()]),
        ..ClientPatch::default()
    };
    let rename = || ClientPatch {
        display_name: Some("Renamed".into()),
        ..ClientPatch::default()
    };
    for refused in [
        service.update_client(&client, logout).await.map(drop),
        service.update_client(&client, rename()).await.map(drop),
        service.set_client_enabled(&client, false).await,
        service.set_client_enabled(&client, true).await,
    ] {
        assert!(
            matches!(
                refused,
                Err(AccountError::Owner(SessionError::StepUpRequired { .. }))
            ),
            "{refused:?}"
        );
    }
    let kept = account.database.oidc().find_client(id.as_str()).await;
    let kept = kept.expect("lookup").expect("client");
    assert_eq!(
        kept.display_name, "Notes",
        "the refused changes were rolled back"
    );
    assert_eq!(kept.post_logout_uris, Vec::<String>::new());
    assert!(kept.enabled);

    let client = account.find(account.owner().await, &id).await;
    let grace = "0".parse().expect("grace period");
    let secret = service.rotate_client_secret(&client, grace).await;
    assert!(secret.expect("rotate").expose().starts_with("pqcs_"));
    let patch = ClientPatch {
        redirect_uris: Some(vec!["https://notes.example/auth".into()]),
        ..rename()
    };
    let changed = service.update_client(&client, patch).await.expect("change");
    assert_eq!(changed.display_name, "Renamed");
    assert_eq!(changed.redirect_uris, ["https://notes.example/auth"]);
    service
        .set_client_enabled(&client, false)
        .await
        .expect("disable");
}

/// An owner found from a cookie their session had before a passkey confirmation
/// never gains that confirmation, even when it commits while the change waits
/// for the account lock: the confirmation replaced the cookie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn confirmations_never_reach_owners_found_before_them() {
    let account = Account::new().await;
    let service = &account.service;
    let id = account.create(ClientKind::Confidential).await;
    let redirect = ClientPatch {
        redirect_uris: Some(vec!["https://attacker.example/callback".into()]),
        ..ClientPatch::default()
    };
    for result in [
        account
            .confirmed_while_waiting(&id, async |client| {
                service.update_client(client, redirect).await.map(drop)
            })
            .await,
        account
            .confirmed_while_waiting(&id, async |client| {
                let grace = GracePeriod::default();
                service.rotate_client_secret(client, grace).await.map(drop)
            })
            .await,
        account
            .confirmed_while_waiting(&id, async |client| {
                service.set_client_enabled(client, false).await
            })
            .await,
        account
            .confirmed_while_waiting(&id, async |client| service.delete_client(client).await)
            .await,
    ] {
        assert!(
            matches!(
                result,
                Err(AccountError::Owner(SessionError::StepUpRequired { .. }))
            ),
            "{result:?}"
        );
    }
    let client = account.database.oidc().find_client(id.as_str()).await;
    let client = client.expect("lookup").expect("client");
    assert_eq!(client.redirect_uris, ["https://notes.example/callback"]);
    assert!(client.enabled && client.deleted_at.is_none());
    let secrets = account.database.oidc().client_secrets(&id).await;
    assert_eq!(secrets.expect("secrets").len(), 1, "no secret was added");
}

/// An invalid setting names its field apart from what is wrong with it, so a
/// form can show the message beside it: owners grant only the standard scopes,
/// send browsers only to URIs auth accepts and name no client after a reserved
/// brand. Settings are checked before
/// anything else, so an unconfirmed owner's invalid registration is refused for
/// its settings rather than for the confirmation.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn invalid_settings_name_their_field_first() {
    let account = Account::new().await;
    let id = account.create(ClientKind::Public).await;
    let client = account.find(account.owner().await, &id).await;
    let social = account.social().await.owner(&account.database).await;
    let blank = NewClient {
        kind: ClientKind::Public,
        settings: ClientSettings {
            display_name: " ".into(),
            ..ClientSettings::test("https://notes.example")
        },
    };
    let invalid = |result: Result<(), AccountError>, field: ClientField| match result {
        Err(AccountError::Client(OwnedClientError::InvalidSetting(error))) => {
            assert_eq!(error.field(), &field);
            assert_eq!(error.to_string(), format!("{field}: {}", error.reason()));
        }
        result => panic!("{field}: {result:?}"),
    };
    let registered = account.service.create_client(&social, blank).await;
    invalid(registered.map(drop), ClientField::DisplayName);
    for (patch, field) in [
        (
            ClientPatch {
                allowed_scopes: Some(vec!["openid".into(), "notes:read".into()]),
                ..ClientPatch::default()
            },
            ClientField::AllowedScopes,
        ),
        (
            ClientPatch {
                redirect_uris: Some(vec!["http://notes.example/callback".into()]),
                ..ClientPatch::default()
            },
            ClientField::RedirectUris,
        ),
        (
            ClientPatch {
                redirect_uris: Some(Vec::new()),
                ..ClientPatch::default()
            },
            ClientField::RedirectUris,
        ),
        (
            ClientPatch {
                display_name: Some(" ".into()),
                ..ClientPatch::default()
            },
            ClientField::DisplayName,
        ),
        (
            ClientPatch {
                display_name: Some("Piquel Settings".into()),
                ..ClientPatch::default()
            },
            ClientField::DisplayName,
        ),
    ] {
        let changed = account.service.update_client(&client, patch).await;
        invalid(changed.map(drop), field);
    }
}

/// An operator's suspension disables a client, and its owner cannot enable it,
/// though they can still see and disable it. Lifting the suspension leaves it
/// disabled, for the owner to enable.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owners_cannot_enable_a_suspended_client() {
    let account = Account::new().await;
    let (service, owner) = (&account.service, account.owner().await);
    let id = account.create(ClientKind::Public).await;
    let client = account.find(owner.clone(), &id).await;
    let suspend = async |suspended: bool| {
        change(&account.database, async |registry| {
            registry.set_suspended(&id, suspended).await
        })
        .await
        .expect("suspension");
    };
    let shown = async || account.find(owner.clone(), &id).await;
    suspend(true).await;
    let suspended = shown().await;
    let suspended = suspended.client();
    assert!(suspended.suspended_at.is_some() && !suspended.enabled);
    let enabled = service.set_client_enabled(&client, true).await;
    assert!(
        matches!(
            enabled,
            Err(AccountError::Client(OwnedClientError::Registry(
                ClientRegistryError::Suspended(_)
            )))
        ),
        "{enabled:?}"
    );
    assert!(matches!(
        change(&account.database, async |registry| {
            registry.set_enabled(&id, true).await
        })
        .await,
        Err(ClientRegistryError::Suspended(_)),
    ));
    service
        .set_client_enabled(&client, false)
        .await
        .expect("disable");

    suspend(false).await;
    let lifted = shown().await;
    let lifted = lifted.client();
    assert!(lifted.suspended_at.is_none() && !lifted.enabled);
    service
        .set_client_enabled(&client, true)
        .await
        .expect("enable");
}
