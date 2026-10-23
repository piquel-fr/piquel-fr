//! Registering, inspecting and changing OIDC clients.

use super::{CliError, Confirm, Console, Output};
use crate::{Applied, DEFAULT_CLIENT_SCOPES, GracePeriod};
use clap::{Args, Subcommand};
use piquel_common::{
    ClientId,
    clients::{
        AllowedScopes, ClientKind, ClientRegistration, DisplayName, PostLogoutUris, RedirectUri,
        RedirectUris, ScopeName,
    },
    config::SecretReference,
};
use piquel_crypto::ClientSecret;
use piquel_repository::StoredOidcClient;

/// Registering, inspecting and changing OIDC clients.
#[derive(Subcommand)]
pub(super) enum ClientCommand {
    /// Register a client. A confidential client's secret is printed once.
    Create(CreateClient),
    /// Register a client, or update it to match, with the secret its deployment
    /// generated: for clients a deployment manages, such as the admin dashboard.
    /// Records nothing when the client already matches.
    Apply(ApplyClient),
    /// List every client, deleted ones included.
    List {
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Print a client's registration and its secrets' lifetimes as JSON.
    Show {
        /// The client's ID.
        id: ClientId,
    },
    /// Change a client's registration; what is not given keeps its value.
    Update(UpdateClient),
    /// Stop a client from authorizing, exchanging codes and refreshing tokens.
    Disable {
        /// The client's ID.
        id: ClientId,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Delete a client: it stops working at once, its refresh tokens, secrets and
    /// consents go, and its ID can never be registered again.
    Delete {
        /// The client's ID.
        id: ClientId,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Let a disabled client work again.
    Enable {
        /// The client's ID.
        id: ClientId,
    },
    /// Block a client: it is disabled, and its owner cannot enable it again
    /// until `unsuspend`.
    Suspend {
        /// The client's ID.
        id: ClientId,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Lift a client's suspension. It stays disabled until enabled.
    Unsuspend {
        /// The client's ID.
        id: ClientId,
    },
    /// Print a new secret for a confidential client. Earlier secrets keep working
    /// during the grace period, while the client switches to the new one.
    RotateSecret {
        /// The client's ID.
        id: ClientId,
        /// How long earlier secrets keep working, e.g. 30m, 24h or 7d; 0 revokes them now.
        #[arg(long, default_value = "24h")]
        grace: GracePeriod,
    },
}

impl ClientCommand {
    /// Runs this command as the operator at this terminal. Each change commits
    /// with its event before anything is printed, so a script never captures a
    /// secret that was not stored.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console { service, operator } = console;
        let done = match self {
            Self::Create(create) => ClientChange::Secret(
                service
                    .create_client(operator, &create.registration()?)
                    .await?,
            ),
            Self::Apply(apply) => {
                let secret = apply.secret()?;
                let id = apply.client.id.clone();
                let applied = service
                    .apply_client(operator, &apply.client.registration()?, secret, apply.grace)
                    .await?;
                ClientChange::Applied(id, applied)
            }
            Self::List { output } => {
                output.print(&service.list_clients().await?, |clients| {
                    println!("ID\tAUTH\tSTATUS\tREFRESH\tTRUSTED\tPAR\tOWNER\tNAME");
                    for client in clients {
                        println!(
                            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                            client.id,
                            client.token_endpoint_auth_method,
                            client.status(),
                            client.allow_refresh,
                            client.trusted,
                            client.require_pushed_authorization_requests,
                            client
                                .owner_id
                                .map_or_else(|| "operator".to_owned(), |id| id.to_string()),
                            client.display_name,
                        );
                    }
                })?;
                ClientChange::Silent
            }
            Self::Show { id } => {
                let details = service.client_details(&id).await?;
                println!("{}", serde_json::to_string_pretty(&details)?);
                ClientChange::Silent
            }
            Self::Update(update) => {
                let id = update.id.clone();
                service
                    .update_client(operator, &id, |client| update.apply(client))
                    .await?;
                ClientChange::Silent
            }
            Self::Disable { id, confirm } => {
                confirm.ask(&format!("Disable client {id}: it stops working at once"))?;
                service.set_client_enabled(operator, &id, false).await?;
                ClientChange::Silent
            }
            Self::Enable { id } => {
                service.set_client_enabled(operator, &id, true).await?;
                ClientChange::Silent
            }
            Self::Suspend { id, confirm } => {
                confirm.ask(&format!(
                    "Suspend client {id}: it stops working, and its owner cannot enable it"
                ))?;
                service.set_client_suspended(operator, &id, true).await?;
                ClientChange::Silent
            }
            Self::Unsuspend { id } => {
                service.set_client_suspended(operator, &id, false).await?;
                ClientChange::Silent
            }
            Self::Delete { id, confirm } => {
                confirm.ask(&format!(
                    "Delete client {id}: it stops working at once, and its ID can never be reused"
                ))?;
                service.delete_client(operator, &id).await?;
                ClientChange::Silent
            }
            Self::RotateSecret { id, grace } => ClientChange::Secret(Some(
                service.rotate_client_secret(operator, &id, grace).await?,
            )),
        };
        done.print();
        Ok(())
    }
}

/// What a committed client command still prints.
enum ClientChange {
    /// A new secret, if the client is confidential.
    Secret(Option<ClientSecret>),
    /// What `client apply` did to the client.
    Applied(ClientId, Applied),
    /// Nothing, or it was printed already: reads print as they go.
    Silent,
}

impl ClientChange {
    /// Prints a new secret alone on standard output, so scripts can capture it,
    /// or what `apply` did on standard error.
    fn print(self) {
        match self {
            Self::Secret(Some(secret)) => {
                println!("{}", secret.expose());
                eprintln!("Store this client secret now: it cannot be shown again.");
            }
            Self::Applied(id, applied) => {
                let applied = match applied {
                    Applied::Registered => "registered",
                    Applied::Updated => "updated",
                    Applied::Unchanged => "unchanged",
                };
                eprintln!("Client {id}: {applied}.");
            }
            Self::Secret(None) | Self::Silent => {}
        }
    }
}

/// The registration of a new client.
#[derive(Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Clap reads each `--x` option into a flag."
)]
pub(super) struct CreateClient {
    /// The client's ID: 1 to 64 characters from A-Z, a-z, 0-9, '.', '_' and '-'.
    id: ClientId,
    /// The name consent screens show.
    #[arg(long)]
    name: DisplayName,
    /// An authorization callback, matched exactly; repeat for several.
    #[arg(long = "redirect-uri", required = true)]
    redirect_uris: Vec<RedirectUri>,
    /// A page the browser may return to after logout; repeat for several.
    #[arg(long = "post-logout-uri")]
    post_logout_uris: Vec<RedirectUri>,
    /// A scope the client may request; repeat for several. Defaults to openid,
    /// profile and email.
    #[arg(long = "scope")]
    scopes: Vec<ScopeName>,
    /// The client runs on a server and authenticates with a secret.
    #[arg(long)]
    confidential: bool,
    /// The client may receive refresh tokens when it requests `offline_access`.
    #[arg(long)]
    refresh: bool,
    /// The client skips the consent screen. Only for first-party clients.
    #[arg(long)]
    trusted: bool,
    /// The client must push its authorization requests (RFC 9126), so none of
    /// their parameters travel through the browser.
    #[arg(long)]
    require_par: bool,
    /// Where auth posts a logout token when a session the client holds tokens from
    /// ends (OIDC Back-Channel Logout); HTTPS with a public address.
    #[arg(long)]
    backchannel_logout_uri: Option<RedirectUri>,
}

/// A client a deployment manages, as `client apply` makes it.
#[derive(Args)]
pub(super) struct ApplyClient {
    /// The registration, as `client create` takes it.
    #[command(flatten)]
    client: CreateClient,
    /// A confidential client's secret, at `file://PATH` or `env://NAME`: 32 random
    /// bytes in unpadded base64url, generated by its deployment. Never printed.
    #[arg(long, value_name = "REFERENCE")]
    secret: Option<SecretReference>,
    /// How long earlier secrets keep working once the secret changes, so the
    /// running deployment keeps signing in until it rolls out.
    #[arg(long, default_value = "1h")]
    grace: GracePeriod,
}

impl ApplyClient {
    /// Reads the given secret, if any.
    fn secret(&self) -> Result<Option<ClientSecret>, CliError> {
        self.secret
            .as_ref()
            .map(|reference| {
                ClientSecret::parse(reference.resolve()?.utf8()?).map_err(CliError::WeakSecret)
            })
            .transpose()
    }
}

impl CreateClient {
    /// Checks the counts of the repeated options and builds the registration.
    fn registration(self) -> Result<ClientRegistration, CliError> {
        let scopes = if self.scopes.is_empty() {
            DEFAULT_CLIENT_SCOPES.map(ScopeName::from).into()
        } else {
            self.scopes
        };
        Ok(ClientRegistration {
            id: self.id,
            display_name: self.name,
            kind: if self.confidential {
                ClientKind::Confidential
            } else {
                ClientKind::Public
            },
            redirect_uris: RedirectUris::new(self.redirect_uris)
                .map_err(CliError::count("redirect URIs"))?,
            post_logout_uris: PostLogoutUris::new(self.post_logout_uris)
                .map_err(CliError::count("post-logout URIs"))?,
            allowed_scopes: AllowedScopes::new(scopes).map_err(CliError::count("scopes"))?,
            allow_refresh: self.refresh,
            trusted: self.trusted,
            require_pushed_authorization_requests: self.require_par,
            backchannel_logout_uri: self.backchannel_logout_uri,
        })
    }
}

/// Changes to a client's registration.
#[derive(Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Clap reads each `--x`/`--no-x` option pair into two flags."
)]
pub(super) struct UpdateClient {
    /// The client's ID.
    id: ClientId,
    /// A new name for consent screens.
    #[arg(long)]
    name: Option<DisplayName>,
    /// An authorization callback to add; repeat for several.
    #[arg(long = "add-redirect-uri")]
    add_redirect_uris: Vec<RedirectUri>,
    /// An authorization callback to remove, exactly as registered; repeat for several.
    #[arg(long = "remove-redirect-uri")]
    remove_redirect_uris: Vec<String>,
    /// A post-logout page to add; repeat for several.
    #[arg(long = "add-post-logout-uri")]
    add_post_logout_uris: Vec<RedirectUri>,
    /// A post-logout page to remove, exactly as registered; repeat for several.
    #[arg(long = "remove-post-logout-uri")]
    remove_post_logout_uris: Vec<String>,
    /// Replaces the scopes the client may request; repeat for several.
    #[arg(long = "scope")]
    scopes: Vec<ScopeName>,
    /// Allow refresh tokens.
    #[arg(long, conflicts_with = "no_refresh")]
    refresh: bool,
    /// Stop issuing refresh tokens; existing ones stop working.
    #[arg(long)]
    no_refresh: bool,
    /// Skip the consent screen.
    #[arg(long, conflicts_with = "untrusted")]
    trusted: bool,
    /// Show the consent screen again.
    #[arg(long)]
    untrusted: bool,
    /// Require pushed authorization requests.
    #[arg(long, conflicts_with = "no_require_par")]
    require_par: bool,
    /// Accept authorization requests sent through the browser again.
    #[arg(long)]
    no_require_par: bool,
    /// Post logout tokens to this URI instead.
    #[arg(long, conflicts_with = "no_backchannel_logout_uri")]
    backchannel_logout_uri: Option<RedirectUri>,
    /// Stop posting logout tokens to the client.
    #[arg(long)]
    no_backchannel_logout_uri: bool,
}

impl UpdateClient {
    /// Applies the changes to `client`'s stored registration, which must still be
    /// valid where it is kept.
    fn apply(self, client: &StoredOidcClient) -> Result<ClientRegistration, CliError> {
        let scopes = if self.scopes.is_empty() {
            client
                .allowed_scopes
                .iter()
                .map(|scope| scope.parse())
                .collect::<Result<_, _>>()?
        } else {
            self.scopes
        };
        Ok(ClientRegistration {
            display_name: self.name.map_or_else(|| client.display_name.parse(), Ok)?,
            kind: client.kind,
            redirect_uris: RedirectUris::new(Self::edit(
                &client.redirect_uris,
                &self.remove_redirect_uris,
                self.add_redirect_uris,
            )?)
            .map_err(CliError::count("redirect URIs"))?,
            post_logout_uris: PostLogoutUris::new(Self::edit(
                &client.post_logout_uris,
                &self.remove_post_logout_uris,
                self.add_post_logout_uris,
            )?)
            .map_err(CliError::count("post-logout URIs"))?,
            allowed_scopes: AllowedScopes::new(scopes).map_err(CliError::count("scopes"))?,
            allow_refresh: self.refresh || (client.allow_refresh && !self.no_refresh),
            trusted: self.trusted || (client.trusted && !self.untrusted),
            require_pushed_authorization_requests: self.require_par
                || (client.require_pushed_authorization_requests && !self.no_require_par),
            backchannel_logout_uri: match self.backchannel_logout_uri {
                Some(uri) => Some(uri),
                None if self.no_backchannel_logout_uri => None,
                None => client
                    .backchannel_logout_uri
                    .as_deref()
                    .map(str::parse)
                    .transpose()?,
            },
            id: client.id.clone(),
        })
    }

    /// Removes `remove` from the `stored` URIs as written, so one registered under
    /// older rules can still be removed, then adds `add`.
    fn edit(
        stored: &[String],
        remove: &[String],
        add: Vec<RedirectUri>,
    ) -> Result<Vec<RedirectUri>, CliError> {
        if let Some(missing) = remove.iter().find(|uri| !stored.contains(uri)) {
            return Err(CliError::NotRegistered(missing.clone()));
        }
        let kept = stored
            .iter()
            .filter(|uri| !remove.contains(uri))
            .map(|uri| uri.parse())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(kept.into_iter().chain(add).collect())
    }
}
