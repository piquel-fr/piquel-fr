//! Registering, inspecting and changing OIDC clients.

use super::{
    CliError, Confirm, Console,
    output::{Cell, Joined, Single, Style, report},
};
use crate::{Applied, ClientDetails, GracePeriod, PUBLIC_BASE_URL, Reason};
use clap::{Args, Subcommand};
use sourceorigin_common::{
    ClientId,
    admin::{ApprovedOrigin, Client},
    clients::{
        AllowedScopes, BackchannelLogoutUri, ClientKind, ClientRegistration, DisplayName,
        PostLogoutUris, RedirectUri, RedirectUris, RelatedOrigin, ScopeName,
    },
    config::{Origin, SecretReference},
};
use sourceorigin_crypto::ClientSecret;
use sourceorigin_repository::StoredOidcClient;

/// Registering, inspecting and changing OIDC clients.
#[derive(Subcommand)]
pub(super) enum ClientCommand {
    /// Register a client. A confidential client's secret is printed once.
    Create(CreateClient),
    /// Register a client, or update it to match, with the secret its deployment
    /// generated: for clients a deployment manages, from its deployment job.
    /// Records nothing when the client already matches.
    Apply(ApplyClient),
    /// List every client, deleted ones included.
    List,
    /// Show a client's registration and its secrets' lifetimes.
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
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Delete a client: it stops working at once, its refresh tokens, secrets and
    /// consents go, and its ID can never be registered again.
    Delete {
        /// The client's ID.
        id: ClientId,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Let a disabled client work again.
    Enable {
        /// The client's ID.
        id: ClientId,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
    /// Block a client: it is disabled, and its owner cannot enable it again
    /// until `unsuspend`.
    Suspend {
        /// The client's ID.
        id: ClientId,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Lift a client's suspension. It stays disabled until enabled.
    Unsuspend {
        /// The client's ID.
        id: ClientId,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
    /// Print a new secret for a confidential client. Earlier secrets keep working
    /// during the grace period, while the client switches to the new one.
    RotateSecret {
        /// The client's ID.
        id: ClientId,
        /// How long earlier secrets keep working, e.g. 30m, 24h or 7d; 0 revokes them
        /// now, which asks first.
        #[arg(long, default_value = "24h")]
        grace: GracePeriod,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation, which `--grace 0` needs.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Approve, remove or list the origins whose pages may sign users in with
    /// their passkeys, without sending them to auth's pages.
    #[command(subcommand)]
    Origin(OriginCommand),
}

/// The origins approved for a client's pages to sign users in with passkeys,
/// which `/.well-known/webauthn` lists as `WebAuthn` related origins.
#[derive(Subcommand)]
pub(super) enum OriginCommand {
    /// Approve an origin. The client must be trusted and have a redirect URI on it,
    /// and approved origins may span at most 5 domains, as browsers honour.
    Add {
        /// The client's ID.
        id: ClientId,
        /// The origin, as browsers send it, e.g. `https://notes.example`.
        origin: RelatedOrigin,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
    /// Remove an origin: its pages stop signing users in.
    Remove {
        /// The client's ID.
        id: ClientId,
        /// The origin, as approved.
        origin: RelatedOrigin,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
    /// List every approved origin.
    List,
}

impl OriginCommand {
    /// Runs this command as the operator at this terminal.
    async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service,
            operator,
            out,
            ..
        } = console;
        match self {
            Self::Add { id, origin, reason } => {
                // Tells hosts within auth's own domain, which browsers accept without the
                // list, from public suffixes.
                let auth: Origin = PUBLIC_BASE_URL.parse()?;
                service
                    .approve_related_origin(operator, &id, &origin, auth.host(), reason)
                    .await?;
                out.info(format_args!("Approved {origin} for client {id}."))
            }
            Self::Remove { id, origin, reason } => {
                service
                    .remove_related_origin(operator, &id, &origin, reason)
                    .await?;
                out.info(format_args!("Removed {origin} from client {id}."))
            }
            Self::List => out.emit(&service.list_related_origins(operator).await?[..]),
        }
    }
}

impl ClientCommand {
    /// Runs this command as the operator at this terminal. Each change commits
    /// with its event before anything is printed, so a script never captures a
    /// secret that was not stored.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service,
            operator,
            out,
            ..
        } = console;
        match self {
            Self::Create(create) => {
                let (id, reason) = (create.id.clone(), create.reason.clone());
                let secret = service
                    .create_client(operator, &create.registration()?, reason)
                    .await?;
                match secret {
                    Some(secret) => Self::secret(console, &secret),
                    None => out.info(format_args!("Registered client {id}.")),
                }
            }
            Self::Apply(apply) => apply.run(console).await,
            Self::List => out.emit(&service.list_clients(operator).await?[..]),
            Self::Show { id } => out.emit(&service.client_details(operator, &id).await?),
            Self::Update(update) => {
                let (id, reason) = (update.id.clone(), update.reason.clone());
                service
                    .update_client(operator, &id, reason, |client| update.apply(client))
                    .await?;
                out.info(format_args!("Updated client {id}."))
            }
            Self::Disable {
                id,
                reason,
                confirm,
            } => {
                confirm.ask(
                    out,
                    &format!("Disable client {id}: it stops working at once"),
                )?;
                service
                    .set_client_enabled(operator, &id, false, reason)
                    .await?;
                out.info(format_args!("Disabled client {id}."))
            }
            Self::Enable { id, reason } => {
                service
                    .set_client_enabled(operator, &id, true, reason)
                    .await?;
                out.info(format_args!("Enabled client {id}."))
            }
            Self::Suspend {
                id,
                reason,
                confirm,
            } => {
                confirm.ask(
                    out,
                    &format!(
                        "Suspend client {id}: it stops working, and its owner cannot enable it"
                    ),
                )?;
                service
                    .set_client_suspended(operator, &id, true, reason)
                    .await?;
                out.info(format_args!("Suspended client {id}."))
            }
            Self::Unsuspend { id, reason } => {
                service
                    .set_client_suspended(operator, &id, false, reason)
                    .await?;
                out.info(format_args!(
                    "Lifted the suspension of client {id}: it stays disabled until enabled."
                ))
            }
            Self::Delete {
                id,
                reason,
                confirm,
            } => {
                confirm.ask(
                    out,
                    &format!(
                        "Delete client {id}: it stops working at once, and its ID can never be reused"
                    ),
                )?;
                service.delete_client(operator, &id, reason).await?;
                out.info(format_args!("Deleted client {id}."))
            }
            Self::RotateSecret {
                id,
                grace,
                reason,
                confirm,
            } => Self::rotate_secret(console, &id, grace, reason, &confirm).await,
            Self::Origin(command) => command.run(console).await,
        }
    }

    /// Gives client `id` a new secret for `reason`, earlier ones working for
    /// `grace`, once confirmed when `grace` revokes them at once.
    async fn rotate_secret(
        console: &Console,
        id: &ClientId,
        grace: GracePeriod,
        reason: Reason,
        confirm: &Confirm,
    ) -> Result<(), CliError> {
        if grace.duration().is_zero() {
            confirm.ask(
                &console.out,
                &format!(
                    "Rotate client {id}'s secret and revoke every earlier one now: the client stops signing users in until it uses the new one"
                ),
            )?;
        }
        let secret = console
            .service
            .rotate_client_secret(&console.operator, id, grace, reason)
            .await?;
        Self::secret(console, &secret)
    }

    /// Prints a new secret alone on standard output, so scripts can capture it,
    /// and that it is shown only this once.
    fn secret(console: &Console, secret: &ClientSecret) -> Result<(), CliError> {
        console.out.emit(&Single {
            name: "secret",
            value: secret.expose(),
        })?;
        console
            .out
            .warning("Store this client secret now: it cannot be shown again.")
    }

    /// A client's status, coloured: `deleted`, `suspended`, `disabled` or
    /// `enabled`. Deletion comes first, then a suspension.
    fn status(deleted: bool, suspended: bool, enabled: bool) -> Cell {
        match (deleted, suspended, enabled) {
            (true, _, _) => Cell::new("deleted").style(Style::Muted),
            (false, true, _) => Cell::new("suspended").style(Style::Bad),
            (false, false, false) => Cell::new("disabled").style(Style::Notice),
            (false, false, true) => Cell::new("enabled").style(Style::Good),
        }
    }
}

// One client per line.
report!([Client], self, out, {
    out.table(
        [
            "ID", "AUTH", "STATUS", "REFRESH", "TRUSTED", "PAR", "OWNER", "NAME",
        ],
        "No clients.",
        self.iter().map(|client| {
            [
                Cell::new(&client.id),
                Cell::new(client.token_endpoint_auth_method),
                ClientCommand::status(
                    client.deleted_at.is_some(),
                    client.suspended_at.is_some(),
                    client.enabled,
                ),
                client.allow_refresh.into(),
                client.trusted.into(),
                client.require_pushed_authorization_requests.into(),
                client
                    .owner_id
                    .map_or_else(|| Cell::new("operator").style(Style::Muted), Cell::new),
                Cell::new(&client.display_name),
            ]
        }),
    )
});

// A client's registration, then its secrets, never their values.
report!(ClientDetails, self, out, {
    let client = &self.client;
    out.title(format_args!("{} ({})", client.display_name, client.id))?;
    let list = |items: &[String]| {
        if items.is_empty() {
            Cell::none()
        } else {
            Cell::new(Joined(items, ", "))
        }
    };
    out.fields(&[
        ("Kind", Cell::new(client.kind)),
        (
            "Status",
            ClientCommand::status(
                client.deleted_at.is_some(),
                client.suspended_at.is_some(),
                client.enabled,
            ),
        ),
        (
            "Owner",
            client
                .owner_id
                .map_or_else(|| Cell::new("operator").style(Style::Muted), Cell::new),
        ),
        ("Redirect URIs", list(&client.redirect_uris)),
        ("Post-logout URIs", list(&client.post_logout_uris)),
        ("Scopes", list(&client.allowed_scopes)),
        ("Refresh tokens", client.allow_refresh.into()),
        ("Trusted", client.trusted.into()),
        (
            "Requires PAR",
            client.require_pushed_authorization_requests.into(),
        ),
        (
            "Back-channel logout",
            client.backchannel_logout_uri.as_deref().into(),
        ),
        ("Created", client.created_at.into()),
        ("Updated", client.updated_at.into()),
        ("Last used", client.last_used_at.into()),
        ("Suspended", client.suspended_at.into()),
        ("Deleted", client.deleted_at.into()),
    ])?;
    out.section("Secrets")?;
    out.table(
        ["ID", "CREATED", "EXPIRES"],
        "No secrets.",
        self.secrets.iter().map(|secret| {
            [
                Cell::new(secret.id),
                secret.created_at.into(),
                secret.expires_at.into(),
            ]
        }),
    )
});

// One approved origin per line, with its client.
report!([ApprovedOrigin], self, out, {
    out.table(
        ["ORIGIN", "CLIENT", "APPROVED"],
        "No approved origins.",
        self.iter().map(|approved| {
            [
                Cell::new(&approved.origin),
                Cell::new(&approved.client_id),
                approved.approved_at.into(),
            ]
        }),
    )
});

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
    /// A scope the client may request; repeat for several. Defaults to `openid`,
    /// `profile` and `email`, and `offline_access` for a confidential client.
    #[arg(long = "scope")]
    scopes: Vec<ScopeName>,
    /// The client runs on a server and authenticates with a secret.
    #[arg(long)]
    confidential: bool,
    /// The client may receive refresh tokens when it requests `offline_access`.
    /// The default for a confidential client.
    #[arg(long, conflicts_with = "no_refresh")]
    refresh: bool,
    /// The client receives no refresh tokens. The default for a public client.
    #[arg(long)]
    no_refresh: bool,
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
    backchannel_logout_uri: Option<BackchannelLogoutUri>,
    /// Why, recorded with the change: 1 to 500 characters.
    #[arg(long)]
    reason: Reason,
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
    /// Registers the client, or updates it to match, as the operator at this
    /// terminal, and says which it did.
    async fn run(self, console: &Console) -> Result<(), CliError> {
        let secret = self.secret()?;
        let id = self.client.id.clone();
        let reason = self.client.reason.clone();
        let registration = self.client.registration()?;
        let applied = console
            .service
            .apply_client(&console.operator, &registration, secret, self.grace, reason)
            .await?;
        let applied = match applied {
            Applied::Registered => "registered",
            Applied::Updated => "updated",
            Applied::Unchanged => "unchanged",
        };
        console.out.info(format_args!("Client {id}: {applied}."))
    }

    /// Reads the given secret, if any.
    fn secret(&self) -> Result<Option<ClientSecret>, CliError> {
        self.secret
            .as_ref()
            .map(|reference| {
                ClientSecret::parse(reference.resolve()?.text()?).map_err(CliError::WeakSecret)
            })
            .transpose()
    }
}

impl CreateClient {
    /// Checks the counts of the repeated options and builds the registration.
    fn registration(self) -> Result<ClientRegistration, CliError> {
        let kind = if self.confidential {
            ClientKind::Confidential
        } else {
            ClientKind::Public
        };
        let scopes = if self.scopes.is_empty() {
            kind.default_scopes()
                .iter()
                .copied()
                .map(ScopeName::from)
                .collect()
        } else {
            self.scopes
        };
        Ok(ClientRegistration {
            id: self.id,
            display_name: self.name,
            kind,
            redirect_uris: RedirectUris::new(self.redirect_uris)
                .map_err(CliError::count("redirect URIs"))?,
            post_logout_uris: PostLogoutUris::new(self.post_logout_uris)
                .map_err(CliError::count("post-logout URIs"))?,
            allowed_scopes: AllowedScopes::new(scopes).map_err(CliError::count("scopes"))?,
            allow_refresh: self.refresh || (kind.default_refresh() && !self.no_refresh),
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
    backchannel_logout_uri: Option<BackchannelLogoutUri>,
    /// Stop posting logout tokens to the client.
    #[arg(long)]
    no_backchannel_logout_uri: bool,
    /// Why, recorded with the change: 1 to 500 characters.
    #[arg(long)]
    reason: Reason,
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
