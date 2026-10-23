//! Authentication service and its administrative CLI.
use auth_service::{
    AdminError, AdminOperations, Applied, AuthConfig, ClientDetails, ClientRegistry,
    ClientRegistryError, DEFAULT_CLIENT_SCOPES, GracePeriod, InviteExpiry, Jobs, Operator,
    PUBLIC_BASE_URL, SERVICE_NAME, TELEMETRY_FILTER,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use piquel_common::{
    ClientId, DeliveryId, ErrorChain, Handle,
    clients::{
        AllowedScopes, ClientKind, ClientOwner, ClientRegistration, DisplayName, InvalidCount,
        InvalidDisplayName, InvalidRedirectUri, InvalidScopeName, PostLogoutUris, RedirectUri,
        RedirectUris, ScopeName,
    },
    config::{ConfigurationError, SecretError, SecretReference, Variable},
};
use piquel_crypto::{ClientSecret, CryptoError};
use piquel_repository::{
    Database, DatabaseConnectionError, DatabaseError, DatabaseTransaction, DeliveryStatus,
    StoredOidcClient,
};
use piquel_telemetry::{Telemetry, TelemetryError};
use thiserror::Error;

use axum::Router;
use std::{net::SocketAddr, process::ExitCode};
use tokio::{net::TcpListener, sync::watch};

/// The operating system user running a command, recorded on the events it causes.
const OS_USER: Variable = Variable::new("USER");
/// The machine's host name, for systems without `/proc`.
const HOST_NAME: Variable = Variable::new("HOSTNAME");
/// Where Linux exposes the host name.
const HOST_NAME_FILE: &str = "/proc/sys/kernel/hostname";
/// Recorded when the operator's user or host name cannot be read.
const UNKNOWN_OPERATOR: &str = "unknown";

/// Failures of startup and administrative commands, preserving their original causes.
#[derive(Debug, Error)]
enum CliError {
    /// A required operator setting is missing or invalid.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    /// The authentication database could not be connected.
    #[error("could not connect to authentication database")]
    Connection(#[from] DatabaseConnectionError),
    /// An administrative database operation failed.
    #[error("authentication database command failed")]
    Database(#[from] DatabaseError),
    /// No delivery with this ID is in a state the command applies to.
    #[error("no {states} delivery has ID {id}")]
    NoSuchDelivery {
        /// The requested delivery.
        id: DeliveryId,
        /// The states the command applies to.
        states: &'static str,
    },
    /// An administrative operation was refused or failed.
    #[error(transparent)]
    Admin(#[from] AdminError),
    /// A client change was refused.
    #[error(transparent)]
    Client(#[from] ClientRegistryError),
    /// A display name, given or stored, is invalid.
    #[error(transparent)]
    DisplayName(#[from] InvalidDisplayName),
    /// A redirect URI, given or stored, is invalid.
    #[error(transparent)]
    RedirectUri(#[from] InvalidRedirectUri),
    /// A scope, given or stored, is invalid.
    #[error(transparent)]
    Scope(#[from] InvalidScopeName),
    /// A registration list has too few or too many values.
    #[error("invalid {field}")]
    Count {
        /// The list, e.g. `redirect URIs`.
        field: &'static str,
        /// The allowed and given counts.
        #[source]
        source: InvalidCount,
    },
    /// The secret given with `--secret` could not be read.
    #[error("could not read the client secret given with --secret")]
    SecretUnreadable(#[from] SecretError),
    /// The secret given with `--secret` is not 256 random bits in base64url.
    #[error("the client secret given with --secret must be 32 bytes in unpadded base64url")]
    WeakSecret(#[source] CryptoError),
    /// A URI to remove is not registered.
    #[error("{0} is not registered for this client")]
    NotRegistered(String),
    /// Command output could not be encoded.
    #[error("could not encode JSON output")]
    Json(#[from] serde_json::Error),
    /// HTTP applications or embedded assets could not be initialized.
    #[error(transparent)]
    Startup(#[from] auth_service::StartupError),
    /// The service listener could not be bound or served.
    #[error("authentication HTTP listener failed")]
    Listener(#[from] std::io::Error),
    /// A background job panicked.
    #[error("a background job panicked")]
    Job(#[from] tokio::task::JoinError),
    /// Telemetry could not be installed.
    #[error(transparent)]
    Telemetry(#[from] TelemetryError),
}

impl CliError {
    /// Names the registration list, e.g. `redirect URIs`, whose count was out of bounds.
    fn count(field: &'static str) -> impl FnOnce(InvalidCount) -> Self {
        move |source| Self::Count { field, source }
    }
}

/// Piquel authentication service. Runs `serve` when no command is given.
#[derive(Parser)]
#[command(
    after_help = "Every command uses AUTH_DATABASE_URL, except migrate when AUTH_DATABASE_OWNER_URL is \
                  set. See README.md for configuration."
)]
struct Cli {
    /// Defaults to serving when no administrative command is supplied.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Commands, each of which connects to the database first.
#[derive(Subcommand)]
enum Command {
    /// Serve the authentication service.
    Serve,
    /// Apply database migrations. Connected as the schema owner, also create or
    /// reset the role other commands connect as.
    Migrate,
    /// Print a single-use signup link.
    Invite {
        /// How long the link stays valid, in hours or days (e.g. 24h, 7d).
        #[arg(long, default_value = "7d")]
        expires_in: InviteExpiry,
    },
    /// Register, inspect and change OIDC clients. Changes apply to the next request.
    #[command(subcommand)]
    Client(ClientCommand),
    /// Inspect, retry and cancel outbound deliveries.
    #[command(subcommand)]
    Deliveries(DeliveriesCommand),
    /// Grant, revoke or list administrators.
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Check accounts against the handle rules, and change their handles.
    #[command(subcommand)]
    Handle(HandleCommand),
}

/// Handle checks and changes. The CLI may act on any account.
#[derive(Subcommand)]
enum HandleCommand {
    /// List accounts whose handle is reserved.
    Check,
    /// Give an account a new handle, without the settings cooldown, and record the
    /// change.
    Rename {
        /// The account's current handle.
        #[arg(value_parser = Handle::parse)]
        handle: Handle,
        /// Its new handle.
        #[arg(value_parser = Handle::parse)]
        new: Handle,
        /// Allow a reserved name, or one that looks like it.
        #[arg(long)]
        allow_reserved: bool,
    },
    /// Delete a released handle, so anyone may claim it again, e.g. after a
    /// trademark dispute. A current handle is never released: rename its account
    /// first.
    Release {
        /// The released handle.
        #[arg(value_parser = Handle::parse)]
        handle: Handle,
    },
}

impl HandleCommand {
    /// Runs the check, or the change as the operator at this terminal.
    async fn run(self, admin: &AdminOperations) -> Result<(), CliError> {
        match self {
            Self::Check => {
                for problem in admin.check_handles().await? {
                    println!("{}\t{}\t{}", problem.handle, problem.user_id, problem.error);
                }
            }
            Self::Rename {
                handle,
                new,
                allow_reserved,
            } => {
                let user = admin.user_named(&handle).await?;
                admin
                    .rename_handle(&Command::operator()?, user, new, allow_reserved)
                    .await?;
            }
            Self::Release { handle } => {
                admin.release_handle(&Command::operator()?, handle).await?;
            }
        }
        Ok(())
    }
}

/// Changes to the administrator list. The CLI may act on any account, and is how
/// the first administrator is granted.
#[derive(Subcommand)]
enum AdminCommand {
    /// Make an active account an administrator.
    Grant {
        /// The account's handle.
        #[arg(value_parser = Handle::parse)]
        handle: Handle,
    },
    /// Remove an account's administrator rights. The last administrator keeps theirs.
    Revoke {
        /// The account's handle.
        #[arg(value_parser = Handle::parse)]
        handle: Handle,
    },
    /// List administrators, oldest grant first.
    List,
}

impl AdminCommand {
    /// Runs the change as the operator at this terminal.
    async fn run(self, admin: &AdminOperations) -> Result<(), CliError> {
        let operator = Command::operator()?;
        match self {
            Self::Grant { handle } => {
                let user = admin.user_named(&handle).await?;
                admin.grant_administrator(&operator, user).await?;
            }
            Self::Revoke { handle } => {
                let user = admin.user_named(&handle).await?;
                admin.revoke_administrator(&operator, user).await?;
            }
            Self::List => {
                for administrator in admin.list_administrators().await? {
                    println!(
                        "{}\t{}\t{}",
                        administrator.handle,
                        administrator.user_id,
                        administrator.granted_at.to_rfc3339()
                    );
                }
            }
        }
        Ok(())
    }
}

impl Command {
    /// Executes this command and returns the original startup or operation failure.
    async fn run(self) -> Result<(), CliError> {
        // `migrate` connects as the schema owner when one is configured, then
        // provisions the role every other command connects as.
        let (config, runtime_role) = match self {
            Self::Migrate => AuthConfig::migration_from_environment()?,
            _ => (AuthConfig::database_from_environment()?, None),
        };
        let database = Database::connect(config).await?;
        match self {
            Self::Serve => Self::serve(database).await,
            Self::Migrate => {
                database.run_migrations().await?;
                if let Some(role) = runtime_role {
                    database.provision(&role).await?;
                }
                Ok(())
            }
            Self::Invite { expires_in } => {
                // Only the secret's digest is stored, so the link is printed once.
                let invitation = AdminOperations::new(database)
                    .create_invitation(&Self::operator()?, &PUBLIC_BASE_URL.parse()?, expires_in)
                    .await?;
                println!("{}", invitation.url);
                Ok(())
            }
            Self::Client(command) => command.run(database).await,
            Self::Deliveries(command) => command.run(&database).await,
            // Grant, revoke and list need only the database, for a bare recovery shell.
            Self::Admin(command) => command.run(&AdminOperations::new(database)).await,
            Self::Handle(command) => command.run(&AdminOperations::new(database)).await,
        }
    }

    /// The operator running a command: `$USER` and the host name, or `unknown` where
    /// they cannot be read, as in some containers.
    fn operator() -> Result<Operator, CliError> {
        let host = std::fs::read_to_string(HOST_NAME_FILE)
            .ok()
            .map(|host| host.trim().to_owned())
            .or(HOST_NAME.optional()?)
            .filter(|host| !host.is_empty());
        Ok(Operator::Cli {
            os_user: OS_USER
                .optional()?
                .unwrap_or_else(|| UNKNOWN_OPERATOR.to_owned()),
            host: host.unwrap_or_else(|| UNKNOWN_OPERATOR.to_owned()),
        })
    }

    /// Resolves on Ctrl+C or SIGTERM, the signal container runtimes send on stop.
    async fn shutdown_signal() {
        use tokio::signal::unix::{SignalKind, signal};
        let ctrl_c = async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(?error, "Ctrl+C handler unavailable");
                std::future::pending::<()>().await;
            }
        };
        let terminate = async {
            match signal(SignalKind::terminate()) {
                Ok(mut terminate) => {
                    terminate.recv().await;
                }
                Err(error) => {
                    tracing::error!(?error, "SIGTERM handler unavailable");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            () = ctrl_c => {}
            () = terminate => {}
        }
        tracing::info!("shutting down");
    }

    /// Builds the configured service, starts background jobs and
    /// serves the public listener, and the admin listener when one is configured,
    /// until a shutdown signal. Once in-flight requests drain, running jobs get a
    /// grace period to finish.
    async fn serve(database: Database) -> Result<(), CliError> {
        let config = AuthConfig::from_environment()?;
        let public = TcpListener::bind(config.public_listener).await?;
        let admin = match config.admin_listener {
            Some(address) => Some(TcpListener::bind(address).await?),
            None => None,
        };
        let router = config.router(database.clone())?;
        let admin_router = config.admin_router(database.clone());
        database.observe_connections();
        let jobs = Jobs::start(&database);
        tracing::info!(address=%config.public_listener,"authentication service listening");
        let (stop, _) = watch::channel(false);
        let admin = async {
            let Some(listener) = admin else {
                return Ok(());
            };
            tracing::info!(address=%listener.local_addr()?, "admin API listening");
            Self::listen(listener, admin_router, &stop).await
        };
        let signal = async {
            let mut stopped = stop.subscribe();
            tokio::select! {
                () = Self::shutdown_signal() => {
                    stop.send_replace(true);
                }
                _ = stopped.wait_for(|stopped| *stopped) => {}
            }
        };
        let (public, admin, ()) = tokio::join!(Self::listen(public, router, &stop), admin, signal);
        let jobs = jobs.shutdown().await;
        public?;
        admin?;
        Ok(jobs?)
    }

    /// Serves `router` on `listener` until `stop` is set. Once this listener ends,
    /// whatever the reason, it sets `stop`, so the other listener ends too.
    async fn listen(
        listener: TcpListener,
        router: Router,
        stop: &watch::Sender<bool>,
    ) -> std::io::Result<()> {
        let mut stopped = stop.subscribe();
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            // Fails only once `stop` is dropped, which also means stopping.
            let _ = stopped.wait_for(|stopped| *stopped).await;
        })
        .await;
        stop.send_replace(true);
        result
    }
}

/// Registering, inspecting and changing OIDC clients, through [`ClientRegistry`].
#[derive(Subcommand)]
enum ClientCommand {
    /// Register a client. A confidential client's secret is printed once.
    Create(CreateClient),
    /// Register a client, or update it to match, with the secret its deployment
    /// generated: for clients a deployment manages, such as the admin dashboard.
    /// Records nothing when the client already matches.
    Apply(ApplyClient),
    /// List every client.
    List {
        /// A table for people, or JSON for scripts.
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
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
    },
    /// Delete a client: it stops working at once, its refresh tokens, secrets and
    /// consents go, and its ID can never be registered again.
    Delete {
        /// The client's ID.
        id: ClientId,
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

/// How `client list` prints clients.
#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// One tab-separated line per client.
    Table,
    /// A JSON array of registrations.
    Json,
}

impl ClientCommand {
    /// Runs this command on `database` in one transaction, recording changes as
    /// made by the operator. What a change prints is printed only once it
    /// committed, so a script never captures a secret that was not stored.
    async fn run(self, database: Database) -> Result<(), CliError> {
        let mut tx = database.begin().await?;
        let mut registry = ClientRegistry::new(&mut tx, Command::operator()?.context());
        let done = match self {
            Self::Create(create) => ClientChange::Secret(
                registry
                    .create(ClientOwner::Operator, &create.registration()?, None)
                    .await?,
            ),
            Self::Apply(apply) => {
                let secret = apply.secret()?;
                let id = apply.client.id.clone();
                let applied = registry
                    .apply(&apply.client.registration()?, secret, apply.grace)
                    .await?;
                ClientChange::Applied(id, applied)
            }
            Self::List { output } => {
                let clients = tx.oidc().list_clients().await?;
                match output {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&clients)?),
                    OutputFormat::Table => {
                        println!("ID\tTYPE\tSTATUS\tREFRESH\tTRUSTED\tPAR\tNAME");
                        for client in clients {
                            println!(
                                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                                client.id,
                                client.kind,
                                match (client.deleted_at, client.suspended_at, client.enabled) {
                                    (Some(_), _, _) => "deleted",
                                    (None, Some(_), _) => "suspended",
                                    (None, None, true) => "enabled",
                                    (None, None, false) => "disabled",
                                },
                                client.allow_refresh,
                                client.trusted,
                                client.require_pushed_authorization_requests,
                                client.display_name,
                            );
                        }
                    }
                }
                ClientChange::Silent
            }
            Self::Show { id } => {
                let details = ClientDetails {
                    client: Self::find(&mut tx, &id).await?,
                    secrets: tx.oidc().client_secrets(&id).await?,
                };
                println!("{}", serde_json::to_string_pretty(&details)?);
                ClientChange::Silent
            }
            Self::Update(update) => {
                let id = update.id.clone();
                registry.update(&id, |client| update.apply(client)).await?;
                ClientChange::Silent
            }
            Self::Disable { id } => {
                registry.set_enabled(&id, false).await?;
                ClientChange::Silent
            }
            Self::Enable { id } => {
                registry.set_enabled(&id, true).await?;
                ClientChange::Silent
            }
            Self::Suspend { id } => {
                registry.set_suspended(&id, true).await?;
                ClientChange::Silent
            }
            Self::Unsuspend { id } => {
                registry.set_suspended(&id, false).await?;
                ClientChange::Silent
            }
            Self::Delete { id } => {
                registry.delete(&id).await?;
                ClientChange::Silent
            }
            Self::RotateSecret { id, grace } => {
                ClientChange::Secret(Some(registry.rotate_secret(&id, grace).await?))
            }
        };
        tx.commit().await?;
        done.print();
        Ok(())
    }

    /// The registered client `id`.
    async fn find(
        tx: &mut DatabaseTransaction<'_>,
        id: &ClientId,
    ) -> Result<StoredOidcClient, CliError> {
        tx.oidc()
            .find_client(id.as_str())
            .await?
            .ok_or_else(|| ClientRegistryError::Unknown(id.clone()).into())
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
struct CreateClient {
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
}

/// A client a deployment manages, as `client apply` makes it.
#[derive(Args)]
struct ApplyClient {
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
        })
    }
}

/// Changes to a client's registration.
#[derive(Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Clap reads each `--x`/`--no-x` option pair into two flags."
)]
struct UpdateClient {
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

/// The break-glass view of the outbound delivery queue.
#[derive(Subcommand)]
enum DeliveriesCommand {
    /// List deliveries, newest first.
    List {
        /// Only deliveries with this status: pending, succeeded, failed or cancelled.
        #[arg(long)]
        status: Option<DeliveryStatus>,
        /// Only deliveries on this channel.
        #[arg(long)]
        channel: Option<String>,
        /// The most deliveries to list.
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Attempt a failed delivery, or a cancelled unordered one, again now.
    Retry {
        /// The delivery's ID.
        id: DeliveryId,
    },
    /// Cancel a pending or failed delivery, which unblocks the deliveries ordered after it.
    Cancel {
        /// The delivery's ID.
        id: DeliveryId,
    },
}

impl DeliveriesCommand {
    /// Runs this command on `database`.
    async fn run(self, database: &Database) -> Result<(), CliError> {
        let (id, states, result) = match self {
            Self::List {
                status,
                channel,
                limit,
            } => {
                let deliveries = database
                    .deliveries()
                    .list(status, channel.as_deref(), limit)
                    .await?;
                println!(
                    "ID\tCHANNEL\tSTATUS\tATTEMPTS\tORDER\tDUE OR FINISHED\tLAST ERROR\tDESTINATION"
                );
                for delivery in deliveries {
                    let order = delivery.ordering.map_or_else(
                        || "-".to_owned(),
                        |(key, ordinal)| format!("{key}#{ordinal}"),
                    );
                    println!(
                        "{}\t{}\t{}\t{}\t{order}\t{}\t{}\t{}",
                        delivery.id,
                        delivery.channel,
                        delivery.status,
                        delivery.attempts,
                        delivery.finished_at.unwrap_or(delivery.next_attempt_at),
                        delivery.last_error.as_deref().unwrap_or("-"),
                        delivery.destination,
                    );
                }
                return Ok(());
            }
            Self::Retry { id } => (
                id,
                "failed or cancelled unordered",
                database.deliveries().retry(id).await,
            ),
            Self::Cancel { id } => (
                id,
                "pending or failed",
                database.deliveries().cancel(id).await,
            ),
        };
        match result {
            Err(DatabaseError::NotFound) => Err(CliError::NoSuchDelivery { id, states }),
            result => Ok(result?),
        }
    }
}

impl Cli {
    /// Installs telemetry, runs the selected command, then flushes telemetry. A
    /// failed flush, such as an unreachable collector, is only reported: it must
    /// not fail a command, such as a deploy's migration job.
    async fn run(self) -> Result<(), CliError> {
        let telemetry = Telemetry::init(SERVICE_NAME, TELEMETRY_FILTER)?;
        let result = self.command.unwrap_or(Command::Serve).run().await;
        if let Err(error) = telemetry.shutdown().await {
            eprintln!("warning: {}", ErrorChain(&error));
        }
        result
    }
}

/// Runs the selected command and prints any failure with its causes.
#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {}", ErrorChain(&error));
            ExitCode::FAILURE
        }
    }
}
