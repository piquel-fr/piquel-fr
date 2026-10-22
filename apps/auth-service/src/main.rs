//! Authentication service and its administrative CLI.
use auth_service::{
    AdminError, AdminOperations, Applied, AuditChain, AuditConfig, AuditError, AuditKeys,
    AuthConfig, ClientRegistry, ClientRegistryError, GracePeriod, InviteExpiry, Jobs, Operator,
    PUBLIC_BASE_URL,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use piquel_admin_api::{AuditVerification, ChainPoint};
use piquel_common::{
    ClientId, DeliveryId, ErrorChain,
    clients::{
        AllowedScopes, ClientKind, ClientRegistration, DisplayName, InvalidCount,
        InvalidDisplayName, InvalidRedirectUri, InvalidScopeName, PostLogoutUris, RedirectUri,
        RedirectUris, ScopeName,
    },
    config::{ConfigurationError, SecretError, SecretReference, Variable},
    protocol::oauth::Scope,
};
use piquel_crypto::{ClientSecret, CryptoError};
use piquel_repository::{
    Database, DatabaseConnectionError, DatabaseError, DeliveryStatus, StoredClientSecret,
    StoredOidcClient,
};
use serde::Serialize;
use thiserror::Error;

use axum::Router;
use std::{net::SocketAddr, path::PathBuf, process::ExitCode};
use tokio::{net::TcpListener, sync::watch};

/// The operating system user running a command, recorded on the events it causes.
const OS_USER: Variable = Variable::new("USER");
/// The machine's host name, for systems without `/proc`.
const HOST_NAME: Variable = Variable::new("HOSTNAME");
/// Where Linux exposes the host name.
const HOST_NAME_FILE: &str = "/proc/sys/kernel/hostname";
/// Recorded when the operator's user or host name cannot be read.
const UNKNOWN_OPERATOR: &str = "unknown";
/// Scopes a new client may request when `--scope` is not given.
const DEFAULT_CLIENT_SCOPES: [Scope; 3] = [Scope::OpenId, Scope::Profile, Scope::Email];

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
    /// The audit chain is broken, or could not be verified or pruned.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// The file given with `--key` could not be read.
    #[error("could not read the verifier keys given with --key")]
    KeyFile(#[source] std::io::Error),
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
}

impl CliError {
    /// Names the registration list, e.g. `redirect URIs`, whose count was out of bounds.
    fn count(field: &'static str) -> impl FnOnce(InvalidCount) -> Self {
        move |source| Self::Count { field, source }
    }
}

/// Piquel authentication service. Runs `serve` when no command is given.
#[derive(Parser)]
#[command(after_help = "Every command uses AUTH_DATABASE_URL. See README.md for configuration.")]
struct Cli {
    /// Defaults to serving when no administrative command is supplied.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Commands, each of which connects to `AUTH_DATABASE_URL` first.
#[derive(Subcommand)]
enum Command {
    /// Serve the authentication service.
    Serve,
    /// Apply database migrations.
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
    /// Verify and prune the tamper-evident audit history.
    #[command(subcommand)]
    Audit(AuditCommand),
}

/// The audit history's break-glass commands. They need only the database.
#[derive(Subcommand)]
enum AuditCommand {
    /// Recompute the chain and check every checkpoint against it. Exits non-zero,
    /// naming the first position that does not match, when the chain is broken.
    Verify(AuditKeyArgs),
    /// Delete the events through a checkpoint, once the chain verifies through it.
    /// The checkpoint becomes the anchor the remaining chain extends.
    Prune {
        /// The position of the checkpoint to prune through.
        #[arg(long)]
        through: u64,
        /// The keys to verify with.
        #[command(flatten)]
        keys: AuditKeyArgs,
    },
    /// Print the verifier key of the configured audit key, to commit to
    /// docs/security/audit-key.pub.
    PublicKey,
}

/// Which keys checkpoint signatures are checked against.
#[derive(Args)]
struct AuditKeyArgs {
    /// A file of verifier keys, one per line, to use instead of the keys committed
    /// to the repository, e.g. a preview's.
    #[arg(long)]
    key: Option<PathBuf>,
}

impl AuditKeyArgs {
    /// The given keys, or the committed ones.
    fn keys(&self) -> Result<AuditKeys, CliError> {
        Ok(match &self.key {
            Some(path) => {
                AuditKeys::given(&std::fs::read_to_string(path).map_err(CliError::KeyFile)?)?
            }
            None => AuditKeys::committed()?,
        })
    }
}

impl AuditCommand {
    /// Runs this command on `database`.
    async fn run(self, database: Database) -> Result<(), CliError> {
        let chain = AuditChain::new(database);
        match self {
            Self::Verify(keys) => {
                let verification = chain.verify(&keys.keys()?).await?;
                Self::print(&verification);
                if let Some(broken) = verification.broken {
                    return Err(AuditError::Broken(broken).into());
                }
            }
            Self::Prune { through, keys } => {
                let deleted = chain.prune(&keys.keys()?, through).await?;
                println!("Pruned {deleted} events through position {through}");
            }
            Self::PublicKey => {
                let config = AuditConfig::from_environment(&PUBLIC_BASE_URL.parse()?)?;
                println!("{}", config.verifier());
            }
        }
        Ok(())
    }

    /// Prints a verification like piqueld's `audit verify`.
    fn print(verification: &AuditVerification) {
        let point = |point: &Option<ChainPoint>| {
            point
                .as_ref()
                .map_or_else(|| "none".to_owned(), ChainPoint::to_string)
        };
        match &verification.broken {
            None => println!("Chain: intact"),
            Some(broken) => println!(
                "Chain: broken at position {}: {}",
                broken.position, broken.problem
            ),
        }
        println!("Events checked: {}", verification.events_checked);
        println!("Checkpoints checked: {}", verification.checkpoints_checked);
        println!("Unsealed: {}", verification.unsealed);
        if verification.anchor.is_some() {
            println!("Pruned through: {}", point(&verification.anchor));
        }
        println!("Newest: {}", point(&verification.newest));
        println!(
            "Latest checkpoint: {}",
            point(&verification.latest_checkpoint)
        );
        println!("Keys: {}", verification.keys);
    }
}

/// Changes to the administrator list. The CLI may act on any account, and is how
/// the first administrator is granted.
#[derive(Subcommand)]
enum AdminCommand {
    /// Make an active account an administrator.
    Grant {
        /// The account's username.
        username: String,
    },
    /// Remove an account's administrator rights. The last administrator keeps theirs.
    Revoke {
        /// The account's username.
        username: String,
    },
    /// List administrators, oldest grant first.
    List,
}

impl AdminCommand {
    /// Runs the change as the operator at this terminal.
    async fn run(self, admin: &AdminOperations) -> Result<(), CliError> {
        let operator = Command::operator()?;
        match self {
            Self::Grant { username } => {
                let user = admin.user_named(&username).await?;
                admin.grant_administrator(&operator, user).await?;
            }
            Self::Revoke { username } => {
                let user = admin.user_named(&username).await?;
                admin.revoke_administrator(&operator, user).await?;
            }
            Self::List => {
                for administrator in admin.list_administrators().await? {
                    println!(
                        "{}\t{}\t{}",
                        administrator.username,
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
        let database = Database::connect(AuthConfig::database_from_environment()?).await?;
        match self {
            Self::Serve => Self::serve(database).await,
            Self::Migrate => Ok(database.run_migrations().await?),
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
            Self::Audit(command) => command.run(database).await,
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
        let jobs = Jobs::start(&database, &config);
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
    /// Let a disabled client work again.
    Enable {
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

/// A client's registration and the lifetimes of its secrets, as `client show` prints them.
#[derive(Serialize)]
struct ClientDetails {
    /// The registration.
    #[serde(flatten)]
    client: StoredOidcClient,
    /// Its secrets, oldest first; never their values.
    secrets: Vec<StoredClientSecret>,
}

impl ClientCommand {
    /// Runs this command on `database`, recording changes as made by the operator.
    async fn run(self, database: Database) -> Result<(), CliError> {
        let registry = ClientRegistry::new(database.clone());
        let context = Command::operator()?;
        match self {
            Self::Create(create) => {
                let secret = registry
                    .create(&context, &create.registration()?, None)
                    .await?;
                Self::print_secret(secret.as_ref());
            }
            Self::Apply(apply) => {
                let secret = apply.secret()?;
                let id = apply.client.id.clone();
                let applied = registry
                    .apply(&context, &apply.client.registration()?, secret, apply.grace)
                    .await?;
                let applied = match applied {
                    Applied::Registered => "registered",
                    Applied::Updated => "updated",
                    Applied::Unchanged => "unchanged",
                };
                eprintln!("Client {id}: {applied}.");
            }
            Self::List { output } => {
                let clients = database.oidc().list_clients().await?;
                match output {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&clients)?),
                    OutputFormat::Table => {
                        println!("ID\tTYPE\tSTATUS\tREFRESH\tTRUSTED\tNAME");
                        for client in clients {
                            println!(
                                "{}\t{}\t{}\t{}\t{}\t{}",
                                client.id,
                                client.kind,
                                if client.enabled {
                                    "enabled"
                                } else {
                                    "disabled"
                                },
                                client.allow_refresh,
                                client.trusted,
                                client.display_name,
                            );
                        }
                    }
                }
            }
            Self::Show { id } => {
                let details = ClientDetails {
                    client: Self::find(&database, &id).await?,
                    secrets: database.oidc().client_secrets(&id).await?,
                };
                println!("{}", serde_json::to_string_pretty(&details)?);
            }
            Self::Update(update) => {
                let id = update.id.clone();
                registry
                    .update(&context, &id, |client| update.apply(client))
                    .await?;
            }
            Self::Disable { id } => registry.set_enabled(&context, &id, false).await?,
            Self::Enable { id } => registry.set_enabled(&context, &id, true).await?,
            Self::RotateSecret { id, grace } => {
                let secret = registry.rotate_secret(&context, &id, grace).await?;
                Self::print_secret(Some(&secret));
            }
        }
        Ok(())
    }

    /// The registered client `id`.
    async fn find(database: &Database, id: &ClientId) -> Result<StoredOidcClient, CliError> {
        database
            .oidc()
            .find_client(id.as_str())
            .await?
            .ok_or_else(|| ClientRegistryError::Unknown(id.clone()).into())
    }

    /// Prints a new secret alone on standard output, so scripts can capture it.
    fn print_secret(secret: Option<&ClientSecret>) {
        if let Some(secret) = secret {
            println!("{}", secret.expose());
            eprintln!("Store this client secret now: it cannot be shown again.");
        }
    }
}

/// The registration of a new client.
#[derive(Args)]
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
}

impl UpdateClient {
    /// Applies the changes to `client`'s stored registration, which must still be
    /// valid where it is kept.
    fn apply(self, client: StoredOidcClient) -> Result<ClientRegistration, CliError> {
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
                client.redirect_uris,
                &self.remove_redirect_uris,
                self.add_redirect_uris,
            )?)
            .map_err(CliError::count("redirect URIs"))?,
            post_logout_uris: PostLogoutUris::new(Self::edit(
                client.post_logout_uris,
                &self.remove_post_logout_uris,
                self.add_post_logout_uris,
            )?)
            .map_err(CliError::count("post-logout URIs"))?,
            allowed_scopes: AllowedScopes::new(scopes).map_err(CliError::count("scopes"))?,
            allow_refresh: self.refresh || (client.allow_refresh && !self.no_refresh),
            trusted: self.trusted || (client.trusted && !self.untrusted),
            id: client.id,
        })
    }

    /// Removes `remove` from the `stored` URIs as written, so one registered under
    /// older rules can still be removed, then adds `add`.
    fn edit(
        stored: Vec<String>,
        remove: &[String],
        add: Vec<RedirectUri>,
    ) -> Result<Vec<RedirectUri>, CliError> {
        if let Some(missing) = remove.iter().find(|uri| !stored.contains(uri)) {
            return Err(CliError::NotRegistered(missing.clone()));
        }
        let kept = stored
            .into_iter()
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

/// Initializes tracing, runs the selected command and prints any failure with its causes.
#[tokio::main]
async fn main() -> ExitCode {
    piquel_telemetry::init("auth_service=info");
    let command = Cli::parse().command.unwrap_or(Command::Serve);
    match command.run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {}", ErrorChain(&error));
            ExitCode::FAILURE
        }
    }
}
