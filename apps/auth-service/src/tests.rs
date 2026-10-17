//! Two instances of the whole service on one database, as piqueld runs replicas.

use crate::{
    AuthConfig,
    config::{FederationConfig, FrontendOrigins, OidcConfig, PasskeyConfig},
    passkey::DecoyKey,
};
use axum::{Extension, Router, extract::ConnectInfo};
use piquel_auth_protocol::UserId;
use piquel_common::{Origin, PublicUrl};
use piquel_crypto::{Rs256Key, Secret};
use piquel_repository::{Database, DatabaseConfig};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

/// Auth origin of the replicas, and of the fixtures that send requests to them.
pub(crate) const AUTH_ORIGIN: &str = "https://auth.piquel.fr";

/// Two routers built by [`AuthConfig::router`] from one configuration. Each has its
/// own database pool and in-process state, so a test passes only if everything it
/// relies on is shared through PostgreSQL or the configuration.
pub(crate) struct Replicas {
    /// The first replica.
    pub a: Router,
    /// The second replica.
    pub b: Router,
}

impl Replicas {
    /// Builds both replicas. Every request comes from one client address, unique to
    /// this fixture, so the replicas share its rate-limit budget and no other test's.
    pub(crate) async fn new() -> Self {
        let origin: Origin = AUTH_ORIGIN.parse().expect("auth origin");
        let settings_url: PublicUrl = "https://piquel.fr/settings".parse().expect("settings URL");
        let config = AuthConfig {
            public_listener: SocketAddr::from(([127, 0, 0, 1], 0)),
            passkey: PasskeyConfig {
                origin: origin.clone(),
                invite_required: false,
                decoy_key: DecoyKey::new(Secret::generate().expect("decoy key")),
            },
            federation: FederationConfig {
                origin: origin.clone(),
                frontends: FrontendOrigins::new([&settings_url]),
                settings_url,
                providers: BTreeMap::new(),
            },
            oidc: OidcConfig {
                origin,
                keys: Arc::new(Rs256Key::generate("replicas").expect("signing key")),
                refresh_key: Arc::new(Secret::generate().expect("refresh key")),
                clients: vec![],
                public_redirects: vec![],
            },
            trusted_proxies: vec![],
        };
        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(UserId::new().as_uuid().as_u128())),
            4321,
        );
        let replica = async || {
            config
                .router(Self::database().await)
                .expect("replica")
                .layer(Extension(ConnectInfo(peer)))
        };
        Self {
            a: replica().await,
            b: replica().await,
        }
    }

    /// Connects a new pool to the migrated test database.
    async fn database() -> Database {
        let url = piquel_common::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
        let database = Database::connect(
            DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5))
                .expect("database configuration"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        database
    }
}
