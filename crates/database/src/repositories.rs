//! Domain repository handles backed by a private pool or transaction connection.

use sqlx::{PgConnection, PgPool};

#[allow(dead_code)]
pub(crate) enum RepositoryExecutor<'a> {
    Pool(&'a PgPool),
    Connection(&'a mut PgConnection),
}

macro_rules! repository {
    ($name:ident) => {
        /// Focused persistence handle; it has no policy and no public SQL escape hatch.
        pub struct $name<'a> {
            #[allow(dead_code)]
            pub(crate) executor: RepositoryExecutor<'a>,
        }
        impl<'a> $name<'a> {
            pub(crate) const fn from_pool(pool: &'a PgPool) -> Self {
                Self {
                    executor: RepositoryExecutor::Pool(pool),
                }
            }
            pub(crate) fn from_connection(connection: &'a mut PgConnection) -> Self {
                Self {
                    executor: RepositoryExecutor::Connection(connection),
                }
            }
        }
    };
}
repository!(UserRepository);
repository!(EmailRepository);
repository!(SessionRepository);
repository!(AuditEventRepository);
repository!(InternalEventRepository);
repository!(PasskeyRepository);
repository!(OidcRepository);
repository!(TokenRepository);
repository!(FederationRepository);
repository!(ServiceIdentityRepository);
