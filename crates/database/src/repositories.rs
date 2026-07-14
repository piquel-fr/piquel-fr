//! Domain repository handles. SQL implementations are added by owning plans.

macro_rules! repository {
    ($name:ident) => {
        /// Focused persistence handle; it has no policy and no public SQL escape hatch.
        pub struct $name<'a>(std::marker::PhantomData<&'a mut ()>);
        impl<'a> $name<'a> {
            pub(crate) const fn new() -> Self {
                Self(std::marker::PhantomData)
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
