//! Lists of operations that every surface serving them must cover: the admin
//! dashboard and the CLI for administration, the owner's routes and the CLI for
//! account settings.

/// Declares an enum of operations, each with its documentation, and its `ALL`
/// constant listing every variant, so the list cannot miss one. Surfaces match on
/// the enum exhaustively, so a new operation does not compile until each says how
/// it runs it.
macro_rules! operations {
    (
        $(#[$meta:meta])*
        $vis:vis enum $enum:ident {
            $($(#[doc = $doc:literal])+ $name:ident,)+
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        $vis enum $enum {
            $($(#[doc = $doc])+ $name,)+
        }

        impl $enum {
            /// Every operation, in declaration order.
            $vis const ALL: &[Self] = &[$(Self::$name),+];
        }
    };
}
pub(crate) use operations;
