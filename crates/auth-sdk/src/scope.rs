//! Scopes as types: an application declares its scopes once with [`scopes!`], and a
//! required scope that was never declared does not compile.

use sourceorigin_common::protocol::oauth::Scopes;

/// One scope, declared with [`scopes!`](crate::scopes), which checks its name at
/// compile time.
pub trait Scope: ScopeSet {
    /// The scope's wire name, such as `notes:read`.
    const NAME: &'static str;
}

/// Scopes a token must hold. Implemented by every [`Scope`], by tuples of scope sets
/// such as `(notes::Read, notes::Write)`, by each [`scopes!`](crate::scopes) module's
/// `All`, and by [`Scopes`], which requires nothing.
///
/// A scope set is never a value: an [`AccessToken<S>`](crate::AccessToken) is the
/// proof that a validated token holds `S`. The trait is sealed, so whether a token
/// holds a set is always this SDK's check, every name granted.
///
/// ```
/// use sourceorigin_auth::ScopeSet;
///
/// sourceorigin_auth::scopes! {
///     /// Scopes of the notes API.
///     pub mod notes {
///         Read = "notes:read",
///         Write = "notes:write",
///     }
/// }
///
/// let granted = "openid notes:read".parse()?;
/// assert!(notes::Read::holds(&granted));
/// assert!(!<(notes::Read, notes::Write)>::holds(&granted));
/// // What a challenge names when the scopes are missing.
/// assert_eq!(<(notes::Write, notes::Read)>::required().to_string(), "notes:read notes:write");
/// assert_eq!(notes::All::required().to_string(), "notes:read notes:write");
/// # Ok::<(), sourceorigin_auth::protocol::oauth::InvalidScope>(())
/// ```
pub trait ScopeSet: sealed::Names + Send + Sync + 'static {
    /// Whether `granted` holds every required scope.
    #[must_use]
    fn holds(granted: &Scopes) -> bool {
        let mut names = Vec::new();
        Self::collect(&mut names);
        names.into_iter().all(|name| granted.contains(name))
    }

    /// Every required scope, as named in challenges and metadata.
    #[must_use]
    fn required() -> Scopes {
        let mut names = Vec::new();
        Self::collect(&mut names);
        // `scopes!` checks its names at compile time; a name declared by hand that is
        // not a scope token is never granted, and is left out here.
        Scopes::try_from_iter(names.into_iter().filter(|name| Scopes::is_token(name)))
            .unwrap_or_default()
    }
}

impl<T: sealed::Names + Send + Sync + 'static> ScopeSet for T {}

/// The names a [`ScopeSet`] requires. In a private module, so no other crate can
/// implement [`ScopeSet`] and change how a set is checked.
mod sealed {
    use super::Declared;
    use sourceorigin_common::protocol::oauth::Scopes;

    /// Lists the names a scope set requires.
    pub trait Names {
        /// Appends the names of every required scope to `names`.
        fn collect(names: &mut Vec<&'static str>);
    }

    impl<T: Declared> Names for T {
        fn collect(names: &mut Vec<&'static str>) {
            names.extend(T::NAMES);
        }
    }

    impl Names for Scopes {
        fn collect(_: &mut Vec<&'static str>) {}
    }

    /// Implements [`Names`] for tuples, requiring every member.
    macro_rules! tuple_names {
        ($(($($member:ident),+)),+ $(,)?) => {$(
            impl<$($member: Names),+> Names for ($($member,)+) {
                fn collect(names: &mut Vec<&'static str>) {
                    $($member::collect(names);)+
                }
            }
        )+};
    }

    tuple_names!(
        (A),
        (A, B),
        (A, B, C),
        (A, B, C, D),
        (A, B, C, D, E),
        (A, B, C, D, E, F),
    );
}

/// The scope names a [`scopes!`](crate::scopes) type requires. Not part of the
/// public API: only the macro implements it, and the check stays the SDK's.
#[doc(hidden)]
pub trait Declared: Send + Sync + 'static {
    /// The names, checked at compile time by the macro.
    const NAMES: &'static [&'static str];
}

/// Declares an application's scopes once, as types.
///
/// ```
/// sourceorigin_auth::scopes! {
///     /// Scopes of the notes API.
///     pub mod notes {
///         /// Read every note.
///         Read = "notes:read",
///         Write = "notes:write",
///     }
/// }
///
/// use sourceorigin_auth::{Scope, ScopeSet};
/// assert_eq!(notes::Read::NAME, "notes:read");
/// assert_eq!(notes::All::required().to_string(), "notes:read notes:write");
/// ```
///
/// This generates the module with a marker type per scope implementing [`Scope`], and
/// `All`, the [`ScopeSet`] of every scope in the module. Markers have no values: they
/// name scopes in types such as `AccessToken<notes::Read>`. Scope names are checked
/// against RFC 6749 §3.3 at compile time, and requiring a scope the module does not
/// declare fails to compile. `All` is reserved as a scope name.
#[macro_export]
macro_rules! scopes {
    (
        $(#[$meta:meta])*
        $vis:vis mod $module:ident {
            $($(#[$scope_meta:meta])* $scope:ident = $name:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis mod $module {
            $(
                #[doc = concat!("The `", $name, "` scope.")]
                #[doc = ""]
                $(#[$scope_meta])*
                #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
                pub enum $scope {}

                impl $crate::Scope for $scope {
                    const NAME: &'static str = $name;
                }

                impl $crate::__private::Declared for $scope {
                    const NAMES: &'static [&'static str] = &[$name];
                }

                const _: () = assert!(
                    $crate::__private::Scopes::is_token($name),
                    concat!("`", $name, "` is not a valid scope (RFC 6749 §3.3)"),
                );
            )+

            /// Every scope this module declares.
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
            pub enum All {}

            impl $crate::__private::Declared for All {
                const NAMES: &'static [&'static str] = &[$($name),+];
            }
        }
    };
}
