//! Scopes as types: an application declares its scopes once with [`scopes!`], and a
//! required scope that was never declared does not compile.

use piquel_auth_protocol::oauth::Scopes;

/// One scope, declared with [`scopes!`](crate::scopes).
pub trait Scope: Copy + Default + Send + Sync + 'static {
    /// The scope's wire name, such as `notes:read`.
    const NAME: &'static str;
}

/// Scopes a token must hold. Implemented by every [`Scope`], by tuples of scope sets
/// such as `(notes::Read, notes::Write)`, by each [`scopes!`](crate::scopes) module's
/// `All`, and by [`Scopes`], which requires nothing and keeps the granted list.
pub trait ScopeSet: Sized + Send + Sync + 'static {
    /// Appends the names of every required scope to `names`.
    fn collect(names: &mut Vec<&'static str>);

    /// Proof that `granted` holds every required scope, or `None`.
    fn from_granted(granted: &Scopes) -> Option<Self>;

    /// Every required scope, as named in challenges and metadata.
    #[must_use]
    fn required() -> Scopes {
        let mut names = Vec::new();
        Self::collect(&mut names);
        names.into_iter().map(str::to_owned).collect()
    }
}

impl<T: Scope> ScopeSet for T {
    fn collect(names: &mut Vec<&'static str>) {
        names.push(T::NAME);
    }

    fn from_granted(granted: &Scopes) -> Option<Self> {
        granted.contains(T::NAME).then(T::default)
    }
}

impl ScopeSet for Scopes {
    fn collect(_: &mut Vec<&'static str>) {}

    fn from_granted(granted: &Scopes) -> Option<Self> {
        Some(granted.clone())
    }
}

/// Implements [`ScopeSet`] for tuples, requiring every member.
macro_rules! tuple_scope_sets {
    ($(($($member:ident),+)),+ $(,)?) => {$(
        impl<$($member: ScopeSet),+> ScopeSet for ($($member,)+) {
            fn collect(names: &mut Vec<&'static str>) {
                $($member::collect(names);)+
            }

            fn from_granted(granted: &Scopes) -> Option<Self> {
                Some(($($member::from_granted(granted)?,)+))
            }
        }
    )+};
}

tuple_scope_sets!(
    (A),
    (A, B),
    (A, B, C),
    (A, B, C, D),
    (A, B, C, D, E),
    (A, B, C, D, E, F),
);

/// Declares an application's scopes once, as types.
///
/// ```
/// piquel_auth::scopes! {
///     /// Scopes of the notes API.
///     pub mod notes {
///         /// Read every note.
///         Read = "notes:read",
///         Write = "notes:write",
///     }
/// }
///
/// use piquel_auth::{Scope, ScopeSet};
/// assert_eq!(notes::Read::NAME, "notes:read");
/// assert_eq!(notes::All::required().to_string(), "notes:read notes:write");
/// let granted = "openid notes:read".parse().unwrap();
/// assert!(<(notes::Read, notes::Write)>::from_granted(&granted).is_none());
/// ```
///
/// This generates the module with a zero-sized marker per scope implementing
/// [`Scope`], and `All`, the [`ScopeSet`] of every scope in the module. Scope names
/// are checked against RFC 6749 §3.3 at compile time, and requiring a scope the
/// module does not declare fails to compile. `All` is reserved as a scope name.
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
                #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
                pub struct $scope;

                impl $crate::Scope for $scope {
                    const NAME: &'static str = $name;
                }

                const _: () = assert!(
                    $crate::__private::Scopes::is_token($name),
                    concat!("`", $name, "` is not a valid scope (RFC 6749 §3.3)"),
                );
            )+

            /// Every scope this module declares.
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
            pub struct All;

            impl $crate::ScopeSet for All {
                fn collect(names: &mut ::std::vec::Vec<&'static str>) {
                    $(names.push($name);)+
                }

                fn from_granted(granted: &$crate::__private::Scopes) -> ::std::option::Option<Self> {
                    ($(granted.contains($name))&&+).then_some(Self)
                }
            }
        }
    };
}
