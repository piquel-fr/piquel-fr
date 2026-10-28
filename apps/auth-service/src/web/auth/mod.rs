//! auth.piquel.fr's sign-in flows: signing in and up, an application's consent
//! and logout, account recovery, and handing an administrator off to the admin
//! dashboard. They serve browsers that may not be signed in yet, so they are
//! pages of their own rather than [`AccountPage`](super::account::AccountPage)s.

/// Handing an administrator off to the admin dashboard.
mod handoff;
/// The sign-in pages: signing in, creating an account and linking a provider.
mod login;
/// The consent page and the confirmation of an application's logout request.
mod oidc;
/// The recovery pages: adding a passkey with a recovery link, and undoing a
/// recovery.
mod recovery;

pub(super) use login::SignInPage;
