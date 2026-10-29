//! The sign-in pages: signing in, creating an account, and linking a provider's
//! sign-in to an existing account.
//!
//! Every link and form of these pages keeps their [`LoginQuery`], which says where
//! the browser goes once signed in. A passkey ceremony runs in the passkey script,
//! which then posts the form, and the page sends the browser on.

use crate::{
    Title,
    form::{
        Ceremony, Checkbox, Fields, Query, change_form, handle_input, new_passkey, open,
        passkey_form,
    },
    intro,
};
use piquel_common::{Provider, TokenId, protocol::claims::Acr};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{View, component, view},
};

piquel_common::str_enum! {
    /// Why a provider's sign-in failed, which its callback sends to the sign-in page.
    pub enum CallbackError {
        /// The provider declined or cancelled authorization.
        Cancelled = "social_cancelled",
        /// The returned authorization could not be verified.
        Failed = "social_failed",
        /// The browser's session was confirmed with a passkey, which social sign-in
        /// cannot re-authenticate.
        PasskeyRequired = "passkey_required",
    }
}

impl CallbackError {
    /// What the sign-in page says.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Cancelled => "Social sign-in was cancelled. You can try again or use a passkey.",
            Self::Failed => {
                "Social sign-in could not be verified. Please try again or use a passkey."
            }
            Self::PasskeyRequired => {
                "You last confirmed this session with a passkey. Use your passkey to sign in again."
            }
        }
    }
}

piquel_common::str_enum! {
    /// What the sign-in page asks of a browser holding a provider's pending sign-in.
    pub enum PendingDestination {
        /// A passkey must confirm the matching account.
        Link = "link",
        /// A first passkey must create the account.
        Signup = "signup",
    }
}

/// The sign-in pages' query: where the browser goes once signed in, and what the
/// page shows. Each field a link may get wrong, such as an old or edited one, reads
/// as absent, so it never loses the others: a page that does not know where to go
/// on would sign the browser in to the settings instead of the application.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginQuery {
    /// The pending authorization the sign-in continues.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    /// The class of authentication the application asked for; `phr` offers only
    /// passkeys.
    #[serde(
        default,
        deserialize_with = "Fields::lenient",
        skip_serializing_if = "Option::is_none"
    )]
    pub acr: Option<Acr>,
    /// The path on auth the browser goes on to, without a pending authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_to: Option<String>,
    /// The invitation creating an account starts with. Links once called it
    /// `invite`.
    #[serde(alias = "invite", skip_serializing_if = "Option::is_none")]
    pub invitation: Option<String>,
    /// Why the provider's sign-in that brought the browser here failed.
    #[serde(
        default,
        deserialize_with = "Fields::lenient",
        skip_serializing_if = "Option::is_none"
    )]
    pub error: Option<CallbackError>,
    /// A provider's sign-in waits in this browser, for a signup or a link.
    #[serde(
        default,
        deserialize_with = "Fields::lenient",
        skip_serializing_if = "Option::is_none"
    )]
    pub social: Option<PendingDestination>,
    /// "Use a handle instead" is open: signing in asks for the account's handle.
    #[serde(default, skip_serializing_if = "Checkbox::is_off")]
    pub handle: Checkbox,
}

impl Query for LoginQuery {}

impl LoginQuery {
    /// What the links between the sign-in pages keep: where the browser goes on to,
    /// and the class of authentication it must reach.
    fn continued(&self) -> Self {
        Self {
            transaction: self.transaction.clone(),
            acr: self.acr,
            return_to: self.return_to.clone(),
            ..Self::default()
        }
    }
}

/// A change a sign-in page posts, named by its `action` field. A ceremony's form
/// posts once the passkey script has run it, with what the ceremony read, which no
/// change keeps.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum LoginChange {
    /// Shows that the passkey script just signed the browser in with a passkey:
    /// this changes nothing, and the browser goes on.
    SignedIn {},
    /// Shows that the passkey script just created the account, signed in: this
    /// changes nothing, and the browser goes on.
    Registered {},
    /// Starts signing in at the provider.
    Social {
        /// The provider.
        provider: Provider,
    },
    /// Links the provider's pending sign-in to the signed-in account.
    Link {},
    /// Abandons the provider's pending sign-in.
    CancelLink {},
    /// Signs this browser out, so another account can sign in or take the link.
    SwitchAccount {},
}

/// Why a provider's pending sign-in must be linked rather than create an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// Its verified email belongs to an existing account.
    Email,
    /// The account's settings started it, in this browser's session.
    Explicit,
}

/// The account a browser is signed in to, as the sign-in and link steps show it.
#[derive(Clone, Debug)]
pub struct SignedIn {
    /// Its handle.
    pub handle: String,
    /// Whether its session confirmed with a passkey recently enough to link
    /// without confirming again.
    pub confirmed: bool,
}

/// What a sign-in page asks of the browser.
#[derive(Clone, Copy, Debug)]
pub enum Step<'a> {
    /// Signing in with a passkey, or at one of the `providers`.
    SignIn {
        /// The application asks for a passkey, so no provider is offered.
        passkey_only: bool,
        /// "Use a handle instead" is open: the form asks for the handle.
        handle_open: bool,
        /// The enabled providers.
        providers: &'a [Provider],
        /// The account the browser is signed in to, if any, which it can sign out
        /// of first: a sign-in that would lower its session's confirmation is
        /// refused.
        signed_in: Option<&'a SignedIn>,
    },
    /// Creating an account with its first passkey.
    SignUp {
        /// The provider whose pending sign-in the account gets, and the ID of its
        /// evidence, which the form names.
        social: Option<(Provider, TokenId)>,
        /// The invitation the form starts with.
        invitation: Option<&'a str>,
        /// Whether creating an account needs an invitation.
        invite_required: bool,
        /// Whether the browser runs Android, which may save the passkey with Google
        /// Password Manager.
        android: bool,
    },
    /// Linking the provider's pending sign-in to an existing account, which
    /// confirms it with a passkey.
    Link {
        /// Why it must be linked.
        kind: LinkKind,
        /// The provider.
        provider: Provider,
        /// The provider's verified email, if any.
        email: Option<&'a str>,
        /// The account the browser is signed in to, if any. A browser signed out
        /// signs in with a passkey first.
        signed_in: Option<&'a SignedIn>,
        /// "Use a handle instead" is open: signing in asks for the handle.
        handle_open: bool,
    },
}

impl<'a> Step<'a> {
    /// The page's title in the browser.
    #[must_use]
    pub const fn title(&self) -> Title {
        match self {
            Self::SignIn { .. } => Title::SignIn,
            Self::SignUp { .. } => Title::SignUp,
            Self::Link { .. } => Title::Link,
        }
    }

    /// The account the browser is signed in to, if the step shows it.
    const fn signed_in(&self) -> Option<&'a SignedIn> {
        match self {
            Self::SignIn { signed_in, .. } | Self::Link { signed_in, .. } => *signed_in,
            Self::SignUp { .. } => None,
        }
    }

    /// What the page says above its forms: its eyebrow, heading and lead.
    fn wording(&self) -> (&'static str, &'static str, String) {
        match self {
            Self::SignIn { passkey_only, .. } => (
                "Your Piquel account",
                "Welcome back.",
                if *passkey_only {
                    "This app asks you to sign in with a passkey."
                } else {
                    "Sign in with a passkey, or use a linked social account."
                }
                .to_owned(),
            ),
            Self::SignUp { .. } => (
                "One account. Your services.",
                "Your account starts here.",
                "Create a passkey with your device or password manager. You’ll use it to sign in and protect your account settings.".to_owned(),
            ),
            Self::Link { kind, provider, .. } => (
                "Social sign-in",
                "Add this sign-in method?",
                match kind {
                    LinkKind::Explicit => format!(
                        "Verify your passkey to add {} sign-in to your account.",
                        provider.name()
                    ),
                    LinkKind::Email => format!(
                        "{} uses an email associated with an existing account. Verify that account with its passkey to add this provider.",
                        provider.name()
                    ),
                },
            ),
        }
    }
}

/// A sign-in page, at `page`, asking the browser for `step`. Its forms post to the
/// page with `query`, which keeps where the browser goes on to, and its links open
/// the sign-in page, `login`, and the page creating an account, `register`, with
/// it. `alert` says why the change just posted failed, or the provider sign-in
/// that brought the browser here.
#[component]
pub async fn sign_in<'a>(
    step: Step<'a>,
    page: &'a str,
    query: &'a LoginQuery,
    login: &'a str,
    register: &'a str,
    #[default] alert: Option<&'a str>,
) -> Result<impl View> {
    let action = query.on(page)?;
    let (eyebrow, title, lead) = step.wording();
    let footer = match step {
        Step::SignIn { .. } => Some((
            "New to Piquel? ",
            "Create an account",
            LoginQuery {
                invitation: query.invitation.clone(),
                ..query.continued()
            }
            .on(register)?,
        )),
        Step::SignUp { .. } => Some((
            "Already have an account? ",
            "Sign in",
            query.continued().on(login)?,
        )),
        Step::Link { .. } => None,
    };
    Ok(view! {
        <section class="auth-shell">
            intro(eyebrow: eyebrow, title: title, lead: lead.as_str())
            match step {
                Step::SignUp { social: Some((provider, _)), .. } => {
                    <p class="notice">
                        (format!("Finish creating your account to add {} sign-in.", provider.name()))
                    </p>
                }
                Step::Link { email: Some(email), .. } => {
                    <p class="notice">(email)</p>
                }
                _ => {}
            }
            if let Some(account) = step.signed_in() {
                <p class="help">(format!("Signed in as @{}.", account.handle))</p>
            }
            if let Some(alert) = alert {
                <p class="notice error" role="alert">(alert)</p>
            }
            <div class="stack">
                match step {
                    Step::SignIn { passkey_only, handle_open, providers, signed_in } => sign_in_forms(
                        action: &action,
                        page: page,
                        query: query,
                        passkey_only: passkey_only,
                        handle_open: handle_open,
                        providers: providers,
                        signed_in: signed_in.is_some(),
                    ),
                    Step::SignUp { social, invitation, invite_required, android } => sign_up_form(
                        action: &action,
                        social: social,
                        invitation: invitation,
                        invite_required: invite_required,
                        android: android,
                    ),
                    Step::Link { kind, signed_in, handle_open, .. } => link_forms(
                        action: &action,
                        page: page,
                        query: query,
                        kind: kind,
                        signed_in: signed_in,
                        handle_open: handle_open,
                    ),
                }
            </div>
            <footer>
                if let Some((question, label, href)) = &footer {
                    <p class="help">(*question)<a href=(href.as_str())>(*label)</a></p>
                }
                <p class="help">"Your passkey stays with your device or password manager."</p>
            </footer>
        </section>
    })
}

/// The forms of [`Step::SignIn`], posting to `action`: signing in with a passkey,
/// opening `page` with `query` to ask for a handle, unless the application asks
/// for a passkey, signing in at one of the `providers`, and, when the browser is
/// `signed_in`, signing it out first.
#[component]
async fn sign_in_forms<'a>(
    action: &'a str,
    page: &'a str,
    query: &'a LoginQuery,
    passkey_only: bool,
    handle_open: bool,
    providers: &'a [Provider],
    signed_in: bool,
) -> Result<impl View> {
    Ok(view! {
        passkey_sign_in(
            action: action,
            page: page,
            query: query,
            change: LoginChange::SignedIn {},
            label: "Sign in with a passkey",
            handle_open: handle_open,
        )
        if !passkey_only && !providers.is_empty() {
            <div class="divider">"or continue with"</div>
            for provider in providers {
                change_form(
                    action: action,
                    change: LoginChange::Social { provider: *provider },
                    label: provider.name(),
                    class: "secondary full",
                )
            }
        }
        if signed_in {
            switch_account(action: action, label: "Sign out")
        }
    })
}

/// The form of [`Step::SignUp`], posting to `action` once the passkey script
/// created the account. It names the `social` evidence the account gets, if any,
/// and asks for an invitation, starting with `invitation`, when one is required. On
/// Android, it offers Google Password Manager.
#[component]
async fn sign_up_form<'a>(
    action: &'a str,
    social: Option<(Provider, TokenId)>,
    invitation: Option<&'a str>,
    invite_required: bool,
    android: bool,
) -> Result<impl View> {
    Ok(view! {
        passkey_form(
            action: action,
            ceremony: Ceremony::Register,
            change: LoginChange::Registered {},
            label: "Create account with a passkey",
            class: "full",
            handle_input(new: true)
            new_passkey(label: "Passkey name", value: "My passkey", android: android)
            if invite_required {
                <label>
                    "Invitation"
                    <input name="invitation" value=(invitation) required="" autocomplete="off">
                </label>
            }
            if let Some((_, id)) = social {
                <input type="hidden" name="pending_signup" value=(id.to_string())>
            }
        )
    })
}

/// The forms of [`Step::Link`], posting to `action`: confirming the link with a
/// passkey, signing in first unless the browser is `signed_in`, or at once when its
/// session confirmed recently; switching accounts, for an email match; and
/// cancelling. Signing in opens `page` with `query` to ask for a handle.
#[component]
async fn link_forms<'a>(
    action: &'a str,
    page: &'a str,
    query: &'a LoginQuery,
    kind: LinkKind,
    signed_in: Option<&'a SignedIn>,
    handle_open: bool,
) -> Result<impl View> {
    let label = "Verify passkey and add provider";
    Ok(view! {
        match signed_in {
            Some(account) => change_form(
                action: action,
                change: LoginChange::Link {},
                label: label,
                class: "full",
                confirm: !account.confirmed,
            ),
            // A passkey sign-in also confirms the new session.
            None => passkey_sign_in(
                action: action,
                page: page,
                query: query,
                change: LoginChange::Link {},
                label: label,
                handle_open: handle_open,
            ),
        }
        // An explicit link belongs to this session: signing out would strand it.
        if signed_in.is_some() && kind == LinkKind::Email {
            switch_account(action: action, label: "Use a different account")
        }
        change_form(
            action: action,
            change: LoginChange::CancelLink {},
            label: "Cancel linking",
            class: "text-button",
        )
    })
}

/// Signing the browser out by posting to `action`, so another account can sign in
/// or take the link, with a button labelled `label`.
#[component]
async fn switch_account<'a>(action: &'a str, label: &'a str) -> Result<impl View> {
    Ok(view! {
        change_form(
            action: action,
            change: LoginChange::SwitchAccount {},
            label: label,
            class: "secondary",
        )
    })
}

/// Signing in with a passkey, then posting `change` to `action`, in a form
/// labelled `label`. With `handle_open`, the form asks for the account's handle,
/// for a passkey the browser's account picker cannot offer; otherwise a button
/// opens `page` with `query` asking for it.
#[component]
async fn passkey_sign_in<'a>(
    action: &'a str,
    page: &'a str,
    query: &'a LoginQuery,
    #[into] change: Fields,
    label: &'a str,
    handle_open: bool,
) -> Result<impl View> {
    Ok(view! {
        passkey_form(
            action: action,
            ceremony: Ceremony::SignIn,
            change: change,
            label: label,
            class: "full",
            if handle_open {
                handle_input(new: false, focus: true)
            }
        )
        if !handle_open {
            open(
                page: page,
                opens: LoginQuery { handle: Checkbox(true), ..query.clone() },
                label: "Use a handle instead",
            )
        }
    })
}

#[cfg(test)]
mod tests {
    //! The sign-in pages' query.
    use super::*;

    /// A field an old or edited link gets wrong reads as absent, never losing where
    /// the browser goes on to; the invitation's old name still reads.
    #[test]
    fn a_wrong_field_keeps_the_rest_of_the_query() {
        let query: LoginQuery = serde_urlencoded::from_str(
            "transaction=t&acr=gold&return_to=%2Fsettings&invite=i&error=nope&social=maybe&handle=",
        )
        .expect("query");
        assert_eq!(
            query,
            LoginQuery {
                transaction: Some("t".into()),
                return_to: Some("/settings".into()),
                invitation: Some("i".into()),
                handle: Checkbox(true),
                ..LoginQuery::default()
            }
        );
        let known: LoginQuery =
            serde_urlencoded::from_str("acr=phr&error=social_failed&social=link").expect("query");
        assert_eq!(
            (known.acr, known.error, known.social),
            (
                Some(Acr::PhishingResistant),
                Some(CallbackError::Failed),
                Some(PendingDestination::Link)
            )
        );
        assert_eq!(
            known.on("/login").expect("link"),
            "/login?acr=phr&error=social_failed&social=link"
        );
    }
}
