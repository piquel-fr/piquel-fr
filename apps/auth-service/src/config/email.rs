//! Email to account holders: the SMTP relay, the sender, and the keys of the
//! links messages carry.

#[cfg(test)]
use super::LinkKeys;
use super::TokenDigestKeys;
use crate::{
    emails::VerificationKeys,
    invitations::InvitationLinks,
    notifications::{SignOutLinks, UnsubscribeLinks},
    recovery::RecoveryLinks,
};
use lettre::{
    AsyncSmtpTransport, Tokio1Executor,
    message::Mailbox,
    transport::smtp::{authentication::Credentials, extension::ClientId},
};
use sourceorigin_common::config::{ConfigurationError, Origin, SecretReference};
use std::{net::IpAddr, time::Duration};

sourceorigin_common::variables! {
    /// Email's variables, in the configuration reference's order.
    #[cfg(test)]
    pub(crate) const VARIABLES;

    /// The SMTP relay auth sends through: `smtps://USER@HOST:465`, with implicit
    /// TLS, or `smtp://USER@HOST:587`, which requires STARTTLS. Only a loopback
    /// host, such as a local Mailpit, may be reached without TLS. Unset, email is
    /// off: adding an address is refused and queued messages are dropped.
    pub(super) const SMTP_URL = "AUTH_SMTP_URL";
    /// Where to read the password of the URL's user, through `env://NAME` or
    /// `file:///path`. Required when the URL names a user; never put it in the
    /// URL.
    const SMTP_PASSWORD = "AUTH_SMTP_PASSWORD";
    /// The sender of every message.
    const EMAIL_FROM = "AUTH_EMAIL_FROM", default DEFAULT_EMAIL_FROM;
}
/// [`EMAIL_FROM`] when none is configured.
const DEFAULT_EMAIL_FROM: &str = "Origin Account <security@sourceorigin.dev>";
/// Port of `smtps://` URLs without one: SMTP submission over implicit TLS.
const SMTPS_PORT: u16 = 465;
/// Port of `smtp://` URLs without one: SMTP submission, upgraded with STARTTLS.
const SUBMISSION_PORT: u16 = 587;
/// The longest one SMTP command may take, like an outbound HTTP request.
const SMTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Email to account holders and the people they invite: where it is sent, as
/// whom, and the keys of the links it carries.
#[derive(Clone)]
pub(crate) struct EmailConfig {
    /// The SMTP relay; `None` when `AUTH_SMTP_URL` is unset, which disables email.
    pub smtp: Option<AsyncSmtpTransport<Tokio1Executor>>,
    /// The `From` of every message.
    pub from: Mailbox,
    /// Auth's origin, whose settings pages every link in a message opens.
    pub origin: Origin,
    /// Derives verification tokens from address IDs.
    pub verification_keys: VerificationKeys,
    /// Derives recovery links from recovery IDs.
    pub recovery_links: RecoveryLinks,
    /// Derives invitation links from invitation IDs.
    pub invitation_links: InvitationLinks,
    /// Derives and checks the unsubscribe links of announcements' emails.
    pub unsubscribe_links: UnsubscribeLinks,
    /// Derives and checks the "sign me out everywhere" links of security
    /// notifications' emails.
    pub sign_out_links: SignOutLinks,
}

impl EmailConfig {
    /// Reads the relay and sender, and derives the verification keys from the
    /// token digest keys.
    pub(super) fn from_environment(
        origin: &Origin,
        digest_keys: &TokenDigestKeys,
    ) -> Result<Self, ConfigurationError> {
        let smtp = match SMTP_URL.optional()? {
            Some(url) => Some(Self::relay(&url, origin)?),
            None if SMTP_PASSWORD.optional()?.is_some() => {
                return Err(SMTP_PASSWORD.invalid("needs AUTH_SMTP_URL, which is unset"));
            }
            None => None,
        };
        Ok(Self {
            smtp,
            from: EMAIL_FROM.parse_or(DEFAULT_EMAIL_FROM)?,
            origin: origin.clone(),
            verification_keys: digest_keys.verification_keys(),
            recovery_links: digest_keys.recovery_links(origin),
            invitation_links: digest_keys.invitation_links(origin),
            unsubscribe_links: digest_keys.unsubscribe_links(origin),
            sign_out_links: digest_keys.sign_out_links(origin),
        })
    }

    /// Builds the relay `url` names. `smtps://` uses implicit TLS, `smtp://`
    /// requires STARTTLS, both with verified certificates. Only a loopback host,
    /// such as a local Mailpit, may be reached without TLS, since plaintext never
    /// leaves the machine. The password comes from `AUTH_SMTP_PASSWORD`, never
    /// from the URL. The service greets the relay with the auth origin's host.
    fn relay(
        url: &str,
        origin: &Origin,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, ConfigurationError> {
        let usage = "must be smtps://USER@HOST[:PORT] or smtp://USER@HOST[:PORT], \
                     without a password, path, query or fragment";
        let url = url::Url::parse(url).map_err(|source| SMTP_URL.error(usage, source))?;
        // `url` only types a bracketed IPv6 host for schemes it does not know, such
        // as `smtp`: an IPv4 address or `LOCALHOST` stays text, parsed here. IPv6
        // reaches lettre without its brackets.
        let host = match url.host().ok_or_else(|| SMTP_URL.invalid(usage))? {
            url::Host::Ipv6(ip) => ip.to_string(),
            host => host.to_string(),
        };
        let loopback = match host.parse::<IpAddr>() {
            Ok(ip) => ip.is_loopback(),
            Err(_) => host.eq_ignore_ascii_case("localhost"),
        };
        if url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(SMTP_URL.invalid(usage));
        }
        let builder = match url.scheme() {
            "smtps" => AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
                .map_err(|source| SMTP_URL.error("could not set up TLS", source))?
                .port(url.port().unwrap_or(SMTPS_PORT)),
            "smtp" if loopback => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
                .port(url.port().unwrap_or(SUBMISSION_PORT)),
            "smtp" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                .map_err(|source| SMTP_URL.error("could not set up TLS", source))?
                .port(url.port().unwrap_or(SUBMISSION_PORT)),
            _ => return Err(SMTP_URL.invalid(usage)),
        };
        let builder = builder
            .timeout(Some(SMTP_TIMEOUT))
            .hello_name(ClientId::Domain(origin.host().to_owned()));
        let password = SMTP_PASSWORD.optional()?;
        Ok(match (url.username(), password) {
            ("", None) => builder.build(),
            ("", Some(_)) => {
                return Err(
                    SMTP_PASSWORD.invalid("needs a user in AUTH_SMTP_URL, e.g. smtps://USER@HOST")
                );
            }
            (_, None) => {
                return Err(SMTP_PASSWORD.invalid("is required when AUTH_SMTP_URL names a user"));
            }
            (user, Some(reference)) => {
                let user = percent_encoding::percent_decode_str(user)
                    .decode_utf8()
                    .map_err(|source| SMTP_URL.error("must hold a UTF-8 user", source))?
                    .into_owned();
                let password = SecretReference::parse(&reference)
                    .and_then(|reference| reference.resolve())
                    .map_err(|source| {
                        SMTP_PASSWORD
                            .error("must resolve through env://NAME or file://PATH", source)
                    })?;
                let password = password
                    .text()
                    .map_err(|source| SMTP_PASSWORD.error("must contain UTF-8 text", source))?
                    .to_owned();
                builder
                    .credentials(Credentials::new(user, password))
                    .build()
            }
        })
    }
}

#[cfg(test)]
impl EmailConfig {
    /// Test settings at `origin`, with fresh verification and recovery keys and
    /// recovery links on it. `enabled` sets a relay that tests never reach, so
    /// accounts can add addresses.
    pub(crate) fn test(origin: &Origin, enabled: bool) -> Self {
        Self {
            smtp: enabled.then(|| {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost").build()
            }),
            from: DEFAULT_EMAIL_FROM.parse().expect("sender"),
            origin: origin.clone(),
            verification_keys: VerificationKeys::new(LinkKeys::generate()),
            recovery_links: RecoveryLinks::new(origin.clone(), LinkKeys::generate()),
            invitation_links: InvitationLinks::new(origin.clone(), LinkKeys::generate()),
            unsubscribe_links: UnsubscribeLinks::new(origin.clone(), LinkKeys::generate()),
            sign_out_links: SignOutLinks::new(origin.clone(), LinkKeys::generate()),
        }
    }
}
