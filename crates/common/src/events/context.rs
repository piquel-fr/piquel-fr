//! Who caused an event, where their request came from and why, recorded beside it.

use crate::{ClientId, SessionId, UserId};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Who caused an event. Every feature attributes events with this one type.
///
/// Operator attribution (`os_user`, `host`, an administrator's user ID) is
/// accountability data, so it stays in the event rather than in personal data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Actor {
    /// A signed-in user, or one signing in.
    User {
        /// The acting account.
        user_id: UserId,
        /// The session acting, once there is one.
        session_id: Option<SessionId>,
    },
    /// An administrator, through the admin dashboard.
    Admin {
        /// The administrator's account.
        user_id: UserId,
        /// The administrator's session.
        session_id: SessionId,
    },
    /// An operator, through the service's command line.
    Cli {
        /// Who the operator is: the name `--operator` or `AUTH_OPERATOR` gave, or
        /// else the operating system user, `$USER`. Named `os_user` in the events
        /// already sealed.
        os_user: String,
        /// The machine's host name.
        host: String,
    },
    /// A client calling a back-channel endpoint.
    Client {
        /// The authenticated client.
        client_id: ClientId,
    },
    /// A background job.
    System {
        /// The job.
        job: JobName,
    },
    /// An unauthenticated browser, e.g. one failing to sign in.
    Anonymous,
    /// Unknown: imported audit rows never recorded who acted.
    Unrecorded,
}

impl Actor {
    /// The client acting, if any.
    #[must_use]
    pub const fn client_id(&self) -> Option<&ClientId> {
        match self {
            Self::Client { client_id } => Some(client_id),
            Self::User { .. }
            | Self::Admin { .. }
            | Self::Cli { .. }
            | Self::System { .. }
            | Self::Anonymous
            | Self::Unrecorded => None,
        }
    }

    /// The session acting, if any.
    #[must_use]
    pub const fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::User { session_id, .. } => *session_id,
            Self::Admin { session_id, .. } => Some(*session_id),
            Self::Cli { .. }
            | Self::Client { .. }
            | Self::System { .. }
            | Self::Anonymous
            | Self::Unrecorded => None,
        }
    }
}

/// Background jobs that act on their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobName {
    /// The periodic expired-state cleanup.
    Cleanup,
    /// The purge of accounts whose deletion grace period ended.
    AccountPurge,
    /// Signing key rotation, which records the steps it takes on its own.
    KeyRotation,
    /// The periodic verification of the audit chain, which records what it found
    /// and the alert of a broken chain.
    AuditVerification,
    /// The sealer of the audit chain, which records the alert of a checkpoint it
    /// refuses to sign over events that no longer match.
    AuditSealer,
}

crate::str_enum! {
    /// Coarse browser derived from a `User-Agent` header, which is never stored.
    pub enum Browser {
        /// Google Chrome and other Chromium browsers that announce no other name.
        Chrome = "chrome",
        /// Microsoft Edge.
        Edge = "edge",
        /// Mozilla Firefox.
        Firefox = "firefox",
        /// Opera.
        Opera = "opera",
        /// Apple Safari.
        Safari = "safari",
        /// Anything else, including back-channel HTTP clients, and browsers a newer
        /// release recognizes.
        Other = "other",
    } else Other
}

crate::str_enum! {
    /// Coarse operating system derived from a `User-Agent` header.
    pub enum Platform {
        /// Android.
        Android = "android",
        /// `ChromeOS`.
        ChromeOs = "chrome_os",
        /// iOS and iPadOS. iPads that request desktop sites announce macOS.
        Ios = "ios",
        /// Linux on the desktop.
        Linux = "linux",
        /// macOS.
        MacOs = "macos",
        /// Windows.
        Windows = "windows",
        /// Anything else, including back-channel HTTP clients, and platforms a newer
        /// release recognizes.
        Other = "other",
    } else Other
}

/// Coarse browser and platform of a `User-Agent` header, the only part of it auth
/// keeps. Stored as text, `browser/platform` (`firefox/linux`); serialized as
/// `{"browser": …, "platform": …}`. A browser or platform this release doesn't
/// know reads as `other`, so a session or event a newer release tagged still loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAgentFamily {
    /// The browser.
    pub browser: Browser,
    /// The operating system it runs on.
    pub platform: Platform,
}

impl UserAgentFamily {
    /// Classifies a `User-Agent` header. Markers are checked in order: Edge and Opera
    /// also announce Chrome, Chrome announces Safari, Android and `ChromeOS` announce
    /// Linux, and iOS announces macOS.
    #[must_use]
    pub fn classify(user_agent: &str) -> Self {
        /// The value of the first marker `user_agent` contains, or `other`.
        fn first<T: Copy>(user_agent: &str, markers: &[(&str, T)], other: T) -> T {
            markers
                .iter()
                .find(|(marker, _)| user_agent.contains(marker))
                .map_or(other, |&(_, value)| value)
        }
        Self {
            browser: first(
                user_agent,
                &[
                    ("Edg/", Browser::Edge),
                    ("EdgA/", Browser::Edge),
                    ("EdgiOS/", Browser::Edge),
                    ("OPR/", Browser::Opera),
                    ("Firefox/", Browser::Firefox),
                    ("FxiOS/", Browser::Firefox),
                    ("Chrome/", Browser::Chrome),
                    ("CriOS/", Browser::Chrome),
                    ("Safari/", Browser::Safari),
                ],
                Browser::Other,
            ),
            platform: first(
                user_agent,
                &[
                    ("Android", Platform::Android),
                    ("CrOS", Platform::ChromeOs),
                    ("iPhone", Platform::Ios),
                    ("iPad", Platform::Ios),
                    ("iPod", Platform::Ios),
                    ("Mac OS X", Platform::MacOs),
                    ("Windows", Platform::Windows),
                    ("Linux", Platform::Linux),
                ],
                Platform::Other,
            ),
        }
    }
}

impl std::fmt::Display for UserAgentFamily {
    /// Formats the stored text, `browser/platform`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.browser, self.platform)
    }
}

impl std::str::FromStr for UserAgentFamily {
    type Err = crate::VocabularyError;
    /// Parses the stored text, `browser/platform`.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (browser, platform) = value.split_once('/').ok_or(crate::VocabularyError {
            vocabulary: "UserAgentFamily",
        })?;
        Ok(Self {
            browser: browser.parse()?,
            platform: platform.parse()?,
        })
    }
}

crate::__str_enum_sqlx!(UserAgentFamily);

/// Where a request came from. Both fields are personal data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestOrigin {
    /// The client's IP address, when the event came from a request.
    pub client_ip: Option<IpAddr>,
    /// The client's browser and platform, when the event came from a request.
    pub user_agent_family: Option<UserAgentFamily>,
}

/// Who caused an event, where their request came from and why, recorded with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventContext {
    /// Who caused the event.
    pub actor: Actor,
    /// Where the request came from; empty outside requests.
    pub origin: RequestOrigin,
    /// Why an administrator or operator changed someone's account, as they wrote
    /// it. Kept with the origin as personal data, since free text may name people,
    /// and shown to the account's owner in their security history.
    pub reason: Option<String>,
}

impl EventContext {
    /// What background `job` does on its own, outside any request.
    #[must_use]
    pub fn system(job: JobName) -> Self {
        Self {
            actor: Actor::System { job },
            origin: RequestOrigin::default(),
            reason: None,
        }
    }
}
