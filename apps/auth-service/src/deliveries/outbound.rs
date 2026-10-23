//! The HTTP client for destinations third parties supply, such as a client's
//! back-channel logout URI. A destination must not reach this network: it must be
//! HTTPS, its address public, and redirects are never followed.

use super::{DeliveryError, Failure, SEND_TIMEOUT};
use axum::http::{HeaderMap, Method, StatusCode, header::RETRY_AFTER};
use chrono::{DateTime, NaiveDateTime, Utc};
use ipnet::{Ipv4Net, Ipv6Net};
use piquel_telemetry::SendTraced;
use reqwest::{
    RequestBuilder,
    dns::{Addrs, Name, Resolve, Resolving},
    redirect,
};
use std::{
    error::Error as StdError,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use url::{Host, Url};

/// The longest connecting to a destination may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Sent with every request.
const USER_AGENT: &str = "piquel-auth";
/// The most of a response body that is read; the rest is ignored.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// The obsolete HTTP-date formats receivers must still accept (RFC 9110 section
/// 5.6.7): RFC 850 and C's `asctime`. The preferred format is RFC 2822's.
const OBSOLETE_HTTP_DATES: [&str; 2] = ["%A, %d-%b-%y %H:%M:%S GMT", "%a %b %e %H:%M:%S %Y"];

/// IPv4 ranges a destination may not use: the special-purpose ranges that are not
/// globally reachable (RFC 6890), multicast, and the reserved block.
const REFUSED_V4: [Ipv4Net; 11] = [
    Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 8),
    Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10),
    Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
    Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 0, 0), 24),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16),
    Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15),
    Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4),
    Ipv4Net::new_assert(Ipv4Addr::new(240, 0, 0, 0), 4),
];
/// IPv6 ranges a destination may not use: unspecified, loopback and the
/// deprecated IPv4-compatible addresses (`::/96`), discard-only, local-use NAT64
/// (RFC 8215), unique-local, link-local, site-local and multicast.
const REFUSED_V6: [Ipv6Net; 7] = [
    Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 96),
    Ipv6Net::new_assert(Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64),
    Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10),
    Ipv6Net::new_assert(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];
/// Well-known NAT64 (RFC 6052): the last 32 bits are the IPv4 address reached.
const NAT64: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96);
/// 6to4 (RFC 3056): bits 16 to 48 are the IPv4 address reached.
const SIX_TO_FOUR: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16);

/// A successful response, with at most [`MAX_RESPONSE_BYTES`] of its body.
// Back-channel logout needs only the status class; channels that read answers,
// such as SCIM, will read these. `expect` fails the build once one does.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "No channel reads response contents yet.")
)]
#[derive(Debug)]
pub(crate) struct OutboundResponse {
    /// The successful status.
    pub status: StatusCode,
    /// The body's first [`MAX_RESPONSE_BYTES`] bytes.
    pub body: Vec<u8>,
}

/// Sends requests to destinations third parties supply. Destinations must be
/// HTTPS URLs whose host is, or resolves only to, public addresses; the
/// connection goes to the addresses that were checked. Redirects and proxies are
/// never used. Attempts time out after [`SEND_TIMEOUT`].
#[derive(Clone)]
pub(crate) struct OutboundClient {
    /// Built with the guarded resolver; never follows redirects.
    client: reqwest::Client,
    /// Which addresses destinations may have.
    reachable: Reachable,
}

impl OutboundClient {
    /// A client for public destinations.
    ///
    /// # Errors
    ///
    /// Fails if the TLS backend cannot initialize.
    pub(crate) fn new() -> Result<Self, reqwest::Error> {
        Self::build(Reachable::Public, reqwest::Client::builder())
    }

    /// A client that also reaches loopback addresses and trusts `root`, so tests
    /// can send to a local HTTPS server.
    #[cfg(test)]
    pub(crate) fn local(root: reqwest::Certificate) -> Self {
        Self::build(
            Reachable::PublicOrLoopback,
            reqwest::Client::builder().add_root_certificate(root),
        )
        .expect("local outbound client")
    }

    /// Applies the guarded settings to `builder`.
    fn build(
        reachable: Reachable,
        builder: reqwest::ClientBuilder,
    ) -> Result<Self, reqwest::Error> {
        let client = builder
            .https_only(true)
            .redirect(redirect::Policy::none())
            // A proxy would resolve the name itself, after our check.
            .no_proxy()
            .dns_resolver(Arc::new(GuardedResolver(reachable)))
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(SEND_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()?;
        Ok(Self { client, reachable })
    }

    /// Sends a `method` request to `destination`, configured by `request`, e.g. to
    /// add a body. Returns the response if its status is successful, with its body
    /// cut at [`MAX_RESPONSE_BYTES`].
    ///
    /// # Errors
    ///
    /// A destination that is not HTTPS or not public, or a redirect, fails
    /// permanently. Timeouts, connection and DNS failures, and HTTP 408, 429 and
    /// 5xx are retryable, after `Retry-After` when the receiver sent one. Other
    /// statuses fail permanently.
    pub(crate) async fn send(
        &self,
        method: Method,
        destination: &str,
        request: impl FnOnce(RequestBuilder) -> RequestBuilder,
    ) -> Result<OutboundResponse, DeliveryError> {
        let url = self.check(destination)?;
        let transport = |error: reqwest::Error| Self::transport_error(&error);
        let mut response = request(self.client.request(method, url))
            .send_traced()
            .await
            .map_err(transport)?;
        Self::check_status(response.status(), response.headers(), Utc::now())?;
        let mut body = Vec::new();
        while body.len() < MAX_RESPONSE_BYTES
            && let Some(chunk) = response.chunk().await.map_err(transport)?
        {
            let room = MAX_RESPONSE_BYTES - body.len();
            body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
        Ok(OutboundResponse {
            status: response.status(),
            body,
        })
    }

    /// Parses `destination`, refusing anything but HTTPS and an IP literal host
    /// that is not public. Names are checked when they resolve.
    fn check(&self, destination: &str) -> Result<Url, DeliveryError> {
        let invalid = DeliveryError::Permanent(Failure::InvalidDestination);
        let url = Url::parse(destination).map_err(|_| invalid)?;
        let address = match url.host() {
            _ if url.scheme() != "https" => return Err(invalid),
            None => return Err(invalid),
            Some(Host::Domain(_)) => None,
            Some(Host::Ipv4(address)) => Some(IpAddr::V4(address)),
            Some(Host::Ipv6(address)) => Some(IpAddr::V6(address)),
        };
        if address.is_some_and(|address| !self.reachable.allows(address)) {
            return Err(DeliveryError::Permanent(Failure::ForbiddenDestination));
        }
        Ok(url)
    }

    /// Classifies a request that got no response. A refused address is found in
    /// the error's sources, where the resolver's error ends up.
    fn transport_error(error: &reqwest::Error) -> DeliveryError {
        let retryable = |failure| DeliveryError::Retryable {
            failure,
            retry_after: None,
        };
        let mut source: Option<&(dyn StdError + 'static)> = Some(error);
        while let Some(current) = source {
            if let Some(refused) = current.downcast_ref::<ResolutionError>() {
                return match refused {
                    ResolutionError::Forbidden(_) => {
                        DeliveryError::Permanent(Failure::ForbiddenDestination)
                    }
                    ResolutionError::Lookup(_) => retryable(Failure::Resolution),
                };
            }
            source = current.source();
        }
        if error.is_timeout() {
            retryable(Failure::Timeout)
        } else if error.is_builder() {
            DeliveryError::Permanent(Failure::InvalidDestination)
        } else {
            retryable(Failure::Connection)
        }
    }

    /// Accepts a successful `status`, received at `now` with `headers`, and
    /// classifies any other.
    pub(super) fn check_status(
        status: StatusCode,
        headers: &HeaderMap,
        now: DateTime<Utc>,
    ) -> Result<(), DeliveryError> {
        if status.is_success() {
            Ok(())
        } else if status.is_redirection() {
            Err(DeliveryError::Permanent(Failure::Redirect))
        } else if status.is_server_error()
            || matches!(
                status,
                StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
            )
        {
            Err(DeliveryError::Retryable {
                failure: Failure::Status(status),
                retry_after: Self::retry_after(headers, now),
            })
        } else {
            Err(DeliveryError::Permanent(Failure::Status(status)))
        }
    }

    /// How long `Retry-After` asks to wait from `now`: a number of seconds or an
    /// HTTP date in any of its three formats (RFC 9110 section 10.2.3). Malformed
    /// values are ignored.
    fn retry_after(headers: &HeaderMap, now: DateTime<Utc>) -> Option<Duration> {
        let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
        if let Ok(seconds) = value.parse::<u64>() {
            return Some(Duration::from_secs(seconds));
        }
        let date = DateTime::parse_from_rfc2822(value)
            .map(|date| date.to_utc())
            .ok()
            .or_else(|| {
                OBSOLETE_HTTP_DATES.iter().find_map(|format| {
                    NaiveDateTime::parse_from_str(value, format)
                        .ok()
                        .map(|date| date.and_utc())
                })
            })?;
        Some((date - now).to_std().unwrap_or_default())
    }
}

/// Which addresses a destination may have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reachable {
    /// Only public addresses.
    Public,
    /// Public and loopback addresses, for tests' local servers.
    #[cfg(test)]
    PublicOrLoopback,
}

impl Reachable {
    /// Whether a destination may have `address`; see [`Self::is_public`].
    pub(super) fn allows(self, address: IpAddr) -> bool {
        let public = Self::is_public(address);
        match self {
            Self::Public => public,
            #[cfg(test)]
            Self::PublicOrLoopback => public || address.to_canonical().is_loopback(),
        }
    }

    /// Whether `address` is outside every refused range, and so is the IPv4
    /// address it reaches when it is IPv4-mapped, NAT64 or 6to4.
    fn is_public(address: IpAddr) -> bool {
        match address.to_canonical() {
            IpAddr::V4(v4) => !REFUSED_V4.iter().any(|range| range.contains(&v4)),
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let embedded = if NAT64.contains(&v6) {
                    u32::try_from(bits & 0xffff_ffff).ok()
                } else if SIX_TO_FOUR.contains(&v6) {
                    u32::try_from((bits >> 80) & 0xffff_ffff).ok()
                } else {
                    None
                };
                !REFUSED_V6.iter().any(|range| range.contains(&v6))
                    && embedded.is_none_or(|v4| Self::is_public(IpAddr::V4(v4.into())))
            }
        }
    }
}

/// Resolves names for [`OutboundClient`], failing unless every address is allowed.
struct GuardedResolver(Reachable);

/// Why a destination's name gave no address to connect to.
#[derive(Debug, Error)]
enum ResolutionError {
    /// The name did not resolve.
    #[error("could not resolve destination")]
    Lookup(#[source] std::io::Error),
    /// The name resolved to an address destinations may not have.
    #[error("destination resolves to non-public address {0}")]
    Forbidden(IpAddr),
}

impl Resolve for GuardedResolver {
    /// Resolves `name` once. If any address is not allowed, none is returned, so
    /// a name cannot pass by also resolving to a public address.
    fn resolve(&self, name: Name) -> Resolving {
        let reachable = self.0;
        Box::pin(async move {
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await
                .map_err(ResolutionError::Lookup)?
                .collect();
            if let Some(address) = addresses.iter().find(|a| !reachable.allows(a.ip())) {
                return Err(ResolutionError::Forbidden(address.ip()).into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}
