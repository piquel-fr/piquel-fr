//! The HTTP client for destinations third parties supply, such as a client's
//! back-channel logout URI. A destination must not reach this network: it must be
//! HTTPS, its address public, and redirects are never followed.

use super::{DeliveryError, Failure, SEND_TIMEOUT};
use axum::http::{HeaderMap, Method, StatusCode, header::RETRY_AFTER};
use chrono::{DateTime, Utc};
use reqwest::{
    RequestBuilder, Response,
    dns::{Addrs, Name, Resolve, Resolving},
    redirect,
};
use std::{
    error::Error as StdError,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use url::{Host, Url};

/// The longest connecting to a destination may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Sent with every request.
const USER_AGENT: &str = "piquel-auth";

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
    /// add a body. Returns the response if its status is successful.
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
    ) -> Result<Response, DeliveryError> {
        let url = self.check(destination)?;
        let response = request(self.client.request(method, url))
            .send()
            .await
            .map_err(|error| Self::transport_error(&error))?;
        Self::check_status(response.status(), response.headers(), Utc::now())?;
        Ok(response)
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
    /// HTTP date (RFC 9110 section 10.2.3). Malformed values are ignored.
    fn retry_after(headers: &HeaderMap, now: DateTime<Utc>) -> Option<Duration> {
        let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
        if let Ok(seconds) = value.parse::<u64>() {
            return Some(Duration::from_secs(seconds));
        }
        let date = DateTime::parse_from_rfc2822(value).ok()?;
        Some(
            (date.with_timezone(&Utc) - now)
                .to_std()
                .unwrap_or_default(),
        )
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
    /// Whether a destination may have `address`. Loopback, private, link-local,
    /// unique-local, shared, unspecified, multicast and broadcast addresses are
    /// refused, including IPv4 ones written as IPv4-mapped IPv6.
    pub(super) fn allows(self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        let public = match address {
            IpAddr::V4(v4) => {
                !(v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_multicast()
                    || Self::is_shared(v4))
            }
            IpAddr::V6(v6) => {
                !(v6.is_loopback()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || v6.is_unspecified()
                    || v6.is_multicast())
            }
        };
        match self {
            Self::Public => public,
            #[cfg(test)]
            Self::PublicOrLoopback => public || address.is_loopback(),
        }
    }

    /// Whether `address` is in the carrier-grade NAT range, `100.64.0.0/10`.
    fn is_shared(address: Ipv4Addr) -> bool {
        let [first, second, ..] = address.octets();
        first == 100 && second & 0b1100_0000 == 0b0100_0000
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
