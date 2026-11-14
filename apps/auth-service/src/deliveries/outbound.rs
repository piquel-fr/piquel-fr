//! The HTTP client for destinations third parties supply, such as a client's
//! back-channel logout URI. A destination must not reach this network: it must be
//! HTTPS, its address public, and redirects are never followed.

use super::{DeliveryError, Failure, SEND_TIMEOUT};
use axum::http::{
    HeaderMap, Method, StatusCode,
    header::{ACCEPT, RETRY_AFTER},
};
use chrono::{DateTime, NaiveDateTime, Utc};
use reqwest::{
    RequestBuilder,
    dns::{Addrs, Name, Resolve, Resolving},
    redirect,
};
use sourceorigin_common::net::PublicAddress;
use sourceorigin_telemetry::SendTraced;
use std::{
    error::Error as StdError,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use url::{Host, Url};

/// The longest connecting to a destination may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Sent with every request.
const USER_AGENT: &str = "sourceorigin-auth";
/// The obsolete HTTP-date formats receivers must still accept (RFC 9110 section
/// 5.6.7): RFC 850 and C's `asctime`. The preferred format is RFC 2822's.
const OBSOLETE_HTTP_DATES: [&str; 2] = ["%A, %d-%b-%y %H:%M:%S GMT", "%a %b %e %H:%M:%S %Y"];

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
    /// add a body, and succeeds as soon as a successful status arrives. The
    /// response's body is never read, so a receiver that stalls after its headers
    /// cannot turn an accepted request into a timeout.
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
    ) -> Result<(), DeliveryError> {
        self.request(method, destination, request).await.map(drop)
    }

    /// Fetches `destination` with `GET`, as [`Self::send`] sends, asking for the
    /// media types `accept` names, and returns at most `limit` bytes of its body:
    /// a file a third party names, such as a provider's profile picture.
    ///
    /// # Errors
    ///
    /// As [`Self::send`], and, while the body is read, a timeout or a broken
    /// connection is retryable as well.
    pub(crate) async fn get(
        &self,
        destination: &str,
        accept: &str,
        limit: usize,
    ) -> Result<Vec<u8>, DeliveryError> {
        let mut response = self
            .request(Method::GET, destination, |request| {
                request.header(ACCEPT, accept)
            })
            .await?;
        let mut body = Vec::new();
        while body.len() < limit
            && let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| Self::transport_error(&error))?
        {
            let room = limit - body.len();
            body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
        Ok(body)
    }

    /// [`Self::send`], returning the successful response with its body unread.
    async fn request(
        &self,
        method: Method,
        destination: &str,
        request: impl FnOnce(RequestBuilder) -> RequestBuilder,
    ) -> Result<reqwest::Response, DeliveryError> {
        let url = self.check(destination)?;
        let response = request(self.client.request(method, url))
            .send_traced()
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
    /// Whether a destination may have `address`: a public one
    /// ([`PublicAddress::is_public`]).
    pub(super) fn allows(self, address: IpAddr) -> bool {
        let public = address.is_public();
        match self {
            Self::Public => public,
            #[cfg(test)]
            Self::PublicOrLoopback => public || address.to_canonical().is_loopback(),
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
