//! The SDK's HTTP client: bounded bodies, errors that name the URL, and a client span
//! around each request.

use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{RequestBuilder, StatusCode, header};
use std::time::Duration;
use thiserror::Error;
use tracing::{Instrument, field::Empty};
use url::Url;

/// Most bytes read from any response. Metadata, key sets and token responses are a
/// few kilobytes.
const MAX_BODY_BYTES: usize = 256 * 1024;
/// Timeout of the default client.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Auth could not be reached, or answered outside its protocol.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// The default HTTP client could not be built.
    #[error("could not build the HTTP client")]
    Client(#[source] reqwest::Error),
    /// The request failed or timed out.
    #[error("request to {url} failed")]
    Request {
        /// Where the request went.
        url: Url,
        /// Why it failed.
        #[source]
        source: reqwest::Error,
    },
    /// A document endpoint answered with an unexpected status.
    #[error("{url} answered HTTP {status}")]
    Status {
        /// Where the request went.
        url: Url,
        /// The status received.
        status: u16,
    },
    /// The response body exceeds the SDK's limit.
    #[error("{url} sent more than {MAX_BODY_BYTES} bytes")]
    TooLarge {
        /// Where the request went.
        url: Url,
    },
}

impl NetworkError {
    /// Whether the request never reached the server: the client could not be built,
    /// or the connection could not be opened. Only the axum login routes ask.
    #[cfg(feature = "axum")]
    pub(crate) fn unsent(&self) -> bool {
        match self {
            Self::Client(_) => true,
            Self::Request { source, .. } => source.is_connect(),
            Self::Status { .. } | Self::TooLarge { .. } => false,
        }
    }
}

/// A response read in full.
pub(crate) struct Reply {
    /// HTTP status.
    pub(crate) status: StatusCode,
    /// `Cache-Control: max-age`, in seconds, when present.
    pub(crate) max_age: Option<u64>,
    /// The body, at most [`MAX_BODY_BYTES`].
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// Requires `200 OK`, as document endpoints answer.
    pub(crate) fn ok(self, url: &Url) -> Result<Self, NetworkError> {
        if self.status == StatusCode::OK {
            Ok(self)
        } else {
            Err(NetworkError::Status {
                url: url.clone(),
                status: self.status.as_u16(),
            })
        }
    }
}

/// How a request authenticates.
pub(crate) enum Authorization<'a> {
    /// No credentials.
    None,
    /// An access token.
    Bearer(&'a str),
    /// A confidential client's ID and secret.
    Basic(&'a str, &'a str),
}

/// A shared `reqwest` client.
#[derive(Clone, Debug)]
pub(crate) struct Http(reqwest::Client);

impl Http {
    /// Wraps an application's client.
    pub(crate) const fn new(client: reqwest::Client) -> Self {
        Self(client)
    }

    /// The default client: a 10-second timeout, and no redirects, since no auth
    /// endpoint redirects and a redirect would carry credentials elsewhere.
    pub(crate) fn default_client() -> Result<Self, NetworkError> {
        reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map(Self)
            .map_err(NetworkError::Client)
    }

    /// Sends a `GET`.
    pub(crate) async fn get(
        &self,
        url: &Url,
        authorization: Authorization<'_>,
    ) -> Result<Reply, NetworkError> {
        self.send(url, self.0.get(url.clone()), authorization).await
    }

    /// Sends a form `POST`.
    pub(crate) async fn post_form(
        &self,
        url: &Url,
        form: &[(&str, &str)],
        authorization: Authorization<'_>,
    ) -> Result<Reply, NetworkError> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let request = self
            .0
            .post(url.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body);
        self.send(url, request, authorization).await
    }

    /// Authenticates, sends and reads a request in an `http.client` span. Like auth's
    /// own client spans, it records only the method, host and status: never the path,
    /// query, headers or body, which carry codes and tokens. A failure or 4xx/5xx
    /// status marks it failed.
    async fn send(
        &self,
        url: &Url,
        request: RequestBuilder,
        authorization: Authorization<'_>,
    ) -> Result<Reply, NetworkError> {
        let request = match authorization {
            Authorization::None => request,
            Authorization::Bearer(token) => request.bearer_auth(token),
            // RFC 6749 §2.3.1 form-encodes the ID and secret before base64.
            Authorization::Basic(id, secret) => {
                let encode = |value: &str| {
                    url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
                };
                let credentials = STANDARD.encode(format!("{}:{}", encode(id), encode(secret)));
                request.header(header::AUTHORIZATION, format!("Basic {credentials}"))
            }
        };
        let failed = |source| NetworkError::Request {
            url: url.clone(),
            source,
        };
        let request = request.build().map_err(failed)?;
        let method = request.method().as_str();
        let span = tracing::info_span!(
            "http.client",
            otel.name = method,
            otel.kind = "client",
            otel.status_code = Empty,
            http.request.method = method,
            server.address = url.host_str(),
            http.response.status_code = Empty,
        );
        let exchange = async {
            let mut response = self.0.execute(request).await.map_err(failed)?;
            let status = response.status();
            span.record("http.response.status_code", status.as_u16());
            if status.is_client_error() || status.is_server_error() {
                span.record("otel.status_code", "ERROR");
            }
            let max_age = response
                .headers()
                .get_all(header::CACHE_CONTROL)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .find_map(|directive| directive.trim().strip_prefix("max-age=")?.parse().ok());
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(failed)? {
                if body.len() + chunk.len() > MAX_BODY_BYTES {
                    return Err(NetworkError::TooLarge { url: url.clone() });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Reply {
                status,
                max_age,
                body,
            })
        };
        let reply = exchange.instrument(span.clone()).await;
        if reply.is_err() {
            span.record("otel.status_code", "ERROR");
        }
        reply
    }
}
