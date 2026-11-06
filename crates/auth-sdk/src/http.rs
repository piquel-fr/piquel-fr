//! The SDK's HTTP client: its transport policy, bounded bodies, errors that name the
//! URL, and a client span around each request.

use base64::{Engine, engine::general_purpose::STANDARD};
use piquel_common::SendTraced;
use reqwest::{
    RequestBuilder, StatusCode,
    header::{self, HeaderMap},
};
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// Most bytes read from any response. Metadata, key sets and token responses are a
/// few kilobytes.
const MAX_BODY_BYTES: usize = 256 * 1024;
/// Longest a request may take, from connecting to its last body byte, whatever the
/// client's own timeout.
const DEADLINE: Duration = Duration::from_secs(10);

/// Auth could not be reached, or answered outside its protocol.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// The default HTTP client could not be built.
    #[error("could not build the HTTP client")]
    Client(#[source] reqwest::Error),
    /// The request failed, or timed out by the client's own timeout.
    #[error("request to {url} failed")]
    Request {
        /// Where the request went.
        url: Url,
        /// Why it failed.
        #[source]
        source: reqwest::Error,
    },
    /// The request did not finish within the SDK's 10-second deadline.
    #[error("request to {url} took longer than {} seconds", DEADLINE.as_secs())]
    TimedOut {
        /// Where the request went.
        url: Url,
        /// The deadline that passed.
        #[source]
        source: tokio::time::error::Elapsed,
    },
    /// The endpoint redirected. No auth endpoint does, and following would carry
    /// credentials elsewhere, so the SDK never does.
    #[error("{url} redirected with HTTP {status}")]
    Redirected {
        /// Where the request went.
        url: Url,
        /// The redirect status.
        status: u16,
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

/// A response read in full.
pub(crate) struct Reply {
    /// HTTP status.
    pub(crate) status: StatusCode,
    /// How long `Cache-Control` lets the body be kept, in seconds, when it says.
    pub(crate) max_age: Option<u64>,
    /// The body, at most [`MAX_BODY_BYTES`].
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// How long `headers` let a response be kept, in seconds (RFC 9111 §5.2): none with
    /// `no-store` or `no-cache`, whatever else they say, else `max-age`, quoted or not.
    pub(crate) fn max_age(headers: &HeaderMap) -> Option<u64> {
        let mut max_age = None;
        let directives = headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','));
        for directive in directives {
            let (name, value) = directive
                .split_once('=')
                .map_or((directive, None), |(name, value)| (name, Some(value)));
            let name = name.trim();
            if name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("no-cache") {
                return Some(0);
            }
            if name.eq_ignore_ascii_case("max-age") && max_age.is_none() {
                max_age = value.and_then(|value| value.trim().trim_matches('"').parse().ok());
            }
        }
        max_age
    }

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

/// A shared `reqwest` client, held to the SDK's transport policy: `https` only, no
/// redirects, and a 10-second deadline on every request.
#[derive(Clone, Debug)]
pub(crate) struct Http(reqwest::Client);

impl Http {
    /// Builds the client from an application's `builder`, for proxies or extra
    /// trusted roots. Whatever it sets, the client then follows no redirects, since a
    /// 307 or 308 would resend a code or token elsewhere, and refuses any URL but
    /// `https`.
    pub(crate) fn build(builder: reqwest::ClientBuilder) -> Result<Self, NetworkError> {
        Self::without_redirects(builder)
            .https_only(true)
            .build()
            .map(Self)
            .map_err(NetworkError::Client)
    }

    /// Like [`Self::build`] from `builder`, but also reaching `http` URLs, for the
    /// tests' local servers.
    #[cfg(test)]
    pub(crate) fn plain(builder: reqwest::ClientBuilder) -> Self {
        Self(
            Self::without_redirects(builder)
                .build()
                .expect("a test HTTP client"),
        )
    }

    /// `builder`, made to follow no redirects.
    fn without_redirects(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder.redirect(reqwest::redirect::Policy::none())
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

    /// Authenticates, sends and reads a request within the deadline. It is sent in the
    /// `http.client` span of [`SendTraced`], which records only the method, host and
    /// status.
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
        tokio::time::timeout(DEADLINE, Self::read(url, request))
            .await
            .map_err(|source| NetworkError::TimedOut {
                url: url.clone(),
                source,
            })?
    }

    /// Sends a request and reads its response, refusing redirects and bodies over
    /// the limit.
    async fn read(url: &Url, request: RequestBuilder) -> Result<Reply, NetworkError> {
        let failed = |source| NetworkError::Request {
            url: url.clone(),
            source,
        };
        let mut response = request.send_traced().await.map_err(failed)?;
        let status = response.status();
        if status.is_redirection() {
            return Err(NetworkError::Redirected {
                url: url.clone(),
                status: status.as_u16(),
            });
        }
        let max_age = Reply::max_age(response.headers());
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
    }
}
