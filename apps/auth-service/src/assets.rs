//! Embedded static auth pages and their browser isolation policy.

use crate::{StartupError, security::ApiError};
use axum::{
    body::Body,
    http::{HeaderValue, header},
    response::Response,
};

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

/// Browser isolation policy; `SvelteKit` adds the per-page script hashes in a CSP meta tag.
const CONTENT_SECURITY_POLICY: &str = "frame-ancestors 'none'; object-src 'none'; base-uri 'self'";
/// `SvelteKit` names these files by content hash, allowing a one-year cache lifetime.
const IMMUTABLE_CACHE_POLICY: &str = "public, max-age=31536000, immutable";
/// Prefix of content-addressed `SvelteKit` bundles.
const IMMUTABLE_PREFIX: &str = "/_app/immutable/";

/// Failures of embedded browser asset lookup.
#[derive(Debug, thiserror::Error)]
enum AssetError {
    /// No generated page or static file matches the requested path.
    #[error("embedded asset not found")]
    NotFound,
}
impl From<AssetError> for ApiError {
    /// Keeps missing-page replies in the same JSON shape as other browser errors.
    fn from(error: AssetError) -> Self {
        match error {
            AssetError::NotFound => Self::not_found("Not found."),
        }
    }
}

/// The completed auth frontend embedded in this executable, as public paths and bytes.
#[derive(Clone, Copy)]
pub(crate) struct EmbeddedAssets(&'static [(&'static str, &'static [u8])]);
impl EmbeddedAssets {
    /// Takes the embedded frontend, rejecting executables compiled before it was built.
    pub(crate) fn new() -> Result<Self, StartupError> {
        if FILES.is_empty() {
            Err(StartupError::MissingAssets)
        } else {
            Ok(Self(FILES))
        }
    }

    /// Serves an exact static path or its prerendered HTML page with browser isolation headers.
    pub(crate) fn serve(self, path: &str) -> Result<Response, ApiError> {
        let html = if path == "/" {
            "/index.html".into()
        } else {
            format!("{}.html", path.trim_end_matches('/'))
        };
        let (name, bytes) = self
            .0
            .iter()
            .find(|(name, _)| *name == path || *name == html)
            .ok_or(AssetError::NotFound)?;
        let content_type = match name.rsplit('.').next() {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("svg") => "image/svg+xml",
            Some("json") => "application/json",
            Some("png") => "image/png",
            Some("ico") => "image/x-icon",
            Some("woff2") => "font/woff2",
            _ => "application/octet-stream",
        };
        let mut response = Response::new(Body::from(*bytes));
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        if name.starts_with(IMMUTABLE_PREFIX) {
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(IMMUTABLE_CACHE_POLICY),
            );
        }
        // SvelteKit emits per-page script hashes in a CSP meta tag; frame-ancestors requires a header.
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
        );
        Ok(response)
    }
}
