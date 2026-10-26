//! The stylesheet and passkey script of auth's pages, embedded under paths naming
//! their content, so browsers and shared caches keep them forever.

use crate::security::{ApiError, CacheClass, Cached};
use axum::{
    http::header,
    response::{IntoResponse, Response},
};
use piquel_ui::Asset;

/// Failures of embedded browser asset lookup.
#[derive(Debug, thiserror::Error)]
enum AssetError {
    /// No embedded file is at the requested path.
    #[error("embedded asset not found")]
    NotFound,
}
impl From<AssetError> for ApiError {
    /// Keeps missing-file replies in the same JSON shape as other browser errors.
    fn from(error: AssetError) -> Self {
        match error {
            AssetError::NotFound => Self::not_found("Not found."),
        }
    }
}

/// The files of auth's pages, embedded in this executable.
pub(crate) struct EmbeddedAssets;
impl EmbeddedAssets {
    /// The stylesheet of auth's pages, `piquel-ui`'s.
    pub(crate) const STYLESHEET: Asset = piquel_ui::STYLESHEET;
    /// The passkey script, the one script of auth's pages.
    pub(crate) const SCRIPT: Asset =
        Asset::script("passkey", include_bytes!("../assets/passkey.js"));

    /// Serves the embedded file at exactly `path`. A file's path changes with its
    /// content, so nothing needs revalidating.
    pub(crate) fn serve(path: &str) -> Result<Response, ApiError> {
        let asset = [Self::STYLESHEET, Self::SCRIPT]
            .into_iter()
            .find(|asset| asset.path() == path)
            .ok_or(AssetError::NotFound)?;
        let headers = [(header::CONTENT_TYPE, asset.content_type())];
        Ok(Cached(CacheClass::Immutable, (headers, asset.bytes())).into_response())
    }
}

#[cfg(test)]
mod tests {
    //! Focused coverage of embedded file serving.
    use super::*;

    /// The pages' stylesheet and passkey script are served at the paths naming their
    /// content, as their own type, so they are cached forever.
    #[test]
    fn the_pages_files_are_immutable() {
        for (asset, content_type) in [
            (EmbeddedAssets::STYLESHEET, "text/css; charset=utf-8"),
            (EmbeddedAssets::SCRIPT, "text/javascript; charset=utf-8"),
        ] {
            let response = EmbeddedAssets::serve(&asset.path()).expect("found");
            assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
            assert_eq!(
                response.extensions().get::<CacheClass>(),
                Some(&CacheClass::Immutable)
            );
        }
    }
}
