//! The stylesheet, typefaces and scripts of auth's pages, and the admin
//! dashboard's script, embedded under paths that never serve other content, so
//! browsers and shared caches keep them forever.

use crate::security::{ApiError, CacheClass, Cached};
use axum::{
    http::header,
    response::{IntoResponse, Response},
};
use sourceorigin_ui::Asset;

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
    /// The stylesheet of auth's pages, `sourceorigin-ui`'s.
    pub(crate) const STYLESHEET: Asset = sourceorigin_ui::STYLESHEET;
    /// The passkey script, which runs the pages' passkey ceremonies.
    pub(crate) const SCRIPT: Asset =
        Asset::script("passkey", include_bytes!("../assets/passkey.js"));
    /// The picture script, which lets the profile's picture form choose its crop.
    pub(crate) const PICTURE_SCRIPT: Asset =
        Asset::script("picture", include_bytes!("../assets/picture.js"));
    /// The scripts every page of auth's own loads.
    pub(crate) const SCRIPTS: [Asset; 2] = [Self::SCRIPT, Self::PICTURE_SCRIPT];
    /// The admin dashboard's script, which confirms it with a passkey in a
    /// dialog on its page. Auth's own pages never load it.
    pub(crate) const DASHBOARD_SCRIPT: Asset =
        Asset::script("dashboard", include_bytes!("../assets/dashboard.js"));
    /// The files the admin dashboard serves too: the stylesheet and the
    /// typefaces it links.
    pub(crate) const SHARED: [Asset; 4] = [
        Self::STYLESHEET,
        sourceorigin_ui::FONTS[0],
        sourceorigin_ui::FONTS[1],
        sourceorigin_ui::FONTS[2],
    ];

    /// Serves the embedded file at exactly `path`. A file's path changes with its
    /// content, or its version, so nothing needs revalidating.
    pub(crate) fn serve(path: &str) -> Result<Response, ApiError> {
        let asset = Self::SHARED
            .into_iter()
            .chain(Self::SCRIPTS)
            .chain([Self::DASHBOARD_SCRIPT])
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

    /// The pages' stylesheet, typefaces and scripts are served at the paths
    /// naming their content or version, as their own type, so they are cached
    /// forever.
    #[test]
    fn the_pages_files_are_immutable() {
        for (asset, content_type) in [
            (EmbeddedAssets::STYLESHEET, "text/css; charset=utf-8"),
            (EmbeddedAssets::SCRIPT, "text/javascript; charset=utf-8"),
            (
                EmbeddedAssets::PICTURE_SCRIPT,
                "text/javascript; charset=utf-8",
            ),
            (
                EmbeddedAssets::DASHBOARD_SCRIPT,
                "text/javascript; charset=utf-8",
            ),
            (sourceorigin_ui::FONTS[0], "font/woff2"),
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
