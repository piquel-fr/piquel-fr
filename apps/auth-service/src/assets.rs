//! The stylesheet, typefaces and scripts of auth's pages and the admin
//! dashboard's, embedded under paths that never serve other content, so browsers
//! and shared caches keep them forever.

use crate::security::{ApiError, CacheClass, Cached};
use axum::{
    http::header,
    response::{IntoResponse, Response},
};
use piquel_common::config::Origin;
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

/// The files of auth's pages, embedded in this executable. The admin dashboard
/// serves them too, on its own origin.
pub(crate) struct EmbeddedAssets;
impl EmbeddedAssets {
    /// The stylesheet of auth's pages, `piquel-ui`'s.
    pub(crate) const STYLESHEET: Asset = piquel_ui::STYLESHEET;

    /// Every file: the stylesheet, the typefaces it links, and the scripts, Topcoat's
    /// runtime and the expressions it runs.
    pub(crate) fn all() -> [Asset; 6] {
        [
            Self::STYLESHEET,
            piquel_ui::FONTS[0],
            piquel_ui::FONTS[1],
            piquel_ui::FONTS[2],
            piquel_ui::RUNTIME,
            *piquel_ui::EXPRESSIONS,
        ]
    }

    /// The `script-src` of a page on `origin`: the scripts, and nothing a page
    /// holds. A source with a path needs the whole URL: `'self'` names none.
    pub(crate) fn script_src(origin: &Origin) -> String {
        format!(
            "{} {}",
            origin.join(&piquel_ui::RUNTIME.path()),
            origin.join(&piquel_ui::EXPRESSIONS.path()),
        )
    }

    /// Serves the embedded file at exactly `path`. A file's path changes with its
    /// content, or its version, so nothing needs revalidating.
    pub(crate) fn serve(path: &str) -> Result<Response, ApiError> {
        let asset = Self::all()
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

    /// The pages' stylesheet, typefaces and scripts are served at the paths
    /// naming their content or version, as their own type, so they are cached
    /// forever.
    #[test]
    fn the_pages_files_are_immutable() {
        for (asset, content_type) in [
            (EmbeddedAssets::STYLESHEET, "text/css; charset=utf-8"),
            (piquel_ui::RUNTIME, "text/javascript; charset=utf-8"),
            (*piquel_ui::EXPRESSIONS, "text/javascript; charset=utf-8"),
            (piquel_ui::FONTS[0], "font/woff2"),
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
