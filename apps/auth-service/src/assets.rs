use axum::{
    body::Body,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
include!(concat!(env!("OUT_DIR"), "/assets.rs"));
pub(crate) async fn serve(uri: Uri) -> Response {
    let path = uri.path();
    let html = if path == "/" {
        "/index.html".into()
    } else {
        format!("{}.html", path.trim_end_matches('/'))
    };
    let Some((name, bytes)) = FILES
        .iter()
        .find(|(name, _)| *name == path || *name == html)
    else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error":"Not found."})),
        )
            .into_response();
    };
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
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type.parse().expect("static content type"),
    );
    // SvelteKit emits per-page script hashes in a CSP meta tag; frame-ancestors requires a header.
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        "frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
            .parse()
            .expect("static CSP"),
    );
    response
}
