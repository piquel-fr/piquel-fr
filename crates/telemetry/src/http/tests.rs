//! What the HTTP layer records of a request.
use super::*;
use axum::{body::Body, http::StatusCode, routing::get};
use tower::ServiceExt;

/// Sends `uri` to a router with one route that fails.
async fn send(uri: &str) -> Response {
    let router = HttpTelemetry::default().wrap(Router::new().route(
        "/items/{id}",
        get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
    ));
    router
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response")
}

/// A matched request is named by its route template and never records its
/// query; a failure is marked and returns its trace ID.
#[tokio::test]
async fn spans_name_the_route_and_mark_failures() {
    let capture = Telemetry::capture("info");
    let response = send("/items/secret-id?token=secret-token").await;
    let span = capture.spans().pop().expect("server span");
    assert_eq!(span.name, "GET /items/{id}");
    assert_eq!(
        response.headers()[HttpTelemetry::TRACE_ID_HEADER],
        span.span_context.trace_id().to_string()
    );
    assert!(matches!(
        span.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    let exported = capture.exported_text();
    assert!(exported.contains(&"http.route=/items/{id}".to_owned()));
    assert!(exported.iter().all(|text| !text.contains("secret")));
}

/// An unmatched request records only its path, without the query.
#[tokio::test]
async fn unmatched_requests_record_their_path() {
    let capture = Telemetry::capture("info");
    let response = send("/missing?token=secret-token").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        !response
            .headers()
            .contains_key(HttpTelemetry::TRACE_ID_HEADER)
    );
    let span = capture.spans().pop().expect("server span");
    assert_eq!(span.name, "GET");
    let exported = capture.exported_text();
    assert!(exported.contains(&"url.path=/missing".to_owned()));
    assert!(exported.iter().all(|text| !text.contains("secret")));
}
