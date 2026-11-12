//! Shared browser-session, passkey confirmation and HTTP trust boundaries.

use crate::keys::StaleKeys;
use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use sourceorigin_common::{
    ErrorChain, HandleError,
    protocol::api::{ErrorBody, ErrorCode},
};
use sourceorigin_repository::DatabaseError;
use std::{borrow::Cow, time::Duration as StdDuration};

/// Where a request came from, which handlers attribute events to.
mod context;
/// Host-only browser cookies.
mod cookie;
/// How the HTTP boundary classifies routes and budgets their requests.
mod endpoint;
/// Origin, proxy, cache, timeout and request-limit policy of each listener.
mod http;
/// The page a navigation's failure shows.
mod page;
/// Browser sessions, their credentials and their extractors.
mod session;

pub(crate) use context::RequestContext;
pub(crate) use cookie::BrowserCookie;
pub(crate) use http::{CacheClass, Cached, FETCH_SITE_HEADER, HttpSecurity, HttpSecurityError};
pub(crate) use page::Explanation;
pub(crate) use session::{Confirmed, Credential, OptionalSession, Session, SessionError, SignedIn};

/// Name of the browser proof required on non-protocol mutations.
pub(crate) const CSRF_HEADER: &str = "x-sourceorigin-csrf";
/// Browser session lifetime, also used by its host cookie.
pub(crate) const SESSION_LIFETIME_DAYS: u32 = 30;
/// How long an admin dashboard session lasts from its sign-in however busy, also
/// used by its host cookie: an unattended browser or a stolen cookie stops working
/// within a working day.
pub(crate) const DASHBOARD_LIFETIME_HOURS: u32 = 12;
/// How long an admin dashboard session lasts without a request.
pub(crate) const DASHBOARD_IDLE_MINUTES: u32 = 30;
pub(crate) use sourceorigin_common::protocol::step_up::CONFIRMATION_MAX_AGE;

/// Browser JSON error `{"error": message}`, plus a machine-readable `code` when the
/// frontend can resolve it. A navigation gets the page saying `message` instead.
/// Internal causes only reach the logs.
#[derive(Debug)]
pub(crate) struct ApiError {
    /// Status code of the error response.
    status: StatusCode,
    /// Non-sensitive explanation shown to the user, specific enough to act on.
    message: Cow<'static, str>,
    /// Stable reason a frontend can react to, serialized next to the message.
    code: Option<ErrorCode>,
    /// When a rate-limited client may try again, sent as `Retry-After`.
    retry_after: Option<StdDuration>,
}

impl ApiError {
    /// An error without a machine-readable code.
    fn new(status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            message: message.into(),
            code: None,
            retry_after: None,
        }
    }

    /// Adds the machine-readable `code` a frontend can resolve the error with.
    pub(crate) fn with_code(mut self, code: ErrorCode) -> Self {
        self.code = Some(code);
        self
    }

    /// What the user is told: the status and the message, as a page shows them.
    pub(crate) fn public(&self) -> (StatusCode, &str) {
        (self.status, &self.message)
    }

    /// Logs a failure with every preserved cause, once, at the HTTP boundary.
    pub(crate) fn log_error(error: &dyn std::error::Error) {
        tracing::error!(error = %ErrorChain(error), "authentication operation failed");
    }

    /// Rejects invalid browser input, explaining what is wrong.
    pub(crate) fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    /// Rejects a request whose body is larger than its route reads.
    pub(crate) fn too_large(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, message)
    }

    /// Reports a missing browser resource.
    pub(crate) fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// Requires the browser to sign in, explaining why its current sign-in is not enough.
    pub(crate) fn unauthorized(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    /// Rejects an operation the browser is not allowed to perform, explaining why.
    pub(crate) fn forbidden(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    /// Tells an application's page to send the user to auth's pages instead,
    /// explaining why.
    pub(crate) fn interaction_required(message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code: Some(ErrorCode::InteractionRequired),
            ..Self::bad_request(message)
        }
    }

    /// Rejects a write that collides with existing data, naming what is already in use.
    pub(crate) fn conflict(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    /// Rejects a request over its rate limit until its window ends.
    pub(crate) fn too_many_requests(
        message: impl Into<Cow<'static, str>>,
        window: StdDuration,
    ) -> Self {
        Self {
            retry_after: Some(window),
            ..Self::new(StatusCode::TOO_MANY_REQUESTS, message)
        }
    }

    /// Refuses a request this replica can't take now, though it or another may in
    /// `retry`: `503`, with `Retry-After`.
    pub(crate) fn busy(message: impl Into<Cow<'static, str>>, retry: StdDuration) -> Self {
        Self {
            retry_after: Some(retry),
            ..Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
        }
    }

    /// Logs why this replica cannot serve the request now and answers `503`, since
    /// another replica, or this one later, may.
    pub(crate) fn unavailable(error: impl std::error::Error) -> Self {
        Self::log_error(&error);
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "The service is unavailable right now. Please try again.",
        )
    }

    /// Logs an internal source chain and returns a generic browser message.
    pub(crate) fn internal(error: impl std::error::Error) -> Self {
        Self::log_error(&error);
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The request could not be completed. Please try again.",
        )
    }
}

impl From<DatabaseError> for ApiError {
    /// Missing rows and conflicts get their own message; other failures are logged 500s.
    fn from(error: DatabaseError) -> Self {
        match error {
            DatabaseError::NotFound => {
                Self::bad_request("This request has expired or is no longer available.")
            }
            DatabaseError::Conflict(_) => Self::conflict("This information is already in use."),
            error @ (DatabaseError::Refused(_)
            | DatabaseError::Timeout(_)
            | DatabaseError::Cancelled(_)
            | DatabaseError::LockUnavailable(_)
            | DatabaseError::InvalidStoredData { .. }
            | DatabaseError::Operation(_)) => Self::internal(error),
        }
    }
}

impl From<StaleKeys> for ApiError {
    /// Stale signing keys are this replica's failure, so another may serve the request.
    fn from(error: StaleKeys) -> Self {
        Self::unavailable(error)
    }
}

impl From<HandleError> for ApiError {
    /// Says how to fix a refused handle, with `handle_invalid` or `handle_reserved`.
    fn from(error: HandleError) -> Self {
        let code = match error {
            HandleError::Length | HandleError::Charset => ErrorCode::HandleInvalid,
            HandleError::Reserved(_) => ErrorCode::HandleReserved,
        };
        Self::bad_request(format!("Choose another handle: {error}.")).with_code(code)
    }
}

impl IntoResponse for ApiError {
    /// Serializes the fixed browser error and adds the retry delay, if any.
    /// The response keeps the message for a navigation's page.
    fn into_response(self) -> Response {
        let message = self.message.into_owned();
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: message.clone(),
                code: self.code,
            }),
        )
            .into_response();
        response.extensions_mut().insert(page::Explanation(message));
        if let Some(retry_after) = self.retry_after {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(retry_after.as_secs()),
            );
        }
        response
    }
}

/// Focused tests for this module and its security contracts, plus shared assertions.
#[cfg(test)]
pub(crate) mod tests;
