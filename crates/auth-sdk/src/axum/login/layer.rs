//! The layer around the app's routes: it hands the extractors the login state,
//! marks a step-up's return, and redirects [`StepUp`] responses through login.

use super::{Login, StepUp};
use crate::axum::BoxFuture;
use axum::{
    extract::Request,
    http::{Method, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::TimeDelta;
use std::{
    fmt,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

impl Login {
    /// Turns a [`StepUp`] response to a `GET` into a redirect through login that
    /// comes back to `path`.
    fn step_up(&self, response: Response, method: &Method, path: &str) -> Response {
        match response.extensions().get::<StepUp>() {
            Some(step_up) if method == Method::GET => {
                Redirect::to(&self.login_url(path.parse().ok().as_ref(), Some(step_up.requirement)))
                    .into_response()
            }
            _ => response,
        }
    }
}

/// The layer [`LoginRoutes::layer`](super::LoginRoutes::layer) builds.
#[derive(Clone)]
pub struct LoginLayer(pub(super) Arc<Login>);

impl fmt::Debug for LoginLayer {
    /// Names the layer.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginLayer")
    }
}

impl<S> Layer<S> for LoginLayer {
    type Service = LoginService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoginService {
            inner,
            login: self.0.clone(),
        }
    }
}

/// The service [`LoginLayer`] wraps around a router.
#[derive(Clone)]
pub struct LoginService<S> {
    /// The wrapped service.
    inner: S,
    /// Shared login state.
    login: Arc<Login>,
}

impl<S> fmt::Debug for LoginService<S> {
    /// Names the service.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginService")
    }
}

impl<S> Service<Request> for LoginService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<Result<Response, S::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        // The clone that was polled ready handles this request.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let login = self.login.clone();
        let method = request.method().clone();
        let path = request
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), ToString::to_string);
        // The `GET` a step-up login returns to is its retry, and uses up the marker.
        // Another tab loading the same page within the minute would use it instead.
        let retry = method == Method::GET
            && Login::cookie(request.headers(), &login.cookies.step_up)
                .and_then(|page| URL_SAFE_NO_PAD.decode(page).ok())
                .is_some_and(|page| page == path.as_bytes());
        if retry {
            request.extensions_mut().insert(StepUpRetry);
        }
        request.extensions_mut().insert(login.clone());
        Box::pin(async move {
            let mut response = login.step_up(inner.call(request).await?, &method, &path);
            if retry {
                response.headers_mut().append(
                    header::SET_COOKIE,
                    Login::set_cookie(&login.cookies.step_up, "", TimeDelta::zero()),
                );
            }
            Ok(response)
        })
    }
}

/// Marks a request returning from a step-up login.
#[derive(Clone, Copy)]
pub(super) struct StepUpRetry;
