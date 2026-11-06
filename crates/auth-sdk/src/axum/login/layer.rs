//! The layer around the app's routes: it hands the extractors the request's session
//! state, sets the cookie a refresh or an ended session needs, marks a step-up's
//! return, and redirects [`StepUp`] responses through login.

use super::{Login, SignedIn, StepUp, refresh::Unavailable};
use crate::axum::BoxFuture;
use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, Method, header},
    response::{IntoResponse, Redirect, Response},
};
use std::{
    fmt,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
};
use tokio::sync::OnceCell;
use tower::{Layer, Service};

/// One request's session state, which the layer puts in the request's extensions for
/// the extractors.
pub(super) struct RequestSession {
    /// The login state.
    pub(super) login: Arc<Login>,
    /// Whether the request returns from a step-up login, so it is the retry.
    pub(super) retry: bool,
    /// The session, once an extractor read it, so a request refreshes at most once.
    read: OnceCell<Result<Option<SignedIn>, Unavailable>>,
    /// The `Set-Cookie` the response needs: a refreshed session, or the deletion of
    /// an ended one.
    cookie: Mutex<Option<HeaderValue>>,
}

impl RequestSession {
    /// The signed-in user the request's `headers` name, read and refreshed by the
    /// first extractor that asks.
    pub(super) async fn user(&self, headers: &HeaderMap) -> Result<Option<SignedIn>, Unavailable> {
        self.read
            .get_or_init(|| self.login.session(headers, self))
            .await
            .clone()
    }

    /// Makes the response set `cookie`.
    pub(super) fn set_cookie(&self, cookie: HeaderValue) {
        // Holding the lock cannot leave the value half-written, so poisoning is ignored.
        *self.cookie.lock().unwrap_or_else(PoisonError::into_inner) = Some(cookie);
    }

    /// The `Set-Cookie` the response needs, if any.
    fn take_cookie(&self) -> Option<HeaderValue> {
        self.cookie
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

impl Login {
    /// Turns a [`StepUp`] response to a browser's navigation into a redirect through
    /// login that comes back to `path`. Other requests keep the 401.
    fn step_up(&self, response: Response, navigation: bool, path: &str) -> Response {
        match response.extensions().get::<StepUp>() {
            Some(step_up) if navigation => {
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
        let navigation = Login::navigation(request.method(), request.headers());
        let path = Login::requested(request.extensions(), request.uri());
        // The `GET` a step-up login returns to is its retry, and uses up the marker.
        // Another tab loading the same page within the minute would use it instead.
        let retry = request.method() == Method::GET
            && Login::cookie(request.headers(), &login.cookies.step_up)
                .is_some_and(|marker| marker == Login::step_up_marker(&path));
        let session = Arc::new(RequestSession {
            login: login.clone(),
            retry,
            read: OnceCell::new(),
            cookie: Mutex::new(None),
        });
        request.extensions_mut().insert(session.clone());
        Box::pin(async move {
            let mut response = login.step_up(inner.call(request).await?, navigation, &path);
            let headers = response.headers_mut();
            if let Some(cookie) = session.take_cookie() {
                headers.append(header::SET_COOKIE, cookie);
                // The response is this user's, and carries their session: no shared
                // cache may keep it.
                headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            }
            if retry {
                headers.append(
                    header::SET_COOKIE,
                    Login::clear_cookie(&login.cookies.step_up),
                );
            }
            Ok(response)
        })
    }
}
