//! Bearer token validation: a layer that validates once, and extractors that check
//! what each handler needs.

use super::BoxFuture;
use crate::{AccessToken, AuthenticationPolicy, ResourceValidator, ScopeSet, Scopes, TokenError};
use axum::{
    extract::{FromRequestParts, Request},
    http::{HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use piquel_common::protocol::challenge::{BearerChallenge, BearerError};
use serde::de::DeserializeOwned;
use std::{
    future::Future,
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use url::Url;

/// What the layer found in `Authorization`, stored in request extensions.
struct Bearer<X> {
    /// Validator for the resource, for checks that need its clock.
    validator: ResourceValidator<X>,
    /// What `Authorization` held.
    outcome: Outcome<X>,
}

/// What `Authorization` held, for the extractors to judge.
enum Outcome<X> {
    /// No bearer token; other schemes count as none.
    Missing,
    /// A Bearer header with no credentials, or several `Authorization` headers.
    Malformed,
    /// A bearer token, and its validation result.
    Validated(Result<Box<AccessToken<Scopes, X>>, Arc<TokenError>>),
}

/// Validates the request's bearer token once, for the extractors to read. A request
/// without a token passes through, so public routes can share the router; only the
/// extractors reject. Tokens are read from `Authorization: Bearer` only, never from
/// the query string.
///
/// ```no_run
/// # async fn run(issuer: piquel_auth::Issuer) -> Result<(), Box<dyn std::error::Error>> {
/// use axum::{Router, routing::get};
/// use piquel_auth::{
///     Resource,
///     axum::{Authenticated, BearerLayer},
/// };
///
/// /// Application claims some tokens carry.
/// #[derive(Clone, serde::Deserialize)]
/// struct Tenant {
///     tenant: String,
/// }
///
/// async fn status() -> &'static str {
///     "public: no token needed"
/// }
///
/// async fn whoami(Authenticated(token): Authenticated<Tenant>) -> String {
///     format!("{:?} in {}", token.subject, token.extra.tenant)
/// }
///
/// let validator = issuer
///     .resource(Resource::new("notes-api")?)
///     .with_claims::<Tenant>();
/// let app: Router = Router::new()
///     .route("/status", get(status))
///     .route("/me", get(whoami))
///     .layer(BearerLayer::new(validator));
/// # Ok(()) }
/// ```
pub struct BearerLayer<X = ()>(ResourceValidator<X>);

impl<X> Clone for BearerLayer<X> {
    /// Shares the validator.
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<X> BearerLayer<X> {
    /// Validates tokens with `validator`.
    #[must_use]
    pub const fn new(validator: ResourceValidator<X>) -> Self {
        Self(validator)
    }
}

impl<S, X> Layer<S> for BearerLayer<X> {
    type Service = BearerService<S, X>;

    fn layer(&self, inner: S) -> Self::Service {
        BearerService {
            inner,
            validator: self.0.clone(),
        }
    }
}

/// The service [`BearerLayer`] wraps around a router.
pub struct BearerService<S, X = ()> {
    /// The wrapped service.
    inner: S,
    /// Validator for the resource.
    validator: ResourceValidator<X>,
}

impl<S: Clone, X> Clone for BearerService<S, X> {
    /// Clones the inner service and shares the validator.
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            validator: self.validator.clone(),
        }
    }
}

impl<S, X> Service<Request> for BearerService<S, X>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
    X: DeserializeOwned + Clone + Send + Sync + 'static,
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
        let validator = self.validator.clone();
        Box::pin(async move {
            let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
            // Other schemes pass through as no token; a malformed Bearer header, or
            // several headers, is a bad request to the extractors only, so public
            // routes still answer.
            let outcome = match (values.next(), values.next()) {
                (Some(value), None) => match value.to_str() {
                    Err(_) => Outcome::Malformed,
                    Ok(value) => {
                        let (scheme, credentials) = value.split_once(' ').unwrap_or((value, ""));
                        match scheme
                            .eq_ignore_ascii_case("Bearer")
                            .then(|| credentials.trim())
                        {
                            None => Outcome::Missing,
                            Some("") => Outcome::Malformed,
                            Some(token) => Outcome::Validated(
                                validator
                                    .validate::<Scopes>(token)
                                    .await
                                    .map(Box::new)
                                    .map_err(Arc::new),
                            ),
                        }
                    }
                },
                (None, _) => Outcome::Missing,
                (Some(_), Some(_)) => Outcome::Malformed,
            };
            request
                .extensions_mut()
                .insert(Arc::new(Bearer { validator, outcome }));
            inner.call(request).await
        })
    }
}

/// Why a bearer extractor rejected the request.
#[derive(Debug)]
enum Reason {
    /// No bearer token was sent; names the scopes the handler needs, if any.
    Missing(Option<Scopes>),
    /// The token failed validation, lacks a scope, or its authentication is too weak
    /// or too old.
    Token(Arc<TokenError>),
    /// `Authorization` was malformed, or sent more than once.
    InvalidRequest,
    /// The handler uses a bearer extractor on a route without [`BearerLayer`].
    MissingLayer,
}

/// A bearer extractor's rejection. Answers with the status and `WWW-Authenticate`
/// challenge of RFC 6750 §3 or RFC 9470 §3, with `resource_metadata` when the
/// [`Resource`](crate::Resource) names it, and an empty body. When signing keys
/// cannot be fetched it answers 503 without a challenge: that failure is the
/// server's, not the client's.
///
/// Take the extractor as a `Result` to see a rejection before answering with it:
///
/// ```no_run
/// use axum::response::{IntoResponse, Response};
/// use piquel_auth::axum::{AuthRejection, Authenticated};
///
/// async fn audited(token: Result<Authenticated, AuthRejection>) -> Response {
///     match token {
///         Ok(Authenticated(token)) => format!("{:?}", token.subject).into_response(),
///         Err(rejection) => {
///             if let Some(error) = rejection.token_error() {
///                 eprintln!("refused a token: {error}");
///             }
///             rejection.into_response()
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct AuthRejection {
    /// Why the request was rejected.
    reason: Reason,
    /// The resource's metadata URL, added to the challenge.
    metadata: Option<Url>,
}

impl AuthRejection {
    /// A rejection for `reason`, by the resource `validator` protects.
    fn new<X>(reason: Reason, validator: Option<&ResourceValidator<X>>) -> Self {
        Self {
            reason,
            metadata: validator.and_then(|validator| validator.resource().metadata().cloned()),
        }
    }

    /// The token error behind the rejection, if any.
    #[must_use]
    pub fn token_error(&self) -> Option<&TokenError> {
        match &self.reason {
            Reason::Token(error) => Some(error),
            Reason::Missing(_) | Reason::InvalidRequest | Reason::MissingLayer => None,
        }
    }

    /// The challenge to send; `None` for server failures.
    #[must_use]
    pub fn challenge(&self) -> Option<BearerChallenge> {
        let challenge = match &self.reason {
            Reason::Missing(scope) => Some(BearerChallenge {
                scope: scope.clone(),
                ..BearerChallenge::default()
            }),
            Reason::Token(error) => error.challenge(),
            Reason::InvalidRequest => Some(BearerChallenge::error(BearerError::InvalidRequest)),
            Reason::MissingLayer => None,
        };
        challenge.map(|challenge| BearerChallenge {
            resource_metadata: self.metadata.clone(),
            ..challenge
        })
    }

    /// The status to send.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match (&self.reason, self.challenge()) {
            (Reason::MissingLayer, _) => StatusCode::INTERNAL_SERVER_ERROR,
            (_, None) => StatusCode::SERVICE_UNAVAILABLE,
            (_, Some(challenge)) => {
                StatusCode::from_u16(challenge.status()).unwrap_or(StatusCode::UNAUTHORIZED)
            }
        }
    }
}

impl IntoResponse for AuthRejection {
    /// Sends the status and challenge.
    fn into_response(self) -> Response {
        let status = self.status();
        match &self.reason {
            Reason::MissingLayer => {
                tracing::error!("bearer extractors need BearerLayer around the route");
            }
            Reason::Token(error) if status.is_server_error() => {
                tracing::error!(error = %ErrorChain(error.as_ref()), "bearer validation failed");
            }
            Reason::Missing(_) | Reason::Token(_) | Reason::InvalidRequest => {}
        }
        let mut response = status.into_response();
        if let Some(value) = self
            .challenge()
            .and_then(|challenge| HeaderValue::try_from(challenge.to_string()).ok())
        {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

/// Formats an error with its sources, for logs.
pub(super) struct ErrorChain<'a>(pub(super) &'a (dyn std::error::Error + 'a));

impl std::fmt::Display for ErrorChain<'_> {
    /// Writes the error, then each source after `: `.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(cause) = source {
            write!(formatter, ": {cause}")?;
            source = cause.source();
        }
        Ok(())
    }
}

/// Reads the layer's result for an extractor requiring `scope`.
fn token<X: Clone + Send + Sync + 'static>(
    parts: &Parts,
    scope: Option<Scopes>,
) -> Result<(AccessToken<Scopes, X>, &ResourceValidator<X>), AuthRejection> {
    let bearer = parts
        .extensions
        .get::<Arc<Bearer<X>>>()
        .ok_or_else(|| AuthRejection::new::<X>(Reason::MissingLayer, None))?;
    let validator = &bearer.validator;
    match &bearer.outcome {
        Outcome::Missing => Err(AuthRejection::new(Reason::Missing(scope), Some(validator))),
        Outcome::Malformed => Err(AuthRejection::new(Reason::InvalidRequest, Some(validator))),
        Outcome::Validated(Err(error)) => Err(AuthRejection::new(
            Reason::Token(error.clone()),
            Some(validator),
        )),
        Outcome::Validated(Ok(token)) => Ok((token.as_ref().clone(), validator)),
    }
}

/// A validated access token. Rejects with 401 when none was sent, or when it is
/// invalid.
///
/// ```no_run
/// use piquel_auth::axum::Authenticated;
///
/// async fn whoami(Authenticated(token): Authenticated) -> String {
///     format!("{:?}", token.subject)
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Authenticated<X = ()>(pub AccessToken<Scopes, X>);

impl<St: Send + Sync, X: Clone + Send + Sync + 'static> FromRequestParts<St> for Authenticated<X> {
    type Rejection = AuthRejection;

    fn from_request_parts(
        parts: &mut Parts,
        _: &St,
    ) -> impl Future<Output = Result<Self, AuthRejection>> + Send {
        std::future::ready(token(parts, None).map(|(token, _)| Self(token)))
    }
}

/// A validated access token holding the scopes `S`. Rejects with 401 naming `S` when
/// no token was sent, and with 403 `insufficient_scope` naming `S` when it lacks one.
///
/// ```no_run
/// piquel_auth::scopes! {
///     pub mod notes {
///         Read = "notes:read",
///         Write = "notes:write",
///     }
/// }
/// use piquel_auth::axum::Scoped;
///
/// async fn edit(Scoped(token): Scoped<(notes::Read, notes::Write)>) {}
/// ```
#[derive(Clone, Debug)]
pub struct Scoped<S, X = ()>(pub AccessToken<S, X>);

impl<St: Send + Sync, S: ScopeSet, X: Clone + Send + Sync + 'static> FromRequestParts<St>
    for Scoped<S, X>
{
    type Rejection = AuthRejection;

    fn from_request_parts(
        parts: &mut Parts,
        _: &St,
    ) -> impl Future<Output = Result<Self, AuthRejection>> + Send {
        std::future::ready(
            token(parts, Some(S::required())).and_then(|(token, validator)| {
                token.require::<S>().map(Self).map_err(|error| {
                    AuthRejection::new(Reason::Token(Arc::new(error)), Some(validator))
                })
            }),
        )
    }
}

/// A validated access token whose authentication meets the policy `P`. Rejects with
/// 401 `insufficient_user_authentication`, naming `P`'s `acr_values` and `max_age`,
/// so the client can sign the user in again (RFC 9470). `phr` meets a social
/// requirement, as auth judges it.
///
/// ```no_run
/// use piquel_auth::{AuthenticationPolicy, StepUpRequirement, axum::RequireAuthentication};
///
/// /// A passkey confirmation within the last five minutes.
/// struct RecentPasskey;
///
/// impl AuthenticationPolicy for RecentPasskey {
///     const REQUIREMENT: StepUpRequirement = StepUpRequirement::passkey_within(300);
/// }
///
/// async fn delete_account(RequireAuthentication(token, ..): RequireAuthentication<RecentPasskey>) {}
/// ```
#[derive(Clone, Debug)]
pub struct RequireAuthentication<P, X = ()>(pub AccessToken<Scopes, X>, pub PhantomData<P>);

impl<St, P, X> FromRequestParts<St> for RequireAuthentication<P, X>
where
    St: Send + Sync,
    P: AuthenticationPolicy,
    X: Clone + Send + Sync + 'static,
{
    type Rejection = AuthRejection;

    fn from_request_parts(
        parts: &mut Parts,
        _: &St,
    ) -> impl Future<Output = Result<Self, AuthRejection>> + Send {
        std::future::ready(token(parts, None).and_then(|(token, validator)| {
            token
                .require_authentication(P::REQUIREMENT, validator.now())
                .map_err(|error| {
                    AuthRejection::new(Reason::Token(Arc::new(error)), Some(validator))
                })?;
            Ok(Self(token, PhantomData))
        }))
    }
}
