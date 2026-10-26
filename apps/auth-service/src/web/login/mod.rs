//! The sign-in pages, `/login` and `/register`: signing in, creating an account,
//! and linking a provider's sign-in to an existing account.
//!
//! Neither is an [`AccountPage`](super::account::AccountPage): they serve browsers
//! that are not signed in. Their `GET` finds the [`Step`] the browser is at, from
//! the query, the provider's sign-in pending in the browser and its session. Their
//! `POST` makes the change its form names, then sends the browser where the
//! [`Continuation`] says, which the server alone decides. A change the service
//! refuses renders the page again, saying why.

use super::{Failure, WebApplication};
use crate::{
    account::Viewer,
    federation::{FederationError, PendingView, ReturnTo},
    oidc::{OAuthError, OidcApplication, TransactionQuery},
    passkey::PasskeyApplication,
    routes,
    security::{ApiError, BrowserCookie, Session, SessionError},
};
use axum::extract::Query as UriQuery;
use piquel_common::{events::RevocationReason, protocol::claims::Acr};
use piquel_repository::StoredAuthorizationRequest;
use piquel_ui::{
    Area, CallbackError, LinkKind, LoginChange, LoginQuery, Onward, Query, QueryError, SignedIn,
    Step, Title,
};
use topcoat::{
    Error,
    context::{Cx, app_context},
    router::{
        Body, StatusCode, Uri,
        error::see_other,
        parse_query_params,
        request::{headers, uri},
        response::{IntoResponse, Response},
    },
    view::view,
};
use url::Url;

#[cfg(test)]
mod tests;

/// Which sign-in page the browser opened, which says what it asks of a browser no
/// provider's sign-in waits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SignInPage {
    /// `/login`: signing in.
    Login,
    /// `/register`: creating an account.
    Register,
}

impl SignInPage {
    /// Its route.
    pub(super) const fn path(self) -> &'static str {
        match self {
            Self::Login => routes::page::LOGIN,
            Self::Register => routes::page::REGISTER,
        }
    }

    /// Its title in the browser, when it cannot render or sends the browser on.
    pub(super) const fn title(self) -> &'static str {
        match self {
            Self::Login => Title::SignIn.as_str(),
            Self::Register => Title::SignUp.as_str(),
        }
    }
}

/// Where a sign-in page sends the browser once it is done.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Continuation {
    /// On to the application whose pending authorization, by this token, the
    /// sign-in continues.
    Authorization(String),
    /// To this path on auth.
    Path(ReturnTo),
}

impl Continuation {
    /// Where the page's `query` and the path the browser's pending provider sign-in
    /// returns to, if any, say to go: the query's authorization, else the pending
    /// path, else the query's.
    fn new(query: &LoginQuery, pending: Option<&str>) -> Self {
        match &query.transaction {
            Some(transaction) => Self::Authorization(transaction.clone()),
            None => Self::parse(pending.or(query.return_to.as_deref())),
        }
    }

    /// The continuation `return_to` names: the authorization it resumes, when it is
    /// the path resuming one, or the path. One that is not a path on auth, or none,
    /// is the account's settings.
    fn parse(return_to: Option<&str>) -> Self {
        let path = ReturnTo::parse(return_to).unwrap_or_default();
        let resumed = path
            .as_str()
            .parse::<Uri>()
            .ok()
            .filter(|uri| uri.path() == routes::oidc::AUTHORIZE_RESUME)
            .and_then(|uri| UriQuery::<TransactionQuery>::try_from_uri(&uri).ok());
        match resumed {
            Some(UriQuery(query)) => Self::Authorization(query.transaction),
            None => Self::Path(path),
        }
    }

    /// The path on auth that goes on to it, which a provider's sign-in returns to:
    /// the path resuming the authorization, or the path.
    fn return_to(&self) -> Result<String, QueryError> {
        match self {
            Self::Authorization(transaction) => TransactionQuery {
                transaction: transaction.clone(),
            }
            .on(routes::oidc::AUTHORIZE_RESUME),
            Self::Path(path) => Ok(path.as_str().to_owned()),
        }
    }

    /// The pending authorization it continues, if any, as `oidc` stores it, and
    /// where its application receives the browser.
    async fn authorization(
        &self,
        oidc: &OidcApplication,
    ) -> Result<Option<(StoredAuthorizationRequest, Url)>, OAuthError> {
        let Self::Authorization(transaction) = self else {
            return Ok(None);
        };
        let request = oidc.find_authorization_request(transaction).await?;
        let client = Url::parse(&request.redirect_uri)?;
        Ok(Some((request, client)))
    }

    /// `query`, naming this continuation as the sign-in pages do. The settings, where
    /// signing in goes by default, need no name.
    fn on(&self, query: LoginQuery) -> LoginQuery {
        let (transaction, return_to) = match self {
            Self::Authorization(transaction) => (Some(transaction.clone()), None),
            Self::Path(path) => (
                None,
                (*path != ReturnTo::default()).then(|| path.as_str().to_owned()),
            ),
        };
        LoginQuery {
            transaction,
            return_to,
            ..query
        }
    }
}

/// What a sign-in page knows of the browser it serves.
struct Visit {
    /// The page's query.
    query: LoginQuery,
    /// The provider's sign-in pending in the browser, read when the query says one
    /// waits.
    pending: Option<Result<PendingView, FederationError>>,
    /// Where the browser goes once done.
    continuation: Continuation,
}

impl Visit {
    /// What `web` knows of the browser requesting the sign-in page `cx` serves. A
    /// query that does not parse at all, from an edited link, names nothing.
    async fn new(web: &WebApplication, cx: &Cx) -> Self {
        let query: LoginQuery = parse_query_params(cx).unwrap_or_default();
        let pending = match query.social {
            Some(_) => Some(web.federation.pending(headers(cx)).await),
            None => None,
        };
        let returns = pending
            .as_ref()
            .and_then(|pending| pending.as_ref().ok())
            .map(|pending| pending.return_to.as_str());
        let continuation = Continuation::new(&query, returns);
        Self {
            query,
            pending,
            continuation,
        }
    }
}

/// Why a change on a sign-in page did not send the browser on.
enum Refusal {
    /// The service refused it: the page renders again, saying why.
    Alert(ApiError),
    /// The page cannot go on.
    Failure(Failure),
}

impl From<ApiError> for Refusal {
    /// The page says why.
    fn from(error: ApiError) -> Self {
        Self::Alert(error)
    }
}

impl From<Failure> for Refusal {
    /// The page explains it instead.
    fn from(failure: Failure) -> Self {
        Self::Failure(failure)
    }
}

impl From<Error> for Refusal {
    /// An internal failure.
    fn from(error: Error) -> Self {
        Self::Failure(error.into())
    }
}

impl From<QueryError> for Refusal {
    /// An internal failure.
    fn from(error: QueryError) -> Self {
        Self::Failure(error.into())
    }
}

impl WebApplication {
    /// `GET` of the sign-in page `page`: the step the browser is at.
    pub(super) async fn sign_in(cx: &Cx, page: SignInPage) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        web.sign_in_page(cx, page, Visit::new(web, cx).await, None)
            .await
    }

    /// `POST` of the sign-in page `page`: makes the change its form names, then
    /// sends the browser on, or renders the page again with why it was refused. A
    /// form from an older page that does not decode changes nothing.
    pub(super) async fn sign_in_change(
        cx: &Cx,
        page: SignInPage,
        body: Body,
    ) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let visit = Visit::new(web, cx).await;
        let refused = match Self::change::<LoginChange>(cx, body).await {
            Some(change) => match web.make(cx, page, visit, change).await {
                Ok(response) => return Ok(response),
                Err(Refusal::Failure(failure)) => return Err(failure),
                Err(Refusal::Alert(error)) => error,
            },
            None => ApiError::bad_request(piquel_ui::OUT_OF_DATE),
        };
        web.sign_in_page(cx, page, Visit::new(web, cx).await, Some(refused))
            .await
    }

    /// Makes `change`, posted to `page` on the `visit`, and answers where the
    /// browser goes next.
    async fn make(
        &self,
        cx: &Cx,
        page: SignInPage,
        visit: Visit,
        change: LoginChange,
    ) -> Result<Response, Refusal> {
        let mut response = match change {
            // The SDK signed the browser in before posting.
            LoginChange::SignedIn {} | LoginChange::Registered {} => {
                return Ok(self.go_on(cx, page, visit.continuation).await?);
            }
            LoginChange::Social { provider } => {
                let authorization = visit
                    .continuation
                    .authorization(&self.oidc)
                    .await
                    .map_err(Failure::from)?;
                let return_to = visit.continuation.return_to()?;
                let (to, cookie) = self
                    .federation
                    .start_sign_in(provider, &return_to)
                    .await
                    .map_err(ApiError::from)?;
                // A provider the user already allowed sends the browser straight back,
                // and on to the application, which this form's `form-action` may not
                // name: then the browser follows a link to the provider instead.
                let mut response = match authorization {
                    Some((_, client)) if Self::source(&client).is_none() => {
                        self.link(cx, page.title(), &to, Onward::Provider(provider))
                            .await?
                    }
                    _ => see_other(to.as_str()).into_response(cx)?,
                };
                cookie.set_on(&mut response).map_err(Error::from)?;
                return Ok(response);
            }
            LoginChange::Link {} => {
                let owner = self
                    .owner(cx)
                    .await?
                    .ok_or_else(|| ApiError::from(SessionError::Missing))?;
                let pending = BrowserCookie::FederationPending
                    .read(headers(cx))
                    .ok_or_else(|| ApiError::from(FederationError::PendingBrowserMissing))?;
                let return_to = self
                    .account
                    .link_identity(&owner, &pending)
                    .await
                    .map_err(ApiError::from)?;
                let continuation = Continuation::new(&visit.query, Some(&return_to));
                self.go_on(cx, page, continuation).await?
            }
            // An explicit link goes back to where it started; an email match offers
            // to sign in before going on.
            LoginChange::CancelLink {} => {
                let pending = visit
                    .pending
                    .unwrap_or(Err(FederationError::PendingBrowserMissing))
                    .map_err(ApiError::from)?;
                self.federation
                    .cancel_pending(headers(cx))
                    .await
                    .map_err(ApiError::from)?;
                match pending.kind.link() {
                    Some(LinkKind::Explicit) => self.go_on(cx, page, visit.continuation).await?,
                    Some(LinkKind::Email) | None => {
                        let sign_in = visit
                            .continuation
                            .on(LoginQuery::default())
                            .on(routes::page::LOGIN)?;
                        see_other(sign_in).into_response(cx)?
                    }
                }
            }
            // Signed out, the page offers to sign in to another account.
            LoginChange::SwitchAccount {} => {
                Session::sign_out(
                    &self.account.database,
                    Self::context(cx)?,
                    headers(cx),
                    RevocationReason::Logout,
                )
                .await
                .map_err(ApiError::from)?;
                let here = uri(cx)
                    .path_and_query()
                    .map_or(page.path(), |here| here.as_str());
                let mut response = see_other(here).into_response(cx)?;
                BrowserCookie::Session
                    .clear_on(&mut response)
                    .map_err(Error::from)?;
                return Ok(response);
            }
        };
        BrowserCookie::FederationPending
            .clear_on(&mut response)
            .map_err(Error::from)?;
        Ok(response)
    }

    /// Sends the browser on to `continuation` from `page`, once it signed in: to
    /// the path, or on through the authorization, which the page continues
    /// in-process, so that its `form-action` governs the redirect to the
    /// application, or links there when it cannot.
    async fn go_on(
        &self,
        cx: &Cx,
        page: SignInPage,
        continuation: Continuation,
    ) -> Result<Response, Failure> {
        match continuation {
            Continuation::Authorization(transaction) => {
                let next = self
                    .oidc
                    .continue_authorization(Self::context(cx)?, headers(cx), transaction)
                    .await?;
                Ok(self.onward(cx, page.title(), &next).await?)
            }
            Continuation::Path(path) => Ok(see_other(path.as_str()).into_response(cx)?),
        }
    }

    /// The account the browser is signed in to, if it is.
    async fn signed_in(&self, cx: &Cx) -> Result<Option<SignedIn>, Failure> {
        let Some(owner) = self.owner(cx).await? else {
            return Ok(None);
        };
        let profile = self.account.profile(&Viewer::from(&owner)).await?;
        Ok(Some(SignedIn {
            handle: profile.handle,
            confirmed: owner.is_confirmed(),
        }))
    }

    /// Renders the sign-in page `page` at the step the `visit` finds, at `refused`'s
    /// status and saying why, if anything was. Its forms may redirect to the
    /// providers, and to the application whose authorization the sign-in
    /// continues; an authorization that is unknown or expired explains itself.
    async fn sign_in_page(
        &self,
        cx: &Cx,
        page: SignInPage,
        visit: Visit,
        refused: Option<ApiError>,
    ) -> Result<Response, Failure> {
        let Visit {
            query,
            pending,
            continuation,
        } = visit;
        let mut targets = self
            .federation
            .authorization_endpoints()
            .map_err(Error::from)?;
        let target_acr = match continuation.authorization(&self.oidc).await? {
            Some((request, client)) => {
                targets.push(client);
                request.target_acr
            }
            None => query.acr,
        };
        let (pending, unavailable) = match pending {
            Some(Ok(pending)) => (Some(pending), None),
            Some(Err(error)) => (None, Some(ApiError::from(error))),
            None => (None, None),
        };
        let link = pending.as_ref().and_then(|pending| pending.kind.link());
        let signed_in = match link {
            Some(_) => self.signed_in(cx).await?,
            None => None,
        };
        let providers: Vec<_> = self.federation.enabled().collect();
        let invitation = query.invitation.as_deref();
        let android = PasskeyApplication::offers_google_password_manager(headers(cx));
        let step = match (&pending, link, page) {
            (Some(pending), Some(kind), _) => Step::Link {
                kind,
                provider: pending.provider,
                email: pending.email.as_deref(),
                signed_in: signed_in.as_ref(),
                handle_open: query.handle.0,
            },
            (None, _, SignInPage::Login) => Step::SignIn {
                passkey_only: target_acr == Some(Acr::PhishingResistant),
                handle_open: query.handle.0,
                providers: &providers,
            },
            (Some(_), None, _) | (None, _, SignInPage::Register) => Step::SignUp {
                social: pending
                    .as_ref()
                    .map(|pending| (pending.provider, pending.id)),
                invitation,
                invite_required: self.invite_required,
                android,
            },
        };
        let status = refused
            .as_ref()
            .map_or(StatusCode::OK, |error| error.public().0);
        let refusal = refused.or(unavailable);
        let alert = refusal
            .as_ref()
            .map(|error| error.public().1)
            .or_else(|| query.error.map(CallbackError::message));
        let kept = continuation.on(LoginQuery {
            error: None,
            ..query.clone()
        });
        let view = view! { cx =>
            piquel_ui::sign_in(
                step: step,
                page: page.path(),
                query: &kept,
                login: routes::page::LOGIN,
                register: routes::page::REGISTER,
                alert: alert,
            )
        };
        Ok(self
            .render(
                cx,
                status,
                step.title().as_str(),
                Area::SignIn,
                &targets,
                view,
            )
            .await?)
    }
}
