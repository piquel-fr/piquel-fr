//! The sign-in pages, `/login` and `/register`: signing in, creating an account,
//! and linking a provider's sign-in to an existing account.
//!
//! Neither is an [`AccountPage`](crate::web::account::AccountPage): they serve browsers
//! that are not signed in. Their `GET` finds the [`Step`] the browser is at, from
//! the query, the provider's sign-in pending in the browser and its session. Their
//! `POST` makes the change its form names, then sends the browser where the
//! [`Continuation`] says, which the server alone decides. A change the service
//! refuses renders the page again, saying why.

use crate::web::{Failure, WebApplication};
use crate::{
    account::{AccountError, Owner, Viewer},
    federation::{FederationError, PendingKind, PendingView, ReturnTo},
    oidc::{AuthorizationView, OAuthError, OidcApplication, TransactionQuery},
    passkey::PasskeyApplication,
    routes,
    security::{ApiError, SessionError},
};
use axum::extract::Query as UriQuery;
use piquel_common::{events::RevocationReason, protocol::claims::Acr};
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

#[cfg(test)]
mod tests;

/// Which sign-in page the browser opened, which says what it asks of a browser no
/// provider's sign-in waits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::web) enum SignInPage {
    /// `/login`: signing in.
    Login,
    /// `/register`: creating an account.
    Register,
}

impl SignInPage {
    /// Its route.
    const fn path(self) -> &'static str {
        match self {
            Self::Login => routes::page::LOGIN,
            Self::Register => routes::page::REGISTER,
        }
    }

    /// Its title in the browser, when it cannot render or sends the browser on.
    pub(in crate::web) const fn title(self) -> &'static str {
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

    /// Whether it goes on to auth's handoff to the admin dashboard, which sends the
    /// browser on to the dashboard.
    fn hands_off(&self) -> bool {
        match self {
            Self::Path(path) => path
                .as_str()
                .parse::<Uri>()
                .is_ok_and(|uri| uri.path() == routes::page::ADMIN),
            Self::Authorization(_) => false,
        }
    }

    /// The pending authorization it continues, if any, as the sign-in page sees it.
    async fn authorization(
        &self,
        oidc: &OidcApplication,
    ) -> Result<Option<AuthorizationView>, OAuthError> {
        let Self::Authorization(transaction) = self else {
            return Ok(None);
        };
        oidc.authorization(transaction).await.map(Some)
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

impl PendingKind {
    /// Why the pending evidence must be linked to an existing account, as the link
    /// step says, or `None` when it creates one.
    const fn link(self) -> Option<LinkKind> {
        match self {
            Self::Signup => None,
            Self::Link => Some(LinkKind::Email),
            Self::ExplicitLink => Some(LinkKind::Explicit),
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
    pub(in crate::web) async fn sign_in(cx: &Cx, page: SignInPage) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        web.sign_in_page(cx, page, Visit::new(web, cx).await, None)
            .await
    }

    /// `POST` of the sign-in page `page`: makes the change its form names, then
    /// sends the browser on, or renders the page again with why it was refused. A
    /// form from an older page that does not decode changes nothing.
    pub(in crate::web) async fn sign_in_change(
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
        let (mut response, cookie) = match change {
            // The passkey script signed the browser in before posting.
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
                let response = match authorization {
                    Some(authorization) if Self::source(&authorization.redirect_uri).is_none() => {
                        self.link(cx, page.title(), &to, Onward::Provider(provider))
                            .await?
                    }
                    _ => see_other(to.as_str()).into_response(cx)?,
                };
                (response, cookie)
            }
            LoginChange::Link {} => {
                let owner = self
                    .owner(cx)
                    .await?
                    .ok_or_else(|| ApiError::from(SessionError::Missing))?;
                let (return_to, cookie) = self
                    .account
                    .link_identity(&owner, headers(cx))
                    .await
                    .map_err(ApiError::from)?;
                let continuation = Continuation::new(&visit.query, Some(&return_to));
                (self.go_on(cx, page, continuation).await?, cookie)
            }
            // An explicit link goes back to where it started; an email match offers
            // to sign in before going on.
            LoginChange::CancelLink {} => {
                let pending = visit
                    .pending
                    .unwrap_or(Err(FederationError::PendingBrowserMissing))
                    .map_err(ApiError::from)?;
                let cookie = self
                    .federation
                    .cancel_pending(headers(cx))
                    .await
                    .map_err(ApiError::from)?;
                let response = match pending.kind {
                    PendingKind::ExplicitLink => self.go_on(cx, page, visit.continuation).await?,
                    PendingKind::Link | PendingKind::Signup => {
                        let sign_in = visit
                            .continuation
                            .on(LoginQuery::default())
                            .on(routes::page::LOGIN)?;
                        see_other(sign_in).into_response(cx)?
                    }
                };
                (response, cookie)
            }
            // Signed out, the page offers to sign in to another account.
            LoginChange::SwitchAccount {} => {
                let signed_out = self
                    .account
                    .sign_out(Self::context(cx)?, headers(cx), RevocationReason::Logout)
                    .await
                    .map_err(ApiError::from)?;
                let here = uri(cx)
                    .path_and_query()
                    .map_or(page.path(), |here| here.as_str());
                let mut response = see_other(here).into_response(cx)?;
                signed_out.clear_on(&mut response).map_err(Error::from)?;
                return Ok(response);
            }
        };
        cookie.set_on(&mut response).map_err(Error::from)?;
        Ok(response)
    }

    /// Sends the browser on to `continuation` from `page`, once it signed in: to
    /// the path, or on through the authorization, which the page continues
    /// in-process, so that its `form-action` governs the redirect to the
    /// application, or links there when it cannot. Before an application, an
    /// account with a recovery that can still be undone asks whether it was its
    /// owner's, going on through the path resuming the authorization; a path on
    /// auth asks on the account's pages.
    async fn go_on(
        &self,
        cx: &Cx,
        page: SignInPage,
        continuation: Continuation,
    ) -> Result<Response, Failure> {
        match &continuation {
            Continuation::Authorization(transaction) => {
                if let Some(owner) = self.owner(cx).await?
                    && let Some(recovery) = self.recovery(&owner).await?
                {
                    let resume = continuation.return_to()?;
                    let prompt = view! { cx =>
                        piquel_ui::recovery_prompt(
                            recovery: &recovery,
                            continue_href: &resume,
                            undo: routes::page::RECOVER_UNDO,
                        )
                    };
                    let title = Title::SignIn.as_str();
                    return Ok(self
                        .render(cx, StatusCode::OK, title, Area::SignIn, &[], prompt)
                        .await?);
                }
                let next = self
                    .oidc
                    .continue_authorization(Self::context(cx)?, headers(cx), transaction.clone())
                    .await?;
                Ok(self.onward(cx, page.title(), &next).await?)
            }
            Continuation::Path(path) => Ok(see_other(path.as_str()).into_response(cx)?),
        }
    }

    /// The account the browser is signed in to as `owner`, or none when it is gone
    /// since its session was found.
    pub(in crate::web) async fn signed_in(
        &self,
        owner: &Owner,
    ) -> Result<Option<SignedIn>, Failure> {
        let profile = match self.account.profile(&Viewer::from(owner)).await {
            Ok(profile) => profile,
            // An account gone since its session was found is signed out.
            Err(AccountError::Owner(SessionError::Missing)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some(SignedIn {
            handle: profile.handle.into(),
            confirmed: owner.is_confirmed(),
        }))
    }

    /// Renders the sign-in page `page` at the step the `visit` finds, at `refused`'s
    /// status and saying why, if anything was. Its forms may redirect to the
    /// providers, to the application whose authorization the sign-in continues,
    /// and through auth's handoff to the admin dashboard; an authorization that is
    /// unknown or expired explains itself.
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
        if let Some(sign_in) = self.dashboard.as_ref().filter(|_| continuation.hands_off()) {
            targets.push(sign_in.dashboard().as_url().clone());
        }
        let target_acr = match continuation.authorization(&self.oidc).await? {
            Some(authorization) => {
                targets.push(authorization.redirect_uri);
                authorization.target_acr
            }
            None => query.acr,
        };
        let (pending, unavailable) = match pending {
            Some(Ok(pending)) => (Some(pending), None),
            Some(Err(error)) => (None, Some(ApiError::from(error))),
            None => (None, None),
        };
        let link = pending.as_ref().and_then(|pending| pending.kind.link());
        let signed_in = match self.owner(cx).await? {
            Some(owner) => self.signed_in(&owner).await?,
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
                signed_in: signed_in.as_ref(),
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
