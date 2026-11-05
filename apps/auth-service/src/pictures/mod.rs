//! Profile pictures: setting one, which only the owner may do, and viewing and
//! removing one, which administrators share; and serving each at its URL, which
//! the `picture` claim carries.
//!
//! A picture's URL names its [`PictureId`], new on every upload, so the image at a
//! URL never changes: browsers keep it for a year without asking again. The path
//! has no file extension, so the edge, which caches static files by extension,
//! keeps no copy of its own, and a removed picture stops being served at once to
//! everyone but the browsers that already hold it.

/// Turning an upload into the stored JPEG.
mod encoding;
#[cfg(test)]
mod tests;

pub(crate) use encoding::{MAX_UPLOAD_BYTES, SIDE};

use crate::{
    account::{AccountError, AccountService, Owner, Subject, Viewer},
    deliveries::{DeliveryError, OutboundClient},
    federation::ProviderPicture,
    routes,
    security::{ApiError, CacheClass, Cached},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, FromRef, Path, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use chrono::{DateTime, Utc};
use encoding::Jpeg;
use piquel_common::{
    PictureId, UserId,
    events::{DomainEvent, EventContext},
};
use piquel_repository::{Database, DatabaseError, StoredPicture};
use serde::Serialize;
use thiserror::Error;

/// Why a picture could not be set, removed or served.
#[derive(Debug, Error)]
pub(crate) enum PictureError {
    /// The upload is over [`MAX_UPLOAD_BYTES`].
    #[error("the upload is over {MAX_UPLOAD_BYTES} bytes")]
    TooLarge,
    /// The upload is not a PNG, JPEG or GIF.
    #[error("the upload is not a PNG, JPEG or GIF image")]
    Unsupported,
    /// The upload declares more pixels, or a longer side, than may be decoded.
    #[error("the image's dimensions are over the limits")]
    Dimensions,
    /// The upload is in a known format, but damaged.
    #[error("the image could not be decoded")]
    Unreadable(#[source] image::ImageError),
    /// Even the lowest quality is over the stored size: almost only noise is.
    #[error("the image does not fit the stored size at any quality")]
    TooDetailed,
    /// Encoding the stored JPEG failed.
    #[error("the picture could not be encoded")]
    Encoding(#[source] image::ImageError),
    /// The decoding queue closed, which it never does.
    #[error("the decoding queue closed")]
    Busy(#[from] tokio::sync::AcquireError),
    /// The decoding task panicked or was cancelled.
    #[error("the decoding task failed")]
    Task(#[from] tokio::task::JoinError),
    /// A provider's picture could not be fetched.
    #[error("the provider's picture could not be fetched")]
    Fetch(#[source] DeliveryError),
    /// The account has no picture to remove.
    #[error("the account has no profile picture")]
    Missing,
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

impl From<PictureError> for ApiError {
    /// Says what to choose instead. Failures of auth's own are internal.
    fn from(error: PictureError) -> Self {
        let size = MAX_UPLOAD_BYTES / (1024 * 1024);
        match error {
            PictureError::TooLarge => {
                Self::bad_request(format!("Choose an image of at most {size} MB."))
            }
            PictureError::Unsupported => Self::bad_request("Choose a PNG, JPEG or GIF image."),
            PictureError::Dimensions => Self::bad_request(
                "This image is too large to process. Choose one under 24 megapixels.",
            ),
            PictureError::Unreadable(_) => {
                Self::bad_request("This image could not be read. It may be damaged.")
            }
            PictureError::TooDetailed => Self::bad_request(
                "This image has too much fine detail to store. Choose another one.",
            ),
            PictureError::Missing => Self::not_found("The account has no profile picture."),
            PictureError::Database(error) => error.into(),
            error @ (PictureError::Encoding(_)
            | PictureError::Fetch(_)
            | PictureError::Busy(_)
            | PictureError::Task(_)) => Self::internal(error),
        }
    }
}

/// The account's picture, as the account API and the CLI show it.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PictureView {
    /// Its ID.
    pub(crate) id: PictureId,
    /// Its path on auth's origin; the `picture` claim is its absolute URL.
    pub(crate) url: String,
    /// When it was uploaded.
    pub(crate) created_at: DateTime<Utc>,
}

impl From<StoredPicture> for PictureView {
    /// The picture, at its path.
    fn from(picture: StoredPicture) -> Self {
        Self {
            id: picture.id,
            url: routes::pictures::of(picture.id),
            created_at: picture.created_at,
        }
    }
}

impl AccountService {
    /// Makes `upload` the owner's picture, replacing any other, once encoded. The
    /// encoding runs before the transaction, which holds no lock meanwhile. A
    /// picture grants nothing, so the session is enough.
    pub(crate) async fn set_picture(
        &self,
        owner: &Owner,
        upload: Vec<u8>,
    ) -> Result<PictureView, AccountError> {
        let jpeg = Jpeg::encode(upload).await?;
        let id = PictureId::new();
        let mut tx = self.database.begin().await?;
        owner.lock(&mut tx).await?;
        let picture = tx.pictures().set(owner.user(), id, jpeg.as_bytes()).await?;
        tx.record(
            &owner.context(),
            Some(owner.user()),
            DomainEvent::PictureChanged { picture_id: id },
        )
        .await?;
        tx.commit().await?;
        Ok(picture.into())
    }

    /// Imports the picture at `url`, one a provider reported, as the picture of
    /// the account `user`, which `context` names, unless it has one already: the
    /// first picture of an account a social signup created. The image is fetched
    /// with `client`, which reaches only public addresses and follows no
    /// redirect, before the transaction.
    pub(crate) async fn import_picture(
        &self,
        client: &OutboundClient,
        user: UserId,
        context: &EventContext,
        url: &ProviderPicture,
    ) -> Result<(), AccountError> {
        let upload = client
            .get(url.as_str(), piquel_ui::PICTURE_TYPES, MAX_UPLOAD_BYTES + 1)
            .await
            .map_err(PictureError::Fetch)?;
        let jpeg = Jpeg::encode(upload).await?;
        let mut tx = self.database.begin().await?;
        if tx
            .users()
            .find_active_by_id_for_update(user)
            .await?
            .is_none()
            || tx.pictures().find(user).await?.is_some()
        {
            return Ok(());
        }
        let id = PictureId::new();
        tx.pictures().set(user, id, jpeg.as_bytes()).await?;
        tx.record(
            context,
            Some(user),
            DomainEvent::PictureChanged { picture_id: id },
        )
        .await?;
        Ok(tx.commit().await?)
    }

    /// The account's picture, if it has one.
    pub(crate) async fn picture(
        &self,
        viewer: &Viewer,
    ) -> Result<Option<PictureView>, AccountError> {
        viewer.authorize(&self.database).await?;
        let picture = self.database.pictures().find(viewer.user()).await?;
        Ok(picture.map(PictureView::from))
    }

    /// Removes the account's picture: the owner's, or an administrator's
    /// moderation, with their reason.
    pub(crate) async fn remove_picture(&self, subject: &Subject) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        subject.lock(&mut tx).await?;
        if !tx.pictures().remove(subject.user()).await? {
            return Err(PictureError::Missing.into());
        }
        tx.record(
            &subject.context(),
            Some(subject.user()),
            DomainEvent::PictureRemoved {},
        )
        .await?;
        subject.commit(tx).await
    }
}

/// Serves pictures at their URLs, and takes the owner's uploads through the
/// account API. Viewing and removing the account's picture are shared settings,
/// which [`AccountService`] serves.
#[derive(Clone)]
pub(crate) struct PictureApplication {
    /// Accounts and their pictures.
    database: Database,
}

impl FromRef<PictureApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &PictureApplication) -> Self {
        application.database.clone()
    }
}

impl PictureApplication {
    /// Serves the pictures in `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Returns the picture route and the upload route, with this application as
    /// state. The upload's body limit is the upload's, not the API's.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::pictures::IMAGE, get(Self::serve))
            .route(
                routes::pictures::OWN,
                put(Self::upload).layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
            )
            .with_state(self)
    }

    /// The picture the path names, as a JPEG any origin may load and any cache keep
    /// for good, or `404` once it is no longer its active account's picture. An ID
    /// that does not parse names none.
    async fn serve(State(app): State<Self>, Path(id): Path<String>) -> Result<Response, ApiError> {
        let missing = || ApiError::not_found("There is no such picture.");
        let id: PictureId = id.parse().map_err(|_| missing())?;
        let image = app
            .database
            .pictures()
            .image(id)
            .await?
            .ok_or_else(missing)?;
        let jpeg = [(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"))];
        Ok(Cached(CacheClass::Immutable, (jpeg, image)).into_response())
    }

    /// Makes the raw body the owner's picture, and answers it as stored.
    async fn upload(
        State(app): State<Self>,
        owner: Owner,
        body: Bytes,
    ) -> Result<Json<PictureView>, ApiError> {
        let picture = AccountService::new(app.database.clone())
            .set_picture(&owner, body.into())
            .await?;
        Ok(Json(picture))
    }
}
