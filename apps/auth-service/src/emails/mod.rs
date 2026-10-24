//! The account's email addresses: adding one sends a verification link, and a
//! verified address can become the primary one, which the OIDC `email` claim
//! reports. Adding, changing the primary address and removing one are sensitive,
//! since the addresses receive security notices, so they need a recent passkey
//! confirmation. Verifying needs only the link's token: possessing it proves
//! control of the mailbox. Administrators may list, change the primary address and
//! remove, but only the owner adds an address.
//!
//! The token is never stored, not even in the delivery that sends it: it is
//! derived from the address's ID with [`VerificationKey`], once here to store its
//! digest, and again by the email sender. See `docs/architecture/delivery-queue.md`.
use crate::{
    account::{AccountError, AccountService, ConfirmedOwner, Owner, Subject, Viewer},
    config::EmailConfig,
    routes,
    security::{ApiError, RequestContext},
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use chrono::{Duration, Utc};
use piquel_common::{
    EmailId, Personal, UserId,
    email::NormalizedEmail,
    events::{Actor, DomainEvent, EventContext},
};
use piquel_crypto::{CryptoError, Digest, Secret};
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertUnverifiedEmail, StoredEmail,
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc, time::Duration as StdDuration};

/// Email failures and their browser response mapping.
mod error;
pub(crate) use error::EmailError;

/// How long a verification link works.
pub(crate) const VERIFICATION_LIFETIME: Duration = Duration::hours(24);
/// The most addresses an account may have, verified or not.
const MAX_EMAILS: usize = 10;
/// The window verification email limits count in.
const VERIFICATION_WINDOW: StdDuration = StdDuration::from_hours(1);
/// Verification emails one account may send per [`VERIFICATION_WINDOW`].
const VERIFICATIONS_PER_ACCOUNT: i32 = 5;
/// Verification emails one client IP may send per [`VERIFICATION_WINDOW`], across
/// accounts.
const VERIFICATIONS_PER_IP: i32 = 10;
/// Verification emails one address may receive per [`VERIFICATION_WINDOW`], across
/// accounts and clients.
const VERIFICATIONS_PER_ADDRESS: i32 = 3;

/// HMAC key deriving each address's verification token from its ID. It is derived
/// from persistent key material, so every replica and the email sender derive the
/// same token, and a restart does not break links already sent.
#[derive(Clone)]
pub(crate) struct VerificationKey(Arc<Secret>);

impl VerificationKey {
    /// Wraps a key reserved for verification tokens.
    pub(crate) fn new(key: Secret) -> Self {
        Self(Arc::new(key))
    }

    /// The token of address `id`'s verification link.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn token(&self, id: EmailId) -> Result<Secret, CryptoError> {
        Secret::derive(self.0.as_bytes(), id.as_uuid().as_bytes())
    }
}

/// The account's addresses and their verification.
#[derive(Clone)]
pub(crate) struct EmailApplication {
    /// Addresses, sessions and events.
    database: Database,
    /// Whether email is sent, and the verification key.
    config: EmailConfig,
}

/// An address as the account sees it.
#[derive(Serialize)]
pub(crate) struct EmailView {
    /// Address ID.
    pub(crate) id: EmailId,
    /// The normalized address.
    pub(crate) address: String,
    /// Whether someone followed its verification link.
    pub(crate) verified: bool,
    /// Whether it is the primary address, which applications receive.
    pub(crate) primary: bool,
}

impl From<StoredEmail> for EmailView {
    /// Keeps what the account sees.
    fn from(email: StoredEmail) -> Self {
        Self {
            id: email.id,
            verified: email.verified_at.is_some(),
            address: email.normalized_email,
            primary: email.is_primary,
        }
    }
}

/// The body of [`routes::emails::LIST`] mutations.
#[derive(Deserialize)]
struct AddEmail {
    /// The address to add.
    email: String,
}

/// The body of [`routes::emails::VERIFY`].
#[derive(Deserialize)]
struct VerifyEmail {
    /// The token from the verification link.
    token: String,
}

/// The answer to a verification.
#[derive(Serialize)]
pub(crate) struct Verified {
    /// The verified address.
    pub(crate) address: String,
    /// Whether it became the primary address, being the account's first.
    pub(crate) primary: bool,
}

impl EmailApplication {
    /// Manages addresses in `database`, sending email as `config` says.
    pub(crate) fn new(database: Database, config: &EmailConfig) -> Self {
        Self {
            database,
            config: config.clone(),
        }
    }

    /// Returns the routes that add and verify addresses, with this application as
    /// state. Only the owner can add a channel that receives the account's email;
    /// listing, changing the primary address and removing are shared settings,
    /// which [`AccountService`] serves.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::emails::LIST, post(Self::add))
            .route(routes::emails::VERIFY, post(Self::verify))
            .with_state(self)
    }

    /// Adds an unverified address to the owner's account, and queues its
    /// verification email.
    async fn add(
        State(app): State<Self>,
        owner: ConfirmedOwner,
        Json(body): Json<AddEmail>,
    ) -> Result<(StatusCode, Json<EmailView>), ApiError> {
        let added = AccountService::new(app.database.clone())
            .add_email(&owner, &app.config, &body.email)
            .await?;
        Ok((StatusCode::CREATED, Json(added)))
    }

    /// Verifies the address whose link holds the body's token, whether this
    /// browser is signed out or signed in to the account the address joins.
    async fn verify(
        State(app): State<Self>,
        context: RequestContext,
        owner: Option<Owner>,
        Json(body): Json<VerifyEmail>,
    ) -> Result<Json<Verified>, ApiError> {
        let verified = AccountService::new(app.database.clone())
            .verify_email(&body.token, owner.as_ref(), context)
            .await?;
        Ok(Json(verified))
    }

    /// Records the removal of `user_id`'s address `id` as `context`'s, then
    /// deletes it. In that order, so the `email` channel still reads a verified
    /// address and copies it into the notice of its removal.
    pub(crate) async fn delete(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user_id: UserId,
        id: EmailId,
    ) -> Result<(), DatabaseError> {
        tx.record(
            context,
            Some(user_id),
            DomainEvent::EmailRemoved { email_id: id },
        )
        .await?;
        tx.emails().remove(user_id, id).await
    }

    /// Counts one verification email against the hourly limits of the account,
    /// the client IP and the address's mailbox, so neither one account, nor one client, nor
    /// many of both can flood a mailbox. In the caller's transaction, so a rejected
    /// or failed addition counts nothing.
    async fn limit(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        client_ip: IpAddr,
        address: &NormalizedEmail,
    ) -> Result<(), EmailError> {
        let buckets = [
            (format!("account:{user_id}"), VERIFICATIONS_PER_ACCOUNT),
            (format!("ip:{client_ip}"), VERIFICATIONS_PER_IP),
            (
                format!("address:{}", address.mailbox()),
                VERIFICATIONS_PER_ADDRESS,
            ),
        ];
        for (key, limit) in buckets {
            let bucket = Digest::sha256(format!("verification-email:{key}").as_bytes());
            if !tx
                .security()
                .allow_request(bucket.as_bytes(), limit, VERIFICATION_WINDOW)
                .await?
            {
                return Err(EmailError::RateLimited { limit });
            }
        }
        Ok(())
    }
}

/// The account's addresses. Any administrator may also list them, choose the
/// primary one among verified ones, and remove one; each change queues the same
/// notices, whoever makes it. Only the owner adds an address, since it receives
/// the account's mail, and verifying one is authorized by its link's token.
impl AccountService {
    /// Lists the account's addresses, primary first.
    pub(crate) async fn emails(&self, viewer: &Viewer) -> Result<Vec<EmailView>, AccountError> {
        viewer.authorize(&self.database).await?;
        let emails = self.database.emails().list(viewer.user()).await?;
        Ok(emails.into_iter().map(EmailView::from).collect())
    }

    /// Adds an unverified address to the owner's account and queues its
    /// verification email, in one transaction, once they confirmed with a passkey.
    /// Adding an address that is still waiting for verification replaces it,
    /// which sends a new link. The address may be another account's: rejecting it
    /// here would tell anyone which addresses have accounts, so only verification,
    /// by whoever controls the mailbox, finds out. Only the owner adds an address,
    /// since it receives the account's mail.
    pub(crate) async fn add_email(
        &self,
        owner: &Owner,
        config: &EmailConfig,
        address: &str,
    ) -> Result<EmailView, AccountError> {
        if config.smtp.is_none() {
            return Err(EmailError::Disabled.into());
        }
        let address = NormalizedEmail::parse(address).map_err(EmailError::Invalid)?;
        // The sender must be able to send to it, or its link would never arrive.
        address
            .as_str()
            .parse::<lettre::Address>()
            .map_err(EmailError::Unsendable)?;
        let user = owner.user();
        let context = owner.context();
        let mut tx = self.database.begin().await?;
        owner.lock_confirmed(&mut tx).await?;
        let emails = tx.emails().list(user).await?;
        let mut count = emails.len();
        if let Some(existing) = emails
            .iter()
            .find(|email| email.normalized_email == address.as_str())
        {
            if existing.verified_at.is_some() {
                return Err(EmailError::AlreadyAdded.into());
            }
            EmailApplication::delete(&mut tx, &context, user, existing.id).await?;
            count -= 1;
        }
        if count >= MAX_EMAILS {
            return Err(EmailError::TooMany { max: MAX_EMAILS }.into());
        }
        EmailApplication::limit(&mut tx, user, owner.request().client_ip, &address).await?;
        let id = EmailId::new();
        let digest = config
            .verification_key
            .token(id)
            .map_err(EmailError::Crypto)?
            .digest();
        tx.emails()
            .insert_unverified(&InsertUnverifiedEmail {
                id,
                user_id: user,
                normalized_email: address.as_str(),
                secret_digest: digest.as_bytes(),
                expires_at: Utc::now() + VERIFICATION_LIFETIME,
            })
            .await?;
        tx.record(
            &context,
            Some(user),
            DomainEvent::EmailAdded {
                email_id: id,
                address: Personal::Value(address.clone()),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(EmailView {
            id,
            address: address.into(),
            verified: false,
            primary: false,
        })
    }

    /// Verifies the address whose link holds `token`, once. It becomes primary if
    /// the account had none. The token authorizes it, not a session: it proves
    /// control of the mailbox, and whoever holds it may be signed out or on another
    /// device. A browser `signed_in` to another account is refused, since it would
    /// confirm the address for an account that is not theirs, as a phishing link
    /// could ask. Pages never verify on `GET`, since mail scanners follow links.
    pub(crate) async fn verify_email(
        &self,
        token: &str,
        signed_in: Option<&Owner>,
        request: RequestContext,
    ) -> Result<Verified, AccountError> {
        // A token that does not parse cannot match: answer as for an unknown one.
        let digest = Secret::parse(token)
            .map_err(|_| EmailError::InvalidToken)?
            .digest();
        let mut tx = self.database.begin().await?;
        let pending = tx
            .emails()
            .find_verification(digest.as_bytes())
            .await?
            .ok_or(EmailError::InvalidToken)?;
        tx.users()
            .find_active_by_id_for_update(pending.user_id)
            .await?
            .ok_or(EmailError::InvalidToken)?;
        let context = match signed_in {
            Some(owner) if owner.user() == pending.user_id => owner.context(),
            Some(_) => return Err(EmailError::OtherAccount.into()),
            None => request.actor(Actor::Anonymous),
        };
        let primary = match tx
            .emails()
            .consume_verification(&pending, digest.as_bytes())
            .await
        {
            Ok(primary) => primary,
            Err(DatabaseError::NotFound) => return Err(EmailError::InvalidToken.into()),
            // The ownership trigger: another active account verified it first.
            Err(DatabaseError::Conflict(_)) => return Err(EmailError::OwnedElsewhere.into()),
            Err(error) => return Err(error.into()),
        };
        let email_id = pending.email_id;
        let subject = Some(pending.user_id);
        tx.record(&context, subject, DomainEvent::EmailVerified { email_id })
            .await?;
        if primary {
            let event = DomainEvent::PrimaryEmailChanged {
                email_id,
                previous_email_id: None,
            };
            tx.record(&context, subject, event).await?;
        }
        tx.commit().await?;
        Ok(Verified {
            address: pending.address,
            primary,
        })
    }

    /// Makes a verified address the primary one, and queues a notice to the
    /// previous primary address.
    pub(crate) async fn make_primary_email(
        &self,
        subject: &Subject,
        id: EmailId,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        subject.lock_confirmed(&mut tx).await?;
        let email = tx
            .emails()
            .find(subject.user(), id)
            .await?
            .ok_or(EmailError::NotFound)?;
        if email.verified_at.is_none() {
            return Err(EmailError::NotVerified.into());
        }
        if !email.is_primary {
            let previous_email_id = tx.emails().set_primary(subject.user(), id).await?;
            tx.record(
                &subject.context(),
                Some(subject.user()),
                DomainEvent::PrimaryEmailChanged {
                    email_id: id,
                    previous_email_id,
                },
            )
            .await?;
        }
        subject.commit(tx).await
    }

    /// Removes an address, and queues a notice to it if it was verified. The
    /// primary address can only be removed once no other verified address could
    /// replace it: another one must be made primary first, which notifies it too.
    /// An address from before an undoable recovery is protected as
    /// [`AccountService::keep_older`] says.
    pub(crate) async fn remove_email(
        &self,
        subject: &Subject,
        id: EmailId,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        subject.lock_confirmed(&mut tx).await?;
        let joined = tx.emails().joined_at(subject.user(), id).await?;
        Self::keep_older(&mut tx, subject, joined).await?;
        let emails = tx.emails().list(subject.user()).await?;
        let email = emails
            .iter()
            .find(|email| email.id == id)
            .ok_or(EmailError::NotFound)?;
        if email.is_primary
            && emails
                .iter()
                .any(|other| other.id != id && other.verified_at.is_some())
        {
            return Err(EmailError::PrimaryInUse.into());
        }
        EmailApplication::delete(&mut tx, &subject.context(), subject.user(), id).await?;
        subject.commit(tx).await
    }
}

/// Supplies the shared database boundary to browser-session extractors.
impl axum::extract::FromRef<EmailApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &EmailApplication) -> Self {
        application.database.clone()
    }
}

/// Database-backed address scenarios.
#[cfg(test)]
mod tests;
