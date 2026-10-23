//! Email address failures and their single mapping to browser responses.

use super::VERIFICATION_WINDOW;
use crate::security::ApiError;
use piquel_common::email::InvalidEmail;
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;
use thiserror::Error;

/// Why an address could not be added, verified, made primary or removed, mapped
/// to HTTP once in `From<EmailError>`.
#[derive(Debug, Error)]
pub(crate) enum EmailError {
    /// `AUTH_SMTP_URL` is unset, so no verification link could be sent.
    #[error("email is disabled")]
    Disabled,
    /// The address is not one Piquel accepts.
    #[error("invalid email address")]
    Invalid(#[source] InvalidEmail),
    /// The SMTP client cannot send to the address.
    #[error("address cannot receive email")]
    Unsendable(#[source] lettre::address::AddressError),
    /// The verifying browser is signed in to another account than the address's.
    #[error("verification link belongs to another account")]
    OtherAccount,
    /// The account already has this address, verified.
    #[error("address already verified on this account")]
    AlreadyAdded,
    /// The account has as many addresses as it may.
    #[error("account already has {max} addresses")]
    TooMany {
        /// The most an account may have.
        max: usize,
    },
    /// The account or its client IP sent as many verification emails as it may
    /// this hour.
    #[error("verification email limit of {limit} per hour reached")]
    RateLimited {
        /// The limit that was reached.
        limit: i32,
    },
    /// The account has no address with this ID.
    #[error("address not found")]
    NotFound,
    /// Only a verified address can become primary.
    #[error("address is not verified")]
    NotVerified,
    /// The primary address cannot be removed while another verified one could
    /// replace it.
    #[error("primary address still replaceable")]
    PrimaryInUse,
    /// The token matches no unexpired, unused verification link of an active
    /// account.
    #[error("verification token is unknown, expired or used")]
    InvalidToken,
    /// Another active account verified this address first.
    #[error("address is verified by another account")]
    OwnedElsewhere,
    /// The verification token could not be derived.
    #[error("could not derive verification token")]
    Crypto(#[source] CryptoError),
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

impl From<EmailError> for ApiError {
    /// Says what to fix. An address another account owns is reported without
    /// naming the account.
    fn from(error: EmailError) -> Self {
        match error {
            EmailError::Disabled => Self::forbidden(
                "This Piquel server does not send email, so addresses cannot be added.",
            ),
            EmailError::Invalid(reason) => {
                Self::bad_request(format!("This email address cannot be used: {reason}."))
            }
            EmailError::Unsendable(_) => {
                Self::bad_request("Piquel cannot send email to this address. Use another one.")
            }
            EmailError::OtherAccount => Self::conflict(
                "This link adds the address to a Piquel account other than the one you are \
                 signed in to. Sign out first if you meant to confirm it.",
            ),
            EmailError::AlreadyAdded => {
                Self::conflict("This address is already verified on your account.")
            }
            EmailError::TooMany { max } => Self::conflict(format!(
                "Your account can have at most {max} addresses. Remove one first."
            )),
            // One message for every limit, so a refusal does not say whose limit
            // it was: the address's would tell that others recently added it.
            EmailError::RateLimited { .. } => Self::too_many_requests(
                "Too many verification emails were sent recently. Please try again later.",
                VERIFICATION_WINDOW,
            ),
            EmailError::NotFound => Self::not_found("Your account has no such email address."),
            EmailError::NotVerified => {
                Self::conflict("Verify this address before making it your primary address.")
            }
            EmailError::PrimaryInUse => Self::conflict(
                "Make another address your primary address before removing this one.",
            ),
            EmailError::InvalidToken => Self::bad_request(
                "This verification link is invalid, has expired or was already used. \
                 Add the address again to get a new one.",
            ),
            EmailError::OwnedElsewhere => {
                Self::conflict("This address is already used by another Piquel account.")
            }
            error @ EmailError::Crypto(_) => Self::internal(error),
            EmailError::Database(error) => error.into(),
        }
    }
}
