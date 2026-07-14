//! Intended downstream facade for Piquel authentication integration.
pub use piquel_auth_middleware::{
    AuthMiddleware, AuthenticatedUser, AuthenticationError, ConfigurationError,
};
pub use piquel_auth_protocol::{AccessTokenClaims, Audience, ClientId, UserId};
