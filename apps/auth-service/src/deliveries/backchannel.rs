//! Sends back-channel logout tokens (OIDC Back-Channel Logout 1.0 §2.5): a token
//! signed with `typ: logout+jwt`, posted as the `logout_token` form field to the
//! client's back-channel logout URI.
//!
//! A token is signed afresh for every attempt, with `iat` the attempt's time, so a
//! retry never carries an expired token. `jti` is the delivery's ID on every
//! attempt: a receiver's replay check also drops repeated sends.

use super::{DeliveryError, Failure, Sender, outbound::OutboundClient};
use crate::SigningKeys;
use axum::http::Method;
use chrono::{DateTime, TimeDelta, Utc};
use piquel_common::protocol::{
    claims::{Absent, Audience, LogoutEvents, LogoutTokenClaims},
    jwt::TokenType,
};
use piquel_crypto::CryptoError;
use piquel_repository::{BackchannelLogout, Delivery};
use std::time::Duration;

/// How long a logout token is accepted after the attempt that signed it.
const TOKEN_LIFETIME: TimeDelta = TimeDelta::minutes(2);

/// Signs and posts logout tokens.
pub(crate) struct BackchannelLogoutSender {
    /// Posts to client URIs, which must be HTTPS and public.
    outbound: OutboundClient,
    /// The `iss` of every token.
    issuer: String,
    /// Auth's signing keys, which clients already trust for ID tokens; each
    /// attempt signs with the key active at the time.
    keys: SigningKeys,
}

impl BackchannelLogoutSender {
    /// Signs as `issuer` with `keys`, and posts with `outbound`.
    pub(crate) const fn new(issuer: String, keys: SigningKeys, outbound: OutboundClient) -> Self {
        Self {
            outbound,
            issuer,
            keys,
        }
    }

    /// The logout token of `delivery`, attempted at `now`.
    fn token(
        &self,
        delivery: &Delivery<BackchannelLogout>,
        now: DateTime<Utc>,
    ) -> Result<String, CryptoError> {
        let recipient = &delivery.recipient;
        self.keys.current().sign(
            TokenType::Logout,
            &LogoutTokenClaims {
                iss: self.issuer.clone(),
                aud: Audience::One(recipient.client_id.to_string()),
                iat: now,
                exp: now + TOKEN_LIFETIME,
                jti: delivery.id,
                sub: Some(recipient.sub.to_string()),
                sid: Some(recipient.sid),
                events: LogoutEvents,
                nonce: Absent,
            },
        )
    }
}

impl Sender for BackchannelLogoutSender {
    type Channel = BackchannelLogout;
    /// A client still unreachable an hour after the logout is given up on; its
    /// session for the user may outlive auth's until it expires.
    const MAX_AGE: Duration = Duration::from_hours(1);

    /// Posts the token. Any 2xx is success; a 400 or other 4xx is final.
    async fn send(&self, delivery: &Delivery<BackchannelLogout>) -> Result<(), DeliveryError> {
        let token = self.token(delivery, Utc::now()).map_err(|error| {
            tracing::error!(?error, id = %delivery.id, "could not sign a logout token");
            DeliveryError::Retryable {
                failure: Failure::Signing,
                retry_after: None,
            }
        })?;
        self.outbound
            .send(Method::POST, &delivery.destination, |request| {
                request.form(&[("logout_token", token)])
            })
            .await
            .map(drop)
    }
}
