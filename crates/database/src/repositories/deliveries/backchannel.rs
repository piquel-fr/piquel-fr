//! Back-channel logout tokens (OIDC Back-Channel Logout 1.0): when a session ends,
//! every client that received tokens from it and registered a back-channel logout
//! URI is told, so it can end its own session for the user.

use super::{Channel, NewDelivery};
use crate::{DatabaseError, DatabaseTransaction};
use piquel_common::{ClientId, SessionId, UserId, events::DomainEvent};
use serde::{Deserialize, Serialize};

/// Logout tokens for the clients of revoked sessions. Every revocation records a
/// [`DomainEvent::SessionRevoked`], so every revocation path reaches this channel.
pub struct BackchannelLogout;

/// Whom a logout token is for, copied when the session ends: the token's `aud`,
/// `sub` and `sid`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutRecipient {
    /// The client told, the token's `aud`.
    pub client_id: ClientId,
    /// The signed-out account, the token's `sub`.
    pub sub: UserId,
    /// The ended session, the token's `sid`.
    pub sid: SessionId,
}

impl Channel for BackchannelLogout {
    const NAME: &'static str = "backchannel_logout";
    type Recipient = LogoutRecipient;
    /// The token is signed afresh on every attempt, from the recipient alone.
    type Payload = ();

    /// One unordered delivery per client of a revoked session with a back-channel
    /// logout URI; deliveries are idempotent, so none waits for another.
    async fn deliveries(
        event: &DomainEvent,
        _: Option<UserId>,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<NewDelivery<Self>>, DatabaseError> {
        let DomainEvent::SessionRevoked { session_id, .. } = event else {
            return Ok(Vec::new());
        };
        Ok(tx
            .oidc()
            .logout_clients(*session_id)
            .await?
            .into_iter()
            .map(|client| NewDelivery {
                destination: client.backchannel_logout_uri,
                recipient: LogoutRecipient {
                    client_id: client.client_id,
                    sub: client.user_id,
                    sid: *session_id,
                },
                payload: (),
                ordering_key: None,
            })
            .collect())
    }
}
