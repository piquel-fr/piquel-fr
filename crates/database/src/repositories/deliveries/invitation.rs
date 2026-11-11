//! The `invitation` channel: an invitation's link, mailed to the address it
//! invites, which belongs to no account yet.
//!
//! A delivery stores only the invitation's ID. The sender reads the address and
//! the token's digest when it sends, through
//! [`SecurityRepository::open_invitation`], so an invitation redeemed, revoked or
//! expired in the meantime receives nothing, and derives the link's token again
//! from the ID, so it is stored nowhere.
//!
//! [`SecurityRepository::open_invitation`]: crate::SecurityRepository::open_invitation

use super::{Channel, NewDelivery};
use crate::{DatabaseError, DatabaseTransaction, Notified};
use sourceorigin_common::{TokenId, UserId, events::DomainEvent};

/// Invitations' emails, sent over SMTP by auth-service.
pub struct Invitation;

impl Channel for Invitation {
    const NAME: &'static str = "invitation";
    /// The invitation.
    type Recipient = TokenId;
    /// Nothing: the invitation says it all.
    type Payload = ();

    /// One unordered delivery each time an invitation is mailed. Its
    /// `destination` names the invitation, never the address.
    fn deliveries(
        event: &DomainEvent,
        _: Option<UserId>,
        _: &[Notified],
        _: &mut DatabaseTransaction<'_>,
    ) -> impl Future<Output = Result<Vec<NewDelivery<Self>>, DatabaseError>> + Send {
        let deliveries = match event {
            DomainEvent::InvitationMailed { invitation_id, .. } => vec![NewDelivery {
                destination: format!("invitation {invitation_id}"),
                recipient: *invitation_id,
                payload: (),
            }],
            _ => Vec::new(),
        };
        std::future::ready(Ok(deliveries))
    }
}
