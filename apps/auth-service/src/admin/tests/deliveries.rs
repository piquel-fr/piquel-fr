//! Retrying and cancelling deliveries.

use super::*;
use crate::security::CONFIRMATION_MAX_AGE;
use sourceorigin_common::DeliveryId;
use sourceorigin_repository::{Channel, DatabaseError, DeliveryStatus, EventFilter, NewDelivery};

/// A delivery no worker sends, which the tests only retry and cancel.
struct Unsent;

impl Channel for Unsent {
    const NAME: &'static str = "test_admin_unsent";
    type Recipient = ();
    type Payload = ();

    fn deliveries(
        _: &DomainEvent,
        _: Option<UserId>,
        _: &[sourceorigin_repository::Notified],
        _: &mut DatabaseTransaction<'_>,
    ) -> impl Future<Output = Result<Vec<NewDelivery<Self>>, DatabaseError>> + Send {
        std::future::ready(Ok(vec![]))
    }
}

/// Retrying and cancelling a delivery check their administrator as every change
/// does, before committing: one whose rights were revoked, or whose confirmation
/// is stale, leaves the delivery as it was. A permitted change is recorded, since
/// cancelling one can hold back a notice to a user.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn delivery_changes_check_and_record_their_administrator() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = harness.admin().await;
    let revoked = harness.admin().await;
    service
        .revoke_administrator(&cli(), revoked.user_id, reason("Asked by email"))
        .await
        .expect("revoke");
    let stale = Utc::now() - Duration::minutes(10);
    let step_up = StepUpRequirement::passkey_within(CONFIRMATION_MAX_AGE);
    let queue = async || {
        let delivery = NewDelivery::<Unsent> {
            destination: "https://receiver.example".into(),
            recipient: (),
            payload: (),
            ordering_key: None,
        };
        harness
            .database
            .deliveries()
            .insert(None, delivery)
            .await
            .expect("insert")
    };
    let status = async |id: DeliveryId| {
        let listed = harness
            .database
            .deliveries()
            .list(None, Some(Unsent::NAME), 1000)
            .await;
        let listed = listed.expect("list");
        listed
            .into_iter()
            .find(|delivery| delivery.id == id)
            .expect("delivery")
            .status
    };
    let (pending, cancelled) = (queue().await, queue().await);
    harness
        .database
        .deliveries()
        .cancel(cancelled)
        .await
        .expect("cancel");
    for (operator, refusal) in [
        (operator(revoked, Utc::now()), AdminError::NotAdministrator),
        (operator(admin, stale), AdminError::StepUpRequired(step_up)),
    ] {
        let refused = service
            .cancel_delivery(&operator, pending, reason("Asked by email"))
            .await
            .expect_err("cancel");
        assert_refused(&refused, &refusal, "cancel");
        let refused = service
            .retry_delivery(&operator, cancelled, reason("Asked by email"))
            .await
            .expect_err("retry");
        assert_refused(&refused, &refusal, "retry");
    }
    assert_eq!(status(pending).await, DeliveryStatus::Pending);
    assert_eq!(status(cancelled).await, DeliveryStatus::Cancelled);

    let admin = operator(admin, Utc::now());
    service
        .cancel_delivery(&admin, pending, reason("Asked by email"))
        .await
        .expect("cancel");
    service
        .retry_delivery(&admin, cancelled, reason("Asked by email"))
        .await
        .expect("retry");
    assert_eq!(status(pending).await, DeliveryStatus::Cancelled);
    assert_eq!(status(cancelled).await, DeliveryStatus::Pending);
    for (kind, delivery_id) in [
        ("delivery_cancelled", pending),
        ("delivery_retried", cancelled),
    ] {
        let filter = EventFilter {
            kind: Some(kind.into()),
            ..EventFilter::default()
        };
        let events = harness
            .database
            .events()
            .list(&filter, 100)
            .await
            .expect("events");
        let recorded = events
            .iter()
            .find(|stored| {
                matches!(
                    stored.event.known(),
                    Some(DomainEvent::DeliveryCancelled { delivery_id: id }
                        | DomainEvent::DeliveryRetried { delivery_id: id }) if *id == delivery_id
                )
            })
            .unwrap_or_else(|| panic!("{kind} recorded"));
        assert_eq!(recorded.actor, admin.reading().actor, "{kind}");
    }
}
