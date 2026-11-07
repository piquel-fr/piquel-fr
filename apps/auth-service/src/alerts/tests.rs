//! How raising, clearing and acknowledging change the current alert of a kind,
//! and what they record. Each test uses a schema of its own, since an alert
//! concerns the whole database.
use super::*;
use crate::{
    AdminError, Reason,
    admin::tests::{Harness, operator},
};
use chrono::Utc;
use piquel_common::{
    admin::{ChainBreak, ChainProblem},
    alerts::AlertState,
    events::{Actor, JobName, RequestOrigin},
};
use piquel_repository::{Database, EventFilter, RecordedEvent};

/// A broken chain at `position`.
fn broken(position: u64) -> Alert {
    Alert::AuditChainBroken(ChainBreak {
        position,
        problem: ChainProblem::EventChanged,
    })
}

/// Raises `alert` if `Some`, or clears the chain's alert, in a transaction of its
/// own.
async fn found(database: &Database, alert: Option<Alert>) {
    let context = EventContext {
        actor: Actor::System {
            job: JobName::AuditVerification,
        },
        origin: RequestOrigin::default(),
        reason: None,
    };
    let mut tx = database.begin().await.expect("transaction");
    let mut alerts = Alerts::new(&mut tx, &context);
    match alert {
        Some(alert) => alerts.raise(alert).await.expect("raise"),
        None => alerts
            .clear(AlertKind::AuditChainBroken)
            .await
            .expect("clear"),
    }
    tx.commit().await.expect("commit");
}

/// The alert events recorded so far, oldest first.
async fn recorded(database: &Database) -> Vec<DomainEvent> {
    let mut events = database
        .events()
        .list(&EventFilter::default(), 100)
        .await
        .expect("events");
    events.reverse();
    events
        .into_iter()
        .filter_map(|stored| match stored.event {
            RecordedEvent::Known(
                event @ (DomainEvent::AlertRaised { .. } | DomainEvent::AlertCleared { .. }),
            ) => Some(event),
            _ => None,
        })
        .collect()
}

/// Raising what the current alert says only marks it seen again; raising
/// something else clears it first; clearing clears it, and clearing nothing
/// records nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_current_alert_changes_only_with_its_condition() {
    let database = Harness::isolated().await.database;
    let current = async || {
        let mut tx = database.begin().await.expect("transaction");
        let current = tx
            .alerts()
            .current(AlertKind::AuditChainBroken)
            .await
            .expect("current");
        tx.commit().await.expect("commit");
        current
    };
    found(&database, None).await;
    assert_eq!(current().await, None);

    found(&database, Some(broken(5))).await;
    let first = current().await.expect("raised");
    assert_eq!(first.alert, Some(broken(5)));
    found(&database, Some(broken(5))).await;
    let seen = current().await.expect("still current");
    assert_eq!(seen.id, first.id);
    assert!(seen.seen_at > first.seen_at);

    found(&database, Some(broken(3))).await;
    let second = current().await.expect("raised again");
    assert_ne!(second.id, first.id);
    found(&database, None).await;
    assert_eq!(current().await, None);

    assert_eq!(
        recorded(&database).await,
        [
            DomainEvent::AlertRaised {
                alert_id: first.id,
                alert: broken(5)
            },
            DomainEvent::AlertCleared {
                alert_id: first.id,
                alert: broken(5)
            },
            DomainEvent::AlertRaised {
                alert_id: second.id,
                alert: broken(3)
            },
            DomainEvent::AlertCleared {
                alert_id: second.id,
                alert: broken(3)
            },
        ]
    );
}

/// Two changes at once never both find no alert current: the second raise waits
/// for the first, then finds what it raised and only marks it seen.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn concurrent_raises_leave_one_alert() {
    let database = Harness::isolated().await.database;
    let context = EventContext {
        actor: Actor::System {
            job: JobName::AuditVerification,
        },
        origin: RequestOrigin::default(),
        reason: None,
    };
    let mut first = database.begin().await.expect("transaction");
    Alerts::new(&mut first, &context)
        .raise(broken(5))
        .await
        .expect("raise");
    let second = tokio::spawn({
        let database = database.clone();
        async move { found(&database, Some(broken(5))).await }
    });
    crate::tests::until_blocked(&mut first, 1).await;
    first.commit().await.expect("commit");
    second.await.expect("second raise");
    let raised = recorded(&database).await;
    assert!(
        matches!(raised.as_slice(), [DomainEvent::AlertRaised { .. }]),
        "{raised:?}"
    );
}

/// Acknowledging an open alert records who did and why. It stays current:
/// finding the same condition again leaves it acknowledged, and a change raises a
/// new alert. Only an open alert is acknowledged.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_acknowledged_alert_stays_quiet_until_its_condition_changes() {
    let harness = Harness::isolated().await;
    let (database, service) = (&harness.database, harness.service());
    let admin = operator(harness.admin().await, Utc::now());
    let states = async || {
        service
            .list_alerts(&admin)
            .await
            .expect("alerts")
            .iter()
            .map(|alert| (alert.alert.clone(), alert.state()))
            .collect::<Vec<_>>()
    };
    found(database, Some(broken(5))).await;
    let id = service.list_alerts(&admin).await.expect("alerts")[0].id;
    let acknowledge = async || {
        let reason = Reason::parse("Looking into it".into()).expect("reason");
        service.acknowledge_alert(&admin, id, reason).await
    };
    acknowledge().await.expect("acknowledge");
    assert!(matches!(
        acknowledge().await,
        Err(AdminError::AlertNotFound)
    ));
    let acknowledged = database
        .events()
        .list(&EventFilter::default(), 1)
        .await
        .expect("events")
        .remove(0);
    assert!(matches!(acknowledged.actor, Actor::Admin { .. }));
    assert_eq!(
        acknowledged.event,
        RecordedEvent::Known(DomainEvent::AlertAcknowledged {
            alert_id: id,
            alert: broken(5)
        })
    );

    found(database, Some(broken(5))).await;
    assert_eq!(
        states().await,
        [(Some(broken(5)), AlertState::Acknowledged)]
    );
    found(database, Some(broken(3))).await;
    assert_eq!(
        states().await,
        [
            (Some(broken(3)), AlertState::Open),
            (Some(broken(5)), AlertState::Cleared),
        ]
    );
}
