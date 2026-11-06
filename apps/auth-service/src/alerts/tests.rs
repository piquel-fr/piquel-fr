//! How raising and clearing change the current alert of a kind, and what they
//! record. Each test uses a schema of its own, since an alert concerns the whole
//! database.
use super::*;
use crate::admin::tests::Harness;
use piquel_common::{
    admin::{ChainBreak, ChainProblem},
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
