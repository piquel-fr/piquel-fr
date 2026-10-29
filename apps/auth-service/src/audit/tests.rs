//! Sealing order, verification of tampered history, and pruning. Each test uses a
//! schema of its own, since the chain covers every event of its database.
use super::*;
use crate::{AdminError, AdminService, tests::operator};
use chrono::SubsecRound;
use piquel_common::{
    Personal, Provider,
    config::Variable,
    events::{Actor, DomainEvent, EventContext, RequestOrigin},
};
use piquel_crypto::NoteKey;
use piquel_repository::{
    DatabaseConfig, DatabaseTransaction, EventFilter, ExclusiveConnection, LockKey, Tamper,
};
use std::{sync::Arc, time::Duration};

/// A migrated schema of its own on `TEST_DATABASE_URL`, with a sealer that signs
/// a checkpoint on every pass with new events.
struct Fixture {
    /// The isolated database.
    database: Database,
    /// Seals, and signs with a key of its own.
    sealer: Sealer,
    /// Verifies the sealer's checkpoints.
    keys: AuditKeys,
    /// Events recorded so far, to tell them apart.
    recorded: u32,
}

impl Fixture {
    /// Creates the schema and a fresh audit key.
    async fn new() -> Self {
        let url = Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
        // Two connections: a test holds at most a transaction and a read at once,
        // and every fixture's pool is one more on the server the suite shares.
        let database = Database::isolated(
            DatabaseConfig::new(&url, 2, Duration::from_secs(5)).expect("database configuration"),
        )
        .await
        .expect("isolated database");
        let key = NoteKey::generate("auth.example/audit").expect("audit key");
        Self {
            database,
            keys: AuditKeys::given(&key.verifier().to_string()).expect("keys"),
            sealer: Sealer::eager(Arc::new(key)),
            recorded: 0,
        }
    }

    /// Records one event, with personal data, in `tx`.
    async fn record_in(&mut self, tx: &mut DatabaseTransaction<'_>) {
        self.recorded += 1;
        let context = EventContext {
            actor: Actor::Cli {
                os_user: "test".into(),
                host: "test".into(),
            },
            origin: RequestOrigin {
                client_ip: Some([192, 0, 2, 1].into()),
                user_agent_family: None,
            },
            reason: Some("Asked".into()),
        };
        let event = DomainEvent::IdentityLinked {
            provider: Provider::GitHub,
            subject: Personal::Value(format!("subject-{}", self.recorded)),
        };
        tx.record(&context, None, event).await.expect("record");
    }

    /// Records `count` events, each in its own committed transaction.
    async fn record(&mut self, count: u32) {
        let database = self.database.clone();
        for _ in 0..count {
            let mut tx = database.begin().await.expect("transaction");
            self.record_in(&mut tx).await;
            tx.commit().await.expect("commit");
        }
    }

    /// Seals until every committed event is sealed, then signs one checkpoint, so
    /// checkpoints land at known positions even while other tests' transactions on
    /// the cluster hold sealing back.
    async fn seal(&self) {
        let mut lock = self.lock().await;
        self.seal_with(&mut lock).await;
        self.sealer.checkpoint(&mut lock).await.expect("checkpoint");
        lock.release().await.expect("release");
    }

    /// Seals, holding the sealer's `lock`, until every committed event is sealed.
    async fn seal_with(&self, lock: &mut ExclusiveConnection) {
        tokio::time::timeout(Duration::from_secs(30), async {
            while self.unsealed().await > 0 {
                if Sealer::seal(lock).await.expect("seal") == 0 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        })
        .await
        .expect("every committed event is sealed");
    }

    /// Takes the sealer's lock. Advisory locks are per database, not per schema, so
    /// the other tests' fixtures take turns with it.
    async fn lock(&self) -> ExclusiveConnection {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(lock) = self
                    .database
                    .try_exclusive(LockKey::AuditChain)
                    .await
                    .expect("lock")
                {
                    return lock;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the sealer lock")
    }

    /// Counts the events not sealed yet.
    async fn unsealed(&self) -> u64 {
        self.database
            .audit()
            .unsealed_count()
            .await
            .expect("unsealed count")
    }

    /// Six sealed events, with checkpoints at positions 3 and 6.
    async fn sealed_six() -> Self {
        let mut fixture = Self::new().await;
        fixture.record(3).await;
        fixture.seal().await;
        fixture.record(3).await;
        fixture.seal().await;
        fixture
    }

    /// Verifies the chain with the sealer's key.
    async fn verify(&self) -> AuditVerification {
        AuditChain::new(self.database.clone())
            .verify(&self.keys)
            .await
            .expect("verification")
    }

    /// Where verification finds the chain broken, if it does.
    async fn broken(&self) -> Option<(u64, ChainProblem)> {
        self.verify()
            .await
            .broken
            .map(|broken| (broken.position, broken.problem))
    }

    /// Applies `tamper`.
    async fn tamper(&self, tamper: Tamper) {
        self.database.audit().tamper(tamper).await.expect("tamper");
    }
}

/// Events are sealed in safe consumer order: an event whose transaction is still
/// running holds back the events committed after it began, and is sealed first
/// once it commits. The chain then verifies, and the sealer signed a checkpoint.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn events_are_sealed_in_safe_order_and_checkpointed() {
    let mut fixture = Fixture::new().await;
    let database = fixture.database.clone();
    // The open transaction holds back sealing in every schema of the cluster, so
    // it stays open only while this test holds the lock other tests seal under.
    let mut lock = fixture.lock().await;
    let mut open = database.begin().await.expect("transaction");
    fixture.record_in(&mut open).await;
    fixture.record(1).await;
    fixture.sealer.pass(&mut lock, None).await.expect("seal");
    assert_eq!(
        fixture.unsealed().await,
        1,
        "the later event waits for the open transaction"
    );
    open.commit().await.expect("commit");
    lock.release().await.expect("release");
    fixture.seal().await;

    let chain = database.audit().chain(0, 10).await.expect("chain");
    let positions: Vec<_> = chain.iter().map(|event| event.link.position).collect();
    assert_eq!(positions, [1, 2]);
    let [first, second] =
        [&chain[0], &chain[1]].map(|event| serde_json::to_value(&event.content).expect("content"));
    assert!(
        first["occurred_at"].as_str() < second["occurred_at"].as_str(),
        "the open transaction's earlier event comes first"
    );
    assert_eq!(
        first["payload"],
        serde_json::json!({"provider": "github", "subject": "$erased"}),
        "personal values stay out of the chain"
    );
    let verification = fixture.verify().await;
    assert_eq!(verification.broken, None);
    assert_eq!(verification.events_checked, 2);
    assert_eq!(verification.checkpoints_checked, 1);
    assert_eq!(verification.latest_checkpoint, verification.newest);
    let latest = database
        .audit()
        .latest_checkpoint()
        .await
        .expect("checkpoint")
        .expect("a checkpoint");
    let text = fixture
        .keys
        .verifiers
        .open(&latest.note)
        .expect("signed note");
    assert!(text.starts_with("auth.example/audit\nposition 2\nhead "));
}

/// Every kind of tampering breaks verification at the first position it changes,
/// while erasing personal data, which the chain does not cover, does not.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn verification_finds_the_first_tampered_position() {
    let other = NoteKey::generate("auth.example/audit").expect("other key");
    let forged = other
        .sign(
            &CheckpointText {
                origin: "auth.example/audit".into(),
                head: ChainLink {
                    position: 3,
                    hash: [7; 32],
                },
                time: Utc::now().trunc_subsecs(0),
            }
            .render(),
        )
        .expect("forged note");
    let cases = [
        (
            Tamper::EditPayload(2, serde_json::json!({})),
            Some((2, ChainProblem::EventChanged)),
        ),
        (
            Tamper::DeleteEvent(2),
            Some((2, ChainProblem::MissingEvent)),
        ),
        (
            Tamper::InsertEvent(2),
            Some((2, ChainProblem::EventChanged)),
        ),
        (
            Tamper::SwapEvents(2, 3),
            Some((2, ChainProblem::EventChanged)),
        ),
        (
            Tamper::DeleteEvent(6),
            Some((6, ChainProblem::CheckpointBeyondChain)),
        ),
        (
            Tamper::EditCheckpointHead(3, [7; 32]),
            Some((3, ChainProblem::CheckpointMalformed)),
        ),
        (
            Tamper::EditCheckpointNote(3, forged.clone()),
            Some((3, ChainProblem::CheckpointSignature)),
        ),
        (
            Tamper::SetAnchor(3),
            Some((1, ChainProblem::EventBeforeAnchor)),
        ),
        (Tamper::ErasePersonalData(2), None),
    ];
    for (tamper, expected) in cases {
        let fixture = Fixture::sealed_six().await;
        assert_eq!(fixture.broken().await, None, "intact before {tamper:?}");
        fixture.tamper(tamper.clone()).await;
        assert_eq!(fixture.broken().await, expected, "after {tamper:?}");
    }

    // Truncated after 3: a forged checkpoint at 9 does not hide the valid one at
    // 6, which pruning through 6 would otherwise accept.
    let mut fixture = Fixture::sealed_six().await;
    fixture.record(3).await;
    fixture.seal().await;
    for position in 4..=9 {
        fixture.tamper(Tamper::DeleteEvent(position)).await;
    }
    fixture.tamper(Tamper::EditCheckpointNote(9, forged)).await;
    assert_eq!(
        fixture.broken().await,
        Some((6, ChainProblem::CheckpointBeyondChain))
    );
}

/// An attacker who edits an event and recomputes every stored hash after it
/// still cannot match the checkpoint signed over the original.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn recomputed_hashes_do_not_match_signed_checkpoints() {
    let fixture = Fixture::sealed_six().await;
    fixture
        .tamper(Tamper::EditPayload(2, serde_json::json!({})))
        .await;
    let chain = fixture.database.audit().chain(0, 10).await.expect("chain");
    let mut head = ChainLink::GENESIS;
    for event in &chain {
        head = head.extend(&event.content).expect("link");
        fixture
            .tamper(Tamper::SetHash(head.position, head.hash))
            .await;
    }
    assert_eq!(
        fixture.broken().await,
        Some((3, ChainProblem::CheckpointMismatch))
    );
}

/// The sealer recomputes the events sealed since the latest checkpoint before
/// signing the next one, and refuses to sign a chain that no longer matches.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn checkpoints_never_sign_a_chain_that_does_not_match() {
    let mut fixture = Fixture::sealed_six().await;
    fixture.record(1).await;
    let mut lock = fixture.lock().await;
    fixture.seal_with(&mut lock).await;
    fixture
        .tamper(Tamper::EditPayload(7, serde_json::json!({})))
        .await;
    assert!(matches!(
        fixture.sealer.checkpoint(&mut lock).await,
        Err(AuditError::Broken(ChainBreak {
            position: 7,
            problem: ChainProblem::EventChanged
        }))
    ));
    lock.release().await.expect("release");
    let latest = fixture
        .database
        .audit()
        .latest_checkpoint()
        .await
        .expect("latest");
    assert_eq!(latest.map(|latest| latest.position), Some(6));
}

/// Pruning needs a checkpoint, refuses a chain broken at or before it, records
/// itself, and leaves an anchor that the remaining and future events extend.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pruning_refuses_broken_chains_and_leaves_a_working_anchor() {
    let broken = Fixture::sealed_six().await;
    broken
        .tamper(Tamper::EditPayload(2, serde_json::json!({})))
        .await;
    let service = AdminService::new(broken.database.clone(), false);
    let prune = async |through| {
        service
            .prune_audit_chain(&operator(), &broken.keys, through)
            .await
    };
    assert!(matches!(
        prune(2).await,
        Err(AdminError::Audit(AuditError::NoCheckpoint(2)))
    ));
    assert!(matches!(
        prune(3).await,
        Err(AdminError::Audit(AuditError::Broken(ChainBreak {
            position: 2,
            ..
        })))
    ));

    let mut fixture = Fixture::sealed_six().await;
    let service = AdminService::new(fixture.database.clone(), false);
    let prune = async |keys, through| service.prune_audit_chain(&operator(), keys, through).await;
    assert_eq!(prune(&fixture.keys, 3).await.expect("prune"), 3);
    let verification = fixture.verify().await;
    assert_eq!(verification.broken, None);
    assert_eq!(verification.anchor.map(|anchor| anchor.position), Some(3));
    assert_eq!(verification.events_checked, 3);
    assert_eq!(verification.unsealed, 1, "the prune is recorded");
    assert_eq!(
        verification.checkpoints_checked, 2,
        "pruned checkpoints stay"
    );
    assert!(matches!(
        prune(&fixture.keys, 3).await,
        Err(AdminError::Audit(AuditError::AlreadyPruned { anchor: 3 }))
    ));

    // Pruning every sealed event leaves the anchor as the head the next event
    // extends: here, the two prunes' own events, then a new one.
    assert_eq!(prune(&fixture.keys, 6).await.expect("prune"), 3);
    fixture.record(1).await;
    fixture.seal().await;
    let verification = fixture.verify().await;
    assert_eq!(verification.broken, None);
    assert_eq!(verification.newest.map(|newest| newest.position), Some(9));
    assert_eq!(verification.events_checked, 3);
    let filter = EventFilter {
        kind: Some("audit_history_pruned".into()),
        ..EventFilter::default()
    };
    let pruned = fixture
        .database
        .events()
        .list(&filter, 10)
        .await
        .expect("events");
    assert_eq!(pruned.len(), 2);
}

/// The dashboard's audit page judges each checkpoint by `audit prune`'s rules:
/// from a break on, none may be pruned through, and once pruned, the page starts
/// after the anchor.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_audit_page_says_where_pruning_is_allowed() {
    let pruning = async |fixture: &Fixture, after| {
        AuditChain::new(fixture.database.clone())
            .page(&fixture.keys, after)
            .await
            .expect("page")
            .checkpoints
            .into_iter()
            .map(|checkpoint| (checkpoint.point.position, checkpoint.pruning))
            .collect::<Vec<_>>()
    };
    let broken = Fixture::sealed_six().await;
    assert_eq!(
        pruning(&broken, None).await,
        [(3, Pruning::Prunable), (6, Pruning::Prunable)]
    );
    broken
        .tamper(Tamper::EditPayload(5, serde_json::json!({})))
        .await;
    let at = ChainBreak {
        position: 5,
        problem: ChainProblem::EventChanged,
    };
    assert_eq!(
        pruning(&broken, None).await,
        [(3, Pruning::Prunable), (6, Pruning::Broken(at))]
    );

    let pruned = Fixture::sealed_six().await;
    AdminService::new(pruned.database.clone(), false)
        .prune_audit_chain(&operator(), &pruned.keys, 3)
        .await
        .expect("prune");
    assert_eq!(pruning(&pruned, None).await, [(6, Pruning::Prunable)]);
    assert_eq!(
        pruning(&pruned, Some(0)).await,
        [(3, Pruning::Pruned { anchor: 3 }), (6, Pruning::Prunable)]
    );
}

/// The newest checkpoint is served as its signed note, and the list pages through
/// checkpoints oldest first; both are cacheable.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn checkpoints_are_published() {
    use crate::AuthConfig;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;

    let fixture = Fixture::sealed_six().await;
    // The whole service, whose security layer sets every response's caching. The
    // schema is the fixture's own, so no other test shares its rate budgets.
    let router = AuthConfig::test(&"https://auth.example".parse().expect("origin"))
        .test_router(fixture.database.clone(), ([192, 0, 2, 1], 1).into())
        .await;
    let get = async |path: &str| {
        let response = router
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).expect("request"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=60, no-transform"
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8(body.to_vec()).expect("UTF-8")
    };
    let latest = get("/audit/checkpoints/latest").await;
    let text = fixture.keys.verifiers.open(&latest).expect("signed note");
    assert!(text.contains("\nposition 6\n"), "{text}");
    let page: serde_json::Value =
        serde_json::from_str(&get("/audit/checkpoints?after=3").await).expect("JSON");
    assert_eq!(page.as_array().map(Vec::len), Some(1));
    assert_eq!(page[0]["position"], 6);
    assert_eq!(page[0]["note"], latest);
}

/// The dashboard verifies with the environment's committed key, or, where none is
/// committed, as on a preview, with the server's own, and says which.
#[test]
fn the_dashboard_falls_back_to_the_servers_own_key() {
    let own = NoteKey::generate("auth.example/audit").expect("key");
    for (origin, source) in [
        ("https://auth.piquel.fr", VerificationKeys::Committed),
        ("https://auth.example", VerificationKeys::Uncommitted),
    ] {
        let keys =
            AuditKeys::for_server(&origin.parse().expect("origin"), own.verifier()).expect("keys");
        assert_eq!(keys.source, source, "{origin}");
    }
}

/// Checkpoint text renders and parses back, and nothing else parses.
#[test]
fn checkpoint_text_round_trips() {
    let text = CheckpointText {
        origin: "auth.piquel.fr/audit".into(),
        head: ChainLink {
            position: 48_211,
            hash: [0xde; 32],
        },
        time: "2026-10-13T12:00:00Z".parse().expect("time"),
    };
    let rendered = text.render();
    assert_eq!(
        rendered,
        "auth.piquel.fr/audit\nposition 48211\nhead 3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t4=\n\
         time 2026-10-13T12:00:00Z\n"
    );
    assert_eq!(CheckpointText::parse(&rendered), Some(text));
    for malformed in [
        rendered.trim_end(),
        &rendered.replace("position 48211", "position 048211"),
        &format!("{rendered}extra\n"),
    ] {
        assert_eq!(CheckpointText::parse(malformed), None);
    }
}

/// Production and staging each find only their own committed key, so one cannot
/// vouch for the other's checkpoints, and `audit verify` works without `--key`.
#[test]
fn committed_keys_are_per_environment() {
    for (host, other) in [
        ("auth.piquel.fr", "auth.staging.piquel.fr"),
        ("auth.staging.piquel.fr", "auth.piquel.fr"),
    ] {
        let keys = AuditKeys::committed(&format!("https://{host}").parse().expect("origin"))
            .expect("committed keys");
        assert!(!keys.verifiers.is_empty(), "{host}");
        assert!(
            keys.verifiers.named(&format!("{other}/audit")).is_empty(),
            "{host} trusts {other}'s key"
        );
    }
    assert!(matches!(
        AuditKeys::committed(&"https://auth.example".parse().expect("origin")),
        Err(AuditError::NoCommittedKey(_))
    ));
}
