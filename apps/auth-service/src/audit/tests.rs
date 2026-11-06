//! Sealing order, verification of tampered history, and pruning. Each test uses a
//! schema of its own, since the chain covers every event of its database.
use super::*;
use crate::{
    AdminError, AdminService, AuthConfig,
    config::AuditConfig,
    tests::{Replicas, operator},
};
use chrono::{SubsecRound, TimeDelta};
use piquel_common::{
    Personal, Provider,
    config::Origin,
    events::{Actor, DomainEvent, EventContext, JobName, RequestOrigin},
};
use piquel_crypto::NoteKey;
use piquel_repository::{
    Checkpoint, DatabaseTransaction, EventFilter, ExclusiveConnection, LockKey, Tamper,
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
    keys: Arc<AuditKeys>,
    /// The audit configuration of a service at `https://auth.example`, signing
    /// with the sealer's key.
    audit: AuditConfig,
    /// Events recorded so far, to tell them apart.
    recorded: u32,
}

impl Fixture {
    /// Creates the schema and a fresh audit key.
    async fn new() -> Self {
        // Two connections: a test holds at most a transaction and a read at once,
        // and every fixture's pool is one more on the server the suite shares.
        let database = Database::isolated(Replicas::database_config(2))
            .await
            .expect("isolated database");
        let key = NoteKey::generate("auth.example/audit").expect("audit key");
        let keys = Arc::new(AuditKeys::given(&key.verifier().to_string()).expect("keys"));
        let audit = AuditConfig::new(&Self::origin(), key).expect("audit configuration");
        Self {
            database,
            keys,
            sealer: Sealer::eager(&audit),
            audit,
            recorded: 0,
        }
    }

    /// The origin of the service the fixture's key is named after.
    fn origin() -> Origin {
        "https://auth.example".parse().expect("origin")
    }

    /// The whole service over the fixture's schema and audit key, whose security
    /// layer sets every response's caching. The schema is the fixture's own, so no
    /// other test shares its rate budgets.
    async fn router(&self) -> axum::Router {
        let mut config = AuthConfig::test(&Self::origin());
        config.audit = self.audit.clone();
        config
            .test_router(self.database.clone(), ([192, 0, 2, 1], 1).into())
            .await
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
                if self.sealer.seal(lock).await.expect("seal") == 0 {
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

    /// Stores a checkpoint of the stored head at `position`, signed by another
    /// key and dated `ahead` of now, as someone with auth's database role but not
    /// its audit key can: a trigger allows up to a minute.
    async fn forge_checkpoint(&self, position: u64, ahead: TimeDelta) {
        let head = self
            .database
            .audit()
            .chain(position - 1, 1)
            .await
            .expect("chain")[0]
            .sealed
            .link;
        let time = (Utc::now() + ahead).trunc_subsecs(0);
        let text = CheckpointText {
            origin: "auth.example/audit".into(),
            head,
            time,
        };
        let other = NoteKey::generate("auth.example/audit").expect("another key");
        self.database
            .audit()
            .insert_checkpoint(&Checkpoint {
                position,
                head: head.hash,
                created_at: time,
                note: other.sign(&text.render()).expect("forged note"),
            })
            .await
            .expect("a checkpoint the database cannot check");
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
    let positions: Vec<_> = chain
        .iter()
        .map(|event| event.sealed.link.position)
        .collect();
    assert_eq!(positions, [1, 2]);
    let [first, second] = [&chain[0], &chain[1]]
        .map(|event| serde_json::to_value(&event.sealed.content).expect("content"));
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
        .newest_checkpoints(None, 1)
        .await
        .expect("checkpoint")
        .pop()
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
        head = head.extend(&event.sealed.content).expect("link");
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
        .newest_checkpoints(None, 1)
        .await
        .expect("latest");
    assert_eq!(latest.first().map(|latest| latest.position), Some(6));
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

/// After a prune, a chain none of whose checkpoints verify, as when the key that
/// signed them was removed, is recomputed from the anchor rather than the first
/// position, which pruning deleted, so signing resumes.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_resumes_from_the_anchor_when_no_checkpoint_verifies() {
    let mut fixture = Fixture::sealed_six().await;
    AdminService::new(fixture.database.clone(), false)
        .prune_audit_chain(&operator(), &fixture.keys, 3)
        .await
        .expect("prune");
    let key = NoteKey::generate("auth.example/audit").expect("new key");
    let audit = AuditConfig::new(&Fixture::origin(), key).expect("audit configuration");
    fixture.sealer = Sealer::eager(&audit);
    fixture.record(1).await;
    fixture.seal().await;
    let latest = fixture
        .database
        .audit()
        .newest_checkpoints(None, 1)
        .await
        .expect("latest");
    assert_eq!(latest.first().map(|latest| latest.position), Some(8));
}

/// The dashboard's audit page verifies nothing: it shows the newest verification
/// recorded, so a break shows only once an operator verifies again, and judges each
/// checkpoint by `audit prune`'s rules against that verification. Once pruned, the
/// page starts after the anchor.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_audit_page_shows_the_newest_recorded_verification() {
    let page = async |fixture: &Fixture, after| {
        AuditChain::new(fixture.database.clone())
            .page(after)
            .await
            .expect("page")
    };
    let pruning = |page: &AuditPage| {
        page.checkpoints
            .iter()
            .map(|checkpoint| (checkpoint.point.position, checkpoint.pruning.clone()))
            .collect::<Vec<_>>()
    };
    let verify = async |fixture: &Fixture| {
        AdminService::new(fixture.database.clone(), false)
            .verify_audit_chain(&operator(), &fixture.keys)
            .await
            .expect("verification")
    };
    let broken = Fixture::sealed_six().await;
    let unverified = page(&broken, None).await;
    assert_eq!(unverified.verified, None);
    assert_eq!(
        unverified.chain.newest.map(|newest| newest.position),
        Some(6)
    );
    let intact = verify(&broken).await;
    broken
        .tamper(Tamper::EditPayload(5, serde_json::json!({})))
        .await;
    let stale = page(&broken, None).await;
    assert_eq!(
        pruning(&stale),
        [(3, Pruning::Prunable), (6, Pruning::Prunable)]
    );
    assert_eq!(
        stale.verified.map(|verified| verified.verification),
        Some(intact)
    );
    let found = verify(&broken).await;
    let at = ChainBreak {
        position: 5,
        problem: ChainProblem::EventChanged,
    };
    assert_eq!(found.broken.as_ref(), Some(&at));
    let reverified = page(&broken, None).await;
    assert_eq!(
        pruning(&reverified),
        [(3, Pruning::Prunable), (6, Pruning::Broken(at))]
    );
    assert_eq!(
        reverified.verified.map(|verified| verified.verification),
        Some(found)
    );

    let pruned = Fixture::sealed_six().await;
    AdminService::new(pruned.database.clone(), false)
        .prune_audit_chain(&operator(), &pruned.keys, 3)
        .await
        .expect("prune");
    assert_eq!(
        pruning(&page(&pruned, None).await),
        [(6, Pruning::Prunable)]
    );
    assert_eq!(
        pruning(&page(&pruned, Some(0)).await),
        [(3, Pruning::Pruned { anchor: 3 }), (6, Pruning::Prunable)]
    );
}

/// The verifier job verifies the chain when no verification was recorded lately,
/// and records what it found as itself, which then holds off its next pass.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_verifier_verifies_when_no_verification_is_recent() {
    let fixture = Fixture::sealed_six().await;
    let verifier = Verifier::new(AuditKeys {
        verifiers: fixture.keys.verifiers.clone(),
        source: fixture.keys.source,
    });
    let mut lock = fixture
        .database
        .try_exclusive(LockKey::AuditVerification)
        .await
        .expect("lock")
        .expect("no other test verifies");
    let intact = fixture.verify().await;
    assert_eq!(verifier.pass(&mut lock).await.expect("pass"), Some(intact));
    let newest = fixture
        .database
        .events()
        .newest_audit_verification()
        .await
        .expect("newest")
        .expect("recorded");
    assert_eq!(
        newest.actor,
        Actor::System {
            job: JobName::AuditVerification
        }
    );
    assert_eq!(verifier.pass(&mut lock).await.expect("pass"), None);
    lock.release().await.expect("release");
}

/// The newest checkpoint is served as its signed note, and the list pages through
/// checkpoints oldest first; both are cacheable.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn checkpoints_are_published() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;

    let fixture = Fixture::sealed_six().await;
    let router = fixture.router().await;
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
    let response = router
        .oneshot(
            Request::get(format!("/audit/checkpoints?after={}", u64::MAX))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "no position is that far"
    );
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
/// Where none is committed, as on a preview, the dashboard verifies with the
/// server's own key, and says which.
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

/// A checkpoint whose signature does not verify, as someone with auth's database
/// role but not the audit key could add, is never served, and postpones nothing
/// though dated ahead: the sealer signs the next one from the newest that
/// verifies, and verification still reports the forged one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn forged_checkpoints_are_passed_over_and_not_served() {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    let mut fixture = Fixture::sealed_six().await;
    fixture.record(1).await;
    let mut lock = fixture.lock().await;
    fixture.seal_with(&mut lock).await;
    // Dated ahead, so a sealer that counted its interval from the newest stored
    // checkpoint would wait for it.
    fixture.forge_checkpoint(7, TimeDelta::seconds(30)).await;
    let response = fixture
        .router()
        .await
        .oneshot(
            Request::get("/audit/checkpoints/latest")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let latest = String::from_utf8(body.to_vec()).expect("UTF-8");
    let text = fixture.keys.verifiers.open(&latest).expect("a signed note");
    assert!(text.contains("\nposition 6\n"), "{text}");

    fixture
        .sealer
        .checkpoint(&mut lock)
        .await
        .expect("checkpoint");
    let newest = fixture.database.audit().newest_checkpoints(None, 1).await;
    assert_eq!(
        newest.expect("checkpoints")[0].position,
        7,
        "the forged checkpoint holds the head until a new event"
    );
    lock.release().await.expect("release");
    fixture.record(1).await;
    fixture.seal().await;
    let newest = fixture.database.audit().newest_checkpoints(None, 1).await;
    let newest = newest.expect("checkpoints").remove(0);
    assert_eq!(newest.position, 8);
    fixture.keys.verifiers.open(&newest.note).expect("signed");
    assert_eq!(
        fixture.broken().await,
        Some((7, ChainProblem::CheckpointSignature))
    );
}

/// A forged checkpoint over a tampered event, as someone with auth's database
/// role can seal one, is never built on: the sealer recomputes from the newest
/// checkpoint that verifies and refuses to sign the broken chain.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn forged_checkpoints_are_never_built_on() {
    let mut fixture = Fixture::sealed_six().await;
    fixture.record(1).await;
    let mut lock = fixture.lock().await;
    fixture.seal_with(&mut lock).await;
    fixture
        .tamper(Tamper::EditPayload(7, serde_json::json!({})))
        .await;
    fixture.forge_checkpoint(7, TimeDelta::zero()).await;
    fixture.record(1).await;
    fixture.seal_with(&mut lock).await;
    assert!(matches!(
        fixture.sealer.checkpoint(&mut lock).await,
        Err(AuditError::Broken(ChainBreak {
            position: 7,
            problem: ChainProblem::EventChanged
        }))
    ));
    lock.release().await.expect("release");
}

/// The sealer checks the order of the first event after the checkpoint it
/// recomputes from against the event that checkpoint signed, so an event sealed
/// out of order right after a checkpoint is never signed.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn checkpoints_never_sign_events_out_of_order() {
    let mut fixture = Fixture::sealed_six().await;
    fixture.record(1).await;
    let mut lock = fixture.lock().await;
    fixture.seal_with(&mut lock).await;
    fixture.tamper(Tamper::SwapTransactions(6, 7)).await;
    assert!(matches!(
        fixture.sealer.checkpoint(&mut lock).await,
        Err(AuditError::Broken(ChainBreak {
            position: 7,
            problem: ChainProblem::OutOfOrder
        }))
    ));
    lock.release().await.expect("release");
}

/// A checkpoint that fails does not stop sealing: the pass seals every batch,
/// then returns the error. Five events of one transaction, in batches of two,
/// are sealed in one pass; sealing a batch per pass would take three.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sealing_goes_on_when_a_checkpoint_fails() {
    let mut fixture = Fixture::sealed_six().await;
    fixture.record(1).await;
    let mut lock = fixture.lock().await;
    fixture.seal_with(&mut lock).await;
    fixture
        .tamper(Tamper::EditPayload(7, serde_json::json!({})))
        .await;
    fixture.sealer = fixture.sealer.sealing(2, EventContent::UNTAGGED);
    let database = fixture.database.clone();
    let mut tx = database.begin().await.expect("transaction");
    for _ in 0..5 {
        fixture.record_in(&mut tx).await;
    }
    tx.commit().await.expect("commit");
    // Events are sealed only once every older transaction has ended, and other
    // tests' transactions can delay that, so passes that seal nothing don't count.
    let mut sealing = 0;
    tokio::time::timeout(Duration::from_secs(30), async {
        while let unsealed @ 1.. = fixture.unsealed().await {
            let pass = fixture.sealer.pass(&mut lock, None).await;
            assert!(matches!(pass, Err(AuditError::Broken(_))), "{pass:?}");
            if fixture.unsealed().await < unsealed {
                sealing += 1;
            } else {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    })
    .await
    .expect("every committed event is sealed");
    lock.release().await.expect("release");
    assert_eq!(sealing, 1, "{sealing} passes sealed events");
}

/// More checkpoints that do not verify than the sealer looks past, as removing a
/// key that signed for days leaves, do not stop signing: it recomputes the chain
/// and signs above them.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_resumes_above_too_many_untrusted_checkpoints() {
    let mut fixture = Fixture::new().await;
    let database = fixture.database.clone();
    let mut tx = database.begin().await.expect("transaction");
    for _ in 0..1_002 {
        fixture.record_in(&mut tx).await;
    }
    tx.commit().await.expect("commit");
    let mut lock = fixture.lock().await;
    fixture.seal_with(&mut lock).await;
    for position in 1..=1_001 {
        fixture.forge_checkpoint(position, TimeDelta::zero()).await;
    }
    fixture
        .sealer
        .checkpoint(&mut lock)
        .await
        .expect("checkpoint");
    lock.release().await.expect("release");
    let newest = fixture.database.audit().newest_checkpoints(None, 1).await;
    let newest = newest.expect("checkpoints").remove(0);
    assert_eq!(newest.position, 1_002);
    fixture.keys.verifiers.open(&newest.note).expect("signed");
}

/// After a checkpoint fails, the sealer tries again only once the interval has
/// passed, so a broken chain is not recomputed on every pass.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_failed_checkpoint_is_retried_after_the_interval() {
    let every = Duration::from_millis(1_500);
    let mut fixture = Fixture::sealed_six().await;
    fixture.sealer = fixture
        .sealer
        .checkpointing_every(TimeDelta::from_std(every).expect("interval"));
    fixture.record(1).await;
    let mut lock = fixture.lock().await;
    fixture.seal_with(&mut lock).await;
    fixture
        .tamper(Tamper::EditPayload(7, serde_json::json!({})))
        .await;
    // The checkpoint at 6 was just signed, and checkpoints have whole seconds.
    tokio::time::sleep(every * 2).await;
    let broken = |result: &Result<(), AuditError>| matches!(result, Err(AuditError::Broken(_)));
    assert!(broken(&fixture.sealer.checkpoint(&mut lock).await));
    assert!(fixture.sealer.checkpoint(&mut lock).await.is_ok(), "waits");
    tokio::time::sleep(every).await;
    assert!(
        broken(&fixture.sealer.checkpoint(&mut lock).await),
        "tries again"
    );
    lock.release().await.expect("release");
}

/// A backlog of full batches does not postpone checkpoints: the sealer checks
/// whether one is due after every batch, so with no interval, no two are more
/// than a batch apart. Other tests' transactions may cut a batch short.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn checkpoints_keep_their_interval_while_batches_stay_full() {
    let mut fixture = Fixture::new().await;
    fixture.sealer = fixture.sealer.sealing(2, EventContent::UNTAGGED);
    // One transaction, so all five become ready to seal at once.
    let database = fixture.database.clone();
    let mut tx = database.begin().await.expect("transaction");
    for _ in 0..5 {
        fixture.record_in(&mut tx).await;
    }
    tx.commit().await.expect("commit");
    let mut lock = fixture.lock().await;
    tokio::time::timeout(Duration::from_secs(30), async {
        while fixture.unsealed().await > 0 {
            fixture.sealer.pass(&mut lock, None).await.expect("pass");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("every committed event is sealed");
    lock.release().await.expect("release");
    let checkpoints = fixture
        .database
        .audit()
        .checkpoints(0, 10)
        .await
        .expect("checkpoints");
    let positions: Vec<_> = std::iter::once(0)
        .chain(checkpoints.iter().map(|checkpoint| checkpoint.position))
        .collect();
    assert_eq!(positions.last(), Some(&5));
    assert!(
        positions.windows(2).all(|pair| pair[1] - pair[0] <= 2),
        "{positions:?}"
    );
}

/// Events sealed in format 2 name it in their canonical form, and events sealed
/// before, untagged, keep hashing without it; one chain holds both and verifies.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_chain_format_is_per_event() {
    let mut fixture = Fixture::new().await;
    fixture.record(1).await;
    fixture.seal().await;
    fixture.sealer = fixture.sealer.sealing(1_000, EventContent::NEWEST_FORMAT);
    fixture.record(1).await;
    fixture.seal().await;
    let chain = fixture.database.audit().chain(0, 10).await.expect("chain");
    let canonical = chain
        .iter()
        .map(|event| serde_json::to_value(&event.sealed.content).expect("content"))
        .collect::<Vec<_>>();
    assert_eq!(canonical[0].get("format"), None);
    assert_eq!(canonical[1]["format"], 2);
    assert_eq!(fixture.verify().await.broken, None);
}

/// Histories list events in the order they were recorded in, which the chain
/// does not cover, so verification checks it against the chain.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn verification_checks_the_recorded_order() {
    let fixture = Fixture::sealed_six().await;
    fixture.tamper(Tamper::SwapTransactions(4, 5)).await;
    assert_eq!(fixture.broken().await, Some((5, ChainProblem::OutOfOrder)));
}
