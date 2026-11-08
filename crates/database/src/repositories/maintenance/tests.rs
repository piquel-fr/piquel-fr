//! Retention of the records an account no longer uses.
use crate::{Database, InsertUser, UserRepository};
use piquel_common::UserId;
use sqlx::PgPool;

/// Inserts an active account whose handle starts with `prefix`.
async fn insert_user(pool: &PgPool, prefix: &str) -> UserId {
    UserRepository::from_pool(pool)
        .insert(&InsertUser::named(prefix))
        .await
        .expect("user")
        .id
}

/// Revoked passkeys, unlinked identities and ended recoveries go 90 days after
/// they end, even a link cancelled after it expired, notifications and an
/// announcement's recipients a year after it arrives, with an announcement to
/// chosen accounts left without one, and a purged account's handles a year after
/// its purge, which released them. Newer ones stay.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "One record past and one within each limit."
)]
async fn ended_records_go_after_their_retention() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool, "retained").await;
    let purged = insert_user(&pool, "purged").await;
    // Test-generated IDs only, so formatting them into the SQL is safe. Each pair
    // is past its limit, then just within it, labelled 'old' and 'new'.
    sqlx::raw_sql(&format!(
        "INSERT INTO passkey_credentials (id, credential_id, user_id, credential, friendly_name, revoked_at)
        SELECT uuidv7(), uuid_send(uuidv7()), '{user}', '{{}}', label, now() - age
        FROM (VALUES ('old', interval '91 days'), ('new', interval '89 days')) v (label, age);
        INSERT INTO external_login_identities (id, user_id, provider_name, issuer, subject, revoked_at)
        SELECT uuidv7(), '{user}', 'github', 'https://github.com', label || '-{user}', now() - age
        FROM (VALUES ('old', interval '91 days'), ('new', interval '89 days')) v (label, age);
        INSERT INTO account_recoveries (id, user_id, secret_digest, started_at, expires_at, cancelled_at)
        VALUES (uuidv7(), '{user}', uuid_send(uuidv7()), now() - interval '92 days',
            now() - interval '91 days', now() - interval '1 day');
        INSERT INTO account_recoveries (id, user_id, secret_digest, started_at, expires_at)
        VALUES (uuidv7(), '{user}', uuid_send(uuidv7()), now() - interval '90 days',
            now() - interval '89 days');
        INSERT INTO notifications (id, user_id, payload, created_at)
        SELECT uuidv7(), '{user}', jsonb_build_object('kind', label), now() - age
        FROM (VALUES ('old', interval '366 days'), ('new', interval '364 days')) v (label, age);
        INSERT INTO announcements (id, subject, body, everyone, sent_at)
        SELECT uuidv7(), label, '{user}', everyone, now() - age
        FROM (VALUES ('old', FALSE, interval '366 days'), ('old to everyone', TRUE, interval '366 days'),
            ('new', FALSE, interval '364 days')) v (label, everyone, age);
        INSERT INTO announcement_recipients (announcement_id, user_id)
        SELECT id, '{user}' FROM announcements WHERE body = '{user}';
        DELETE FROM users WHERE id = '{purged}';"
    ))
    .execute(&pool)
    .await
    .expect("ended records");
    let handle: (String, bool) = sqlx::query_as(
        "SELECT handle, released_at > now() - interval '1 minute' FROM handles
        WHERE handle LIKE 'purged-' || right($1::text, 12)",
    )
    .bind(purged.to_string())
    .fetch_one(&pool)
    .await
    .expect("purged handle");
    assert!(handle.1, "the purge released {}", handle.0);

    // Other tests' announcements to everyone reach this account too, so only its
    // own rows count.
    let remaining = || async {
        sqlx::query_scalar::<_, String>(
            "SELECT 'passkey ' || friendly_name FROM passkey_credentials WHERE user_id = $1
            UNION ALL SELECT 'identity ' || split_part(subject, '-', 1)
            FROM external_login_identities WHERE user_id = $1
            UNION ALL SELECT 'recovery ' || CASE WHEN cancelled_at IS NULL THEN 'new' ELSE 'old' END
            FROM account_recoveries WHERE user_id = $1
            UNION ALL SELECT 'notification ' || (payload ->> 'kind') FROM notifications
            WHERE user_id = $1 AND payload ->> 'kind' IN ('old', 'new')
            UNION ALL SELECT 'announcement ' || subject FROM announcements WHERE body = $1::text
            UNION ALL SELECT 'recipient of ' || a.subject FROM announcement_recipients r
            JOIN announcements a ON a.id = r.announcement_id
            WHERE r.user_id = $1 AND a.body = $1::text
            UNION ALL SELECT 'handle ' || handle FROM handles WHERE handle = $2
            ORDER BY 1",
        )
        .bind(user.as_uuid())
        .bind(&handle.0)
        .fetch_all(&pool)
        .await
        .expect("remaining")
    };
    let maintenance = || async {
        Database { pool: pool.clone() }
            .maintenance()
            .purge_expired_auth_state(1000)
            .await
            .expect("cleanup")
    };
    maintenance().await;
    // The announcement to everyone stays, saying it no longer knows whom it
    // reached rather than counting no one.
    let kept: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM announcements WHERE body = $1 AND subject = 'old to everyone'",
    )
    .bind(user.to_string())
    .fetch_one(&pool)
    .await
    .expect("announcement to everyone");
    let kept = crate::AnnouncementRepository::from_pool(&pool)
        .find(piquel_common::AnnouncementId::from_uuid(kept).expect("ID"))
        .await
        .expect("find")
        .expect("kept");
    assert!(!kept.recipients_kept);
    let purged_handle = format!("handle {}", handle.0);
    assert_eq!(
        remaining().await,
        [
            "announcement new",
            "announcement old to everyone",
            purged_handle.as_str(),
            "identity new",
            "notification new",
            "passkey new",
            "recipient of new",
            "recovery new"
        ]
    );
    sqlx::query("UPDATE handles SET released_at = now() - interval '366 days' WHERE handle = $1")
        .bind(&handle.0)
        .execute(&pool)
        .await
        .expect("a year on");
    maintenance().await;
    assert_eq!(
        remaining().await,
        [
            "announcement new",
            "announcement old to everyone",
            "identity new",
            "notification new",
            "passkey new",
            "recipient of new",
            "recovery new"
        ]
    );
}
