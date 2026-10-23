//! Renames, reclaims and their races, against the schema's keys.
use crate::{
    Database, DatabaseError, InsertUser, connection::MIGRATOR, repositories::UserRepository,
};
use piquel_common::{Handle, UserId};
use sqlx::{Connection, PgConnection};

/// The schema's `handle_skeleton` is the Rust type's skeleton, which the generated
/// `skeleton` column, and so look-alike uniqueness, relies on.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn the_schema_computes_the_rust_skeleton() {
    let pool = Database::test_pool().await;
    for handle in [
        "pique1",
        "p-iquel",
        "rnoon",
        "vvave",
        "b0b-5am",
        "a1i-rn-vv-r-n",
        "plain",
    ] {
        let handle = Handle::parse(handle).expect("handle");
        let stored: String = sqlx::query_scalar("SELECT handle_skeleton($1)")
            .bind(handle.as_str())
            .fetch_one(&pool)
            .await
            .expect("skeleton");
        assert_eq!(stored, handle.skeleton(), "{handle}");
    }
}

/// Two accounts renaming to one handle at once: exactly one gets it, whichever
/// commits first.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn concurrent_renames_to_one_handle_let_one_win() {
    let database = Database {
        pool: Database::test_pool().await,
    };
    let accounts = [InsertUser::named("race"), InsertUser::named("race")];
    for account in &accounts {
        database.users().insert(account).await.expect("user");
    }
    let wanted =
        Handle::parse(&format!("won-{}", &accounts[0].id.to_string()[24..])).expect("handle");
    let rename = async |user: UserId| -> Result<bool, DatabaseError> {
        let mut tx = database.begin().await?;
        tx.users().find_active_by_id_for_update(user).await?;
        if !tx.rename_handle(user, &wanted).await? {
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    };
    let (first, second) = tokio::join!(rename(accounts[0].id), rename(accounts[1].id));
    let won: Vec<bool> = [first, second]
        .into_iter()
        .map(|result| match result {
            Ok(won) => won,
            Err(DatabaseError::Conflict(_)) => false,
            Err(error) => panic!("rename failed: {error}"),
        })
        .collect();
    assert_eq!(won.iter().filter(|won| **won).count(), 1, "{won:?}");
    let winner = UserRepository::from_pool(&database.pool)
        .find_by_handle(&wanted)
        .await
        .expect("lookup")
        .expect("holder");
    assert_eq!(won[0], winner.id == accounts[0].id);
}

/// Two accounts asking for each other's handles are both refused, without a
/// deadlock: neither releases its own handle first.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn swapping_handles_is_refused_without_a_deadlock() {
    let database = Database {
        pool: Database::test_pool().await,
    };
    let accounts = [InsertUser::named("swap"), InsertUser::named("swap")];
    for account in &accounts {
        database.users().insert(account).await.expect("user");
    }
    let rename = async |user: UserId, handle: &Handle| -> Result<bool, DatabaseError> {
        let mut tx = database.begin().await?;
        tx.users().find_active_by_id_for_update(user).await?;
        tx.rename_handle(user, handle).await
    };
    let (first, second) = tokio::join!(
        rename(accounts[0].id, &accounts[1].handle),
        rename(accounts[1].id, &accounts[0].handle)
    );
    assert!(matches!(first, Ok(false)), "{first:?}");
    assert!(matches!(second, Ok(false)), "{second:?}");
}

/// A locked lookup that waited for a rename reads the new handle with the new
/// profile version, not the handle its statement's snapshot saw.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn locked_lookups_read_a_rename_they_waited_for() {
    let pool = Database::test_pool().await;
    let database = Database { pool: pool.clone() };
    let account = InsertUser::named("locked");
    database.users().insert(&account).await.expect("user");
    let renamed = Handle::parse(&format!("now-{}", &account.id.to_string()[24..])).expect("handle");
    let mut rename = database.begin().await.expect("rename transaction");
    rename
        .users()
        .find_active_by_id_for_update(account.id)
        .await
        .expect("lock");
    assert!(
        rename
            .rename_handle(account.id, &renamed)
            .await
            .expect("rename")
    );
    let lookup = tokio::spawn(async move {
        let database = Database { pool };
        let mut tx = database.begin().await.expect("lookup transaction");
        tx.users()
            .find_active_by_id_for_update(account.id)
            .await
            .expect("lookup")
            .expect("user")
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!lookup.is_finished(), "the lookup must wait for the rename");
    rename.commit().await.expect("commit");
    let user = lookup.await.expect("lookup task");
    assert_eq!((user.handle, user.profile_version), (renamed, 2));
}

/// The handles migration refuses to run while a username breaks the handle rules
/// or looks like another, naming them all, and copies them once fixed. It runs in a
/// scratch schema, since the test database is migrated.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn the_migration_refuses_usernames_that_are_not_handles() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let mut connection = PgConnection::connect(&url).await.expect("connect");
    let schema = format!("handles_{}", UserId::new().as_uuid().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .execute(&mut connection)
    .await
    .expect("schema");
    let (earlier, handles): (Vec<_>, Vec<_>) = MIGRATOR
        .iter()
        .partition(|migration| migration.version < 13);
    for migration in earlier {
        sqlx::raw_sql(&migration.sql)
            .execute(&mut connection)
            .await
            .expect("earlier migration");
    }
    for username in ["a_b", "piquel", "pique1", "fine"] {
        sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Migration test')")
            .bind(UserId::new().as_uuid())
            .bind(username)
            .execute(&mut connection)
            .await
            .expect("user");
    }
    let migration = &handles[0].sql;
    let refused = sqlx::raw_sql(migration)
        .execute(&mut connection)
        .await
        .expect_err("invalid usernames");
    assert!(
        refused.to_string().contains("a_b, pique1, piquel"),
        "{refused}"
    );
    sqlx::raw_sql(
        "UPDATE users SET username = 'a-b' WHERE username = 'a_b';
        UPDATE users SET username = 'renamed' WHERE username = 'pique1'",
    )
    .execute(&mut connection)
    .await
    .expect("rename");
    sqlx::raw_sql(migration)
        .execute(&mut connection)
        .await
        .expect("migration");
    let copied: Vec<(String, bool)> = sqlx::query_as(
        "SELECT h.handle, u.handle_changed_at = u.created_at
        FROM handles h JOIN users u ON u.id = h.user_id
        WHERE h.released_at IS NULL ORDER BY h.handle",
    )
    .fetch_all(&mut connection)
    .await
    .expect("handles");
    assert_eq!(
        copied,
        ["a-b", "fine", "piquel", "renamed"].map(|handle| (handle.to_owned(), true))
    );
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut connection)
        .await
        .expect("drop schema");
}
