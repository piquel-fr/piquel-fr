//! What a database error shows when logged.
use super::*;

/// A driver error whose `Debug`, like `PostgreSQL`'s, quotes the values.
#[derive(Debug, Error)]
#[error("duplicate key value violates unique constraint \"emails_address_key\"")]
struct Duplicate {
    /// Like `PgDatabaseError`'s `detail`.
    detail: &'static str,
}

/// A stored value that does not decode is never quoted.
#[test]
fn decode_failures_leave_out_the_value() {
    let decoded = serde_json::from_str::<u8>(r#""alice@example.com""#);
    let error = DatabaseError::InvalidStoredData {
        column: "payload".into(),
        source: decoded.expect_err("not a number").into(),
    };
    assert_eq!(
        format!("{error:?}"),
        "stored column payload is invalid: JSON that does not match its type at line 1 \
         column 19"
    );
}

/// `Debug` is the error chain: its messages, never the driver's details.
#[test]
fn debug_leaves_out_driver_details() {
    let error = DatabaseError::Conflict(Box::new(Duplicate {
        detail: "Key (address)=(alice@example.com) already exists.",
    }));
    assert_eq!(
        format!("{error:?}"),
        "the operation conflicts with existing data: duplicate key value violates \
         unique constraint \"emails_address_key\""
    );
}
