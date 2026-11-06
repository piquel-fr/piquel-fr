//! Challenge syntax at the parser's edges; the shared vectors cover the formats.
use super::*;

/// Other schemes, `token68` credentials, escapes and unknown parameters do not hide
/// the Bearer challenge.
#[test]
fn finds_bearer_among_challenges() {
    let challenge: BearerChallenge =
        r#"Negotiate YWJjZA==, Basic realm="a, b", bearer error = invalid_token, error_description="say \'hi\'", foo=bar"#
            .parse()
            .expect("Bearer challenge");
    assert_eq!(challenge.error, Some(BearerError::InvalidToken));
    assert_eq!(
        challenge
            .error_description
            .as_ref()
            .map(ErrorDescription::as_str),
        Some("say 'hi'")
    );
    assert_eq!(
        challenge.to_string(),
        r#"Bearer error="invalid_token", error_description="say 'hi'""#
    );
}

/// No value can break the header: control characters are written as `?`.
#[test]
fn formatting_never_emits_control_characters() {
    let challenge = BearerChallenge::error(BearerError::from("new_error\r\nX-Test: yes"));
    assert_eq!(
        challenge.to_string(),
        r#"Bearer error="new_error??X-Test: yes""#
    );
}

/// Malformed, repeated or non-Bearer headers are rejected, with the reason. The
/// shared vectors' `parse-*` cases cover the other syntax errors.
#[test]
fn rejects_invalid_headers() {
    for (header, expected) in [
        ("Basic realm=\"x\"", ChallengeError::NotBearer),
        ("Bearer error=\"unterminated", ChallengeError::Syntax(13)),
        ("=x", ChallengeError::Syntax(0)),
        ("Bearer error=\"a\r\nb\"", ChallengeError::Syntax(13)),
        ("Negotiate abc==, error=x", ChallengeError::Syntax(17)),
        (
            "Bearer scope=\"a\tb\"",
            ChallengeError::InvalidValue("scope"),
        ),
        (
            "Bearer scope=a, scope=b",
            ChallengeError::Duplicate("scope".into()),
        ),
        (
            "Bearer max_age=soon",
            ChallengeError::InvalidValue("max_age"),
        ),
        (
            "Bearer error_description=\"say \\\"hi\\\"\"",
            ChallengeError::InvalidValue("error_description"),
        ),
    ] {
        assert_eq!(header.parse::<BearerChallenge>(), Err(expected), "{header}");
    }
}
