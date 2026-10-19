//! Known vectors and boundary tests for each primitive.
use super::*;
use piquel_common::protocol::jwt::TokenType;

/// Random secrets round-trip and reject malformed encodings without exposing bytes.
#[test]
fn secrets_round_trip() {
    let first = Secret::generate().expect("random");
    let second = Secret::generate().expect("random");
    assert_ne!(first.as_bytes(), second.as_bytes());
    assert_eq!(
        Secret::parse(&first.encoded()).expect("decode").as_bytes(),
        first.as_bytes()
    );
    assert_eq!(first.encoded().len(), 43);
    assert_eq!(first.digest(), Digest::sha256(first.as_bytes()));
    for value in ["", "short", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"] {
        assert!(Secret::parse(value).is_err());
    }
    assert!(Secret::parse(&(first.encoded() + "=")).is_err());
    assert_eq!(format!("{first:?}"), "Secret(REDACTED)");
}

/// SHA-256 and HMAC match published test vectors.
#[test]
fn digests_match_vectors() {
    assert_eq!(
        Digest::sha256(b"abc").encoded(),
        "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    );
    // RFC 4231, test case 1.
    assert_eq!(
        Digest::hmac(&[0x0b; 20], b"Hi There")
            .expect("HMAC")
            .as_bytes(),
        &[
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ]
    );
    assert!(Digest::constant_time_eq(b"same", b"same"));
    assert!(!Digest::constant_time_eq(b"same", b"samp"));
    assert!(!Digest::constant_time_eq(b"same", b"short"));
    assert!(Digest::constant_time_eq(b"", b""));
}

/// Client hashing retains its wire contract and uses SHA-256 over encoded text.
#[test]
fn client_secret_contract() {
    let secret = Secret::generate().expect("secret").encoded();
    assert_eq!(
        Digest::client_secret(&secret).expect("hash"),
        Digest::sha256(secret.as_bytes())
    );
    assert!(Digest::client_secret(&"x".repeat(42)).is_err());
    assert!(Digest::client_secret(&"x".repeat(512)).is_ok());
    assert!(Digest::client_secret(&"x".repeat(513)).is_err());
}

/// PKCE matches RFC 7636 appendix B and enforces verifier syntax.
#[test]
fn pkce_matches_rfc() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert_eq!(Pkce::challenge(verifier).expect("challenge"), challenge);
    assert!(Pkce::verify(verifier, challenge).is_ok());
    assert!(Pkce::verify(verifier, "incorrect").is_err());
    assert!(Pkce::valid_challenge(challenge));
    assert!(!Pkce::valid_challenge("short"));
    for verifier in ["short".to_owned(), "x".repeat(129), "!".repeat(43)] {
        assert!(Pkce::challenge(&verifier).is_err());
    }
}

/// Key loading preserves parse sources and rejects unsafe key identifiers and sizes.
#[test]
fn rsa_configuration_boundaries() {
    assert!(Rs256Key::from_pem("key", "not PEM").is_err());
    assert!(Rs256Key::generate("has whitespace").is_err());
    let small = openssl::rsa::Rsa::generate(1024).expect("small key");
    let pem = small.private_key_to_pem().expect("PEM");
    assert!(matches!(
        Rs256Key::from_pem("small", std::str::from_utf8(&pem).expect("ASCII")),
        Err(CryptoError::RsaKeySize)
    ));
}

/// Generated keys survive PEM persistence and reject unrelated keys and malformed claims.
#[test]
fn jwt_persistence_and_trust_boundaries() {
    let key = Rs256Key::generate("persistent").expect("RSA key");
    let pem = key.private_key_pem().expect("export PEM");
    let restored = Rs256Key::from_pem("persistent", std::str::from_utf8(&pem).expect("ASCII PEM"))
        .expect("restore key");
    assert_eq!(key.jwks(), restored.jwks());
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({"iss":"https://auth.example", "iat":now, "exp":now+300});
    let token = key.sign(TokenType::Id, &claims).expect("sign");
    assert_eq!(
        restored
            .verify::<serde_json::Value>(&token, TokenType::Id, "https://auth.example")
            .expect("verify"),
        claims
    );
    let unrelated = Rs256Key::generate("persistent").expect("different RSA key with the same ID");
    assert!(
        unrelated
            .verify::<serde_json::Value>(&token, TokenType::Id, "https://auth.example")
            .is_err()
    );
    for token in [
        String::new(),
        "one.two".to_owned(),
        "a.b.c.d".to_owned(),
        "x".repeat(16385),
    ] {
        assert!(
            key.verify::<serde_json::Value>(&token, TokenType::Id, "https://auth.example")
                .is_err()
        );
    }
    for (field, invalid) in [
        ("iat", serde_json::json!(now + 60)),
        ("iat", serde_json::json!("not a timestamp")),
        ("iat", serde_json::Value::Null),
        ("exp", serde_json::json!("not a timestamp")),
        ("exp", serde_json::Value::Null),
    ] {
        let mut invalid_claims = claims.clone();
        invalid_claims[field] = invalid;
        let token = key
            .sign(TokenType::Id, &invalid_claims)
            .expect("sign malformed claims");
        assert!(
            key.verify::<serde_json::Value>(&token, TokenType::Id, "https://auth.example")
                .is_err()
        );
    }
}
