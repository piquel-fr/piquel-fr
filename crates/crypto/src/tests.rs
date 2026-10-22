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

/// Client secrets carry their scanner prefix and are stored as the digest of
/// exactly what clients present.
#[test]
fn client_secret_contract() {
    let secret = ClientSecret::generate().expect("secret");
    let (prefix, random) = secret.expose().split_at(CLIENT_SECRET_PREFIX.len());
    assert_eq!(prefix, CLIENT_SECRET_PREFIX);
    assert!(Secret::parse(random).is_ok());
    assert_eq!(
        secret.digest(),
        ClientSecret::digest_presented(secret.expose())
    );
    assert_eq!(secret.digest(), Digest::sha256(secret.expose().as_bytes()));
    assert_eq!(format!("{secret:?}"), "ClientSecret(REDACTED)");
}

/// Secrets generated elsewhere are kept exactly as given, and must be as strong
/// as generated ones.
#[test]
fn client_secret_parse() {
    let random = Secret::generate().expect("secret").encoded();
    let generated = ClientSecret::generate().expect("secret");
    for value in [random.as_str(), generated.expose()] {
        let parsed = ClientSecret::parse(value).expect("valid secret");
        assert_eq!(parsed.expose(), value);
    }
    for value in ["", "short", &format!("{random}A"), &format!("{random}\n")] {
        assert!(ClientSecret::parse(value).is_err(), "{value:?}");
    }
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

/// Signed notes match the Go reference implementation (`golang.org/x/mod/sumdb/note`):
/// the same seed gives the same verifier key and the same signature line.
#[test]
fn notes_match_the_reference_vectors() {
    let key = NoteKey::from_hex_seed(
        "PeterNeumann",
        "810a1402d5146c8d84f2443330f54080ebf98ee17d9c74f6252fc5d5c7283173\n",
    )
    .expect("seed");
    let vkey = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
    assert_eq!(key.verifier().to_string(), vkey);
    assert_eq!(
        NoteVerifier::parse(vkey).expect("verifier key"),
        *key.verifier()
    );
    let text = "If you think cryptography is the answer to your problem,\n\
                then you don't know what your problem is.\n";
    let note = key.sign(text).expect("sign");
    assert_eq!(
        note,
        format!(
            "{text}\n\u{2014} PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n"
        )
    );
    let verifiers = NoteVerifiers::parse(&format!("\n{vkey}\n")).expect("verifier list");
    // Base64 keys may contain `+`, the field separator; several of these do.
    for seed in 0..32_u8 {
        let key = NoteKey::from_hex_seed("audit", &format!("{seed:064x}")).expect("seed");
        let vkey = key.verifier().to_string();
        assert_eq!(
            NoteVerifier::parse(&vkey).expect("verifier key"),
            *key.verifier()
        );
    }
    assert_eq!(verifiers.open(&note).expect("open"), text);
}

/// A note opens only with a valid signature by a listed key. Other keys'
/// signatures are ignored, but a listed key's invalid signature fails.
#[test]
fn notes_open_only_with_a_valid_listed_signature() {
    let key = NoteKey::generate("auth.example/audit").expect("key");
    let other = NoteKey::generate("other.example/audit").expect("key");
    let verifiers = NoteVerifiers::from(key.verifier().clone());
    let note = key.sign("position 1\n").expect("sign");
    assert_eq!(verifiers.open(&note).expect("open"), "position 1\n");

    let cosigned = format!(
        "{note}{}",
        other
            .sign("position 1\n")
            .expect("sign")
            .split_once("\n\n")
            .expect("split")
            .1
    );
    assert_eq!(
        verifiers.open(&cosigned).expect("other key ignored"),
        "position 1\n"
    );
    assert!(matches!(
        NoteVerifiers::from(other.verifier().clone()).open(&note),
        Err(CryptoError::NoteUnverified)
    ));
    assert!(matches!(
        verifiers.open(&note.replace("position 1", "position 2")),
        Err(CryptoError::NoteSignature)
    ));
    for malformed in [
        "position 1\n",
        "position 1\n\n",
        "position 1\n\nsignature\n",
    ] {
        assert!(matches!(
            verifiers.open(malformed),
            Err(CryptoError::NoteFormat)
        ));
    }
    for text in ["no newline", "tab\there\n"] {
        assert!(matches!(key.sign(text), Err(CryptoError::NoteText)));
    }
}

/// Seeds must be exactly 32 hex-encoded bytes; one trailing newline is allowed.
/// Key names must be usable in signature lines and verifier keys.
#[test]
fn note_keys_reject_malformed_seeds_and_names() {
    let seed = "00".repeat(32);
    assert!(NoteKey::from_hex_seed("audit", &seed).is_ok());
    assert!(NoteKey::from_hex_seed("audit", &format!("{seed}\n")).is_ok());
    for bad in [
        String::new(),
        "00".repeat(31),
        "00".repeat(33),
        format!("{seed}\n\n"),
        format!("+f{}", "00".repeat(31)),
        format!("zz{}", "00".repeat(31)),
    ] {
        assert!(matches!(
            NoteKey::from_hex_seed("audit", &bad),
            Err(CryptoError::NoteKeySeed)
        ));
    }
    for name in ["", "two words", "a+b"] {
        assert!(matches!(
            NoteKey::from_hex_seed(name, &seed),
            Err(CryptoError::NoteKeyName)
        ));
    }
    assert!(
        format!("{:?}", NoteKey::from_hex_seed("audit", &seed).expect("key"))
            .starts_with("NoteKey { verifier")
    );
}
