//! JWT policy, tampering, protected-header trust boundaries and key selection.
use super::*;
use serde_json::json;

/// Signing enforces token types, signatures, issuer and expiry, while logout permits expired hints.
#[test]
fn rsa_verifies_signatures_types_expiry_and_logout_hints() {
    let keys = KeySet::single(Rs256Key::generate("test").expect("generate RSA test key"));
    let now = Utc::now().timestamp();
    let claims =
        json!({"iss":"https://auth.example","sub":"user","aud":"client","iat":now-60,"exp":now-1});
    let expired = keys
        .sign(TokenType::Id, &claims)
        .expect("sign expired ID token hint");
    assert!(
        keys.verify::<Value>(&expired, TokenType::Id, "https://auth.example")
            .is_err()
    );
    assert!(
        keys.verify_id_token_hint(&expired, "https://auth.example")
            .is_ok()
    );
    assert!(
        keys.verify_id_token_hint(&expired, "https://evil.example")
            .is_err()
    );
    let mut valid = claims;
    valid["exp"] = json!(now + 300);
    let token = keys
        .sign(TokenType::Access, &valid)
        .expect("sign access token");
    assert!(
        keys.verify::<Value>(&token, TokenType::Access, "https://auth.example")
            .is_ok()
    );
    assert!(
        keys.verify::<Value>(&token, TokenType::Id, "https://auth.example")
            .is_err()
    );
    let mut bytes = token.into_bytes();
    let n = bytes.len();
    bytes[n - 10] = if bytes[n - 10] == b'A' { b'B' } else { b'A' };
    assert!(
        keys.verify::<Value>(
            std::str::from_utf8(&bytes).expect("modified compact token remains ASCII"),
            TokenType::Access,
            "https://auth.example"
        )
        .is_err()
    );
}

/// Even correctly RSA-signed inputs cannot choose an algorithm, type, key or critical extension.
#[test]
fn rejects_algorithm_confusion_and_unrecognized_headers() {
    let keys = KeySet::single(Rs256Key::generate("headers").expect("RSA key"));
    let key = keys.signer();
    let now = Utc::now().timestamp();
    let claims = json!({"iss":"https://auth.example", "iat":now, "exp":now+300});
    for (field, value) in [
        ("alg", json!("none")),
        ("alg", json!("HS256")),
        ("alg", json!("RS512")),
        ("typ", json!("at+jwt")),
        ("kid", json!("untrusted")),
        ("crit", json!([])),
        ("crit", json!(["b64"])),
    ] {
        let mut header =
            json!({"alg":Algorithm::Rs256.as_str(), "kid":key.kid, "typ":TokenType::Id.as_str()});
        header[field] = value;
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"))
        );
        // A valid RSA signature isolates header-policy rejection from signature failure.
        let mut signer = Signer::new(MessageDigest::sha256(), &key.key).expect("signer");
        signer.update(input.as_bytes()).expect("input");
        let token = format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signer.sign_to_vec().expect("signature"))
        );
        assert!(
            matches!(
                keys.verify::<Value>(&token, TokenType::Id, "https://auth.example"),
                Err(CryptoError::InvalidToken | CryptoError::UnknownKey | CryptoError::Json(_))
            ),
            "accepted {field}"
        );
    }
    // HMAC with public-key bytes is the classic asymmetric/symmetric algorithm confusion.
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"headers","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let input = format!("{header}.{payload}");
    let signature =
        crate::Digest::hmac(&key.public_key_pem().expect("public key"), input.as_bytes())
            .expect("HMAC")
            .encoded();
    let token = format!("{input}.{signature}");
    assert!(matches!(
        keys.verify::<Value>(&token, TokenType::Id, "https://auth.example"),
        Err(CryptoError::Json(_))
    ));
}

/// During a rotation, tokens of every published key verify and JWKS lists them;
/// a retired key verifies only ID token hints, and a key outside the set nothing.
#[test]
fn key_set_verifies_by_kid_and_limits_retired_keys_to_hints() {
    let [retiring, active, retired, unknown] = ["retiring", "active", "retired", "unknown"]
        .map(|kid| Rs256Key::generate(kid).expect("key"));
    let now = Utc::now().timestamp();
    let claims = json!({"iss":"https://auth.example", "aud":"client", "iat":now, "exp":now+300});
    let [by_retiring, by_retired, by_unknown] =
        [&retiring, &retired, &unknown].map(|key| key.sign(TokenType::Id, &claims).expect("sign"));
    // A signer must be published, or verifiers could not check its tokens.
    assert!(matches!(
        KeySet::new(unknown, vec![retiring.public_key().clone()], vec![]),
        Err(CryptoError::KeySet)
    ));
    let published = vec![retiring.public_key().clone(), active.public_key().clone()];
    let keys = KeySet::new(active, published, vec![retired.public_key().clone()]).expect("key set");
    let by_active = keys.sign(TokenType::Id, &claims).expect("sign");
    for token in [&by_active, &by_retiring] {
        assert!(
            keys.verify::<Value>(token, TokenType::Id, "https://auth.example")
                .is_ok()
        );
        assert!(
            keys.verify_id_token_hint(token, "https://auth.example")
                .is_ok()
        );
    }
    assert!(matches!(
        keys.verify::<Value>(&by_retired, TokenType::Id, "https://auth.example"),
        Err(CryptoError::UnknownKey)
    ));
    assert!(
        keys.verify_id_token_hint(&by_retired, "https://auth.example")
            .is_ok()
    );
    assert!(matches!(
        keys.verify_id_token_hint(&by_unknown, "https://auth.example"),
        Err(CryptoError::UnknownKey)
    ));
    let kids: Vec<_> = keys
        .jwks()
        .keys
        .iter()
        .map(|key| key.kid.as_str())
        .collect();
    assert_eq!(kids, ["retiring", "active"]);

    // A repeated key identifier, even between published and retired keys, is refused.
    let signer = Rs256Key::generate("same").expect("key");
    let twin = Rs256Key::generate("same").expect("key");
    let published = vec![signer.public_key().clone()];
    assert!(matches!(
        KeySet::new(signer, published, vec![twin.public_key().clone()]),
        Err(CryptoError::KeySet)
    ));
}
