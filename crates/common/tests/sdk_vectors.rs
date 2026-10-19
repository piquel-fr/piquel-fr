//! Builds the cross-language SDK vectors in `tests/sdk-vectors` from fixed test keys
//! and the shared protocol types, signing with auth's own signer. Without
//! `UPDATE_SDK_VECTORS=1` it only compares, so `just validate` fails on stale files;
//! `just sdk-vectors` rewrites them. The format is described in that directory's README.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use piquel_common::{
    AuthenticationMethod, ClientId, SessionId, TokenId,
    protocol::{
        challenge::{BearerChallenge, BearerError},
        claims::{
            AccessTokenClaims, Acr, Actor, Amr, Audience, AuthenticationClaims, Confirmation,
            IdTokenClaims, ProfileClaims,
        },
        jwt::{Algorithm, Claim, JwkSet, TokenType},
        metadata::ServerMetadata,
        oauth::{
            ClientAuthMethod, CodeChallengeMethod, GrantType, ResponseMode, ResponseType, Scope,
            SubjectType,
        },
        sdk::{ErrorCategory, ErrorReason, SdkError},
        step_up::StepUpRequirement,
    },
};
use piquel_crypto::{Digest, Rs256Key};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Every case's clock: 2026-01-01T00:00:00Z.
const NOW: i64 = 1_767_225_600;
/// Issuer the SDK is configured with.
const ISSUER: &str = "https://auth.example.com";
/// Resource identifier, the access token audience.
const RESOURCE: &str = "https://notes.example.com";
/// Client that requested the tokens, the ID token audience.
const CLIENT: &str = "notes-web";
/// Nonce sent with the authorization request.
const NONCE: &str = "n-0S6_WzA2Mj";
/// `state` sent with the authorization request.
const STATE: &str = "af0ifjsldkj";
/// Authorization code in callbacks.
const CODE: &str = "pac_v1_01936f3e-8c00-7000-8000-000000000004.c2VjcmV0";
/// Key signing before the rotation.
const OLD_KID: &str = "key-2025";
/// Key signing after the rotation.
const NEW_KID: &str = "key-2026";

/// One case file: inputs, the clock, and the expected result.
#[derive(Serialize)]
struct Case {
    /// What the case checks.
    description: &'static str,
    /// Unix time the SDK's clock is pinned to, for time-dependent cases.
    #[serde(skip_serializing_if = "Option::is_none")]
    now: Option<i64>,
    /// Category-specific inputs.
    input: Value,
    /// The parsed value, or the shared error code.
    expected: Expected,
}

/// A case's expected result.
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Expected {
    /// The operation succeeds with this value.
    Ok(Value),
    /// The operation fails with this code.
    Error(SdkError),
}

impl Expected {
    /// Success with a serializable value.
    fn ok(value: &impl Serialize) -> Self {
        Self::Ok(serde_json::to_value(value).expect("serialize expected value"))
    }

    /// Failure in `code` caused by `reason`.
    const fn error(code: ErrorCategory, reason: ErrorReason) -> Self {
        Self::Error(SdkError::new(code, reason))
    }
}

/// The vector files being built, keyed by path relative to the vector directory.
struct Vectors {
    /// Rendered files.
    files: BTreeMap<PathBuf, String>,
    /// Key that signs before the rotation.
    old: Rs256Key,
    /// Key that signs after the rotation.
    new: Rs256Key,
    /// The old key's PEM, to sign tokens whose header auth's signer would never write.
    old_pem: String,
}

impl Vectors {
    /// The committed vector directory.
    fn directory() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/sdk-vectors")
    }

    /// Loads the fixed test keys.
    fn new() -> Self {
        let pem = |kid: &str| {
            fs::read_to_string(Self::directory().join(format!("keys/{kid}.pem")))
                .expect("read fixed test key")
        };
        let key = |kid: &str| Rs256Key::from_pem(kid, &pem(kid)).expect("parse fixed test key");
        Self {
            files: BTreeMap::new(),
            old: key(OLD_KID),
            new: key(NEW_KID),
            old_pem: pem(OLD_KID),
        }
    }

    /// Records one case as pretty JSON at `path`.
    fn case(&mut self, path: &str, case: &Case) {
        let mut text = serde_json::to_string_pretty(case).expect("serialize case");
        text.push('\n');
        assert!(
            self.files.insert(path.into(), text).is_none(),
            "{path} is generated twice"
        );
    }

    /// Writes the files when updating; otherwise fails on any difference, including
    /// committed cases that are no longer generated.
    fn finish(self) {
        let directory = Self::directory();
        let committed: Vec<PathBuf> = ["discovery", "jwks", "tokens", "challenges", "callbacks"]
            .into_iter()
            .flat_map(|category| fs::read_dir(directory.join(category)).into_iter().flatten())
            .map(|entry| entry.expect("read vector directory").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect();
        if std::env::var_os("UPDATE_SDK_VECTORS").is_some() {
            for path in committed {
                fs::remove_file(path).expect("remove old vector");
            }
            for (path, text) in &self.files {
                let path = directory.join(path);
                fs::create_dir_all(path.parent().expect("vector category"))
                    .expect("create vector category");
                fs::write(path, text).expect("write vector");
            }
            return;
        }
        let mut stale: Vec<String> = committed
            .iter()
            .filter_map(|path| path.strip_prefix(&directory).ok())
            .filter(|path| !self.files.contains_key(*path))
            .map(|path| format!("{} is no longer generated", path.display()))
            .collect();
        for (path, text) in &self.files {
            if fs::read_to_string(directory.join(path)).ok().as_ref() != Some(text) {
                stale.push(format!("{} is missing or out of date", path.display()));
            }
        }
        assert!(
            stale.is_empty(),
            "SDK vectors are stale; run `just sdk-vectors`:\n{}",
            stale.join("\n")
        );
    }

    /// The published key set holding the keys named in `kids`.
    fn jwks(&self, kids: &[&str]) -> Value {
        let keys = kids
            .iter()
            .flat_map(|kid| match *kid {
                OLD_KID => self.old.jwks().keys.clone(),
                NEW_KID => self.new.jwks().keys.clone(),
                _ => unreachable!("unknown test key {kid}"),
            })
            .collect();
        serde_json::to_value(JwkSet { keys }).expect("serialize JWKS")
    }

    /// Discovery cases: the document is checked before anything else is trusted.
    fn discovery(&mut self) {
        let metadata = Self::metadata();
        let valid = serde_json::to_value(&metadata).expect("serialize metadata");
        self.case(
            "discovery/valid.json",
            &Case {
                description: "auth's metadata document for the configured issuer",
                now: None,
                input: json!({ "issuer": ISSUER, "document": valid }),
                expected: Expected::ok(&metadata),
            },
        );
        let mut mismatch = valid.clone();
        mismatch["issuer"] = json!(format!("{ISSUER}/"));
        self.case(
            "discovery/issuer-mismatch.json",
            &Case {
                description: "the returned issuer must equal the configured one exactly, \
                              so a trailing slash fails",
                now: None,
                input: json!({ "issuer": ISSUER, "document": mismatch }),
                expected: Expected::error(ErrorCategory::Discovery, ErrorReason::IssuerMismatch),
            },
        );
        let mut newer = valid.clone();
        newer["code_challenge_methods_supported"] = json!(["plain", "S256"]);
        newer["grant_types_supported"]
            .as_array_mut()
            .expect("grant types")
            .push(json!("urn:ietf:params:oauth:grant-type:token-exchange"));
        newer["acr_values_supported"] = json!(["phrh", "phr", "urn:piquel:acr:social"]);
        self.case(
            "discovery/unknown-values.json",
            &Case {
                description: "advertised values this version does not know are dropped, \
                              so a newer issuer does not break older SDKs",
                now: None,
                input: json!({ "issuer": ISSUER, "document": newer }),
                expected: Expected::ok(&metadata),
            },
        );
        let mut insecure = valid.clone();
        insecure["token_endpoint"] = json!("http://auth.example.com/oauth/token");
        self.case(
            "discovery/insecure-endpoint.json",
            &Case {
                description: "every endpoint must use https, or credentials and keys would \
                              cross the network in the clear (OIDC Discovery 1.0 §3)",
                now: None,
                input: json!({ "issuer": ISSUER, "document": insecure }),
                expected: Expected::error(ErrorCategory::Discovery, ErrorReason::InvalidDocument),
            },
        );
        let mut no_pkce = valid;
        no_pkce
            .as_object_mut()
            .expect("metadata object")
            .remove("code_challenge_methods_supported");
        self.case(
            "discovery/missing-code-challenge-methods.json",
            &Case {
                description: "without code_challenge_methods_supported the issuer does not \
                              support PKCE (RFC 8414 §2), so it cannot be used",
                now: None,
                input: json!({ "issuer": ISSUER, "document": no_pkce }),
                expected: Expected::error(ErrorCategory::Discovery, ErrorReason::PkceUnsupported),
            },
        );
    }

    /// The metadata auth publishes for [`ISSUER`].
    fn metadata() -> ServerMetadata {
        let url = |path: &str| format!("{ISSUER}{path}").parse().expect("endpoint URL");
        ServerMetadata {
            issuer: ISSUER.into(),
            authorization_endpoint: url("/oauth/authorize"),
            token_endpoint: url("/oauth/token"),
            revocation_endpoint: url("/oauth/revoke"),
            userinfo_endpoint: url("/oidc/userinfo"),
            end_session_endpoint: url("/oidc/logout"),
            jwks_uri: url("/.well-known/jwks.json"),
            service_documentation: "https://github.com/piquel-fr/piquel-fr#oidc-clients"
                .parse()
                .expect("documentation URL"),
            scopes_supported: Scope::ALL.into(),
            response_types_supported: ResponseType::ALL.into(),
            response_modes_supported: ResponseMode::ALL.into(),
            grant_types_supported: GrantType::ALL.into(),
            token_endpoint_auth_methods_supported: ClientAuthMethod::ALL.into(),
            revocation_endpoint_auth_methods_supported: ClientAuthMethod::ALL.into(),
            code_challenge_methods_supported: CodeChallengeMethod::ALL.into(),
            subject_types_supported: SubjectType::ALL.into(),
            id_token_signing_alg_values_supported: Algorithm::ALL.into(),
            claims_supported: vec![
                Claim::Subject,
                Claim::Name,
                Claim::Username,
                Claim::Email,
                Claim::EmailVerified,
                Claim::ProfileVersion,
                Claim::AuthTime,
                Claim::Methods,
                Claim::AuthenticationClass,
                Claim::Session,
            ],
            acr_values_supported: Acr::ALL.into(),
            claims_parameter_supported: false,
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            authorization_response_iss_parameter_supported: true,
        }
    }

    /// Key set cases: which `kid`s a set makes usable.
    fn jwks_cases(&mut self) {
        for (name, description, kids) in [
            (
                "rotation-before",
                "before a rotation only the old key is published",
                &[OLD_KID][..],
            ),
            (
                "rotation-during",
                "during a rotation both keys are published, so tokens from either verify",
                &[OLD_KID, NEW_KID][..],
            ),
            (
                "rotation-after",
                "after a rotation only the new key is published",
                &[NEW_KID][..],
            ),
        ] {
            self.case(
                &format!("jwks/{name}.json"),
                &Case {
                    description,
                    now: None,
                    input: json!({ "jwks": self.jwks(kids) }),
                    expected: Expected::Ok(json!({ "kids": kids })),
                },
            );
        }
        let mut duplicate = self.jwks(&[OLD_KID, NEW_KID]);
        duplicate["keys"][1]["kid"] = json!(OLD_KID);
        self.case(
            "jwks/duplicate-kid.json",
            &Case {
                description: "two keys sharing a kid make the set ambiguous, so it is \
                              rejected and the previous set stays in use",
                now: None,
                input: json!({ "jwks": duplicate }),
                expected: Expected::error(ErrorCategory::Keys, ErrorReason::DuplicateKeyId),
            },
        );
        let mut unsupported = self.jwks(&[OLD_KID]);
        let keys = unsupported["keys"].as_array_mut().expect("keys array");
        keys.insert(
            0,
            json!({
                "kty": "EC", "crv": "P-256", "kid": "ec-1", "use": "sig", "alg": "ES256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            }),
        );
        keys.push(json!({ "kty": "oct", "kid": "hmac-1", "k": "c2VjcmV0" }));
        self.case(
            "jwks/unsupported-kty.json",
            &Case {
                description: "keys of an unsupported kty are skipped (RFC 7517 §5), not fatal",
                now: None,
                input: json!({ "jwks": unsupported }),
                expected: Expected::Ok(json!({ "kids": [OLD_KID] })),
            },
        );
        let mut encryption = self.jwks(&[OLD_KID, NEW_KID]);
        encryption["keys"][1]["use"] = json!("enc");
        self.case(
            "jwks/encryption-key.json",
            &Case {
                description: "a key published for encryption is never used to verify",
                now: None,
                input: json!({ "jwks": encryption }),
                expected: Expected::Ok(json!({ "kids": [OLD_KID] })),
            },
        );
    }

    /// Token cases: one failing check each, in the documented validation order.
    #[expect(
        clippy::too_many_lines,
        reason = "One table of cases reads better than many small builders."
    )]
    fn tokens(&mut self) {
        let during = self.jwks(&[OLD_KID, NEW_KID]);
        let access = Self::access_claims();
        let access_case = |token: String, jwks: &Value| {
            json!({
                "issuer": ISSUER, "jwks": jwks, "kind": "access",
                "audience": RESOURCE, "token": token,
            })
        };
        let valid = Self::sign(&self.old, TokenType::Access, &access);
        self.token(
            "access-valid",
            "an access token as auth issues it",
            access_case(valid.clone(), &during),
            Expected::ok(&access),
        );
        let mut unknown = serde_json::to_value(&access).expect("claims");
        unknown["amr"] = json!(["pop", "hwk"]);
        unknown["acr"] = json!("urn:example:gold");
        let mut known = access.clone();
        known.authentication.amr = vec![Amr::Pop];
        known.authentication.acr = None;
        self.token(
            "access-unknown-authentication",
            "amr values the SDK does not know are dropped, and an unknown acr reads as none",
            access_case(Self::sign(&self.old, TokenType::Access, &unknown), &during),
            Expected::ok(&known),
        );
        let mut reserved = access.clone();
        reserved.act = Some(Actor {
            sub: "orders-api".into(),
            act: Some(Box::new(Actor {
                sub: "gateway".into(),
                act: None,
            })),
        });
        reserved.cnf = Some(Confirmation {
            jkt: Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".into()),
        });
        self.token(
            "access-reserved-claims",
            "act and cnf parse",
            access_case(Self::sign(&self.old, TokenType::Access, &reserved), &during),
            Expected::ok(&reserved),
        );
        let mut new_key = access.clone();
        new_key.jti = "01936f3e-8c00-7000-8000-000000000005"
            .parse()
            .expect("token ID");
        self.token(
            "access-new-key",
            "a token signed by the rotated-in key verifies during the rotation",
            access_case(Self::sign(&self.new, TokenType::Access, &new_key), &during),
            Expected::ok(&new_key),
        );
        self.token(
            "access-old-key-after-rotation",
            "once the old key is withdrawn its tokens have an unknown kid",
            access_case(valid.clone(), &self.jwks(&[NEW_KID])),
            Expected::error(ErrorCategory::InvalidToken, ErrorReason::UnknownKey),
        );
        self.token(
            "access-unknown-kid",
            "a kid absent from the published set is rejected",
            access_case(
                Self::sign(&self.new, TokenType::Access, &access),
                &self.jwks(&[OLD_KID]),
            ),
            Expected::error(ErrorCategory::InvalidToken, ErrorReason::UnknownKey),
        );
        self.token(
            "access-malformed",
            "a token that is not three base64url segments is malformed",
            access_case("eyJhbGciOiJSUzI1NiJ9.e30".into(), &during),
            Expected::error(ErrorCategory::InvalidToken, ErrorReason::Malformed),
        );
        self.token(
            "access-wrong-type",
            "an ID token's typ is rejected where an access token is expected",
            access_case(Self::sign(&self.old, TokenType::Id, &access), &during),
            Expected::error(ErrorCategory::InvalidToken, ErrorReason::WrongType),
        );
        let header = |alg: &str| {
            URL_SAFE_NO_PAD.encode(
                json!({ "alg": alg, "kid": OLD_KID, "typ": TokenType::Access.as_str() })
                    .to_string(),
            )
        };
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&access).expect("serialize claims"));
        self.token(
            "access-alg-none",
            "unsigned tokens are never accepted",
            access_case(format!("{}.{payload}.", header("none")), &during),
            Expected::error(
                ErrorCategory::InvalidToken,
                ErrorReason::UnsupportedAlgorithm,
            ),
        );
        let input = format!("{}.{payload}", header("HS256"));
        let public_key = self.old.public_key_pem().expect("public key PEM");
        let mac = Digest::hmac(&public_key, input.as_bytes())
            .expect("HMAC")
            .encoded();
        self.token(
            "access-alg-hs256",
            "HMAC keyed with the public key (algorithm confusion) is rejected",
            access_case(format!("{input}.{mac}"), &during),
            Expected::error(
                ErrorCategory::InvalidToken,
                ErrorReason::UnsupportedAlgorithm,
            ),
        );
        let (signed, signature) = valid.rsplit_once('.').expect("compact token");
        let mut tampered = URL_SAFE_NO_PAD.decode(signature).expect("signature bytes");
        tampered[10] ^= 1;
        self.token(
            "access-tampered-signature",
            "a signature that does not verify is rejected",
            access_case(
                format!("{signed}.{}", URL_SAFE_NO_PAD.encode(tampered)),
                &during,
            ),
            Expected::error(ErrorCategory::InvalidToken, ErrorReason::BadSignature),
        );
        let mut incomplete = serde_json::to_value(&access).expect("serialize claims");
        incomplete
            .as_object_mut()
            .expect("claims object")
            .remove("exp");
        self.token(
            "access-missing-exp",
            "a token without a required claim is rejected",
            access_case(
                Self::sign(&self.old, TokenType::Access, &incomplete),
                &during,
            ),
            Expected::error(ErrorCategory::InvalidToken, ErrorReason::InvalidClaims),
        );
        for (name, description, change, reason) in [
            (
                "access-wrong-issuer",
                "iss must equal the issuer exactly",
                (|claims: &mut AccessTokenClaims| claims.iss = format!("{ISSUER}/"))
                    as fn(&mut AccessTokenClaims),
                ErrorReason::IssuerMismatch,
            ),
            (
                "access-wrong-audience",
                "aud must contain the resource",
                |claims| claims.aud = Audience::One("https://files.example.com".into()),
                ErrorReason::WrongAudience,
            ),
            (
                "access-expired",
                "exp 30 seconds in the past is expired: the leeway ends there",
                |claims| claims.exp = at(-30),
                ErrorReason::Expired,
            ),
            (
                "access-not-yet-valid",
                "nbf more than 30 seconds in the future is not yet valid",
                |claims| claims.nbf = Some(at(31)),
                ErrorReason::NotYetValid,
            ),
            (
                "access-issued-in-future",
                "iat more than 30 seconds in the future is rejected",
                |claims| claims.iat = at(31),
                ErrorReason::IssuedInFuture,
            ),
        ] {
            let mut claims = access.clone();
            change(&mut claims);
            self.token(
                name,
                description,
                access_case(Self::sign(&self.old, TokenType::Access, &claims), &during),
                Expected::error(ErrorCategory::InvalidToken, reason),
            );
        }
        let mut leeway = access.clone();
        leeway.exp = at(-29);
        leeway.nbf = Some(at(30));
        leeway.iat = at(30);
        self.token(
            "access-within-leeway",
            "exp 29 seconds past, and nbf and iat 30 seconds ahead, are within the leeway",
            access_case(Self::sign(&self.old, TokenType::Access, &leeway), &during),
            Expected::ok(&leeway),
        );
        let typed = |extra: (&str, Value)| {
            let mut header = json!({
                "alg": Algorithm::Rs256.as_str(), "kid": OLD_KID, "typ": TokenType::Access.as_str(),
            });
            header[extra.0] = extra.1;
            header
        };
        self.token(
            "access-media-type",
            "typ may be written as the media type application/at+jwt (RFC 9068 §4)",
            access_case(
                self.sign_header(&typed(("typ", json!("application/at+jwt"))), &access),
                &during,
            ),
            Expected::ok(&access),
        );
        let mut critical = typed(("crit", json!(["unknown_extension"])));
        critical["unknown_extension"] = json!(true);
        self.token(
            "access-critical-header",
            "a correctly signed token with a critical extension the SDK does not \
             understand is rejected (RFC 7515 §4.1.11)",
            access_case(self.sign_header(&critical, &access), &during),
            Expected::error(
                ErrorCategory::InvalidToken,
                ErrorReason::UnsupportedCriticalHeader,
            ),
        );
        self.id_tokens(&during);
    }

    /// ID token cases, checked against the pending login's nonce and `max_age`. The
    /// fixture session signed in an hour before [`NOW`].
    fn id_tokens(&mut self, jwks: &Value) {
        let id = Self::id_claims();
        let token = Self::sign(&self.old, TokenType::Id, &id);
        let id_case = |nonce: &str, max_age: Option<u64>, token: &str| {
            json!({
                "issuer": ISSUER, "jwks": jwks, "kind": "id", "audience": CLIENT,
                "nonce": nonce, "max_age": max_age, "token": token,
            })
        };
        self.token(
            "id-valid",
            "an ID token as auth issues it, matching the pending login",
            id_case(NONCE, Some(7200), &token),
            Expected::ok(&id),
        );
        self.token(
            "id-max-age-boundary",
            "auth_time exactly max_age plus the leeway ago is accepted",
            id_case(NONCE, Some(3570), &token),
            Expected::ok(&id),
        );
        self.token(
            "id-max-age",
            "auth_time one second older than max_age plus the leeway is rejected",
            id_case(NONCE, Some(3569), &token),
            Expected::error(
                ErrorCategory::InvalidToken,
                ErrorReason::AuthenticationTooOld,
            ),
        );
        self.token(
            "id-nonce-mismatch",
            "an ID token from another login attempt is rejected",
            id_case("another-nonce", None, &token),
            Expected::error(ErrorCategory::InvalidToken, ErrorReason::NonceMismatch),
        );
        self.token(
            "id-wrong-type",
            "an ID token signed with the access token typ is rejected",
            id_case(NONCE, None, &Self::sign(&self.old, TokenType::Access, &id)),
            Expected::error(ErrorCategory::InvalidToken, ErrorReason::WrongType),
        );
        for (name, description, change, reason) in [
            (
                "id-missing-auth-time",
                "without auth_time, max_age cannot be checked, so it fails",
                (|claims: &mut IdTokenClaims| claims.authentication.auth_time = None)
                    as fn(&mut IdTokenClaims),
                ErrorReason::AuthenticationTooOld,
            ),
            (
                "id-not-yet-valid",
                "nbf more than 30 seconds in the future is not yet valid",
                |claims| claims.nbf = Some(at(31)),
                ErrorReason::NotYetValid,
            ),
            (
                "id-extra-audience",
                "an audience naming another client is untrusted, even with azp set",
                |claims| {
                    claims.aud = Audience::Many(vec![CLIENT.into(), "untrusted-client".into()]);
                    claims.azp = Some(ClientId::new(CLIENT));
                },
                ErrorReason::WrongAudience,
            ),
            (
                "id-wrong-azp",
                "azp naming another client is rejected",
                |claims| claims.azp = Some(ClientId::new("another-client")),
                ErrorReason::WrongAuthorizedParty,
            ),
        ] {
            let mut claims = id.clone();
            change(&mut claims);
            self.token(
                name,
                description,
                id_case(
                    NONCE,
                    Some(7200),
                    &Self::sign(&self.old, TokenType::Id, &claims),
                ),
                Expected::error(ErrorCategory::InvalidToken, reason),
            );
        }
    }

    /// Signs `claims` under a hand-written `header` with the old key, for headers
    /// auth's signer never writes.
    fn sign_header(&self, header: &Value, claims: &impl Serialize) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("header")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims"))
        );
        let key = PKey::private_key_from_pem(self.old_pem.as_bytes()).expect("test key");
        let mut signer = Signer::new(MessageDigest::sha256(), &key).expect("signer");
        signer.update(input.as_bytes()).expect("signing input");
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signer.sign_to_vec().expect("signature"))
        )
    }

    /// Signs `claims` as auth does.
    fn sign(key: &Rs256Key, typ: TokenType, claims: &impl Serialize) -> String {
        key.sign(typ, claims).expect("sign test token")
    }

    /// Records a token case.
    fn token(&mut self, name: &str, description: &'static str, input: Value, expected: Expected) {
        self.case(
            &format!("tokens/{name}.json"),
            &Case {
                description,
                now: Some(NOW),
                input,
                expected,
            },
        );
    }

    /// Claims of the access token auth issues for the fixture user.
    fn access_claims() -> AccessTokenClaims {
        AccessTokenClaims {
            iss: ISSUER.into(),
            sub: USER.into(),
            aud: Audience::One(RESOURCE.into()),
            client_id: ClientId::new(CLIENT),
            jti: "01936f3e-8c00-7000-8000-000000000003"
                .parse::<TokenId>()
                .expect("token ID"),
            scope: "openid profile notes:read".parse().expect("scopes"),
            iat: at(-60),
            exp: at(240),
            nbf: None,
            authentication: Self::authentication(),
            act: None,
            cnf: None,
            profile: Self::profile(),
            extra: (),
        }
    }

    /// Claims of the ID token issued with [`Self::access_claims`].
    fn id_claims() -> IdTokenClaims {
        IdTokenClaims {
            iss: ISSUER.into(),
            sub: USER.into(),
            aud: Audience::One(CLIENT.into()),
            azp: None,
            iat: at(-60),
            exp: at(240),
            nbf: None,
            nonce: Some(NONCE.into()),
            authentication: Self::authentication(),
            profile: Self::profile(),
        }
    }

    /// The fixture session, signed in by passkey an hour ago.
    fn authentication() -> AuthenticationClaims {
        AuthenticationClaims {
            sid: Some(
                "01936f3e-8c00-7000-8000-000000000002"
                    .parse::<SessionId>()
                    .expect("session ID"),
            ),
            auth_time: Some(at(-3600)),
            amr: AuthenticationMethod::Passkey.amr().into(),
            acr: Some(Acr::PhishingResistant),
        }
    }

    /// The fixture user's profile claims.
    fn profile() -> ProfileClaims {
        ProfileClaims {
            preferred_username: Some("ada".into()),
            name: Some("Ada Lovelace".into()),
            profile_version: Some(1),
            ..ProfileClaims::default()
        }
    }

    /// Challenge cases. Format cases go both ways: the challenge formats to exactly
    /// the header and the header parses back. Parse cases only parse.
    #[expect(
        clippy::too_many_lines,
        reason = "One table of cases reads better than many small builders."
    )]
    fn challenges(&mut self) {
        let metadata = || {
            Some(
                format!("{RESOURCE}/.well-known/oauth-protected-resource")
                    .parse()
                    .expect("metadata URL"),
            )
        };
        let scope = |scopes: &str| Some(scopes.parse().expect("scopes"));
        for (name, description, challenge) in [
            (
                "missing-token",
                "no token was sent and the resource has no metadata",
                BearerChallenge::default(),
            ),
            (
                "missing-token-scope",
                "no token was sent; the challenge names the scope the handler enforces",
                BearerChallenge {
                    scope: scope("notes:read"),
                    resource_metadata: metadata(),
                    ..BearerChallenge::default()
                },
            ),
            (
                "invalid-token",
                "the token failed validation",
                BearerChallenge {
                    error_description: "the access token expired".parse().ok(),
                    resource_metadata: metadata(),
                    ..BearerChallenge::error(BearerError::InvalidToken)
                },
            ),
            (
                "insufficient-scope",
                "the token lacks a scope; the challenge names every scope required",
                BearerChallenge {
                    scope: scope("notes:read notes:write"),
                    resource_metadata: metadata(),
                    ..BearerChallenge::error(BearerError::InsufficientScope)
                },
            ),
            (
                "insufficient-user-authentication",
                "the user must confirm with a passkey within the last five minutes",
                BearerChallenge {
                    error_description: "A passkey confirmation is required".parse().ok(),
                    resource_metadata: metadata(),
                    ..BearerChallenge::step_up(StepUpRequirement::passkey_within(300))
                },
            ),
            (
                "invalid-request",
                "the request sent a token in more than one way",
                BearerChallenge::error(BearerError::InvalidRequest),
            ),
        ] {
            // Format cases go both ways, so the canonical header must parse back.
            let header = challenge.to_string();
            assert_eq!(
                header.parse::<BearerChallenge>().as_ref(),
                Ok(&challenge),
                "{name}: the header does not parse back to the challenge"
            );
            self.case(
                &format!("challenges/{name}.json"),
                &Case {
                    description,
                    now: None,
                    input: json!({ "challenge": challenge }),
                    expected: Expected::Ok(json!({
                        "status": challenge.status(),
                        "header": header,
                    })),
                },
            );
        }
        for (name, description, header) in [
            (
                "parse-unknown-error",
                "an error code this version does not know is kept, with the rest of \
                 the challenge",
                "Bearer error=\"invalid_dpop_proof\", scope=\"notes:read\"",
            ),
            (
                "parse-reordered",
                "parameters in any order, with token values; the first known acr is the target",
                "Bearer max_age=300, acr_values=\"urn:example:gold phr\", \
                 error=insufficient_user_authentication",
            ),
            (
                "parse-other-schemes",
                "the Bearer challenge is found among others, including token68 credentials; \
                 escapes resolve and unknown parameters are ignored",
                "Negotiate YWJjZA==, DPoP algs=\"ES256 PS256\", bearer realm=\"no\\tes\", \
                 error=\"invalid_token\", error_description=\"token 'abc' expired\"",
            ),
            (
                "parse-missing-comma",
                "parameters must be separated by commas, so this header has no valid challenge",
                "Bearer error=\"invalid_token\"scope=\"notes:write\"",
            ),
            (
                "parse-scheme-without-space",
                "parameters follow the scheme after a space (RFC 9110 §11), so this header \
                 has no valid challenge",
                "Bearer,error=invalid_token",
            ),
            (
                "parse-tab-in-scope",
                "scope tokens are separated by single spaces (RFC 6750 §3), so this header \
                 has no valid challenge",
                "Bearer error=\"insufficient_scope\", scope=\"notes:read\tnotes:write\"",
            ),
            (
                "parse-forbidden-description",
                "error_description may not contain a quote (RFC 6750 §3), so this header has \
                 no valid challenge",
                "Bearer error=\"invalid_token\", error_description=\"say \\\"hi\\\"\"",
            ),
        ] {
            let challenge: Option<BearerChallenge> = header.parse().ok();
            self.case(
                &format!("challenges/{name}.json"),
                &Case {
                    description,
                    now: None,
                    input: json!({ "header": header }),
                    expected: Expected::ok(&json!({ "challenge": challenge })),
                },
            );
        }
    }

    /// Authorization response cases (RFC 9207 §2.4). Failures happen before any code
    /// exchange.
    fn callbacks(&mut self) {
        let other = "https://evil.example.com";
        for (name, description, advertised, parameters, expected) in [
            (
                "iss-match",
                "iss equal to the issuer is accepted",
                true,
                json!({ "code": CODE, "state": STATE, "iss": ISSUER }),
                Expected::Ok(json!({ "code": CODE })),
            ),
            (
                "iss-mismatch",
                "iss naming another issuer is a mix-up attack",
                true,
                json!({ "code": CODE, "state": STATE, "iss": other }),
                Expected::error(ErrorCategory::Callback, ErrorReason::IssuerMismatch),
            ),
            (
                "iss-missing-advertised",
                "iss is required once the metadata advertises it",
                true,
                json!({ "code": CODE, "state": STATE }),
                Expected::error(ErrorCategory::Callback, ErrorReason::MissingIssuer),
            ),
            (
                "iss-missing-not-advertised",
                "iss may be absent when the metadata does not advertise it",
                false,
                json!({ "code": CODE, "state": STATE }),
                Expected::Ok(json!({ "code": CODE })),
            ),
            (
                "state-mismatch",
                "state from another login attempt is rejected before iss is checked",
                true,
                json!({ "code": CODE, "state": "another-state", "iss": other }),
                Expected::error(ErrorCategory::Callback, ErrorReason::StateMismatch),
            ),
            (
                "error-response",
                "an error from the issuer is reported as an OAuth error",
                true,
                json!({ "error": "access_denied", "error_description": "the user denied the request", "state": STATE, "iss": ISSUER }),
                Expected::Error(SdkError::category(ErrorCategory::OAuth)),
            ),
            (
                "error-response-iss-mismatch",
                "iss is checked on error responses too, before the error is trusted",
                true,
                json!({ "error": "access_denied", "state": STATE, "iss": other }),
                Expected::error(ErrorCategory::Callback, ErrorReason::IssuerMismatch),
            ),
            (
                "missing-code",
                "a response with neither code nor error is rejected",
                true,
                json!({ "state": STATE, "iss": ISSUER }),
                Expected::error(ErrorCategory::Callback, ErrorReason::MissingCode),
            ),
        ] {
            self.case(
                &format!("callbacks/{name}.json"),
                &Case {
                    description,
                    now: None,
                    input: json!({
                        "issuer": ISSUER,
                        "authorization_response_iss_parameter_supported": advertised,
                        "state": STATE,
                        "parameters": parameters,
                    }),
                    expected,
                },
            );
        }
    }
}

/// The fixture user's account ID.
const USER: &str = "01936f3e-8c00-7000-8000-000000000001";

/// `seconds` from [`NOW`].
fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(NOW, 0).expect("fixed clock") + Duration::seconds(seconds)
}

/// Generates every case, then writes or compares them.
#[test]
fn sdk_vectors_are_current() {
    let mut vectors = Vectors::new();
    vectors.discovery();
    vectors.jwks_cases();
    vectors.tokens();
    vectors.challenges();
    vectors.callbacks();
    vectors.finish();
}
