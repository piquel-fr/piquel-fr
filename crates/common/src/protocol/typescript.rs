//! Writes `packages/auth/src/protocol.ts`, the TypeScript SDK's declarations of these
//! wire types, with ts-rs. Without `UPDATE_SDK_TYPES=1` it only compares, so
//! `just test` fails while the committed file is stale; `just sdk-types` rewrites it.
//!
//! The structs derive `TS` under `cfg(test)`, so ts-rs stays a dev-dependency. Types
//! that serialize by hand implement it here, from the same values serde writes:
//! vocabularies as unions of their spellings, validated strings as `string`.

use super::{
    challenge::{BearerChallenge, BearerError},
    claims::{
        Absent, AccessTokenClaims, Acr, Actor, Amr, Audience, AuthenticationClaims,
        BACKCHANNEL_LOGOUT_EVENT, Confirmation, IdTokenClaims, LogoutEvents, LogoutTokenClaims,
        ProfileClaims, UserInfo,
    },
    jwt::{Algorithm, Claim, Jwk, JwkSet, KeyId, KeyType, KeyUse, TokenType},
    metadata::ServerMetadata,
    oauth::{
        ClientAuthMethod, CodeChallengeMethod, ErrorCode, ErrorDescription, ErrorResponse,
        GrantType, Prompt, ResponseMode, ResponseType, Scope, Scopes, SubjectType,
    },
    sdk::{ErrorCategory, ErrorReason, SdkError},
    step_up::StepUpRequirement,
};
use crate::{ClientId, DeliveryId, SessionId, TokenId};
use std::{collections::BTreeSet, fs, path::PathBuf};
use ts_rs::{Config, TS};

/// Opens the generated file.
const HEADER: &str = "\
// Generated from piquel_common::protocol by `just sdk-types`. Do not edit.
// The wire types auth and every SDK share; docs/architecture/sdk.md describes them.
";

/// Implements `TS` for a type declared in the generated file.
macro_rules! declared {
    ($name:ty, $inline:expr) => {
        impl TS for $name {
            type WithoutGenerics = Self;
            type OptionInnerType = Self;
            fn name(_: &Config) -> String {
                stringify!($name).to_owned()
            }
            fn inline(_: &Config) -> String {
                $inline
            }
            fn decl(cfg: &Config) -> String {
                format!("type {} = {};", Self::name(cfg), Self::inline(cfg))
            }
            fn output_path() -> Option<PathBuf> {
                Some(PathBuf::from("protocol.ts"))
            }
        }
    };
}

/// Declares closed vocabularies as the union of their spellings.
macro_rules! closed {
    ($($name:ident),+ $(,)?) => {$(
        declared!($name, union($name::ALL.iter().map(|value| value.as_str())));
    )+};
}

/// Declares open vocabularies as their known spellings or any other string, which
/// keeps the known ones in editors' completions.
macro_rules! open {
    ($($name:ident),+ $(,)?) => {$(
        declared!(
            $name,
            format!(
                "{} | (string & Record<never, never>)",
                union($name::KNOWN.iter().map(|value| value.as_str()))
            )
        );
    )+};
}

/// Writes validated strings as `string`, inline.
macro_rules! strings {
    ($($name:ty),+ $(,)?) => {$(
        impl TS for $name {
            type WithoutGenerics = Self;
            type OptionInnerType = Self;
            fn name(_: &Config) -> String {
                "string".to_owned()
            }
            fn inline(cfg: &Config) -> String {
                Self::name(cfg)
            }
        }
    )+};
}

closed!(
    Amr,
    Acr,
    TokenType,
    Claim,
    Algorithm,
    KeyType,
    KeyUse,
    GrantType,
    ResponseType,
    ResponseMode,
    ClientAuthMethod,
    SubjectType,
    CodeChallengeMethod,
    Prompt,
    Scope,
    ErrorCategory,
    ErrorReason,
);
open!(ErrorCode, BearerError);
strings!(
    ClientId,
    SessionId,
    TokenId,
    DeliveryId,
    KeyId,
    ErrorDescription,
    Scopes
);
declared!(
    LogoutEvents,
    format!("{{ {BACKCHANNEL_LOGOUT_EVENT:?}: Record<string, unknown> }}")
);

impl TS for Absent {
    type WithoutGenerics = Self;
    type OptionInnerType = Self;
    fn name(_: &Config) -> String {
        "never".to_owned()
    }
    fn inline(cfg: &Config) -> String {
        Self::name(cfg)
    }
}

/// `"a" | "b"`, from spellings that need no escaping.
fn union<'a>(values: impl Iterator<Item = &'a str>) -> String {
    values
        .map(|value| format!("{value:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// The generated file, built from declarations in order.
struct Declarations {
    /// Options for ts-rs.
    cfg: Config,
    /// The file so far.
    text: String,
    /// Names declared so far.
    declared: BTreeSet<String>,
    /// Names each declaration refers to.
    referenced: BTreeSet<String>,
}

impl Declarations {
    /// Starts the file.
    fn new() -> Self {
        Self {
            cfg: Config::new().with_large_int("number"),
            text: HEADER.to_owned(),
            declared: BTreeSet::new(),
            referenced: BTreeSet::new(),
        }
    }

    /// Appends `T`'s declaration, with its docs.
    fn add<T: TS + 'static>(mut self) -> Self {
        self.text.push('\n');
        self.text.push_str(&T::docs().unwrap_or_default());
        self.text.push_str("export ");
        self.text.push_str(&T::decl(&self.cfg));
        self.text.push('\n');
        self.declared.insert(T::ident(&self.cfg));
        self.referenced.extend(
            T::dependencies(&self.cfg)
                .into_iter()
                .map(|dependency| dependency.ts_name),
        );
        self
    }

    /// The file, once every referenced type is declared in it. Drops the docs' Rust
    /// examples and ts-rs's trailing spaces.
    fn finish(self) -> String {
        let missing: Vec<_> = self.referenced.difference(&self.declared).collect();
        assert!(missing.is_empty(), "declare {missing:?} too");
        let mut example = false;
        let mut lines: Vec<&str> = Vec::new();
        for line in self.text.lines().map(str::trim_end) {
            let fence = line.trim_start().strip_prefix('*').map(str::trim) == Some("```");
            example ^= fence;
            if example || fence {
                continue;
            }
            // An example that ended a doc leaves an empty line before its end.
            if line == " */" && lines.last() == Some(&" *") {
                lines.pop();
            }
            lines.push(line);
        }
        lines.join("\n") + "\n"
    }
}

/// Every type the TypeScript SDK reads, grouped as in `docs/architecture/sdk.md`.
fn generate() -> String {
    Declarations::new()
        // claims
        .add::<AccessTokenClaims>()
        .add::<IdTokenClaims>()
        .add::<LogoutTokenClaims>()
        .add::<LogoutEvents>()
        .add::<UserInfo>()
        .add::<AuthenticationClaims>()
        .add::<ProfileClaims>()
        .add::<Audience>()
        .add::<Actor>()
        .add::<Confirmation>()
        .add::<Amr>()
        .add::<Acr>()
        // metadata
        .add::<ServerMetadata>()
        // step_up
        .add::<StepUpRequirement>()
        // jwt
        .add::<TokenType>()
        .add::<Claim>()
        .add::<Algorithm>()
        .add::<JwkSet>()
        .add::<Jwk>()
        .add::<KeyType>()
        .add::<KeyUse>()
        // oauth
        .add::<GrantType>()
        .add::<ResponseType>()
        .add::<ResponseMode>()
        .add::<ClientAuthMethod>()
        .add::<SubjectType>()
        .add::<CodeChallengeMethod>()
        .add::<Prompt>()
        .add::<Scope>()
        .add::<ErrorCode>()
        .add::<ErrorResponse>()
        // challenge
        .add::<BearerChallenge>()
        .add::<BearerError>()
        // sdk
        .add::<SdkError>()
        .add::<ErrorCategory>()
        .add::<ErrorReason>()
        .finish()
}

/// The committed declarations match the Rust types.
#[test]
fn typescript_declarations_are_current() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packages/auth/src/protocol.ts");
    let generated = generate();
    if std::env::var_os("UPDATE_SDK_TYPES").is_some() {
        fs::write(&path, generated).expect("write the declarations");
        return;
    }
    assert!(
        fs::read_to_string(&path).ok().as_ref() == Some(&generated),
        "{} is stale; run `just sdk-types`",
        path.display()
    );
}
