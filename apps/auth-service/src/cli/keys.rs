//! Signing keys, key-encryption keys, token digest keys and the audit key. None
//! needs the HTTP service, and every replica picks up a signing key change
//! within a minute.
//! Signing key commands run their admin operation, as the dashboard's signing
//! keys page does.

use super::{
    CliError, Confirm, Console,
    output::{Cell, Output, Single, report},
};
use crate::{
    AuditConfig, KeyEncryptionKeys, KeyStore, PUBLIC_BASE_URL, Reason, TokenDigestKeys,
    admin::{AdminOperation, OperatorName},
};
use clap::Subcommand;
use serde::Serialize;
use sourceorigin_common::{admin::SigningKey, protocol::jwt::KeyId};
use sourceorigin_repository::{Database, DigestUsage};
use std::sync::Arc;

/// Inspecting, rotating, revoking and rewrapping signing keys, and checking token
/// digest keys. Changes are recorded as made by the operator at this terminal.
#[derive(Subcommand)]
pub(super) enum KeysCommand {
    /// List signing keys with their state and dates, oldest first.
    List,
    /// Publish a new signing key, which signs after 24 hours. Prints its ID.
    Rotate {
        /// Sign with it at once, skipping pre-publication: verifiers that cached
        /// the previous key set reject its tokens until they fetch keys again.
        /// Asks first.
        #[arg(long)]
        now: bool,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation, which `--now` needs.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Delete a signing key at once, e.g. a compromised one. When it was the active
    /// key, the `next` and `retiring` keys go with it, since their private keys
    /// were stored alongside, and a new one signs at once. Apps verifying with the
    /// SDKs keep accepting it for up to 90 minutes.
    Revoke {
        /// The key's ID.
        id: KeyId,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Seal every stored signing key again under `AUTH_KEY_ENCRYPTION_KEY`, after
    /// a change of key-encryption key, so `AUTH_KEY_ENCRYPTION_KEY_ACCEPTED` can
    /// be removed. Refuses, changing nothing, if a key opens under neither.
    Rewrap {
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Count stored token digests per token digest key, to tell when
    /// `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` can be removed.
    DigestUsage,
    /// Print the verifier key of the audit key `AUTH_AUDIT_KEY_PROVIDER` names,
    /// for `AUTH_PUBLIC_BASE_URL`'s host, to commit to docs/dev/security/audit-key.pub.
    Audit,
}

impl KeysCommand {
    /// What revoking the key `id`, among `keys`, does, for its confirmation. It
    /// names the key's state as read now, and says what revoking an active key
    /// does whatever that state, since a waiting key may start signing before the
    /// operator answers. Sessions and refresh grants stay: applications refresh
    /// into tokens the new key signs.
    fn revoking(id: &KeyId, keys: &[SigningKey]) -> String {
        let state = keys
            .iter()
            .find(|key| key.id == *id)
            .map(|key| format!(", now {},", key.state))
            .unwrap_or_default();
        format!(
            "Revoke signing key {id}{state} at once: every replica stops accepting the tokens it signed within a minute, or 15 minutes if it cannot reload its keys, and apps verifying with the SDKs within 90 minutes. If it signs when revoked, the keys waiting and retiring beside it go too, and a new key signs at once"
        )
    }

    /// The admin operation this command runs, if any. Checking token digest keys
    /// and printing the audit key's verifier read the deployment's configuration,
    /// which operators change outside auth, so neither is one.
    pub(super) const fn operation(&self) -> Option<AdminOperation> {
        Some(match self {
            Self::List => AdminOperation::ListSigningKeys,
            Self::Rotate { .. } => AdminOperation::RotateSigningKey,
            Self::Revoke { .. } => AdminOperation::RevokeSigningKey,
            Self::Rewrap { .. } => AdminOperation::RewrapSigningKeys,
            Self::DigestUsage | Self::Audit => return None,
        })
    }

    /// Runs this command on `database`, a signing key's as the operator at this
    /// terminal, `operator` when given, printing to `out`.
    pub(super) async fn run(
        self,
        database: Database,
        operator: Option<OperatorName>,
        out: Output,
    ) -> Result<(), CliError> {
        let store = || -> Result<KeyStore, CliError> {
            Ok(KeyStore::new(
                database.clone(),
                Arc::new(KeyEncryptionKeys::from_environment()?),
            ))
        };
        let console = || Console::new(database.clone(), operator, out.clone());
        match self {
            Self::List => {
                let Console {
                    service, operator, ..
                } = &console()?;
                out.emit(&service.list_signing_keys(operator).await?[..])?;
            }
            Self::Rotate {
                now,
                reason,
                confirm,
            } => {
                let Console {
                    service, operator, ..
                } = &console()?;
                if now {
                    confirm.ask(
                        &out,
                        "Make a new signing key sign at once: verifiers that cached the key set reject its tokens until they fetch it again, for up to an hour",
                    )?;
                }
                let id = service
                    .rotate_signing_key(operator, &store()?, now, reason)
                    .await?;
                out.emit(&Single {
                    name: "id",
                    value: id,
                })?;
            }
            Self::Revoke {
                id,
                reason,
                confirm,
            } => {
                let Console {
                    service, operator, ..
                } = &console()?;
                let keys = service.list_signing_keys(operator).await?;
                confirm.ask(&out, &Self::revoking(&id, &keys))?;
                match service
                    .revoke_signing_key(operator, &store()?, &id, reason)
                    .await?
                {
                    Some(replacement) => out.info(format_args!(
                        "Revoked key {id}; key {replacement} signs from now on."
                    ))?,
                    None => out.info(format_args!("Revoked key {id}."))?,
                }
            }
            Self::Rewrap { reason, confirm } => {
                let Console {
                    service, operator, ..
                } = &console()?;
                confirm.ask(
                    &out,
                    "Seal every signing key again under AUTH_KEY_ENCRYPTION_KEY: a replica that has it neither as its key-encryption key nor as its accepted one can no longer open them",
                )?;
                let ids = service
                    .rewrap_signing_keys(operator, &store()?, reason)
                    .await?;
                if ids.is_empty() {
                    out.info("No signing key has a private key to rewrap.")?;
                } else {
                    let ids: Vec<_> = ids.iter().map(KeyId::as_str).collect();
                    out.info(format_args!("Rewrapped signing keys {}.", ids.join(", ")))?;
                }
            }
            Self::DigestUsage => {
                let keys = TokenDigestKeys::from_environment()?;
                let usage: Vec<_> = database
                    .maintenance()
                    .digest_usage()
                    .await?
                    .into_iter()
                    .map(|usage| KeyUsage {
                        key: keys.name(usage.digest_key.as_deref()),
                        usage,
                    })
                    .collect();
                out.emit(&usage[..])?;
            }
            Self::Audit => {
                let config = AuditConfig::from_environment(&PUBLIC_BASE_URL.parse()?)?;
                out.emit(&Single {
                    name: "verifier",
                    value: config.verifier().to_string(),
                })?;
            }
        }
        Ok(())
    }
}

// One signing key per line, oldest first.
report!([SigningKey], self, out, {
    out.table(
        [
            "ID",
            "TYPE",
            "STATE",
            "CREATED",
            "ACTIVATED",
            "DEACTIVATED",
            "RETIRED",
        ],
        "No signing keys.",
        self.iter().map(|key| {
            [
                Cell::new(&key.id),
                Cell::new(key.key_type),
                key.state.into(),
                key.created_at.into(),
                key.activated_at.into(),
                key.deactivated_at.into(),
                key.retired_at.into(),
            ]
        }),
    )
});

/// How many stored digests of one kind a token digest key made, and which of
/// the configured keys it is.
#[derive(Serialize)]
struct KeyUsage {
    /// The count.
    #[serde(flatten)]
    usage: DigestUsage,
    /// `current`, `accepted`, `unrecorded` or `unknown`.
    key: &'static str,
}

// One kind of record per line, per digest key.
report!([KeyUsage], self, out, {
    out.table(
        ["RECORD", "KEY", "FINGERPRINT", "STORED"],
        "No stored digests.",
        self.iter().map(|KeyUsage { usage, key }| {
            [
                Cell::new(usage.secret),
                Cell::new(key),
                usage.digest_key.as_deref().into(),
                usage.stored.into(),
            ]
        }),
    )
});
