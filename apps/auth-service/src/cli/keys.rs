//! Signing keys, token digest keys and the audit key. None needs the HTTP
//! service, and every replica picks up a signing key change within a minute.
//! Signing key commands run their admin operation, as the dashboard's signing
//! keys page does.

use super::{CliError, Confirm, Console};
use crate::{
    AuditConfig, AuthConfig, KeyStore, PUBLIC_BASE_URL, TokenDigestKeys,
    admin::{AdminOperation, OperatorName},
};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use piquel_common::{admin::SigningKey, config::SecretReference, protocol::jwt::KeyId};
use piquel_crypto::Rs256Key;
use piquel_repository::Database;
use std::sync::Arc;

/// The key ID `keys import` gives the PEM key, the default of the removed
/// `AUTH_SIGNING_KEY_ID`, so tokens it signed keep naming a known key.
const DEFAULT_IMPORTED_KEY_ID: &str = "primary";

/// Inspecting, rotating, revoking and importing signing keys, and checking token
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
        /// Confirmation, which `--now` needs.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Delete a signing key at once, e.g. a compromised one. When it was the active
    /// key, the `next` and `retiring` keys go with it, since their private keys
    /// were stored alongside, and a new one signs at once. Verifiers that cached it keep accepting it
    /// until their cache expires, up to an hour.
    Revoke {
        /// The key's ID.
        id: KeyId,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Count stored token digests per token digest key, to tell when
    /// `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` can be removed.
    DigestUsage,
    /// Import the deployment's PEM signing key as the active key, so tokens it
    /// signed keep verifying. Does nothing unless the key set is empty.
    Import {
        /// The PEM key, at `file://PATH` or `env://NAME`.
        #[arg(value_name = "REFERENCE")]
        pem: SecretReference,
        /// The key's ID, as tokens it signed name it.
        #[arg(long, default_value = DEFAULT_IMPORTED_KEY_ID)]
        id: KeyId,
    },
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
            "Revoke signing key {id}{state} at once: every replica stops accepting the tokens it signed within a minute, and verifiers that cached it within an hour. If it signs when revoked, the keys waiting and retiring beside it go too, and a new key signs at once"
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
            Self::Import { .. } => AdminOperation::ImportSigningKey,
            Self::DigestUsage | Self::Audit => return None,
        })
    }

    /// Runs this command on `database`, a signing key's as the operator at this
    /// terminal, `operator` when given.
    pub(super) async fn run(
        self,
        database: Database,
        operator: Option<OperatorName>,
    ) -> Result<(), CliError> {
        let store = || -> Result<KeyStore, CliError> {
            Ok(KeyStore::new(
                database.clone(),
                Arc::new(AuthConfig::key_encryption_key_from_environment()?),
            ))
        };
        let console = || Console::new(database.clone(), operator);
        match self {
            Self::List => {
                let Console {
                    service, operator, ..
                } = &console()?;
                let format = |at: Option<DateTime<Utc>>| {
                    at.map_or_else(|| "-".to_owned(), |at| at.to_rfc3339())
                };
                println!("ID\tTYPE\tSTATE\tCREATED\tACTIVATED\tDEACTIVATED\tRETIRED");
                for key in service.list_signing_keys(operator).await? {
                    println!(
                        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                        key.id,
                        key.key_type,
                        key.state,
                        key.created_at.to_rfc3339(),
                        format(key.activated_at),
                        format(key.deactivated_at),
                        format(key.retired_at),
                    );
                }
            }
            Self::Rotate { now, confirm } => {
                let Console {
                    service, operator, ..
                } = &console()?;
                if now {
                    confirm.ask(
                        "Make a new signing key sign at once: verifiers that cached the key set reject its tokens until they fetch it again, for up to an hour",
                    )?;
                }
                let id = service.rotate_signing_key(operator, &store()?, now).await?;
                println!("{id}");
            }
            Self::Revoke { id, confirm } => {
                let Console {
                    service, operator, ..
                } = &console()?;
                let keys = service.list_signing_keys(operator).await?;
                confirm.ask(&Self::revoking(&id, &keys))?;
                match service.revoke_signing_key(operator, &store()?, &id).await? {
                    Some(replacement) => {
                        eprintln!("Key {id} revoked; key {replacement} signs from now on.");
                    }
                    None => eprintln!("Key {id} revoked."),
                }
            }
            Self::DigestUsage => {
                let keys = TokenDigestKeys::from_environment()?;
                println!("RECORD\tKEY\tFINGERPRINT\tSTORED");
                for usage in database.maintenance().digest_usage().await? {
                    println!(
                        "{}\t{}\t{}\t{}",
                        usage.secret,
                        keys.name(usage.digest_key.as_deref()),
                        usage.digest_key.as_deref().unwrap_or("-"),
                        usage.stored,
                    );
                }
            }
            Self::Audit => {
                let config = AuditConfig::from_environment(&PUBLIC_BASE_URL.parse()?)?;
                println!("{}", config.verifier());
            }
            Self::Import { pem, id } => {
                let Console {
                    service, operator, ..
                } = &console()?;
                let pem = pem.resolve().map_err(CliError::PemUnreadable)?;
                let key =
                    Rs256Key::from_pem(id.as_str(), pem.utf8()?).map_err(CliError::InvalidPem)?;
                if service.import_signing_key(operator, &store()?, key).await? {
                    eprintln!("Key {id} imported; it signs from now on.");
                } else {
                    eprintln!("Signing keys already exist; nothing was imported.");
                }
            }
        }
        Ok(())
    }
}
