//! Generated private RPC contract and client-assertion creation.
#![allow(missing_docs)]

pub mod v1 {
    #![allow(clippy::all, clippy::pedantic)]
    tonic::include_proto!("piquel.auth.v1");
}

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use piquel_auth_protocol::TokenId;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("service assertion creation failed")]
pub struct AssertionError;
/// Creates a one-minute ES256 assertion for the private token service.
///
/// # Errors
///
/// Returns an error when identifiers are empty or serialization fails.
pub fn create_client_assertion(
    service_id: &str,
    kid: &str,
    audience: &str,
    key: &SigningKey,
) -> Result<String, AssertionError> {
    if service_id.is_empty() || kid.is_empty() {
        return Err(AssertionError);
    }
    let now = Utc::now().timestamp();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"alg":"ES256","typ":"client-assertion+jwt","kid":kid}))
            .map_err(|_| AssertionError)?,
    );
    let payload=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":service_id,"sub":service_id,"aud":audience,"jti":TokenId::new(),"iat":now,"exp":now+60})).map_err(|_|AssertionError)?);
    let input = format!("{header}.{payload}");
    let signature: Signature = key.sign(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}
