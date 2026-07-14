//! Strict `OIDC` request and opaque refresh-token primitives.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use piquel_auth_protocol::{Audience, ClientId, TokenId};
use sha2::{Digest, Sha256};
use std::str::FromStr;

type HmacSha256 = Hmac<Sha256>;

pub(super) fn validate_exact_redirect(registered: &[String], requested: &str) -> Result<(), ()> {
    if registered.iter().any(|uri| uri == requested) {
        Ok(())
    } else {
        Err(())
    }
}
pub(super) fn validate_pkce_s256(verifier: &str, challenge: &str) -> Result<(), ()> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(());
    }
    let digest = Sha256::digest(verifier.as_bytes());
    if URL_SAFE_NO_PAD.encode(digest) == challenge {
        Ok(())
    } else {
        Err(())
    }
}
pub(super) struct ParsedRefreshToken {
    pub token_id: TokenId,
    pub secret: Vec<u8>,
}
pub(super) fn parse_refresh_token(value: &str) -> Result<ParsedRefreshToken, ()> {
    let (prefix, remainder) = value.split_once('_').ok_or(())?;
    if prefix != "prt" {
        return Err(());
    }
    let (version, remainder) = remainder.split_once('_').ok_or(())?;
    if version != "v1" {
        return Err(());
    }
    let (token_id, secret) = remainder.split_once('.').ok_or(())?;
    let secret = URL_SAFE_NO_PAD.decode(secret).map_err(|_| ())?;
    if secret.len() < 32 {
        return Err(());
    }
    Ok(ParsedRefreshToken {
        token_id: TokenId::from_str(token_id).map_err(|_| ())?,
        secret,
    })
}
pub(super) fn refresh_digest(key: &[u8], secret: &[u8]) -> Result<[u8; 32], ()> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ())?;
    mac.update(secret);
    Ok(mac.finalize().into_bytes().into())
}
pub(super) fn exact_audience(
    client_audiences: &[Audience],
    requested: &Audience,
) -> Result<(), ()> {
    if client_audiences.contains(requested) {
        Ok(())
    } else {
        Err(())
    }
}
#[allow(dead_code)]
pub(super) fn client_id(value: &str) -> Result<ClientId, ()> {
    ClientId::from_str(value).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prohibits_redirect_prefixes_and_bad_pkce() {
        assert!(
            validate_exact_redirect(
                &["https://a.example/cb".into()],
                "https://a.example/cb.evil"
            )
            .is_err()
        );
        assert!(validate_pkce_s256("short", "x").is_err());
    }
    #[test]
    fn refresh_parser_is_strict() {
        assert!(parse_refresh_token("prt_v1_invalid.not-base64").is_err());
    }
}
