//! mTLS-protected service-token issuance and permissioned private RPC.

use crate::KeyProvider;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{TimeZone, Utc};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use piquel_repository::Database;
use piquel_service_auth::v1::{
    self, auth_service_server::AuthService, service_token_service_server::ServiceTokenService,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{str::FromStr, sync::Arc};
use tonic::{Request, Response, Status};

/// Private RPC implementation shared by the token and authority services.
#[derive(Clone)]
pub struct ServiceRpcApplication {
    database: Database,
    issuer: String,
    keys: Arc<dyn KeyProvider>,
}
impl ServiceRpcApplication {
    /// Constructs the private RPC service.
    #[must_use]
    pub fn new(database: Database, issuer: String, keys: Arc<dyn KeyProvider>) -> Self {
        Self {
            database,
            issuer,
            keys,
        }
    }
    /// Builds the permissioned authority server.
    #[must_use]
    pub fn auth_server(self) -> v1::auth_service_server::AuthServiceServer<Self> {
        v1::auth_service_server::AuthServiceServer::new(self)
    }
    /// Builds the replay-protected service-token server.
    #[must_use]
    pub fn token_server(self) -> v1::service_token_service_server::ServiceTokenServiceServer<Self> {
        v1::service_token_service_server::ServiceTokenServiceServer::new(self)
    }
}

#[derive(Deserialize)]
struct AssertionHeader {
    alg: String,
    typ: String,
    kid: String,
}
#[derive(Deserialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    iat: i64,
    exp: i64,
}
impl ServiceRpcApplication {
    async fn verify_assertion(
        &self,
        token: &str,
        peer_service_id: &str,
    ) -> Result<(String, Vec<String>), Status> {
        if token.len() > 8192 {
            return Err(Status::unauthenticated("invalid service credential"));
        }
        let mut parts = token.split('.');
        let hp = parts.next().ok_or_else(auth_error)?;
        let cp = parts.next().ok_or_else(auth_error)?;
        let sp = parts.next().ok_or_else(auth_error)?;
        if parts.next().is_some() {
            return Err(auth_error());
        }
        let header: AssertionHeader = decode_part(hp)?;
        let claims: AssertionClaims = decode_part(cp)?;
        let now = Utc::now().timestamp();
        if header.alg != "ES256"
            || header.typ != "client-assertion+jwt"
            || claims.iss != claims.sub
            || claims.sub != peer_service_id
            || claims.aud != "piquel-service-token"
            || claims.exp <= now
            || claims.exp > claims.iat + 60
            || claims.iat > now + 30
        {
            return Err(auth_error());
        }
        let identity = self
            .database
            .service_identities()
            .find_active_key(&claims.iss, &header.kid)
            .await
            .map_err(internal)?
            .ok_or_else(auth_error)?;
        let key = VerifyingKey::from_sec1_bytes(&identity.public_key).map_err(|_| auth_error())?;
        let signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(sp).map_err(|_| auth_error())?)
                .map_err(|_| auth_error())?;
        key.verify(format!("{hp}.{cp}").as_bytes(), &signature)
            .map_err(|_| auth_error())?;
        let jti = TokenId::from_str(&claims.jti).map_err(|_| auth_error())?;
        let expires = Utc
            .timestamp_opt(claims.exp, 0)
            .single()
            .ok_or_else(auth_error)?;
        self.database
            .service_identities()
            .record_assertion(jti, &identity.id, expires)
            .await
            .map_err(|_| auth_error())?;
        Ok((identity.id, identity.permissions))
    }
    #[allow(clippy::result_large_err)]
    fn authorize<T>(&self, request: &Request<T>, method: &str) -> Result<Value, Status> {
        let peer_service_id = service_identity_from_peer(request)?;
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(auth_error)?;
        let claims = self
            .keys
            .verify(token, "service+jwt", &self.issuer)
            .map_err(|()| auth_error())?;
        if claims.get("aud") != Some(&json!("piquel-internal-api"))
            || claims.get("sub").and_then(Value::as_str) != Some(peer_service_id.as_str())
            || !claims
                .get("permissions")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value == method))
        {
            return Err(Status::permission_denied("service is not permitted"));
        }
        Ok(claims)
    }
}

#[allow(clippy::result_large_err)]
fn service_identity_from_peer<T>(request: &Request<T>) -> Result<String, Status> {
    let certificates = request.peer_certs().ok_or_else(auth_error)?;
    let leaf = certificates.first().ok_or_else(auth_error)?;
    service_identity_from_certificate(leaf.as_ref()).ok_or_else(auth_error)
}

fn service_identity_from_certificate(der: &[u8]) -> Option<String> {
    const PREFIX: &str = "spiffe://piquel.fr/service/";
    let certificate = openssl::x509::X509::from_der(der).ok()?;
    let identities: Vec<_> = certificate
        .subject_alt_names()?
        .iter()
        .filter_map(|name| name.uri())
        .filter_map(|uri| uri.strip_prefix(PREFIX))
        .filter(|service_id| {
            !service_id.is_empty()
                && service_id.len() <= 64
                && service_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .map(str::to_owned)
        .collect();
    (identities.len() == 1).then(|| identities[0].clone())
}
#[allow(clippy::result_large_err)]
fn decode_part<T: for<'de> Deserialize<'de>>(part: &str) -> Result<T, Status> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).map_err(|_| auth_error())?)
        .map_err(|_| auth_error())
}
fn auth_error() -> Status {
    Status::unauthenticated("invalid service credential")
}
fn internal(_: piquel_repository::DatabaseError) -> Status {
    Status::internal("service operation failed")
}

#[tonic::async_trait]
impl ServiceTokenService for ServiceRpcApplication {
    async fn issue_service_token(
        &self,
        request: Request<v1::IssueServiceTokenRequest>,
    ) -> Result<Response<v1::IssueServiceTokenResponse>, Status> {
        let peer_service_id = service_identity_from_peer(&request)?;
        let (service_id, permissions) = self
            .verify_assertion(&request.into_inner().client_assertion, &peer_service_id)
            .await?;
        let now = Utc::now().timestamp();
        let token=self.keys.sign("service+jwt",&json!({"iss":self.issuer,"sub":service_id,"aud":"piquel-internal-api","jti":TokenId::new(),"permissions":permissions,"iat":now,"exp":now+300})).map_err(|()|Status::internal("token issuance failed"))?;
        Ok(Response::new(v1::IssueServiceTokenResponse {
            access_token: token,
            expires_in: 300,
            token_type: "Bearer".into(),
        }))
    }
}

#[tonic::async_trait]
impl AuthService for ServiceRpcApplication {
    async fn get_user(
        &self,
        request: Request<v1::GetUserRequest>,
    ) -> Result<Response<v1::GetUserResponse>, Status> {
        self.authorize(&request, "GetUser")?;
        let id = UserId::from_str(&request.get_ref().user_id)
            .map_err(|_| Status::invalid_argument("invalid user id"))?;
        let user = self
            .database
            .users()
            .find_by_id(id)
            .await
            .map_err(internal)?
            .ok_or_else(|| Status::not_found("user not found"))?;
        Ok(Response::new(user_response(user)))
    }
    async fn batch_get_users(
        &self,
        request: Request<v1::BatchGetUsersRequest>,
    ) -> Result<Response<v1::BatchGetUsersResponse>, Status> {
        self.authorize(&request, "BatchGetUsers")?;
        if request.get_ref().user_ids.len() > 100 {
            return Err(Status::invalid_argument("batch too large"));
        }
        let mut users = Vec::new();
        for id in &request.get_ref().user_ids {
            let id =
                UserId::from_str(id).map_err(|_| Status::invalid_argument("invalid user id"))?;
            if let Some(user) = self
                .database
                .users()
                .find_by_id(id)
                .await
                .map_err(internal)?
            {
                users.push(user_response(user));
            }
        }
        Ok(Response::new(v1::BatchGetUsersResponse { users }))
    }
    async fn get_session_status(
        &self,
        request: Request<v1::GetSessionStatusRequest>,
    ) -> Result<Response<v1::GetSessionStatusResponse>, Status> {
        self.authorize(&request, "GetSessionStatus")?;
        let id = SessionId::from_str(&request.get_ref().session_id)
            .map_err(|_| Status::invalid_argument("invalid session id"))?;
        let session = self
            .database
            .sessions()
            .find_active_by_id(id)
            .await
            .map_err(internal)?;
        let (active, user_id) = session.map_or((false, String::new()), |session| {
            (true, session.user_id.to_string())
        });
        Ok(Response::new(v1::GetSessionStatusResponse {
            active,
            user_id,
        }))
    }
    async fn revoke_session(
        &self,
        request: Request<v1::RevokeSessionRequest>,
    ) -> Result<Response<v1::RevokeSessionResponse>, Status> {
        self.authorize(&request, "RevokeSession")?;
        let id = SessionId::from_str(&request.get_ref().session_id)
            .map_err(|_| Status::invalid_argument("invalid session id"))?;
        let revoked = self
            .database
            .sessions()
            .revoke(id)
            .await
            .map_err(internal)?;
        Ok(Response::new(v1::RevokeSessionResponse { revoked }))
    }
    async fn revoke_all_user_sessions(
        &self,
        request: Request<v1::RevokeAllUserSessionsRequest>,
    ) -> Result<Response<v1::RevokeAllUserSessionsResponse>, Status> {
        self.authorize(&request, "RevokeAllUserSessions")?;
        let id = UserId::from_str(&request.get_ref().user_id)
            .map_err(|_| Status::invalid_argument("invalid user id"))?;
        let count = self
            .database
            .sessions()
            .revoke_all_for_user(id)
            .await
            .map_err(internal)?;
        Ok(Response::new(v1::RevokeAllUserSessionsResponse {
            revoked_count: u32::try_from(count).unwrap_or(u32::MAX),
        }))
    }
    async fn get_service_configuration(
        &self,
        request: Request<v1::GetServiceConfigurationRequest>,
    ) -> Result<Response<v1::GetServiceConfigurationResponse>, Status> {
        self.authorize(&request, "GetServiceConfiguration")?;
        Ok(Response::new(v1::GetServiceConfigurationResponse {
            issuer: self.issuer.clone(),
            jwks_uri: format!("{}/.well-known/jwks.json", self.issuer),
        }))
    }
}
fn user_response(user: piquel_repository::StoredUser) -> v1::GetUserResponse {
    v1::GetUserResponse {
        user_id: user.id.to_string(),
        display_name: user.display_name,
        account_status: match user.status {
            piquel_auth_protocol::AccountStatus::Active => "active",
            piquel_auth_protocol::AccountStatus::Disabled => "disabled",
        }
        .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
    };

    fn certificate(uri: &str) -> Vec<u8> {
        let key = PKey::from_rsa(Rsa::generate(2048).expect("RSA key")).expect("private key");
        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", "service test")
            .expect("common name");
        let name = name.build();
        let mut builder = X509::builder().expect("certificate");
        builder.set_version(2).expect("version");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&key).expect("public key");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("not before"))
            .expect("not before");
        builder
            .set_not_after(&Asn1Time::days_from_now(1).expect("not after"))
            .expect("not after");
        let extension = SubjectAlternativeName::new()
            .uri(uri)
            .build(&builder.x509v3_context(None, None))
            .expect("SAN");
        builder.append_extension(extension).expect("extension");
        builder
            .sign(&key, MessageDigest::sha256())
            .expect("signature");
        builder.build().to_der().expect("DER")
    }

    #[test]
    fn service_identity_is_an_exact_spiffe_uri_san() {
        assert_eq!(
            service_identity_from_certificate(&certificate(
                "spiffe://piquel.fr/service/catalog-api"
            )),
            Some("catalog-api".into())
        );
        assert!(
            service_identity_from_certificate(&certificate(
                "spiffe://attacker.example/service/catalog-api"
            ))
            .is_none()
        );
    }
}
