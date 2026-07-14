//! Concurrency-safe private RPC client with short-lived service-token caching.
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc, clippy::too_many_arguments)]

use chrono::Utc;
use p256::ecdsa::SigningKey;
use piquel_service_auth::{
    create_client_assertion,
    v1::{
        self, auth_service_client::AuthServiceClient,
        service_token_service_client::ServiceTokenServiceClient,
    },
};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::Mutex;
use tonic::{
    Request,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

#[derive(Debug, Error)]
#[error("private authentication RPC failed")]
pub struct ClientError;
struct CachedToken {
    value: String,
    renew_at: i64,
}
#[derive(Clone)]
pub struct ServiceAuthClient {
    auth: AuthServiceClient<Channel>,
    tokens: ServiceTokenServiceClient<Channel>,
    service_id: String,
    kid: String,
    audience: String,
    key: Arc<SigningKey>,
    cache: Arc<Mutex<Option<CachedToken>>>,
}
impl ServiceAuthClient {
    pub async fn connect(
        uri: String,
        domain: String,
        ca: Vec<u8>,
        identity_certificate: Vec<u8>,
        identity_key: Vec<u8>,
        service_id: String,
        kid: String,
        key: SigningKey,
    ) -> Result<Self, ClientError> {
        let tls = ClientTlsConfig::new()
            .domain_name(domain)
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(identity_certificate, identity_key));
        let channel = Endpoint::from_shared(uri)
            .map_err(|_| ClientError)?
            .tls_config(tls)
            .map_err(|_| ClientError)?
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .map_err(|_| ClientError)?;
        Ok(Self {
            auth: AuthServiceClient::new(channel.clone()),
            tokens: ServiceTokenServiceClient::new(channel),
            service_id,
            kid,
            audience: "piquel-service-token".into(),
            key: Arc::new(key),
            cache: Arc::new(Mutex::new(None)),
        })
    }
    async fn token(&mut self) -> Result<String, ClientError> {
        let mut cache = self.cache.lock().await;
        let now = Utc::now().timestamp();
        if let Some(token) = cache.as_ref().filter(|token| token.renew_at > now) {
            return Ok(token.value.clone());
        }
        let assertion = create_client_assertion(
            &self.service_id,
            &self.kid,
            &self.audience,
            self.key.as_ref(),
        )
        .map_err(|_| ClientError)?;
        let response = self
            .tokens
            .issue_service_token(v1::IssueServiceTokenRequest {
                client_assertion: assertion,
            })
            .await
            .map_err(|_| ClientError)?
            .into_inner();
        *cache = Some(CachedToken {
            value: response.access_token.clone(),
            renew_at: now + i64::from(response.expires_in) - 30,
        });
        Ok(response.access_token)
    }
    async fn authorized<T>(&mut self, message: T) -> Result<Request<T>, ClientError> {
        let token = self.token().await?;
        let mut request = Request::new(message);
        request.set_timeout(Duration::from_secs(3));
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from(format!("Bearer {token}")).map_err(|_| ClientError)?,
        );
        Ok(request)
    }
    pub async fn get_user(&mut self, user_id: String) -> Result<v1::GetUserResponse, ClientError> {
        let request = self.authorized(v1::GetUserRequest { user_id }).await?;
        self.auth
            .get_user(request)
            .await
            .map(tonic::Response::into_inner)
            .map_err(|_| ClientError)
    }
    pub async fn revoke_session(&mut self, session_id: String) -> Result<bool, ClientError> {
        let request = self
            .authorized(v1::RevokeSessionRequest { session_id })
            .await?;
        Ok(self
            .auth
            .revoke_session(request)
            .await
            .map_err(|_| ClientError)?
            .into_inner()
            .revoked)
    }
}
