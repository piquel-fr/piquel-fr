#![allow(missing_docs)]

use auth_service::{Es256KeyProvider, ServiceRpcApplication};
use chrono::{Duration as ChronoDuration, Utc};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use p256::ecdsa::SigningKey;
use piquel_auth_client::ServiceAuthClient;
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use piquel_repository::{BootstrapServiceIdentity, Database, DatabaseConfig, InsertUser};
use piquel_service_auth::{
    create_client_assertion,
    v1::{IssueServiceTokenRequest, service_token_service_client::ServiceTokenServiceClient},
};
use rand::rngs::OsRng;
use std::{env, sync::Arc, time::Duration};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Code,
    transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig},
};

async fn database() -> Database {
    let url = env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
    Database::connect(
        DatabaseConfig::new_development(&url, 8, Duration::from_secs(5))
            .expect("test database configuration"),
    )
    .await
    .expect("connect test database")
}

fn name(common_name: &str) -> openssl::x509::X509Name {
    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_text("CN", common_name)
        .expect("common name");
    name.build()
}

fn certificate(
    serial: u32,
    common_name: &str,
    key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
    dns_name: Option<&str>,
    uri: Option<&str>,
) -> X509 {
    let mut builder = X509::builder().expect("certificate builder");
    builder.set_version(2).expect("certificate version");
    let serial =
        Asn1Integer::from_bn(&BigNum::from_u32(serial).expect("serial bignum")).expect("serial");
    builder
        .set_serial_number(&serial)
        .expect("certificate serial");
    let subject = name(common_name);
    builder.set_subject_name(&subject).expect("subject");
    builder
        .set_issuer_name(issuer.map_or(&subject, |(certificate, _)| certificate.subject_name()))
        .expect("issuer");
    builder.set_pubkey(key).expect("public key");
    builder
        .set_not_before(Asn1Time::days_from_now(0).expect("not before").as_ref())
        .expect("not before");
    builder
        .set_not_after(Asn1Time::days_from_now(1).expect("not after").as_ref())
        .expect("not after");
    if issuer.is_none() {
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().expect("CA"))
            .expect("CA extension");
        builder
            .append_extension(
                KeyUsage::new()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .expect("CA usage"),
            )
            .expect("CA usage extension");
    } else {
        builder
            .append_extension(BasicConstraints::new().critical().build().expect("leaf"))
            .expect("leaf extension");
        builder
            .append_extension(
                KeyUsage::new()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .expect("leaf usage"),
            )
            .expect("leaf usage extension");
        let mut usage = ExtendedKeyUsage::new();
        if dns_name.is_some() {
            usage.server_auth();
        }
        if uri.is_some() {
            usage.client_auth();
        }
        builder
            .append_extension(usage.build().expect("extended usage"))
            .expect("extended usage extension");
        let alternative_name = {
            let mut names = SubjectAlternativeName::new();
            if let Some(dns_name) = dns_name {
                names.dns(dns_name);
            }
            if let Some(uri) = uri {
                names.uri(uri);
            }
            names
                .build(&builder.x509v3_context(issuer.map(|value| value.0.as_ref()), None))
                .expect("alternative name")
        };
        builder
            .append_extension(alternative_name)
            .expect("alternative name extension");
    }
    builder
        .sign(issuer.map_or(key, |(_, key)| key), MessageDigest::sha256())
        .expect("certificate signature");
    builder.build()
}

struct TlsMaterial {
    ca: Vec<u8>,
    server_certificate: Vec<u8>,
    server_key: Vec<u8>,
    client_certificate: Vec<u8>,
    client_key: Vec<u8>,
    wrong_certificate: Vec<u8>,
    wrong_key: Vec<u8>,
}

fn tls_material(service_id: &str) -> TlsMaterial {
    let ca_key = PKey::from_rsa(Rsa::generate(2048).expect("CA key")).expect("CA PKey");
    let ca = certificate(1, "Piquel test CA", &ca_key, None, None, None);
    let server_key = PKey::from_rsa(Rsa::generate(2048).expect("server key")).expect("server PKey");
    let server = certificate(
        2,
        "localhost",
        &server_key,
        Some((&ca, &ca_key)),
        Some("localhost"),
        None,
    );
    let client_key = PKey::from_rsa(Rsa::generate(2048).expect("client key")).expect("client PKey");
    let client = certificate(
        3,
        service_id,
        &client_key,
        Some((&ca, &ca_key)),
        None,
        Some(&format!("spiffe://piquel.fr/service/{service_id}")),
    );
    let wrong_client_key =
        PKey::from_rsa(Rsa::generate(2048).expect("wrong client key")).expect("wrong client PKey");
    let wrong_client = certificate(
        4,
        "different-service",
        &wrong_client_key,
        Some((&ca, &ca_key)),
        None,
        Some("spiffe://piquel.fr/service/different-service"),
    );
    TlsMaterial {
        ca: ca.to_pem().expect("CA PEM"),
        server_certificate: server.to_pem().expect("server PEM"),
        server_key: server_key
            .private_key_to_pem_pkcs8()
            .expect("server key PEM"),
        client_certificate: client.to_pem().expect("client PEM"),
        client_key: client_key
            .private_key_to_pem_pkcs8()
            .expect("client key PEM"),
        wrong_certificate: wrong_client.to_pem().expect("wrong client PEM"),
        wrong_key: wrong_client_key
            .private_key_to_pem_pkcs8()
            .expect("wrong client key PEM"),
    }
}

async fn channel(
    uri: String,
    ca: Vec<u8>,
    certificate: Vec<u8>,
    key: Vec<u8>,
) -> tonic::transport::Channel {
    Endpoint::from_shared(uri)
        .expect("endpoint")
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(Certificate::from_pem(ca))
                .identity(Identity::from_pem(certificate, key)),
        )
        .expect("client TLS")
        .connect()
        .await
        .expect("mTLS connection")
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL after migrations"]
#[allow(clippy::too_many_lines)]
async fn private_rpc_enforces_mtls_replay_and_permissions() {
    let database = database().await;
    let service_id = format!("rpc-test-{}", TokenId::new());
    let kid = "assertion-key";
    let assertion_key = SigningKey::random(&mut OsRng);
    database
        .service_identities()
        .bootstrap(&BootstrapServiceIdentity {
            id: service_id.clone(),
            display_name: "RPC integration test".into(),
            enabled: true,
            kid: kid.into(),
            public_key: assertion_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            not_before: Utc::now() - ChronoDuration::minutes(1),
            expires_at: Utc::now() + ChronoDuration::hours(1),
            permissions: vec!["GetUser".into()],
        })
        .await
        .expect("service identity");
    let user_id = UserId::new();
    database
        .users()
        .insert(&InsertUser {
            id: user_id,
            username: format!("rpc_{}", &user_id.to_string()[..8]),
            display_name: "RPC User".into(),
        })
        .await
        .expect("RPC user");

    let TlsMaterial {
        ca,
        server_certificate,
        server_key,
        client_certificate,
        client_key,
        wrong_certificate,
        wrong_key,
    } = tls_material(&service_id);
    let authority_keys = Arc::new(Es256KeyProvider::generate_for_development("rpc-authority"));
    let rpc = ServiceRpcApplication::new(database, "https://auth.piquel.fr".into(), authority_keys);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("RPC listener");
    let address = listener.local_addr().expect("RPC address");
    let incoming = TcpListenerStream::new(listener);
    let tls = ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            server_certificate.clone(),
            server_key,
        ))
        .client_ca_root(Certificate::from_pem(ca.clone()));
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("server TLS")
            .add_service(rpc.clone().token_server())
            .add_service(rpc.auth_server())
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .expect("RPC server");
    });
    let uri = format!("https://{address}");

    let raw_channel = channel(
        uri.clone(),
        ca.clone(),
        client_certificate.clone(),
        client_key.clone(),
    )
    .await;
    let mut tokens = ServiceTokenServiceClient::new(raw_channel);
    let assertion =
        create_client_assertion(&service_id, kid, "piquel-service-token", &assertion_key)
            .expect("assertion");
    tokens
        .issue_service_token(IssueServiceTokenRequest {
            client_assertion: assertion.clone(),
        })
        .await
        .expect("first assertion use");
    let replay = tokens
        .issue_service_token(IssueServiceTokenRequest {
            client_assertion: assertion,
        })
        .await
        .expect_err("assertion replay must fail");
    assert_eq!(replay.code(), Code::Unauthenticated);

    let mut client = ServiceAuthClient::connect(
        uri.clone(),
        "localhost".into(),
        ca.clone(),
        client_certificate,
        client_key,
        service_id.clone(),
        kid.into(),
        assertion_key.clone(),
    )
    .await
    .expect("service auth client");
    let user = client
        .get_user(user_id.to_string())
        .await
        .expect("permitted GetUser");
    assert_eq!(user.user_id, user_id.to_string());
    assert_eq!(user.display_name, "RPC User");
    assert!(
        client
            .revoke_session(SessionId::new().to_string())
            .await
            .is_err()
    );

    let mut wrong_identity = ServiceAuthClient::connect(
        uri.clone(),
        "localhost".into(),
        ca.clone(),
        wrong_certificate,
        wrong_key,
        service_id.clone(),
        kid.into(),
        assertion_key.clone(),
    )
    .await
    .expect("trusted but mismatched client certificate");
    assert!(wrong_identity.get_user(user_id.to_string()).await.is_err());
    let without_identity = Endpoint::from_shared(uri)
        .expect("endpoint")
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(Certificate::from_pem(ca)),
        )
        .expect("TLS config")
        .connect()
        .await
        .expect("channel creation is lazy");
    let assertion =
        create_client_assertion(&service_id, kid, "piquel-service-token", &assertion_key)
            .expect("assertion without TLS identity");
    assert!(
        ServiceTokenServiceClient::new(without_identity)
            .issue_service_token(IssueServiceTokenRequest {
                client_assertion: assertion,
            })
            .await
            .is_err()
    );

    let _ = shutdown.send(());
    server.await.expect("server task");
}
