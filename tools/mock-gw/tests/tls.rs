//! Certificat auto-signé, empreinte SHA-256 (épinglage) et validation PKI.

mod common;

use std::sync::Arc;

use common::{SNI, connect, connect_with, pinned_config, provider, sha256_hex};
use mock_gw::MockGateway;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

#[tokio::test]
async fn fingerprint_is_sha256_of_der_lowercase_hex() {
    let gw = MockGateway::builder().start().await.unwrap();
    let fp = gw.cert().sha256_hex();
    assert_eq!(fp, sha256_hex(gw.cert().der()), "calcul indépendant (sha2)");
    assert_eq!(fp.len(), 64);
    assert!(fp.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    gw.shutdown().await;
}

#[tokio::test]
async fn presented_certificate_is_the_advertised_one() {
    let gw = MockGateway::builder().start().await.unwrap();
    let s = connect(&gw).await;
    let (_, conn) = s.get_ref();
    let certs = conn.peer_certificates().expect("certificat présenté");
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].as_ref(), gw.cert().der());
    gw.shutdown().await;
}

#[tokio::test]
async fn wrong_pin_is_refused() {
    let gw = MockGateway::builder().start().await.unwrap();
    let wrong = "0".repeat(64);
    let err = connect_with(gw.addr(), pinned_config(&wrong), SNI)
        .await
        .expect_err("empreinte fausse");
    assert!(err.to_string().contains("empreinte"), "{err}");
    gw.shutdown().await;
}

fn pki_config(der: &[u8]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(der.to_vec())).unwrap();
    ClientConfig::builder_with_provider(Arc::clone(&provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[tokio::test]
async fn pki_validation_accepts_san_names_and_rejects_others() {
    let gw = MockGateway::builder().start().await.unwrap();
    for name in ["vpn.example.com", "localhost", "127.0.0.1"] {
        connect_with(gw.addr(), pki_config(gw.cert().der()), name)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    connect_with(gw.addr(), pki_config(gw.cert().der()), "other.example.org")
        .await
        .expect_err("nom absent du SAN");
    gw.shutdown().await;
}

#[tokio::test]
async fn custom_hostnames() {
    let gw = MockGateway::builder()
        .hostnames(["gw.test.invalid"])
        .start()
        .await
        .unwrap();
    connect_with(gw.addr(), pki_config(gw.cert().der()), "gw.test.invalid")
        .await
        .unwrap();
    connect_with(gw.addr(), pki_config(gw.cert().der()), SNI)
        .await
        .expect_err("vpn.example.com absent du SAN");
    gw.shutdown().await;
}

#[tokio::test]
async fn each_gateway_has_its_own_certificate() {
    let a = MockGateway::builder().start().await.unwrap();
    let b = MockGateway::builder().start().await.unwrap();
    assert_ne!(a.cert().sha256_hex(), b.cert().sha256_hex());
    assert_ne!(a.addr(), b.addr());
}
