//! Certificat auto-signé généré à la volée et configuration TLS serveur.

use std::io;
use std::sync::Arc;

use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Certificat présenté par la fausse passerelle.
///
/// `sha256_hex` est l'empreinte au format attendu par l'épinglage (`trusted-cert`,
/// docs/protocol.md §2.3) : SHA-256 du certificat feuille **entier** en DER, 64 caractères
/// hexadécimaux minuscules, sans séparateur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayCert {
    der: Vec<u8>,
    sha256_hex: String,
}

impl GatewayCert {
    /// Certificat feuille encodé en DER.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Empreinte SHA-256 du DER, hexadécimal minuscule (64 caractères).
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }
}

/// SHA-256 d'un DER en hexadécimal minuscule.
pub(crate) fn sha256_hex(der: &[u8]) -> String {
    hex_lower(ring::digest::digest(&ring::digest::SHA256, der).as_ref())
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Fournisseur crypto explicite : n'utilise jamais le fournisseur « par défaut du
/// processus » (ambigu si un autre crate du workspace active aws-lc-rs).
pub(crate) fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Génère un certificat auto-signé pour `hostnames` (noms DNS ou IP littérales) et la
/// configuration serveur rustls associée.
pub(crate) fn generate(hostnames: &[String]) -> io::Result<(GatewayCert, Arc<ServerConfig>)> {
    let key = KeyPair::generate().map_err(io::Error::other)?;
    let mut params = CertificateParams::new(hostnames.to_vec()).map_err(io::Error::other)?;
    if let Some(cn) = hostnames.first() {
        params
            .distinguished_name
            .push(DnType::CommonName, cn.as_str());
    }
    params
        .distinguished_name
        .push(DnType::OrganizationName, "fortivpn-rs mock-gw");
    let cert = params.self_signed(&key).map_err(io::Error::other)?;
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let config = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .map_err(io::Error::other)?;

    let der = cert_der.as_ref().to_vec();
    let gateway_cert = GatewayCert {
        sha256_hex: sha256_hex(&der),
        der,
    };
    Ok((gateway_cert, Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn generated_cert_fingerprint_is_lowercase_hex() {
        let (cert, _) = generate(&["vpn.example.com".into(), "127.0.0.1".into()]).unwrap();
        assert_eq!(cert.sha256_hex().len(), 64);
        assert!(
            cert.sha256_hex()
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(cert.sha256_hex(), sha256_hex(cert.der()));
    }
}
