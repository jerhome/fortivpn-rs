//! TLS vers la passerelle (`docs/protocol.md` §2.2, §2.3) : rustls, TLS 1.2 minimum,
//! racines système, épinglage SHA-256 optionnel du certificat feuille.
//!
//! # Politique de confiance
//!
//! - **Sans épinglage** : validation PKI standard (racines système via
//!   `rustls-native-certs`, plus les racines supplémentaires de [`TlsOptions`]) **et**
//!   vérification du nom d'hôte de la passerelle (SAN), comme openfortivpn.
//! - **Avec épinglage** (au moins une empreinte `trusted-cert`) : le certificat feuille
//!   **doit** avoir l'une des empreintes configurées, que la chaîne PKI soit valide ou
//!   non. C'est **plus strict** qu'openfortivpn, qui accepte tout certificat PKI valide
//!   sans consulter la liste (l'épinglage n'y est qu'une exception pour certificat non
//!   validable). Choix fait ici : si l'utilisateur épingle, c'est qu'il veut ce
//!   certificat-là et aucun autre ; une CA compromise ou une interception d'entreprise
//!   ne peut alors pas substituer un autre certificat. En contrepartie, un
//!   renouvellement du certificat de la passerelle impose de mettre à jour l'empreinte
//!   (l'erreur [`SslVpnError::TlsUntrusted`] affiche la nouvelle).
//!
//! Dans les deux cas la signature de la poignée de main est vérifiée avec la clé
//! publique du certificat présenté (preuve de possession de la clé privée).
//! L'empreinte est `SHA-256(DER du certificat feuille entier)` (pas la SPKI),
//! comparée en temps constant.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, OtherError, RootCertStore,
    SignatureScheme,
};

use super::error::SslVpnError;

/// Empreinte SHA-256 du certificat feuille encodé en DER.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertFingerprint([u8; 32]);

impl CertFingerprint {
    /// Calcule l'empreinte d'un certificat DER.
    pub fn of_der(der: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, der);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Self(out)
    }

    /// Octets bruts.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Forme canonique : 64 caractères hexadécimaux minuscules (format `trusted-cert`).
    pub fn to_hex(&self) -> String {
        use fmt::Write;
        self.0.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// Comparaison en temps constant.
    pub fn ct_eq(&self, other: &Self) -> bool {
        let diff = self
            .0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        std::hint::black_box(diff) == 0
    }
}

impl fmt::Display for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertFingerprint({})", self.to_hex())
    }
}

/// Empreinte mal formée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("empreinte SHA-256 invalide : 64 caractères hexadécimaux attendus (':' tolérés)")]
pub struct InvalidFingerprint;

impl FromStr for CertFingerprint {
    type Err = InvalidFingerprint;

    /// Accepte majuscules/minuscules et séparateurs `:` (normalisation §2.3).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex: Vec<u8> = s.trim().bytes().filter(|&b| b != b':').collect();
        if hex.len() != 64 {
            return Err(InvalidFingerprint);
        }
        let nibble = |c: u8| char::from(c).to_digit(16).ok_or(InvalidFingerprint);
        let mut out = [0u8; 32];
        for (o, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
            let v = nibble(pair[0])? << 4 | nibble(pair[1])?;
            *o = u8::try_from(v).map_err(|_| InvalidFingerprint)?;
        }
        Ok(Self(out))
    }
}

/// Options TLS.
#[derive(Debug, Clone)]
pub struct TlsOptions {
    /// Nom envoyé en SNI à la place de l'hôte (`--sni`). La vérification du nom porte
    /// toujours sur l'hôte de la passerelle.
    pub sni: Option<String>,
    /// Empreintes `trusted-cert` épinglées (voir la politique du module).
    pub pinned: Vec<CertFingerprint>,
    /// Charger les racines du magasin système (défaut : oui).
    pub use_system_roots: bool,
    /// Racines supplémentaires (équivalent de `--ca-file`).
    pub extra_roots: Vec<CertificateDer<'static>>,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            sni: None,
            pinned: Vec::new(),
            use_system_roots: true,
            extra_roots: Vec::new(),
        }
    }
}

/// Erreur portée par l'erreur rustls quand le certificat est refusé : permet de
/// remonter l'empreinte à l'utilisateur.
#[derive(Debug)]
pub(crate) struct UntrustedCertificate {
    pub(crate) fingerprint: CertFingerprint,
    pub(crate) reason: String,
}

impl fmt::Display for UntrustedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "certificat refusé ({}), sha256={}",
            self.reason, self.fingerprint
        )
    }
}

impl std::error::Error for UntrustedCertificate {}

fn untrusted(fingerprint: CertFingerprint, reason: String) -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
        UntrustedCertificate {
            fingerprint,
            reason,
        },
    ))))
}

/// Vérificateur : PKI + nom d'hôte, ou épinglage strict.
#[derive(Debug)]
struct GatewayVerifier {
    pki: Option<Arc<WebPkiServerVerifier>>,
    pins: Vec<CertFingerprint>,
    /// Nom vérifié (hôte de la passerelle), indépendant du SNI envoyé.
    verify_name: ServerName<'static>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for GatewayVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = CertFingerprint::of_der(end_entity);
        if !self.pins.is_empty() {
            // Pas de court-circuit : on parcourt toutes les empreintes.
            let matched = self.pins.iter().fold(false, |acc, p| acc | p.ct_eq(&fp));
            return if matched {
                tracing::debug!(sha256 = %fp, "certificat de la passerelle épinglé : accepté");
                Ok(ServerCertVerified::assertion())
            } else {
                Err(untrusted(fp, "empreinte non épinglée".into()))
            };
        }
        let Some(pki) = &self.pki else {
            return Err(untrusted(fp, "aucune racine de confiance".into()));
        };
        pki.verify_server_cert(
            end_entity,
            intermediates,
            &self.verify_name,
            ocsp_response,
            now,
        )
        .map_err(|e| untrusted(fp, e.to_string()))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn server_name(name: &str) -> Result<ServerName<'static>, SslVpnError> {
    ServerName::try_from(name.to_owned())
        .map_err(|_| SslVpnError::InvalidOptions(format!("nom TLS invalide : {name}")))
}

/// Configuration TLS prête à l'emploi pour une passerelle.
#[derive(Debug, Clone)]
pub(crate) struct TlsSetup {
    pub(crate) config: Arc<ClientConfig>,
    /// Nom passé à rustls (SNI).
    pub(crate) connect_name: ServerName<'static>,
}

/// Construit la configuration rustls : TLS 1.3 et 1.2 uniquement, suites par défaut
/// de rustls (AEAD), vérificateur [`GatewayVerifier`].
pub(crate) fn setup(host: &str, opts: &TlsOptions) -> Result<TlsSetup, SslVpnError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut roots = RootCertStore::empty();
    if opts.use_system_roots && opts.pinned.is_empty() {
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() {
            tracing::debug!(
                errors = loaded.errors.len(),
                "erreurs de lecture du magasin système"
            );
        }
        let (added, ignored) = roots.add_parsable_certificates(loaded.certs);
        tracing::debug!(added, ignored, "racines système chargées");
    }
    let (added, ignored) = roots.add_parsable_certificates(opts.extra_roots.iter().cloned());
    if ignored > 0 {
        tracing::warn!(ignored, added, "racines supplémentaires invalides ignorées");
    }
    if roots.is_empty() && opts.pinned.is_empty() {
        return Err(SslVpnError::InvalidOptions(
            "aucune racine de confiance ni empreinte épinglée".into(),
        ));
    }
    let pki = if roots.is_empty() {
        None
    } else {
        Some(
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|e| SslVpnError::InvalidOptions(format!("vérificateur TLS : {e}")))?,
        )
    };

    let verifier = GatewayVerifier {
        pki,
        pins: opts.pinned.clone(),
        verify_name: server_name(host)?,
        provider: provider.clone(),
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| SslVpnError::InvalidOptions(format!("versions TLS : {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let connect_name = server_name(opts.sni.as_deref().unwrap_or(host))?;
    Ok(TlsSetup {
        config: Arc::new(config),
        connect_name,
    })
}

/// Extrait l'empreinte d'un certificat refusé d'une erreur de poignée de main.
pub(crate) fn untrusted_from_io(err: &std::io::Error) -> Option<(CertFingerprint, String)> {
    let inner = err.get_ref()?.downcast_ref::<rustls::Error>()?;
    match inner {
        rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(e))) => e
            .downcast_ref::<UntrustedCertificate>()
            .map(|u| (u.fingerprint, u.reason.clone())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_parse_and_format() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let fp: CertFingerprint = hex.parse().unwrap();
        assert_eq!(fp.to_hex(), hex);
        let colons = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";
        assert_eq!(colons.parse::<CertFingerprint>().unwrap(), fp);
        assert!("00".parse::<CertFingerprint>().is_err());
        assert!(hex.replace('0', "g").parse::<CertFingerprint>().is_err());
        assert!(format!("{hex}00").parse::<CertFingerprint>().is_err());
    }

    #[test]
    fn fingerprint_of_der_is_sha256() {
        // SHA-256("abc")
        let fp = CertFingerprint::of_der(b"abc");
        assert_eq!(
            fp.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(fp.ct_eq(&fp));
        assert!(!fp.ct_eq(&CertFingerprint::of_der(b"abd")));
    }

    #[test]
    fn setup_requires_trust_anchor() {
        let opts = TlsOptions {
            use_system_roots: false,
            ..TlsOptions::default()
        };
        assert!(matches!(
            setup("vpn.example.com", &opts),
            Err(SslVpnError::InvalidOptions(_))
        ));
        let opts = TlsOptions {
            use_system_roots: false,
            pinned: vec![CertFingerprint::of_der(b"x")],
            ..TlsOptions::default()
        };
        assert!(setup("vpn.example.com", &opts).is_ok());
        assert!(setup("192.0.2.1", &opts).is_ok());
    }
}
