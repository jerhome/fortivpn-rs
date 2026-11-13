//! Authentification du répondeur par certificat (RFC 7296 §2.15/§3.6/§3.8, RFC 7427).
//!
//! Sans I/O : extraction de la clé publique d'un certificat X.509 DER, épinglage SHA-256 du
//! certificat feuille (comparaison en temps constant) et vérification d'une AUTH par signature :
//! - méthode 1 (RSA Digital Signature) : RSASSA-PKCS1-v1_5 avec SHA-1 (RFC 7296 §3.8) ;
//! - méthode 14 (Digital Signature, RFC 7427) : `sha256WithRSAEncryption`, RSASSA-PSS
//!   (SHA-256, MGF1-SHA-256) ou `ecdsa-with-SHA256` sur P-256 (signature DER).
//!
//! La confiance repose sur l'épinglage : pas de validation de chaîne ni de dates (un certificat
//! épinglé est explicitement approuvé par l'utilisateur, à la manière d'une clé d'hôte SSH).

use p256::pkcs8::DecodePublicKey as _;
use pkcs1::{RsaPssParams, TrailerField};
use rsa::RsaPublicKey;
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use x509_cert::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::AlgorithmIdentifierRef;

use crate::error::{Error, Result};

/// Méthode AUTH 1 : signature RSA (PKCS#1 v1.5, SHA-1).
pub const AUTH_METHOD_RSA_SIG: u8 = 1;
/// Méthode AUTH 14 : signature numérique RFC 7427.
pub const AUTH_METHOD_DIGITAL_SIG: u8 = 14;
/// Encodage de certificat 4 : certificat X.509 (signature), DER.
pub const CERT_ENCODING_X509: u8 = 4;
/// Identifiant de hachage RFC 7427 §4 : SHA2-256 (seul annoncé et accepté).
pub const SIG_HASH_SHA2_256: u16 = 2;

/// Taille maximale acceptée d'un certificat reçu.
pub const MAX_CERT_LEN: usize = 16 * 1024;
/// Taille minimale d'un module RSA accepté (bits).
pub const MIN_RSA_BITS: usize = 2048;

/// Empreinte épinglée : SHA-256 du certificat feuille DER.
pub type CertPin = [u8; 32];

const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

const BAD_SIG: Error = Error::Crypto("signature AUTH invalide");

/// Empreinte SHA-256 d'un certificat DER.
pub fn cert_pin(der: &[u8]) -> CertPin {
    Sha256::digest(der).into()
}

/// `true` ssi l'empreinte de `der` figure dans `pins` (comparaisons en temps constant, sans
/// court-circuit).
pub fn pin_matches(der: &[u8], pins: &[CertPin]) -> bool {
    let fp = cert_pin(der);
    let mut ok = Choice::from(0);
    for p in pins {
        ok |= fp.ct_eq(p);
    }
    ok.into()
}

/// Clé publique extraite du certificat.
enum PeerKey {
    Rsa(RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
}

fn peer_key(cert_der: &[u8]) -> Result<PeerKey> {
    if cert_der.len() > MAX_CERT_LEN {
        return Err(Error::TooLarge("certificat"));
    }
    let cert = Certificate::from_der(cert_der).map_err(|_| Error::Malformed("certificat X.509"))?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let spki_der = spki
        .to_der()
        .map_err(|_| Error::Malformed("SubjectPublicKeyInfo"))?;
    if spki.algorithm.oid == OID_RSA_ENCRYPTION {
        let k = RsaPublicKey::from_public_key_der(&spki_der)
            .map_err(|_| Error::Malformed("clé publique RSA"))?;
        if k.n().bits() < MIN_RSA_BITS {
            return Err(Error::Unsupported("clé RSA < 2048 bits"));
        }
        Ok(PeerKey::Rsa(k))
    } else if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
        // Vérifie aussi que la courbe nommée est P-256.
        let k = p256::PublicKey::from_public_key_der(&spki_der)
            .map_err(|_| Error::Unsupported("clé EC autre que P-256"))?;
        Ok(PeerKey::P256(k.into()))
    } else {
        Err(Error::Unsupported(
            "algorithme de clé publique du certificat",
        ))
    }
}

/// Vérifie l'AUTH `data` (méthode 1 ou 14) sur `signed` avec la clé du certificat `cert_der`.
pub fn verify_auth(method: u8, data: &[u8], signed: &[u8], cert_der: &[u8]) -> Result<()> {
    let key = peer_key(cert_der)?;
    match method {
        AUTH_METHOD_RSA_SIG => {
            let PeerKey::Rsa(k) = key else {
                return Err(Error::Unsupported("méthode AUTH 1 avec une clé non RSA"));
            };
            verify_pkcs1::<sha1::Sha1>(k, signed, data)
        }
        AUTH_METHOD_DIGITAL_SIG => {
            let (alg, sig) = split_digital_sig(data)?;
            verify_digital(&key, &alg, signed, sig)
        }
        _ => Err(Error::Unsupported("méthode AUTH")),
    }
}

/// Découpe la donnée AUTH RFC 7427 §3 : longueur (1 octet), AlgorithmIdentifier DER, signature.
fn split_digital_sig(data: &[u8]) -> Result<(AlgorithmIdentifierRef<'_>, &[u8])> {
    let (&len, rest) = data.split_first().ok_or(Error::Truncated)?;
    let len = usize::from(len);
    if rest.len() <= len {
        return Err(Error::Truncated);
    }
    let (alg, sig) = rest.split_at(len);
    let alg = AlgorithmIdentifierRef::from_der(alg)
        .map_err(|_| Error::Malformed("AlgorithmIdentifier"))?;
    Ok((alg, sig))
}

/// Paramètres absents ou NULL.
fn params_null(alg: &AlgorithmIdentifierRef<'_>) -> bool {
    alg.parameters.is_none_or(x509_cert::der::AnyRef::is_null)
}

fn is_sha256(alg: &AlgorithmIdentifierRef<'_>) -> bool {
    alg.oid == OID_SHA256 && params_null(alg)
}

fn verify_digital(
    key: &PeerKey,
    alg: &AlgorithmIdentifierRef<'_>,
    signed: &[u8],
    sig: &[u8],
) -> Result<()> {
    match key {
        PeerKey::Rsa(k) if alg.oid == OID_SHA256_WITH_RSA => {
            if !params_null(alg) {
                return Err(Error::Malformed("paramètres sha256WithRSAEncryption"));
            }
            verify_pkcs1::<Sha256>(k.clone(), signed, sig)
        }
        PeerKey::Rsa(k) if alg.oid == OID_RSASSA_PSS => {
            let params = alg
                .parameters
                .ok_or(Error::Unsupported("RSASSA-PSS sans paramètres (SHA-1)"))?
                .to_der()
                .map_err(|_| Error::Malformed("paramètres RSASSA-PSS"))?;
            let p = RsaPssParams::from_der(&params)
                .map_err(|_| Error::Malformed("paramètres RSASSA-PSS"))?;
            let mgf_sha256 =
                p.mask_gen.oid == OID_MGF1 && p.mask_gen.parameters.as_ref().is_some_and(is_sha256);
            if !is_sha256(&p.hash) || !mgf_sha256 || p.trailer_field != TrailerField::BC {
                return Err(Error::Unsupported(
                    "RSASSA-PSS autre que SHA-256/MGF1-SHA-256",
                ));
            }
            let vk = rsa::pss::VerifyingKey::<Sha256>::new_with_salt_len(
                k.clone(),
                usize::from(p.salt_len),
            );
            let s = rsa::pss::Signature::try_from(sig).map_err(|_| BAD_SIG)?;
            Verifier::verify(&vk, signed, &s).map_err(|_| BAD_SIG)
        }
        PeerKey::P256(k) if alg.oid == OID_ECDSA_SHA256 => {
            if alg.parameters.is_some() {
                return Err(Error::Malformed("paramètres ecdsa-with-SHA256"));
            }
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| BAD_SIG)?;
            Verifier::verify(k, signed, &s).map_err(|_| BAD_SIG)
        }
        _ => Err(Error::Unsupported(
            "algorithme de signature AUTH incompatible avec la clé du certificat",
        )),
    }
}

fn verify_pkcs1<D>(k: RsaPublicKey, signed: &[u8], sig: &[u8]) -> Result<()>
where
    D: Digest + AssociatedOid,
{
    let vk = rsa::pkcs1v15::VerifyingKey::<D>::new(k);
    let s = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| BAD_SIG)?;
    Verifier::verify(&vk, signed, &s).map_err(|_| BAD_SIG)
}
