//! Authentification de la passerelle par certificat épinglé (revue 6.5, M1).

use crate::cert::{self, CertPin, cert_pin, pin_matches, verify_auth};
use crate::crypto::{Prf, signed_octets};
use crate::error::Error;
use crate::ike::*;
use crate::ike_tests::run;
use crate::testutil::*;
use crate::wire::*;

const ALL_SIG: [GwAuth; 4] = [
    GwAuth::RsaSha1,
    GwAuth::RsaPkcs1Sha256,
    GwAuth::RsaPss,
    GwAuth::EcdsaP256,
];

fn ini(c: IkeConfig) -> IkeInitiator {
    IkeInitiator::new(c, det_rng()).unwrap()
}

/// Échec attendu dès le premier IKE_AUTH, sans envoi de l'identité EAP.
fn assert_fails_before_identity(c: IkeConfig, resp: &mut Responder, want: &FailReason) {
    let r = run(&mut ini(c), resp);
    assert_eq!(r.sent_auth_mids, vec![1], "aucune requête après MID 1");
    assert_eq!(resp.seen_user, None, "identité EAP envoyée");
    match r.events.as_slice() {
        [Event::Failed(f)] => assert_eq!(f, want),
        e => panic!("échec attendu : {e:?}"),
    }
}

#[test]
fn cert_pinned_established_for_each_signature_scheme() {
    for gw in ALL_SIG {
        let mut resp = Responder::with_auth(Quirk::None, gw);
        let r = run(&mut ini(cfg_cert(gw)), &mut resp);
        assert!(
            matches!(r.events.as_slice(), [Event::Established { .. }]),
            "{gw:?} : {:?}",
            r.events
        );
        assert_eq!(r.sent_auth_mids, vec![1, 2, 3, 4, 5]);
        assert_eq!(resp.seen_user.as_deref(), Some(USER));
        assert!(resp.certreq_seen, "{gw:?} : CERTREQ attendu");
        assert_eq!(resp.sig_hashes_seen.as_deref(), Some(&[0u8, 2][..]));
    }
}

#[test]
fn cert_pinned_with_expected_idr() {
    let mut c = cfg_cert(GwAuth::EcdsaP256);
    c.expected_idr = Some((2, IDR.to_vec()));
    let mut resp = Responder::with_auth(Quirk::None, GwAuth::EcdsaP256);
    let r = run(&mut ini(c), &mut resp);
    assert!(matches!(r.events.as_slice(), [Event::Established { .. }]));

    let mut c = cfg_cert(GwAuth::EcdsaP256);
    c.expected_idr = Some((2, b"autre.example.test".to_vec()));
    let mut resp = Responder::with_auth(Quirk::None, GwAuth::EcdsaP256);
    assert_fails_before_identity(c, &mut resp, &FailReason::IdrMismatch);
}

#[test]
fn psk_mode_sends_neither_certreq_nor_hash_notify() {
    let mut resp = Responder::new(Quirk::None);
    let r = run(&mut ini(cfg()), &mut resp);
    assert!(matches!(r.events.as_slice(), [Event::Established { .. }]));
    assert!(!resp.certreq_seen);
    assert_eq!(resp.sig_hashes_seen, None);
}

#[test]
fn wrong_pin_fails_before_eap_identity() {
    for gw in ALL_SIG {
        let mut c = cfg();
        c.responder_auth = ResponderAuth::CertPinned {
            pins: vec![[0xAB; 32], cert_pin(b"un autre certificat")],
        };
        let mut resp = Responder::with_auth(Quirk::None, gw);
        assert_fails_before_identity(c, &mut resp, &FailReason::GatewayCertNotPinned);
    }
    // Certificat RSA épinglé mais la passerelle présente le certificat P-256.
    let mut resp = Responder::with_auth(Quirk::None, GwAuth::EcdsaP256);
    assert_fails_before_identity(
        cfg_cert(GwAuth::RsaPss),
        &mut resp,
        &FailReason::GatewayCertNotPinned,
    );
}

#[test]
fn tampered_signature_fails_before_eap_identity() {
    for gw in ALL_SIG {
        let mut resp = Responder::with_auth(Quirk::TamperSignature, gw);
        let r = run(&mut ini(cfg_cert(gw)), &mut resp);
        assert_eq!(r.sent_auth_mids, vec![1]);
        assert_eq!(resp.seen_user, None);
        assert!(
            matches!(
                r.events.as_slice(),
                [Event::Failed(FailReason::GatewaySignatureInvalid(_))]
            ),
            "{gw:?} : {:?}",
            r.events
        );
    }
}

#[test]
fn missing_cert_payload_fails() {
    let mut resp = Responder::with_auth(Quirk::OmitCert, GwAuth::RsaPkcs1Sha256);
    assert_fails_before_identity(
        cfg_cert(GwAuth::RsaPkcs1Sha256),
        &mut resp,
        &FailReason::GatewayCertNotPinned,
    );
}

#[test]
fn psk_auth_refused_when_cert_pinned_required() {
    // La passerelle (ou un détenteur de la PSK de groupe) répond avec une AUTH PSK valide.
    let mut resp = Responder::new(Quirk::None);
    assert_fails_before_identity(
        cfg_cert(GwAuth::RsaPss),
        &mut resp,
        &FailReason::GatewayAuthMethodRefused(2),
    );
}

#[test]
fn signature_auth_refused_in_psk_mode() {
    let mut resp = Responder::with_auth(Quirk::None, GwAuth::EcdsaP256);
    assert_fails_before_identity(cfg(), &mut resp, &FailReason::GatewayAuthMethodRefused(14));
}

#[test]
fn psk_and_cert_pinned_accepts_both() {
    let pins = vec![cert_pin(TEST_RSA_CERT)];
    for gw in [GwAuth::Psk, GwAuth::RsaPkcs1Sha256] {
        let mut c = cfg();
        c.responder_auth = ResponderAuth::PskAndCertPinned { pins: pins.clone() };
        let mut resp = Responder::with_auth(Quirk::None, gw);
        let r = run(&mut ini(c), &mut resp);
        assert!(
            matches!(r.events.as_slice(), [Event::Established { .. }]),
            "{gw:?} : {:?}",
            r.events
        );
    }
    // Le certificat présenté doit malgré tout être épinglé.
    let mut c = cfg();
    c.responder_auth = ResponderAuth::PskAndCertPinned { pins };
    let mut resp = Responder::with_auth(Quirk::None, GwAuth::EcdsaP256);
    assert_fails_before_identity(c, &mut resp, &FailReason::GatewayCertNotPinned);
}

#[test]
fn config_validation() {
    let mut c = cfg();
    c.responder_auth = ResponderAuth::CertPinned { pins: vec![] };
    assert!(IkeInitiator::new(c, det_rng()).is_err(), "pins vides");
    let mut c = cfg();
    c.responder_auth = ResponderAuth::PskAndCertPinned { pins: vec![] };
    assert!(IkeInitiator::new(c, det_rng()).is_err(), "pins vides");
    // PSK inutile en CertPinned : vide acceptée.
    let mut c = cfg_cert(GwAuth::RsaPss);
    c.psk = secrecy::SecretString::from("");
    assert!(IkeInitiator::new(c, det_rng()).is_ok());
    // PSK courte refusée en mode transition.
    let mut c = cfg();
    c.psk = secrecy::SecretString::from("court");
    c.responder_auth = ResponderAuth::PskAndCertPinned {
        pins: vec![[1; 32]],
    };
    assert!(IkeInitiator::new(c, det_rng()).is_err());
}

// ---------- cert.rs ----------

#[test]
fn pin_matching() {
    let p: CertPin = cert_pin(TEST_RSA_CERT);
    assert!(pin_matches(TEST_RSA_CERT, &[[0; 32], p]));
    assert!(!pin_matches(TEST_RSA_CERT, &[]));
    assert!(!pin_matches(TEST_P256_CERT, &[p]));
    let mut alt = TEST_RSA_CERT.to_vec();
    alt[100] ^= 1;
    assert!(!pin_matches(&alt, &[p]));
}

#[test]
fn verify_auth_accepts_valid_and_rejects_altered_message() {
    let signed = signed_octets(
        Prf::HmacSha256,
        b"msg2",
        &[7; 32],
        &[9; 32],
        b"\x02\0\0\0gw",
    );
    for gw in ALL_SIG {
        let (m, d) = gw.sign(&signed);
        assert_eq!(verify_auth(m, &d, &signed, gw.cert()), Ok(()), "{gw:?}");
        let mut other = signed.clone();
        other[0] ^= 1;
        assert!(verify_auth(m, &d, &other, gw.cert()).is_err(), "{gw:?}");
    }
}

#[test]
fn verify_auth_rejects_key_and_algorithm_mismatch() {
    let signed = b"octets signes".to_vec();
    // Signature RSA présentée avec le certificat P-256 (et inversement).
    let (m, d) = GwAuth::RsaPss.sign(&signed);
    assert!(verify_auth(m, &d, &signed, TEST_P256_CERT).is_err());
    let (m, d) = GwAuth::EcdsaP256.sign(&signed);
    assert!(verify_auth(m, &d, &signed, TEST_RSA_CERT).is_err());
    // Méthode 1 avec une clé EC.
    let (_, d) = GwAuth::RsaSha1.sign(&signed);
    assert!(verify_auth(cert::AUTH_METHOD_RSA_SIG, &d, &signed, TEST_P256_CERT).is_err());
    // Méthode PSK ou inconnue.
    assert!(verify_auth(2, &d, &signed, TEST_RSA_CERT).is_err());
    // Méthode 14 : PKCS#1 SHA-256 déclarée, signature PSS fournie.
    let (_, pss) = GwAuth::RsaPss.sign(&signed);
    let sig = &pss[1 + ALG_RSA_PSS_SHA256.len()..];
    let mut forged = vec![u8::try_from(ALG_SHA256_RSA.len()).unwrap()];
    forged.extend_from_slice(ALG_SHA256_RSA);
    forged.extend_from_slice(sig);
    assert!(verify_auth(14, &forged, &signed, TEST_RSA_CERT).is_err());
}

#[test]
fn verify_auth_rejects_malformed_inputs() {
    let signed = b"x".to_vec();
    let (m, d) = GwAuth::EcdsaP256.sign(&signed);
    // Certificat tronqué / vide.
    assert!(verify_auth(m, &d, &signed, &TEST_P256_CERT[..50]).is_err());
    assert!(verify_auth(m, &d, &signed, &[]).is_err());
    // Données AUTH tronquées ou longueur d'AlgorithmIdentifier incohérente.
    for bad in [&[][..], &[12][..], &d[..13], &[0xff, 0x30, 0x00][..]] {
        assert!(verify_auth(14, bad, &signed, TEST_P256_CERT).is_err());
    }
    // RSASSA-PSS sans paramètres (= SHA-1 par défaut) refusé (RFC 7427 A.4.1).
    let (_, pss) = GwAuth::RsaPss.sign(&signed);
    let sig = &pss[1 + ALG_RSA_PSS_SHA256.len()..];
    let empty_pss: &[u8] = &[
        0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    ];
    let mut d2 = vec![u8::try_from(empty_pss.len()).unwrap()];
    d2.extend_from_slice(empty_pss);
    d2.extend_from_slice(sig);
    assert!(matches!(
        verify_auth(14, &d2, &signed, TEST_RSA_CERT),
        Err(Error::Unsupported(_))
    ));
}

/// Encodages d'AlgorithmIdentifier de RFC 7427 annexe A (A.1.2, A.3.1, A.4.3) : vérifiés
/// contre la sortie DER d'OpenSSL pour PSS ; interprétés par le décodeur de `cert`.
#[test]
fn rfc7427_algorithm_identifiers() {
    use x509_cert::der::Decode;
    use x509_cert::spki::AlgorithmIdentifierRef;
    let a = AlgorithmIdentifierRef::from_der(ALG_SHA256_RSA).unwrap();
    assert_eq!(a.oid.to_string(), "1.2.840.113549.1.1.11");
    let a = AlgorithmIdentifierRef::from_der(ALG_ECDSA_SHA256).unwrap();
    assert_eq!(a.oid.to_string(), "1.2.840.10045.4.3.2");
    assert!(a.parameters.is_none());
    let a = AlgorithmIdentifierRef::from_der(ALG_RSA_PSS_SHA256).unwrap();
    assert_eq!(a.oid.to_string(), "1.2.840.113549.1.1.10");
    assert_eq!(ALG_RSA_PSS_SHA256.len(), 67);
}

#[test]
fn cert_and_certreq_payload_roundtrip() {
    let ps = vec![
        Payload::CertReq {
            encoding: 4,
            data: vec![],
        },
        Payload::Cert {
            encoding: 4,
            data: TEST_P256_CERT.to_vec(),
        },
    ];
    let (first, bytes) = encode_chain(&ps).unwrap();
    assert_eq!(first, ptype::CERTREQ);
    assert_eq!(decode_chain(first, &bytes).unwrap(), ps);
    // CERT sans octet d'encodage : tronqué.
    assert!(decode_chain(ptype::CERT, &[0, 0, 0, 4]).is_err());
}
