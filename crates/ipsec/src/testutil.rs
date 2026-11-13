//! Répondeur IKEv2 simulé (PSK + EAP-MSCHAPv2) partagé par les tests unitaires et
//! les tests d'intégration (feature `test-util`).

#![allow(
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::wildcard_imports,
    clippy::assigning_clones
)]

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::crypto::*;
use crate::esp::{EspTunnel, Inbound};
use crate::ike::*;
use crate::mschapv2::*;
use crate::sk;
use crate::wire::*;

pub const GW_IP: [u8; 4] = [198, 51, 100, 1];
pub const PSK: &str = "psk-de-test";
pub const USER: &str = "alice";
pub const PASS: &str = "pass-de-test";
pub const SPI_R: [u8; 8] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];
pub const SPI_CHILD_R: u32 = 0x1122_3344;
pub const AUTH_CHALLENGE: [u8; 16] = [0x5B; 16];
pub const NR: [u8; 32] = [0x77; 32];

/// Aléa déterministe (compteur → octets ; scalaires ECP/MODP valides).
pub fn det_rng() -> Box<dyn Entropy + Send> {
    let mut ctr: u8 = 1;
    Box::new(move |out: &mut [u8]| {
        for b in out.iter_mut() {
            ctr = ctr.wrapping_mul(31).wrapping_add(17);
            *b = ctr | 1;
        }
    })
}

pub fn cfg() -> IkeConfig {
    let mut c = IkeConfig::new(
        GW_IP,
        [192, 0, 2, 10],
        500,
        SecretString::from(PSK),
        USER.to_owned(),
        SecretString::from(PASS),
    );
    c.dh_groups = vec![DhGroup::Modp2048, DhGroup::Ecp256];
    c
}

/// Certificat RSA-2048 auto-signé de test (CN=gw.example.test) et sa clé PKCS#8.
/// Matériel **de test uniquement**, non secret (généré pour ce dépôt).
pub const TEST_RSA_CERT: &[u8] = include_bytes!("../testdata/test-gw-rsa.cert.der");
pub const TEST_RSA_KEY: &[u8] = include_bytes!("../testdata/test-gw-rsa.key.p8.der");
/// Certificat ECDSA P-256 auto-signé de test et sa clé PKCS#8 (test uniquement).
pub const TEST_P256_CERT: &[u8] = include_bytes!("../testdata/test-gw-p256.cert.der");
pub const TEST_P256_KEY: &[u8] = include_bytes!("../testdata/test-gw-p256.key.p8.der");

/// AlgorithmIdentifier DER (RFC 7427 annexe A) : sha256WithRSAEncryption (A.1.2).
pub const ALG_SHA256_RSA: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
];
/// ecdsa-with-SHA256 (A.3.1).
pub const ALG_ECDSA_SHA256: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
/// RSASSA-PSS SHA-256, MGF1-SHA-256, sel 32 (A.4.3).
pub const ALG_RSA_PSS_SHA256: &[u8] = &[
    0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0,
    0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03,
    0x02, 0x01, 0x20,
];

/// Mode d'authentification de la passerelle simulée dans le premier IKE_AUTH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GwAuth {
    /// AUTH PSK (méthode 2).
    Psk,
    /// Méthode 1 : RSA PKCS#1 v1.5 / SHA-1, certificat RSA.
    RsaSha1,
    /// Méthode 14 : sha256WithRSAEncryption, certificat RSA.
    RsaPkcs1Sha256,
    /// Méthode 14 : RSASSA-PSS SHA-256, certificat RSA.
    RsaPss,
    /// Méthode 14 : ECDSA P-256 / SHA-256, certificat P-256.
    EcdsaP256,
}

impl GwAuth {
    pub fn cert(self) -> &'static [u8] {
        if self == Self::EcdsaP256 {
            TEST_P256_CERT
        } else {
            TEST_RSA_CERT
        }
    }

    /// (méthode, données AUTH) signant `signed`.
    pub fn sign(self, signed: &[u8]) -> (u8, Vec<u8>) {
        use ring::signature as rs;
        let rng = ring::rand::SystemRandom::new();
        let rsa = || rs::RsaKeyPair::from_pkcs8(TEST_RSA_KEY).unwrap();
        let ring_rsa = |pad: &'static dyn rs::RsaEncoding| {
            let k = rsa();
            let mut sig = vec![0u8; k.public().modulus_len()];
            k.sign(pad, &rng, signed, &mut sig).unwrap();
            sig
        };
        let digital = |alg: &[u8], sig: Vec<u8>| {
            let mut v = vec![u8::try_from(alg.len()).unwrap()];
            v.extend_from_slice(alg);
            v.extend_from_slice(&sig);
            (14, v)
        };
        match self {
            Self::Psk => panic!("pas de signature en mode PSK"),
            Self::RsaSha1 => {
                use rsa::pkcs8::DecodePrivateKey;
                use rsa::signature::{SignatureEncoding, Signer};
                let k = rsa::RsaPrivateKey::from_pkcs8_der(TEST_RSA_KEY).unwrap();
                let sk = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(k);
                (1, sk.sign(signed).to_vec())
            }
            Self::RsaPkcs1Sha256 => digital(ALG_SHA256_RSA, ring_rsa(&rs::RSA_PKCS1_SHA256)),
            Self::RsaPss => digital(ALG_RSA_PSS_SHA256, ring_rsa(&rs::RSA_PSS_SHA256)),
            Self::EcdsaP256 => {
                let k = rs::EcdsaKeyPair::from_pkcs8(
                    &rs::ECDSA_P256_SHA256_ASN1_SIGNING,
                    TEST_P256_KEY,
                    &rng,
                )
                .unwrap();
                digital(
                    ALG_ECDSA_SHA256,
                    k.sign(&rng, signed).unwrap().as_ref().to_vec(),
                )
            }
        }
    }
}

/// Configuration client exigeant le certificat épinglé de `gw`.
pub fn cfg_cert(gw: GwAuth) -> IkeConfig {
    let mut c = cfg();
    c.responder_auth = ResponderAuth::CertPinned {
        pins: vec![crate::cert::cert_pin(gw.cert())],
    };
    c
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Quirk {
    None,
    WrongPsk,
    WrongPassword,
    BadServerSuccess,
    RequireGroup(DhGroup),
    RequireCookie,
    /// Signature AUTH altérée (un octet inversé).
    TamperSignature,
    /// AUTH par signature sans payload CERT.
    OmitCert,
}

pub struct Responder {
    pub quirk: Quirk,
    pub psk: String,
    pub password: String,
    pub suite: Option<IkeSuite>,
    pub keys: Option<SkKeys>,
    pub spi_i: [u8; 8],
    pub ni: Vec<u8>,
    pub msg1: Vec<u8>,
    pub msg2: Vec<u8>,
    pub nt: Option<[u8; 24]>,
    pub msk: Option<Zeroizing<[u8; 64]>>,
    pub idi_body: Vec<u8>,
    pub seen_user: Option<String>,
    pub child_spi_i: u32,
    pub esp_chosen: Option<Proposal>,
    pub gcm_ctr: u64,
    pub cookie_seen: bool,
    pub init_count: u32,
    /// Authentification présentée dans le premier IKE_AUTH (défaut : PSK).
    pub gw_auth: GwAuth,
    /// CERTREQ reçu dans le premier IKE_AUTH du client.
    pub certreq_seen: bool,
    /// Données de SIGNATURE_HASH_ALGORITHMS reçues dans IKE_SA_INIT.
    pub sig_hashes_seen: Option<Vec<u8>>,
}

pub const IDR: &[u8] = b"gw.example.test";

impl Responder {
    pub fn new(quirk: Quirk) -> Self {
        Self {
            quirk,
            psk: if quirk == Quirk::WrongPsk {
                "autre-psk".into()
            } else {
                PSK.into()
            },
            password: if quirk == Quirk::WrongPassword {
                "autre-mdp".into()
            } else {
                PASS.into()
            },
            suite: None,
            keys: None,
            spi_i: [0; 8],
            ni: vec![],
            msg1: vec![],
            msg2: vec![],
            nt: None,
            msk: None,
            idi_body: vec![],
            seen_user: None,
            child_spi_i: 0,
            esp_chosen: None,
            gcm_ctr: 0,
            cookie_seen: false,
            init_count: 0,
            gw_auth: GwAuth::Psk,
            certreq_seen: false,
            sig_hashes_seen: None,
        }
    }

    /// Répondeur authentifié par certificat (`gw`).
    pub fn with_auth(quirk: Quirk, gw: GwAuth) -> Self {
        let mut r = Self::new(quirk);
        r.gw_auth = gw;
        r
    }

    pub fn hdr(&self, exch: u8, mid: u32) -> Header {
        Header {
            spi_i: self.spi_i,
            spi_r: SPI_R,
            next_payload: 0,
            exchange_type: exch,
            flags: flags::RESPONSE,
            message_id: mid,
            length: 0,
        }
    }

    pub fn seal(&mut self, mid: u32, inner: &[Payload]) -> Vec<u8> {
        self.gcm_ctr += 1;
        let suite = self.suite.unwrap();
        let iv = if suite.encr.is_aead() {
            self.gcm_ctr.to_be_bytes().to_vec()
        } else {
            vec![0x42u8; 16]
        };
        let m = sk::seal(
            &suite,
            self.keys.as_ref().unwrap(),
            false,
            &self.hdr(exchange::IKE_AUTH, mid),
            inner,
            &iv,
        )
        .unwrap();
        let mut d = vec![0u8; 4];
        d.extend_from_slice(&m);
        d
    }

    pub fn eap(code: u8, id: u8, data: Vec<u8>) -> Payload {
        Payload::Eap(EapPacket { code, id, data }.encode().unwrap())
    }

    /// Traite un datagramme du client, renvoie les datagrammes de réponse.
    pub fn handle(&mut self, dg: &[u8]) -> Vec<Vec<u8>> {
        let raw = if dg[..4] == [0; 4] { &dg[4..] } else { dg };
        let h = Header::parse(raw).unwrap();
        match h.exchange_type {
            exchange::IKE_SA_INIT => self.on_init(raw),
            exchange::IKE_AUTH => self.on_auth(raw, h.message_id),
            _ => vec![],
        }
    }

    pub fn on_init(&mut self, raw: &[u8]) -> Vec<Vec<u8>> {
        self.init_count += 1;
        let m = Message::decode(raw).unwrap();
        self.spi_i = m.header.spi_i;
        let mut hdr = self.hdr(exchange::IKE_SA_INIT, 0);
        hdr.spi_r = if self.quirk == Quirk::RequireCookie && !self.cookie_seen {
            [0; 8]
        } else {
            SPI_R
        };
        let mut sa = None;
        let mut ke = None;
        let mut ni = None;
        for p in &m.payloads {
            match p {
                Payload::Sa(v) => sa = Some(v.clone()),
                Payload::Ke { group, data } => ke = Some((*group, data.clone())),
                Payload::Nonce(n) => ni = Some(n.clone()),
                _ => {}
            }
        }
        if self.quirk == Quirk::RequireCookie && !self.cookie_seen {
            if m.notifies()
                .any(|n| n.ty == notify::COOKIE && n.data == b"cookie-test")
            {
                self.cookie_seen = true;
            } else {
                let p = [Payload::Notify(Notify::new(
                    notify::COOKIE,
                    b"cookie-test".to_vec(),
                ))];
                return vec![Message::encode(&hdr, &p).unwrap()];
            }
            hdr.spi_r = SPI_R;
        }
        let (kegroup, kedata) = ke.unwrap();
        if let Quirk::RequireGroup(g) = self.quirk
            && kegroup != g.id()
        {
            let p = [Payload::Notify(Notify::new(
                notify::INVALID_KE_PAYLOAD,
                g.id().to_be_bytes().to_vec(),
            ))];
            return vec![Message::encode(&hdr, &p).unwrap()];
        }
        // Retient la dernière requête (RealMessage1) et choisit la 1re proposition.
        self.msg1 = raw.to_vec();
        self.sig_hashes_seen = m
            .notifies()
            .find(|n| n.ty == notify::SIGNATURE_HASH_ALGORITHMS)
            .map(|n| n.data.clone());
        self.ni = ni.unwrap();
        let prop = sa.unwrap().remove(0);
        let pick = |ty: u8| prop.transforms.iter().find(|t| t.ty == ty).cloned();
        let encr = pick(1).unwrap();
        let prf = pick(2).unwrap();
        let integ = pick(3);
        let suite = IkeSuite::new(
            Encr::from_id(encr.id, encr.key_len.unwrap()).unwrap(),
            Prf::from_id(prf.id).unwrap(),
            integ.as_ref().map(|t| Integ::from_id(t.id).unwrap()),
        )
        .unwrap();
        let group = DhGroup::from_id(kegroup).unwrap();
        let kp = DhKeypair::new(group, &[0x2Du8; 32]).unwrap();
        let shared = kp.shared_secret(&kedata).unwrap();
        self.keys =
            Some(derive_sk_keys(&suite, &self.ni, &NR, &self.spi_i, &SPI_R, &shared).unwrap());
        self.suite = Some(suite);
        let mut transforms = vec![encr, prf];
        transforms.extend(integ);
        transforms.push(Transform {
            ty: 4,
            id: kegroup,
            key_len: None,
        });
        let payloads = [
            Payload::Sa(vec![Proposal {
                number: prop.number,
                protocol: 1,
                spi: vec![],
                transforms,
            }]),
            Payload::Ke {
                group: kegroup,
                data: kp.public().to_vec(),
            },
            Payload::Nonce(NR.to_vec()),
        ];
        let msg2 = Message::encode(&hdr, &payloads).unwrap();
        self.msg2 = msg2.clone();
        vec![msg2]
    }

    pub fn open(&self, raw: &[u8]) -> Vec<Payload> {
        sk::open(
            self.suite.as_ref().unwrap(),
            self.keys.as_ref().unwrap(),
            true,
            raw,
        )
        .unwrap()
        .1
    }

    #[allow(clippy::too_many_lines)]
    pub fn on_auth(&mut self, raw: &[u8], mid: u32) -> Vec<Vec<u8>> {
        let inner = self.open(raw);
        let suite = self.suite.unwrap();
        match mid {
            1 => {
                assert!(!inner.iter().any(|p| matches!(p, Payload::Auth { .. })));
                for p in &inner {
                    match p {
                        Payload::Id { id_type, data, .. } => {
                            self.idi_body = id_body(*id_type, data);
                        }
                        Payload::Sa(v) => {
                            // choisit la 1re proposition ESP
                            let mut p = v[0].clone();
                            self.child_spi_i = u32::from_be_bytes(p.spi[..4].try_into().unwrap());
                            p.spi = SPI_CHILD_R.to_be_bytes().to_vec();
                            p.transforms.retain(|t| t.ty != 4);
                            self.esp_chosen = Some(p);
                        }
                        Payload::Cp(cp) => assert_eq!(cp.cfg_type, 1),
                        Payload::CertReq { encoding, .. } => {
                            assert_eq!(*encoding, 4);
                            self.certreq_seen = true;
                        }
                        _ => {}
                    }
                }
                let keys = self.keys.as_ref().unwrap();
                let mut payloads = vec![Payload::Id {
                    responder: true,
                    id_type: 2,
                    data: IDR.to_vec(),
                }];
                if self.gw_auth == GwAuth::Psk {
                    let a = auth_value(
                        suite.prf,
                        self.psk.as_bytes(),
                        &self.msg2,
                        &self.ni,
                        &keys.sk_pr,
                        &id_body(2, IDR),
                    );
                    payloads.push(Payload::Auth {
                        method: 2,
                        data: a.to_vec(),
                    });
                } else {
                    let signed = signed_octets(
                        suite.prf,
                        &self.msg2,
                        &self.ni,
                        &keys.sk_pr,
                        &id_body(2, IDR),
                    );
                    let (method, mut data) = self.gw_auth.sign(&signed);
                    if self.quirk == Quirk::TamperSignature {
                        let last = data.len() - 1;
                        data[last] ^= 0x01;
                    }
                    if self.quirk != Quirk::OmitCert {
                        payloads.push(Payload::Cert {
                            encoding: 4,
                            data: self.gw_auth.cert().to_vec(),
                        });
                    }
                    payloads.push(Payload::Auth { method, data });
                }
                payloads.push(Self::eap(1, 1, vec![1]));
                vec![self.seal(1, &payloads)]
            }
            2 => {
                let Some(Payload::Eap(e)) = inner.first() else {
                    panic!("EAP attendu")
                };
                let p = EapPacket::parse(e).unwrap();
                assert_eq!((p.code, p.data[0]), (2, 1));
                self.seen_user = Some(String::from_utf8(p.data[1..].to_vec()).unwrap());
                let ch = MsChapV2::Challenge {
                    id: 7,
                    challenge: AUTH_CHALLENGE,
                    name: b"gw".to_vec(),
                }
                .encode()
                .unwrap();
                vec![self.seal(2, &[Self::eap(1, 2, ch)])]
            }
            3 => {
                let Some(Payload::Eap(e)) = inner.first() else {
                    panic!("EAP attendu")
                };
                let p = EapPacket::parse(e).unwrap();
                let MsChapV2::Response {
                    peer_challenge,
                    nt_response,
                    ..
                } = MsChapV2::parse(&p.data).unwrap()
                else {
                    panic!("Response attendu")
                };
                let pw = SecretString::from(self.password.clone());
                let expect = generate_nt_response(&AUTH_CHALLENGE, &peer_challenge, USER, &pw);
                let reply = if expect == nt_response {
                    self.nt = Some(nt_response);
                    self.msk = Some(eap_msk(&pw, &nt_response));
                    let mut s = generate_authenticator_response(
                        &pw,
                        &nt_response,
                        &peer_challenge,
                        &AUTH_CHALLENGE,
                        USER,
                    );
                    if self.quirk == Quirk::BadServerSuccess {
                        s = s.replace(|c: char| c.is_ascii_hexdigit(), "0");
                    }
                    s.push_str(" M=welcome");
                    MsChapV2::Success {
                        id: 7,
                        message: s.into_bytes(),
                    }
                } else {
                    MsChapV2::Failure {
                        id: 7,
                        message: b"E=691 R=1 C=00 V=3 M=Authentication failed".to_vec(),
                    }
                };
                vec![self.seal(3, &[Self::eap(1, 3, reply.encode().unwrap())])]
            }
            4 => vec![self.seal(4, &[Self::eap(3, 4, vec![])])],
            5 => {
                let keys = self.keys.as_ref().unwrap();
                let msk = self.msk.as_ref().unwrap();
                let Some(Payload::Auth { data, .. }) = inner.first() else {
                    panic!("AUTH attendu")
                };
                let want = auth_value(
                    suite.prf,
                    &msk[..],
                    &self.msg1,
                    &NR,
                    &keys.sk_pi,
                    &self.idi_body,
                );
                assert_eq!(data, &want.to_vec(), "AUTH client");
                let a = auth_value(
                    suite.prf,
                    &msk[..],
                    &self.msg2,
                    &self.ni,
                    &keys.sk_pr,
                    &id_body(2, IDR),
                );
                let cp = Cp {
                    cfg_type: 2,
                    attrs: vec![
                        CpAttr {
                            ty: cp_attr::INTERNAL_IP4_ADDRESS,
                            value: vec![10, 10, 2, 7],
                        },
                        CpAttr {
                            ty: cp_attr::INTERNAL_IP4_NETMASK,
                            value: vec![255, 255, 255, 255],
                        },
                        CpAttr {
                            ty: cp_attr::INTERNAL_IP4_DNS,
                            value: vec![10, 20, 0, 53],
                        },
                        CpAttr {
                            ty: cp_attr::INTERNAL_IP4_SUBNET,
                            value: vec![10, 20, 0, 0, 255, 255, 255, 0],
                        },
                        CpAttr {
                            ty: cp_attr::INTERNAL_DNS_DOMAIN,
                            value: b"corp.example.test".to_vec(),
                        },
                    ],
                };
                let mut tsr = TrafficSelector::any();
                tsr.start = [10, 20, 0, 0];
                tsr.end = [10, 20, 0, 255];
                let mut tsi = TrafficSelector::any();
                tsi.start = [10, 10, 2, 7];
                tsi.end = [10, 10, 2, 7];
                let payloads = [
                    Payload::Auth {
                        method: 2,
                        data: a.to_vec(),
                    },
                    Payload::Cp(cp),
                    Payload::Sa(vec![self.esp_chosen.clone().unwrap()]),
                    Payload::Ts {
                        responder: false,
                        selectors: vec![tsi],
                    },
                    Payload::Ts {
                        responder: true,
                        selectors: vec![tsr],
                    },
                ];
                vec![self.seal(5, &payloads)]
            }
            _ => panic!("MID inattendu {mid}"),
        }
    }
}

impl core::fmt::Debug for Responder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Responder")
            .field("quirk", &self.quirk)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Passerelle simulée complète (IKE établi, ESP, DPD, rekey CHILD, Delete)
// ---------------------------------------------------------------------------

fn mirror(k: &ChildSaKeys) -> ChildSaKeys {
    ChildSaKeys {
        spi_in: k.spi_out,
        spi_out: k.spi_in,
        encr: k.encr,
        integ: k.integ,
        encr_key_out: k.encr_key_in.clone(),
        integ_key_out: k.integ_key_in.clone(),
        encr_key_in: k.encr_key_out.clone(),
        integ_key_in: k.integ_key_out.clone(),
    }
}

/// Passerelle simulée sans-io : handshake via [`Responder`], puis, une fois IKE_AUTH terminé,
/// réponses aux DPD, Delete et rekey CHILD (PFS) du client, et ESP côté passerelle.
/// Les datagrammes retournés sont des charges UDP prêtes à émettre (marqueur non-ESP inclus).
pub struct SimGateway {
    pub resp: Responder,
    esp: Option<EspTunnel>,
    esp_prop: Option<EspProposal>,
    /// SPI entrant courant de la passerelle (SPI sortant du client).
    gw_spi_in: u32,
    gw_spi_old: Option<u32>,
    gcm: u64,
    iv_ctr: u8,
    /// Delete(IKE) reçu du client : la session est terminée.
    pub closed: bool,
    /// Nombre de DPD (INFORMATIONAL vides) reçus du client.
    pub dpd_received: u32,
    /// Nombre de rekeys CHILD acceptés.
    pub rekeys: u32,
    next_gw_mid: u32,
}

impl core::fmt::Debug for SimGateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SimGateway")
            .field("closed", &self.closed)
            .field("dpd_received", &self.dpd_received)
            .field("rekeys", &self.rekeys)
            .finish_non_exhaustive()
    }
}

impl Default for SimGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl SimGateway {
    pub fn new() -> Self {
        Self {
            resp: Responder::new(Quirk::None),
            esp: None,
            esp_prop: None,
            gw_spi_in: SPI_CHILD_R,
            gw_spi_old: None,
            gcm: 10_000,
            iv_ctr: 1,
            closed: false,
            dpd_received: 0,
            rekeys: 0,
            next_gw_mid: 0,
        }
    }

    /// `true` une fois l'IKE_AUTH terminé (ESP prêt).
    pub fn established(&self) -> bool {
        self.esp.is_some()
    }

    /// Traite une charge UDP IKE du client (port 500 brut ou 4500 avec marqueur).
    pub fn handle_ike(&mut self, dg: &[u8]) -> Vec<Vec<u8>> {
        if self.esp.is_none() {
            let out = self.resp.handle(dg);
            let raw = if dg[..4] == [0; 4] { &dg[4..] } else { dg };
            if Header::parse(raw)
                .is_ok_and(|h| h.exchange_type == exchange::IKE_AUTH && h.message_id == 5)
            {
                self.finish_auth();
            }
            return out;
        }
        self.handle_est(dg)
    }

    fn finish_auth(&mut self) {
        let prop = self.resp.esp_chosen.clone().unwrap();
        let pick = |ty: u8| {
            prop.transforms
                .iter()
                .find(|t| t.ty == ty)
                .cloned()
                .unwrap()
        };
        let e = pick(1);
        let encr = Encr::from_id(e.id, e.key_len.unwrap()).unwrap();
        let integ = prop
            .transforms
            .iter()
            .find(|t| t.ty == 3)
            .map(|t| Integ::from_id(t.id).unwrap());
        let esp = EspProposal { encr, integ };
        let suite = self.resp.suite.unwrap();
        let keys = self.resp.keys.as_ref().unwrap();
        let client = derive_child_keys(
            suite.prf,
            &keys.sk_d,
            &self.resp.ni,
            &NR,
            esp,
            self.resp.child_spi_i,
            SPI_CHILD_R,
        )
        .unwrap();
        self.esp = Some(EspTunnel::new(&mirror(&client), false).unwrap());
        self.esp_prop = Some(esp);
    }

    fn seal_ike(&mut self, exch: u8, mid: u32, response: bool, inner: &[Payload]) -> Vec<u8> {
        self.gcm += 1;
        self.iv_ctr = self.iv_ctr.wrapping_add(1);
        let suite = self.resp.suite.unwrap();
        let iv = if suite.encr.is_aead() {
            self.gcm.to_be_bytes().to_vec()
        } else {
            vec![self.iv_ctr; 16]
        };
        let h = Header {
            spi_i: self.resp.spi_i,
            spi_r: SPI_R,
            next_payload: 0,
            exchange_type: exch,
            flags: if response { flags::RESPONSE } else { 0 },
            message_id: mid,
            length: 0,
        };
        let m = sk::seal(
            &suite,
            self.resp.keys.as_ref().unwrap(),
            false,
            &h,
            inner,
            &iv,
        )
        .unwrap();
        let mut d = vec![0u8; 4];
        d.extend_from_slice(&m);
        d
    }

    fn handle_est(&mut self, dg: &[u8]) -> Vec<Vec<u8>> {
        let raw = if dg[..4] == [0; 4] { &dg[4..] } else { dg };
        let suite = self.resp.suite.unwrap();
        let Ok((h, p)) = sk::open(&suite, self.resp.keys.as_ref().unwrap(), true, raw) else {
            return vec![];
        };
        if h.flags & flags::RESPONSE != 0 {
            return vec![];
        }
        match h.exchange_type {
            exchange::INFORMATIONAL => {
                let dels: Vec<_> = p.iter().filter_map(parse_delete).collect();
                if dels.iter().any(|(pr, _)| *pr == 1) {
                    self.closed = true;
                    return vec![self.seal_ike(h.exchange_type, h.message_id, true, &[])];
                }
                if dels.iter().any(|(pr, _)| *pr == 3) {
                    // Le client supprime l'ancienne SA : on acquitte et on la retire.
                    let old = self.gw_spi_old.take();
                    if let (Some(o), Some(esp)) = (old, self.esp.as_mut()) {
                        esp.drop_old(o);
                    }
                    let ack = delete_payload(3, &old.into_iter().collect::<Vec<_>>());
                    return vec![self.seal_ike(h.exchange_type, h.message_id, true, &[ack])];
                }
                self.dpd_received += 1;
                vec![self.seal_ike(h.exchange_type, h.message_id, true, &[])]
            }
            exchange::CREATE_CHILD_SA => self.rekey_child(&h, &p),
            _ => vec![],
        }
    }

    fn rekey_child(&mut self, h: &Header, p: &[Payload]) -> Vec<Vec<u8>> {
        let mut prop = None;
        let (mut ni, mut ke) = (None, None);
        for x in p {
            match x {
                Payload::Sa(v) => prop = Some(v[0].clone()),
                Payload::Nonce(n) => ni = Some(n.clone()),
                Payload::Ke { group, data } => ke = Some((*group, data.clone())),
                _ => {}
            }
        }
        let (mut prop, ni, (group, kedata)) = (prop.unwrap(), ni.unwrap(), ke.unwrap());
        let spi_cl = u32::from_be_bytes(prop.spi[..4].try_into().unwrap());
        let gw_spi = 0x5000_0000 + self.rekeys + 1;
        prop.spi = gw_spi.to_be_bytes().to_vec();
        let kp = DhKeypair::new(DhGroup::from_id(group).unwrap(), &[0x2Du8; 32]).unwrap();
        let shared = kp.shared_secret(&kedata).unwrap();
        let nr = vec![0x66u8; 32];
        let suite = self.resp.suite.unwrap();
        let gw_keys = derive_child_keys_ex(
            suite.prf,
            &self.resp.keys.as_ref().unwrap().sk_d,
            Some(&shared),
            &ni,
            &nr,
            self.esp_prop.unwrap(),
            gw_spi,
            spi_cl,
            false,
        )
        .unwrap();
        self.esp.as_mut().unwrap().rekey(&gw_keys).unwrap();
        self.gw_spi_old = Some(self.gw_spi_in);
        self.gw_spi_in = gw_spi;
        self.rekeys += 1;
        let any = || TrafficSelector::any();
        let resp = [
            Payload::Sa(vec![prop]),
            Payload::Nonce(nr),
            Payload::Ke {
                group,
                data: kp.public().to_vec(),
            },
            Payload::Ts {
                responder: false,
                selectors: vec![any()],
            },
            Payload::Ts {
                responder: true,
                selectors: vec![any()],
            },
        ];
        vec![self.seal_ike(h.exchange_type, h.message_id, true, &resp)]
    }

    /// Requête INFORMATIONAL Delete(IKE) initiée par la passerelle.
    pub fn delete_ike(&mut self) -> Vec<u8> {
        let mid = self.next_gw_mid;
        self.next_gw_mid += 1;
        self.seal_ike(
            exchange::INFORMATIONAL,
            mid,
            false,
            &[delete_payload(1, &[])],
        )
    }

    /// Requête DPD (INFORMATIONAL vide) initiée par la passerelle.
    pub fn dpd(&mut self) -> Vec<u8> {
        let mid = self.next_gw_mid;
        self.next_gw_mid += 1;
        self.seal_ike(exchange::INFORMATIONAL, mid, false, &[])
    }

    /// Décapsule un paquet ESP du client (charge UDP sans marqueur) : paquet IPv4 interne.
    pub fn open_esp(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        match self.esp.as_mut()?.open(data) {
            Ok(Inbound::Packet(p)) => Some(p),
            _ => None,
        }
    }

    /// Encapsule un paquet IPv4 vers le client (charge UDP à envoyer sur 4500).
    pub fn seal_esp(&mut self, pkt: &[u8]) -> Vec<u8> {
        self.iv_ctr = self.iv_ctr.wrapping_add(1);
        let esp = self.esp.as_mut().unwrap();
        esp.seal(pkt, Some(&[self.iv_ctr; 16])).unwrap()
    }
}

fn csum(d: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in d.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0xffff)
}

/// Construit un ICMP echo request IPv4 (sans options) de 8 octets de données.
pub fn icmp_echo_request(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 36, 0, 0, 0, 0, 64, 1, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let c = csum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    let mut icmp = vec![8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"fortivpn");
    let c = csum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(&icmp);
    p
}

/// Réponse ICMP echo reply à une requête produite par [`icmp_echo_request`].
pub fn icmp_echo_reply(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 28 || req[0] != 0x45 || req[9] != 1 || req[20] != 8 {
        return None;
    }
    let mut p = req.to_vec();
    let (src, dst) = (req[12..16].to_vec(), req[16..20].to_vec());
    p[12..16].copy_from_slice(&dst);
    p[16..20].copy_from_slice(&src);
    p[10..12].copy_from_slice(&[0, 0]);
    let c = csum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20] = 0;
    p[22..24].copy_from_slice(&[0, 0]);
    let c = csum(&p[20..]);
    p[22..24].copy_from_slice(&c.to_be_bytes());
    Some(p)
}
