//! Initiateur IKEv2 sans-io : IKE_SA_INIT, IKE_AUTH (EAP-MSCHAPv2), dérivation KEYMAT.
//!
//! Machine d'états pilotée par événements, sur le modèle de `proto::ppp::PppSession` :
//! - [`IkeInitiator::start`] : ouverture ;
//! - [`IkeInitiator::handle_datagram`] : datagramme UDP reçu (500 ou 4500) ;
//! - [`IkeInitiator::handle_timeout`] : tick, `now` fourni par l'appelant ;
//! - sorties : [`Output::Send`] (datagramme à émettre, port de destination indiqué) et
//!   [`Output::Event`] ([`Event::Established`] / [`Event::Failed`]).
//!
//! L'aléa (nonces, clés DH, SPI, IV CBC, peer challenge) vient de l'[`Entropy`] de l'appelant.
//! Limites de cette tranche : pas de fragmentation RFC 7383, PSK ASCII
//! uniquement (pas de forme `0x…`), IPv4 seulement.
//! DPD, rekey, Delete : voir `ike/established.rs` (story 6.3).

mod established;

use std::time::{Duration, Instant};

use established::{Est, IkeSa, ReqKind};

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::cert::{
    AUTH_METHOD_DIGITAL_SIG, AUTH_METHOD_RSA_SIG, CERT_ENCODING_X509, CertPin, SIG_HASH_SHA2_256,
    pin_matches, verify_auth,
};
use crate::crypto::{
    DhGroup, DhKeypair, Encr, IkeSuite, Integ, Prf, SkKeys, auth_value, ct_eq, derive_sk_keys,
    derive_sk_keys_rekey, prf_plus, signed_octets,
};
use crate::error::Error;
use crate::mschapv2::{
    ClientResponse, EAP_TYPE_MSCHAPV2, EapPacket, MsChapV2, eap_msk, respond, verify_success,
};
use crate::sk;
use crate::wire::{
    Cp, Header, Message, Notify, Payload, Proposal, TrafficSelector, Transform, exchange, flags,
    id_body, nat_detection_hash, notify,
};

/// Port IKE initial.
pub const IKE_PORT: u16 = 500;
/// Port NAT-T (« floating »).
pub const NATT_PORT: u16 = 4500;

const NO_PROPOSAL_CHOSEN: u16 = 14;
const MAX_INIT_RESTARTS: u8 = 4;
/// Taille maximale d'un cookie IKE_SA_INIT (RFC 7296 §3.10.1).
/// Longueur minimale de la PSK acceptée.
pub const MIN_PSK_LEN: usize = 8;
const MAX_COOKIE_LEN: usize = 64;
const AUTH_METHOD_PSK: u8 = 2;

/// Source d'aléa fournie par l'appelant (CSPRNG en production, suite déterministe en test).
pub trait Entropy {
    fn fill(&mut self, out: &mut [u8]);
}

impl<F: FnMut(&mut [u8])> Entropy for F {
    fn fill(&mut self, out: &mut [u8]) {
        self(out);
    }
}

/// Politique d'authentification de la passerelle (répondeur) dans le premier IKE_AUTH.
///
/// Avec une PSK de groupe, tout détenteur de la PSK peut se faire passer pour la passerelle et
/// obtenir la NT-Response MS-CHAPv2 (revue 6.5, M1). `CertPinned` exige une AUTH par signature
/// (méthodes 1 ou 14) vérifiée avec la clé d'un certificat dont l'empreinte SHA-256 (DER du
/// certificat feuille) figure dans `pins` ; une AUTH PSK est alors refusée.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ResponderAuth {
    /// AUTH PSK (méthode 2) uniquement (défaut, comportement historique).
    #[default]
    Psk,
    /// AUTH par signature avec certificat épinglé uniquement ; la PSK n'est pas utilisée.
    CertPinned { pins: Vec<CertPin> },
    /// Mode de transition : AUTH par certificat épinglé **ou** AUTH PSK. N'apporte pas la
    /// protection de `CertPinned` contre un détenteur de la PSK (il peut répondre en PSK).
    PskAndCertPinned { pins: Vec<CertPin> },
}

impl ResponderAuth {
    /// AUTH PSK du répondeur acceptée.
    pub fn accepts_psk(&self) -> bool {
        !matches!(self, Self::CertPinned { .. })
    }

    /// Empreintes acceptées (vide : AUTH par certificat refusée).
    pub fn pins(&self) -> &[CertPin] {
        match self {
            Self::Psk => &[],
            Self::CertPinned { pins } | Self::PskAndCertPinned { pins } => pins,
        }
    }

    fn wants_cert(&self) -> bool {
        !matches!(self, Self::Psk)
    }
}

/// Proposition ESP offerte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspProposal {
    pub encr: Encr,
    /// `None` ssi `encr` est AEAD.
    pub integ: Option<Integ>,
}

/// Configuration de l'initiateur.
#[derive(Debug, Clone)]
pub struct IkeConfig {
    /// Adresse de la passerelle (entrée de NAT_DETECTION_DESTINATION_IP).
    pub gateway_ip: [u8; 4],
    /// Adresse et port locaux (sert uniquement à fabriquer un NAT_DETECTION_SOURCE_IP faux).
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub psk: SecretString,
    pub username: String,
    pub password: SecretString,
    /// IDi : (type, données). Défaut : ID_FQDN `fortivpn-client`.
    pub idi: (u8, Vec<u8>),
    /// IDr imposé (type, données) ; `None` : accepter n'importe lequel.
    ///
    /// Recommandé : le renseigner. Avec une PSK de groupe, tout détenteur de la PSK peut se faire
    /// passer pour la passerelle (cf. docs/securite-versions-futures.md) ; imposer l'IDr de la
    /// passerelle attendue limite la réutilisation d'une PSK entre passerelles.
    pub expected_idr: Option<(u8, Vec<u8>)>,
    /// Authentification exigée de la passerelle (défaut : PSK).
    pub responder_auth: ResponderAuth,
    /// Une proposition IKE par suite, chacune listant tous les groupes DH.
    pub ike_suites: Vec<IkeSuite>,
    /// Groupes DH ; le premier est utilisé pour le KE initial.
    pub dh_groups: Vec<DhGroup>,
    pub esp_proposals: Vec<EspProposal>,
    /// Délai de base de retransmission (défaut 2 s, doublé, plafonné à 8x).
    pub retransmit_base: Duration,
    /// Nombre total d'envois d'une requête avant abandon (défaut 5).
    pub max_sends: u8,
    /// Durées de vie des SA (rekey soft / expiration hard).
    pub lifetimes: Lifetimes,
    /// DPD : silence entrant au-delà duquel un INFORMATIONAL vide est émis (défaut 30 s).
    pub dpd_idle: Duration,
    /// Fenêtre pendant laquelle l'ancienne CHILD SA entrante reste acceptée (défaut 10 s).
    pub rekey_overlap: Duration,
    /// Délai avant nouvelle tentative après un rekey refusé (défaut 60 s).
    pub rekey_retry: Duration,
}

/// Durées de vie locales (docs/protocol-ipsec.md §2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetimes {
    /// Rekey CHILD SA initié par nous (défaut 90 % de 8 h).
    pub child_soft: Duration,
    /// Expiration de la CHILD SA (défaut 8 h < 43 200 s).
    pub child_hard: Duration,
    /// Rekey IKE SA (défaut 23 h).
    pub ike_soft: Duration,
    /// Expiration de l'IKE SA (défaut 24 h < 86 400 s).
    pub ike_hard: Duration,
}

impl Default for Lifetimes {
    fn default() -> Self {
        Self {
            child_soft: Duration::from_secs(25_920),
            child_hard: Duration::from_secs(28_800),
            ike_soft: Duration::from_secs(82_800),
            ike_hard: Duration::from_secs(86_399),
        }
    }
}

impl IkeConfig {
    /// Configuration par défaut (propositions de `docs/protocol-ipsec.md` §2.3).
    pub fn new(
        gateway_ip: [u8; 4],
        local_ip: [u8; 4],
        local_port: u16,
        psk: SecretString,
        username: String,
        password: SecretString,
    ) -> Self {
        let cbc = |e, p, i| IkeSuite {
            prf: p,
            encr: e,
            integ: Some(i),
        };
        let gcm = |e, p| IkeSuite {
            prf: p,
            encr: e,
            integ: None,
        };
        Self {
            gateway_ip,
            local_ip,
            local_port,
            psk,
            username,
            password,
            idi: (2, b"fortivpn-client".to_vec()),
            expected_idr: None,
            responder_auth: ResponderAuth::Psk,
            ike_suites: vec![
                cbc(Encr::AesCbc128, Prf::HmacSha256, Integ::HmacSha256_128),
                cbc(Encr::AesCbc256, Prf::HmacSha256, Integ::HmacSha256_128),
                cbc(Encr::AesCbc128, Prf::HmacSha1, Integ::HmacSha1_96),
                cbc(Encr::AesCbc256, Prf::HmacSha1, Integ::HmacSha1_96),
                gcm(Encr::AesGcm16_128, Prf::HmacSha256),
                gcm(Encr::AesGcm16_256, Prf::HmacSha256),
            ],
            // ECP-256 d'abord (arithmétique à temps constant) ; MODP-2048 en repli.
            dh_groups: vec![DhGroup::Ecp256, DhGroup::Modp2048],
            esp_proposals: vec![
                EspProposal {
                    encr: Encr::AesGcm16_128,
                    integ: None,
                },
                EspProposal {
                    encr: Encr::AesGcm16_256,
                    integ: None,
                },
                EspProposal {
                    encr: Encr::AesCbc128,
                    integ: Some(Integ::HmacSha256_128),
                },
                EspProposal {
                    encr: Encr::AesCbc256,
                    integ: Some(Integ::HmacSha256_128),
                },
                EspProposal {
                    encr: Encr::AesCbc128,
                    integ: Some(Integ::HmacSha1_96),
                },
            ],
            retransmit_base: Duration::from_secs(2),
            max_sends: 5,
            lifetimes: Lifetimes::default(),
            dpd_idle: Duration::from_secs(30),
            rekey_overlap: Duration::from_secs(10),
            rekey_retry: Duration::from_secs(60),
        }
    }
}

/// Raison d'échec.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FailReason {
    #[error("aucune réponse de la passerelle (timeout)")]
    Timeout,
    #[error("aucune proposition commune (NO_PROPOSAL_CHOSEN)")]
    NoProposalChosen,
    #[error("authentification refusée par la passerelle (notification {0})")]
    PeerNotify(u16),
    #[error("clé partagée (PSK) incorrecte : AUTH de la passerelle invalide")]
    GatewayAuthFailed,
    #[error("IDr de la passerelle différent de celui attendu")]
    IdrMismatch,
    #[error("méthode d'authentification de la passerelle refusée par la politique (méthode {0})")]
    GatewayAuthMethodRefused(u8),
    #[error("certificat de la passerelle absent ou non épinglé")]
    GatewayCertNotPinned,
    #[error("signature AUTH de la passerelle invalide : {0}")]
    GatewaySignatureInvalid(String),
    #[error("identifiants refusés (EAP-MSCHAPv2 / EAP Failure)")]
    CredentialsRejected,
    #[error("la passerelle n'a pas prouvé la connaissance du mot de passe (MS-CHAPv2 S=)")]
    ServerAuthFailed,
    #[error("pair injoignable (DPD sans réponse)")]
    DeadPeer,
    #[error("durée de vie maximale atteinte sans rekey")]
    Expired,
    #[error("erreur de protocole : {0}")]
    Protocol(String),
}

impl From<Error> for FailReason {
    fn from(e: Error) -> Self {
        Self::Protocol(e.to_string())
    }
}

fn proto(msg: &str) -> FailReason {
    FailReason::Protocol(msg.to_owned())
}

/// Paramètres de tunnel obtenus (CP reply + TS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    pub ip: [u8; 4],
    pub netmask: Option<[u8; 4]>,
    pub dns: Vec<[u8; 4]>,
    pub subnets: Vec<([u8; 4], [u8; 4])>,
    pub dns_domains: Vec<String>,
    /// TSi accepté par la passerelle.
    pub ts_local: Vec<TrafficSelector>,
    /// TSr accepté par la passerelle.
    pub ts_remote: Vec<TrafficSelector>,
}

/// CHILD SA négociée et son KEYMAT (RFC 7296 §2.17), pour l'ESP (story 6.2).
///
/// `*_out` : client → passerelle (i→r), `*_in` : passerelle → client. Les clés de chiffrement
/// GCM contiennent le sel de 4 octets en fin.
pub struct ChildSaKeys {
    /// SPI que nous avons annoncé (entrant).
    pub spi_in: u32,
    /// SPI choisi par la passerelle (à utiliser en émission).
    pub spi_out: u32,
    pub encr: Encr,
    pub integ: Option<Integ>,
    pub encr_key_out: Zeroizing<Vec<u8>>,
    pub integ_key_out: Zeroizing<Vec<u8>>,
    pub encr_key_in: Zeroizing<Vec<u8>>,
    pub integ_key_in: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for ChildSaKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChildSaKeys")
            .field("spi_in", &self.spi_in)
            .field("spi_out", &self.spi_out)
            .field("encr", &self.encr)
            .field("integ", &self.integ)
            .finish_non_exhaustive()
    }
}

/// KEYMAT = prf+(SK_d, Ni | Nr), découpé : ENCR_i→r | INTEG_i→r | ENCR_r→i | INTEG_r→i.
pub fn derive_child_keys(
    prf: Prf,
    sk_d: &[u8],
    ni: &[u8],
    nr: &[u8],
    esp: EspProposal,
    spi_in: u32,
    spi_out: u32,
) -> Result<ChildSaKeys, Error> {
    derive_child_keys_ex(prf, sk_d, None, ni, nr, esp, spi_in, spi_out, true)
}

/// Variante générale : `shared` = g^ir (rekey avec PFS), `initiator` = nous sommes l'initiateur
/// de la CHILD SA (sinon les blocs i→r / r→i sont permutés pour rester en vue « client »).
#[allow(clippy::too_many_arguments)]
pub fn derive_child_keys_ex(
    prf: Prf,
    sk_d: &[u8],
    shared: Option<&[u8]>,
    ni: &[u8],
    nr: &[u8],
    esp: EspProposal,
    spi_in: u32,
    spi_out: u32,
    initiator: bool,
) -> Result<ChildSaKeys, Error> {
    let e = esp.encr.key_len() + esp.encr.salt_len();
    let a = esp.integ.map_or(0, Integ::key_len);
    let mut seed = Vec::with_capacity(shared.map_or(0, <[u8]>::len) + ni.len() + nr.len());
    seed.extend_from_slice(shared.unwrap_or(&[]));
    seed.extend_from_slice(ni);
    seed.extend_from_slice(nr);
    let km = prf_plus(prf, sk_d, &seed, 2 * (e + a))?;
    let mut pos = 0;
    let mut take = |n: usize| {
        let v = Zeroizing::new(km[pos..pos + n].to_vec());
        pos += n;
        v
    };
    let (e1, a1, e2, a2) = (take(e), take(a), take(e), take(a));
    let ((encr_key_out, integ_key_out), (encr_key_in, integ_key_in)) = if initiator {
        ((e1, a1), (e2, a2))
    } else {
        ((e2, a2), (e1, a1))
    };
    Ok(ChildSaKeys {
        spi_in,
        spi_out,
        encr: esp.encr,
        integ: esp.integ,
        encr_key_out,
        integ_key_out,
        encr_key_in,
        integ_key_in,
    })
}

/// Événement applicatif.
#[derive(Debug)]
pub enum Event {
    Established {
        config: Box<TunnelConfig>,
        child_sa_keys: Box<ChildSaKeys>,
    },
    Failed(FailReason),
    /// Rekey de la CHILD SA abouti : émettre avec les nouvelles clés (`EspTunnel::rekey`) ;
    /// `old_spi` (ancien SPI entrant) reste accepté jusqu'à [`Event::OldChildExpired`].
    ChildRekeyed {
        keys: Box<ChildSaKeys>,
        old_spi: u32,
    },
    /// Fin de la fenêtre de transition : `EspTunnel::drop_old(spi)`.
    OldChildExpired {
        spi: u32,
    },
    /// Le tunnel est fermé (Delete reçu ou `close()`).
    Closed(CloseReason),
}

/// Cause d'un [`Event::Closed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Delete(IKE) reçu.
    PeerDeletedIke,
    /// Delete(ESP) reçu pour la CHILD SA courante.
    PeerDeletedChild,
    /// Fermeture demandée localement.
    Local,
}

/// Sortie de la machine d'états.
#[derive(Debug)]
pub enum Output {
    /// Charge UDP à envoyer vers `gateway:port` (marqueur non-ESP déjà inclus sur 4500).
    Send {
        port: u16,
        data: Vec<u8>,
    },
    Event(Event),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    AwaitInit,
    AwaitAuth1,
    AwaitEapChallenge,
    AwaitMsSuccess,
    AwaitEapSuccess,
    AwaitFinal,
    Established,
    Closed,
    Failed,
}

struct InitState {
    dh: DhKeypair,
    ni: Vec<u8>,
    msg1: Vec<u8>,
}

struct Sa {
    suite: IkeSuite,
    keys: SkKeys,
    spi_r: [u8; 8],
    ni: Vec<u8>,
    nr: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    idi_body: Vec<u8>,
    idr_body: Vec<u8>,
    child_spi_in: u32,
    resp: Option<ClientResponse>,
    msk: Option<Zeroizing<[u8; 64]>>,
}

struct Pending {
    data: Vec<u8>,
    port: u16,
    mid: u32,
    sends: u8,
    deadline: Instant,
    kind: ReqKind,
    /// SPI (i, r) de l'IKE SA sur laquelle la requête est partie.
    spis: ([u8; 8], [u8; 8]),
}

/// Initiateur IKEv2.
pub struct IkeInitiator {
    cfg: IkeConfig,
    rng: Box<dyn Entropy + Send>,
    phase: Phase,
    spi_i: [u8; 8],
    dh_idx: usize,
    cookie: Option<Vec<u8>>,
    init_restarts: u8,
    init: Option<InitState>,
    sa: Option<Sa>,
    next_mid: u32,
    gcm_counter: u64,
    pending: Option<Pending>,
    est: Option<Est>,
}

impl core::fmt::Debug for IkeInitiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IkeInitiator")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl IkeInitiator {
    pub fn new(cfg: IkeConfig, rng: Box<dyn Entropy + Send>) -> Result<Self, Error> {
        if cfg.ike_suites.is_empty() || cfg.dh_groups.is_empty() || cfg.esp_proposals.is_empty() {
            return Err(Error::Unsupported("configuration IKE/ESP vide"));
        }
        if cfg.responder_auth.accepts_psk() && cfg.psk.expose_secret().len() < MIN_PSK_LEN {
            return Err(Error::Unsupported(
                "PSK vide ou trop courte (< 8 caractères)",
            ));
        }
        if cfg.responder_auth.wants_cert() && cfg.responder_auth.pins().is_empty() {
            return Err(Error::Unsupported(
                "authentification par certificat sans empreinte épinglée",
            ));
        }
        if cfg.max_sends == 0 {
            return Err(Error::Unsupported("max_sends = 0"));
        }
        for e in &cfg.esp_proposals {
            if e.encr.is_aead() != e.integ.is_none() {
                return Err(Error::Unsupported("combinaison ESP ENCR/INTEG"));
            }
        }
        for s in &cfg.ike_suites {
            IkeSuite::new(s.encr, s.prf, s.integ)?;
        }
        Ok(Self {
            cfg,
            rng,
            phase: Phase::Idle,
            spi_i: [0; 8],
            dh_idx: 0,
            cookie: None,
            init_restarts: 0,
            init: None,
            sa: None,
            next_mid: 1,
            gcm_counter: 0,
            pending: None,
            est: None,
        })
    }

    /// Ouverture : produit IKE_SA_INIT. Sans effet hors de l'état initial.
    pub fn start(&mut self, now: Instant) -> Vec<Output> {
        let mut out = Vec::new();
        if self.phase != Phase::Idle {
            return out;
        }
        loop {
            self.rng.fill(&mut self.spi_i);
            if self.spi_i != [0; 8] {
                break;
            }
        }
        if let Err(r) = self.send_init(now, &mut out) {
            self.fail(r, &mut out);
        }
        out
    }

    /// Prochaine échéance de retransmission.
    pub fn next_deadline(&self) -> Option<Instant> {
        let p = self.pending.as_ref().map(|p| p.deadline);
        let e = self.est_deadline();
        match (p, e) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// `true` une fois terminé (établi ou échoué).
    pub fn is_finished(&self) -> bool {
        matches!(
            self.phase,
            Phase::Established | Phase::Closed | Phase::Failed
        )
    }

    /// Tick : retransmet ou abandonne si l'échéance est passée.
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<Output> {
        let mut out = Vec::new();
        if self.phase == Phase::Established {
            self.est_timeout(now, &mut out);
            return out;
        }
        let max = self.cfg.max_sends;
        let base = self.cfg.retransmit_base;
        let Some(p) = self.pending.as_mut() else {
            return out;
        };
        if now < p.deadline {
            return out;
        }
        if p.sends >= max {
            self.fail(FailReason::Timeout, &mut out);
            return out;
        }
        p.sends += 1;
        p.deadline = now + backoff(base, p.sends);
        out.push(Output::Send {
            port: p.port,
            data: p.data.clone(),
        });
        out
    }

    /// Datagramme reçu (port 500 ou 4500 ; le marqueur non-ESP est retiré si présent).
    pub fn handle_datagram(&mut self, now: Instant, data: &[u8]) -> Vec<Output> {
        let mut out = Vec::new();
        if matches!(self.phase, Phase::Idle | Phase::Closed | Phase::Failed) {
            return out;
        }
        let raw = if data.len() > 4 && data[..4] == [0; 4] {
            &data[4..]
        } else {
            data
        };
        if self.phase == Phase::Established {
            self.est_datagram(now, raw, &mut out);
            return out;
        }
        if let Err(r) = self.on_datagram(now, raw, &mut out) {
            self.fail(r, &mut out);
        }
        out
    }

    fn fail(&mut self, reason: FailReason, out: &mut Vec<Output>) {
        self.phase = Phase::Failed;
        self.pending = None;
        self.init = None;
        self.sa = None;
        self.est = None;
        out.push(Output::Event(Event::Failed(reason)));
    }

    // ---------- émission ----------

    fn new_keypair(&mut self, group: DhGroup) -> Result<DhKeypair, FailReason> {
        for _ in 0..8 {
            let mut k = Zeroizing::new([0u8; 32]);
            self.rng.fill(&mut k[..]);
            if let Ok(kp) = DhKeypair::new(group, &k[..]) {
                return Ok(kp);
            }
        }
        Err(proto("génération de clé DH impossible"))
    }

    fn arm(&mut self, now: Instant, port: u16, mid: u32, data: Vec<u8>, out: &mut Vec<Output>) {
        out.push(Output::Send {
            port,
            data: data.clone(),
        });
        self.pending = Some(Pending {
            data,
            port,
            mid,
            sends: 1,
            deadline: now + backoff(self.cfg.retransmit_base, 1),
            kind: ReqKind::Handshake,
            spis: (self.spi_i, self.sa.as_ref().map_or([0; 8], |s| s.spi_r)),
        });
    }

    fn send_init(&mut self, now: Instant, out: &mut Vec<Output>) -> Result<(), FailReason> {
        let group = self.cfg.dh_groups[self.dh_idx];
        let dh = self.new_keypair(group)?;
        let mut ni = vec![0u8; 32];
        self.rng.fill(&mut ni);
        let mut p = [0u8; 2];
        self.rng.fill(&mut p);
        let mut fake_port = u16::from_be_bytes(p);
        if fake_port == self.cfg.local_port {
            fake_port = fake_port.wrapping_add(1);
        }
        // SOURCE_IP volontairement faux : force l'encapsulation ESP-in-UDP 4500.
        let nat_src = nat_detection_hash(&self.spi_i, &[0; 8], self.cfg.local_ip, fake_port);
        let nat_dst = nat_detection_hash(&self.spi_i, &[0; 8], self.cfg.gateway_ip, IKE_PORT);

        let mut payloads = Vec::new();
        if let Some(c) = &self.cookie {
            payloads.push(Payload::Notify(Notify::new(notify::COOKIE, c.clone())));
        }
        payloads.push(Payload::Sa(self.ike_proposals()));
        payloads.push(Payload::Ke {
            group: group.id(),
            data: dh.public().to_vec(),
        });
        payloads.push(Payload::Nonce(ni.clone()));
        payloads.push(Payload::Notify(Notify::new(
            notify::NAT_DETECTION_SOURCE_IP,
            nat_src.to_vec(),
        )));
        payloads.push(Payload::Notify(Notify::new(
            notify::NAT_DETECTION_DESTINATION_IP,
            nat_dst.to_vec(),
        )));
        if self.cfg.responder_auth.wants_cert() {
            // RFC 7427 §4 : sans cette annonce, le répondeur ne peut pas utiliser la méthode 14.
            payloads.push(Payload::Notify(Notify::new(
                notify::SIGNATURE_HASH_ALGORITHMS,
                SIG_HASH_SHA2_256.to_be_bytes().to_vec(),
            )));
        }
        let header = Header {
            spi_i: self.spi_i,
            spi_r: [0; 8],
            next_payload: 0,
            exchange_type: exchange::IKE_SA_INIT,
            flags: flags::INITIATOR,
            message_id: 0,
            length: 0,
        };
        let msg = Message::encode(&header, &payloads)?;
        self.init = Some(InitState {
            dh,
            ni,
            msg1: msg.clone(),
        });
        self.phase = Phase::AwaitInit;
        self.arm(now, IKE_PORT, 0, msg, out);
        Ok(())
    }

    fn ike_proposals(&self) -> Vec<Proposal> {
        let mut v = Vec::new();
        for (i, s) in self.cfg.ike_suites.iter().enumerate() {
            let mut t = vec![encr_transform(s.encr)];
            t.push(Transform {
                ty: 2,
                id: s.prf.id(),
                key_len: None,
            });
            if let Some(i) = s.integ {
                t.push(Transform {
                    ty: 3,
                    id: integ_id(i),
                    key_len: None,
                });
            }
            for g in &self.cfg.dh_groups {
                t.push(Transform {
                    ty: 4,
                    id: g.id(),
                    key_len: None,
                });
            }
            v.push(Proposal {
                number: u8::try_from(i + 1).unwrap_or(u8::MAX),
                protocol: 1,
                spi: Vec::new(),
                transforms: t,
            });
        }
        v
    }

    fn esp_proposals(&self, spi: u32) -> Vec<Proposal> {
        let group = self.cfg.dh_groups[self.dh_idx];
        let mut v = Vec::new();
        for (i, e) in self.cfg.esp_proposals.iter().enumerate() {
            let mut t = vec![encr_transform(e.encr)];
            if let Some(i) = e.integ {
                t.push(Transform {
                    ty: 3,
                    id: integ_id(i),
                    key_len: None,
                });
            }
            t.push(Transform {
                ty: 4,
                id: group.id(),
                key_len: None,
            });
            t.push(Transform {
                ty: 5,
                id: 0,
                key_len: None,
            });
            v.push(Proposal {
                number: u8::try_from(i + 1).unwrap_or(u8::MAX),
                protocol: 3,
                spi: spi.to_be_bytes().to_vec(),
                transforms: t,
            });
        }
        v
    }

    /// Chiffre et arme l'envoi d'une requête IKE_AUTH sur 4500.
    fn send_auth_request(
        &mut self,
        now: Instant,
        inner: &[Payload],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        let mid = self.next_mid;
        self.next_mid += 1;
        let encr = self
            .sa
            .as_ref()
            .ok_or_else(|| proto("pas de SA"))?
            .suite
            .encr;
        let iv = if encr.is_aead() {
            self.gcm_counter += 1;
            self.gcm_counter.to_be_bytes().to_vec()
        } else {
            let mut v = vec![0u8; 16];
            self.rng.fill(&mut v);
            v
        };
        let sa = self.sa.as_ref().ok_or_else(|| proto("pas de SA"))?;
        let header = Header {
            spi_i: self.spi_i,
            spi_r: sa.spi_r,
            next_payload: 0,
            exchange_type: exchange::IKE_AUTH,
            flags: flags::INITIATOR,
            message_id: mid,
            length: 0,
        };
        let msg = sk::seal(&sa.suite, &sa.keys, true, &header, inner, &iv)?;
        let mut data = vec![0u8; 4];
        data.extend_from_slice(&msg);
        self.arm(now, NATT_PORT, mid, data, out);
        Ok(())
    }

    // ---------- réception ----------

    fn on_datagram(
        &mut self,
        now: Instant,
        raw: &[u8],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        // Un datagramme invalide (non authentifié) est simplement ignoré (RFC 7296 §2.21).
        let Ok(header) = Header::parse(raw) else {
            return Ok(());
        };
        let expected_mid = match &self.pending {
            Some(p) => p.mid,
            None => return Ok(()),
        };
        if header.spi_i != self.spi_i
            || header.flags & flags::RESPONSE == 0
            || header.message_id != expected_mid
        {
            return Ok(());
        }
        if self.phase == Phase::AwaitInit {
            if header.exchange_type != exchange::IKE_SA_INIT {
                return Ok(());
            }
            return self.on_init_response(now, raw, out);
        }
        if header.exchange_type != exchange::IKE_AUTH {
            return Ok(());
        }
        let payloads = {
            let Some(sa) = &self.sa else { return Ok(()) };
            if header.spi_r != sa.spi_r {
                return Ok(());
            }
            match sk::open(&sa.suite, &sa.keys, false, raw) {
                Ok((_, p)) => p,
                Err(_) => return Ok(()),
            }
        };
        self.pending = None;
        if let Some(f) = error_notify(&payloads) {
            return Err(f);
        }
        match self.phase {
            Phase::AwaitAuth1 => self.on_auth1(now, &payloads, out),
            Phase::AwaitEapChallenge => self.on_eap_challenge(now, &payloads, out),
            Phase::AwaitMsSuccess => self.on_ms_success(now, &payloads, out),
            Phase::AwaitEapSuccess => self.on_eap_success(now, &payloads, out),
            Phase::AwaitFinal => self.on_final(now, &payloads, out),
            _ => Ok(()),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn on_init_response(
        &mut self,
        now: Instant,
        raw: &[u8],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        let Ok(msg) = Message::decode(raw) else {
            return Ok(());
        };
        // Réponse IKE_SA_INIT non authentifiée : toute erreur est ignorée (l'attaquant sur le
        // chemin pourrait sinon tuer la connexion) jusqu'au timeout (RFC 7296 §2.21.1).
        for n in msg.notifies() {
            match n.ty {
                notify::INVALID_KE_PAYLOAD if n.data.len() == 2 => {
                    let want = u16::from_be_bytes([n.data[0], n.data[1]]);
                    let idx = self.cfg.dh_groups.iter().position(|g| g.id() == want);
                    return match idx {
                        Some(i) if i != self.dh_idx && self.init_restarts < MAX_INIT_RESTARTS => {
                            self.restart_init(now, Some(i), None, out)
                        }
                        _ => Ok(()),
                    };
                }
                notify::COOKIE => {
                    // RFC 7296 §3.10.1 : cookie de 1 à 64 octets.
                    if n.data.is_empty()
                        || n.data.len() > MAX_COOKIE_LEN
                        || self.init_restarts >= MAX_INIT_RESTARTS
                    {
                        return Ok(());
                    }
                    return self.restart_init(now, None, Some(n.data.clone()), out);
                }
                t if t < 16384 => return Ok(()),
                _ => {}
            }
        }
        if msg.header.spi_r == [0; 8] {
            return Ok(());
        }
        let mut sa_p = None;
        let mut ke = None;
        let mut nonce = None;
        for p in &msg.payloads {
            match p {
                Payload::Sa(v) => sa_p = Some(v),
                Payload::Ke { group, data } => ke = Some((*group, data)),
                Payload::Nonce(n) => nonce = Some(n),
                _ => {}
            }
        }
        let (Some(props), Some((kegroup, kedata)), Some(nr)) = (sa_p, ke, nonce) else {
            return Ok(());
        };
        let [prop] = props.as_slice() else {
            return Ok(());
        };
        let Ok(ch) = parse_chosen(prop, 1) else {
            return Ok(());
        };
        let (Some(prf), Some(dhg)) = (ch.prf, ch.dh) else {
            return Ok(());
        };
        let Ok(suite) = IkeSuite::new(ch.encr, prf, ch.integ) else {
            return Ok(());
        };
        if !self.cfg.ike_suites.contains(&suite)
            || dhg != self.cfg.dh_groups[self.dh_idx]
            || kegroup != dhg.id()
        {
            return Ok(());
        }
        let Some(init) = self.init.as_ref() else {
            return Ok(());
        };
        let Ok(shared) = init.dh.shared_secret(kedata) else {
            return Ok(());
        };
        let Ok(keys) = derive_sk_keys(
            &suite,
            &init.ni,
            nr,
            &self.spi_i,
            &msg.header.spi_r,
            &shared,
        ) else {
            return Ok(());
        };
        let Some(init) = self.init.take() else {
            return Ok(());
        };
        let mut spi_buf = [0u8; 4];
        let child_spi_in = loop {
            self.rng.fill(&mut spi_buf);
            let v = u32::from_be_bytes(spi_buf);
            if v > 255 {
                break v;
            }
        };
        let idi_body = id_body(self.cfg.idi.0, &self.cfg.idi.1);
        self.sa = Some(Sa {
            suite,
            keys,
            spi_r: msg.header.spi_r,
            ni: init.ni,
            nr: nr.clone(),
            msg1: init.msg1,
            msg2: raw.to_vec(),
            idi_body,
            idr_body: Vec::new(),
            child_spi_in,
            resp: None,
            msk: None,
        });
        self.pending = None;
        let mut inner = vec![Payload::Id {
            responder: false,
            id_type: self.cfg.idi.0,
            data: self.cfg.idi.1.clone(),
        }];
        if self.cfg.responder_auth.wants_cert() {
            // CERTREQ sans liste d'AC : la confiance repose sur l'épinglage du certificat feuille.
            inner.push(Payload::CertReq {
                encoding: CERT_ENCODING_X509,
                data: Vec::new(),
            });
        }
        inner.extend([
            Payload::Notify(Notify::new(notify::INITIAL_CONTACT, Vec::new())),
            Payload::Cp(Cp::request()),
            Payload::Sa(self.esp_proposals(child_spi_in)),
            Payload::Ts {
                responder: false,
                selectors: vec![TrafficSelector::any()],
            },
            Payload::Ts {
                responder: true,
                selectors: vec![TrafficSelector::any()],
            },
        ]);
        self.phase = Phase::AwaitAuth1;
        self.send_auth_request(now, &inner, out)
    }

    fn restart_init(
        &mut self,
        now: Instant,
        dh_idx: Option<usize>,
        cookie: Option<Vec<u8>>,
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        self.init_restarts += 1;
        if self.init_restarts > MAX_INIT_RESTARTS {
            return Err(proto("trop de relances d'IKE_SA_INIT"));
        }
        if let Some(i) = dh_idx {
            self.dh_idx = i;
        }
        if cookie.is_some() {
            self.cookie = cookie;
        }
        self.pending = None;
        self.send_init(now, out)
    }

    fn on_auth1(
        &mut self,
        now: Instant,
        payloads: &[Payload],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        let mut idr = None;
        let mut auth = None;
        let mut eap = None;
        let mut cert = None;
        for p in payloads {
            match p {
                // RFC 7296 §3.6 : le premier CERT porte la clé qui vérifie l'AUTH.
                Payload::Cert { encoding, data } if cert.is_none() => {
                    cert = Some((*encoding, data));
                }
                Payload::Id {
                    responder: true,
                    id_type,
                    data,
                } => idr = Some((*id_type, data)),
                Payload::Auth { method, data } => auth = Some((*method, data)),
                Payload::Eap(e) => eap = Some(e),
                _ => {}
            }
        }
        let (Some((idt, idd)), Some((method, auth_data)), Some(eap)) = (idr, auth, eap) else {
            return Err(proto("IKE_AUTH : IDr/AUTH/EAP manquant"));
        };
        if let Some((t, d)) = &self.cfg.expected_idr
            && (*t != idt || d != idd)
        {
            return Err(FailReason::IdrMismatch);
        }
        let idr_body = id_body(idt, idd);
        let sa = self.sa.as_mut().ok_or_else(|| proto("pas de SA"))?;
        let policy = &self.cfg.responder_auth;
        match method {
            AUTH_METHOD_PSK => {
                if !policy.accepts_psk() {
                    return Err(FailReason::GatewayAuthMethodRefused(method));
                }
                let expect = auth_value(
                    sa.suite.prf,
                    self.cfg.psk.expose_secret().as_bytes(),
                    &sa.msg2,
                    &sa.ni,
                    &sa.keys.sk_pr,
                    &idr_body,
                );
                if !ct_eq(&expect, auth_data) {
                    return Err(FailReason::GatewayAuthFailed);
                }
            }
            AUTH_METHOD_RSA_SIG | AUTH_METHOD_DIGITAL_SIG => {
                if policy.pins().is_empty() {
                    return Err(FailReason::GatewayAuthMethodRefused(method));
                }
                let Some((CERT_ENCODING_X509, cert_der)) = cert else {
                    return Err(FailReason::GatewayCertNotPinned);
                };
                // Épinglage d'abord : aucune analyse ASN.1 d'un certificat non approuvé.
                if !pin_matches(cert_der, policy.pins()) {
                    return Err(FailReason::GatewayCertNotPinned);
                }
                let signed =
                    signed_octets(sa.suite.prf, &sa.msg2, &sa.ni, &sa.keys.sk_pr, &idr_body);
                verify_auth(method, auth_data, &signed, cert_der)
                    .map_err(|e| FailReason::GatewaySignatureInvalid(e.to_string()))?;
            }
            m => return Err(FailReason::GatewayAuthMethodRefused(m)),
        }
        sa.idr_body = idr_body;
        // Gateway authentifiée : seulement maintenant l'identité EAP part.
        let pkt = EapPacket::parse(eap)?;
        if pkt.code != 1 || pkt.data.first() != Some(&1) {
            return Err(proto("EAP Request/Identity attendu"));
        }
        let resp = EapPacket::identity_response(pkt.id, &self.cfg.username).encode()?;
        self.phase = Phase::AwaitEapChallenge;
        self.send_auth_request(now, &[Payload::Eap(resp)], out)
    }

    fn eap_packet(payloads: &[Payload]) -> Result<EapPacket, FailReason> {
        let e = payloads
            .iter()
            .find_map(|p| {
                if let Payload::Eap(e) = p {
                    Some(e)
                } else {
                    None
                }
            })
            .ok_or_else(|| proto("payload EAP manquant"))?;
        Ok(EapPacket::parse(e)?)
    }

    fn on_eap_challenge(
        &mut self,
        now: Instant,
        payloads: &[Payload],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        let pkt = Self::eap_packet(payloads)?;
        if pkt.code == 4 {
            return Err(FailReason::CredentialsRejected);
        }
        if pkt.code != 1 || pkt.data.first() != Some(&EAP_TYPE_MSCHAPV2) {
            return Err(proto("EAP-MSCHAPv2 Challenge attendu"));
        }
        match MsChapV2::parse(&pkt.data)? {
            MsChapV2::Challenge { id, challenge, .. } => {
                let mut peer = [0u8; 16];
                self.rng.fill(&mut peer);
                let r = respond(
                    id,
                    &challenge,
                    &peer,
                    &self.cfg.username,
                    &self.cfg.password,
                )?;
                let reply = EapPacket {
                    code: 2,
                    id: pkt.id,
                    data: r.eap_data.clone(),
                }
                .encode()?;
                self.sa.as_mut().ok_or_else(|| proto("pas de SA"))?.resp = Some(r);
                self.phase = Phase::AwaitMsSuccess;
                self.send_auth_request(now, &[Payload::Eap(reply)], out)
            }
            MsChapV2::Failure { .. } => Err(FailReason::CredentialsRejected),
            _ => Err(proto("opcode MS-CHAPv2 inattendu")),
        }
    }

    fn on_ms_success(
        &mut self,
        now: Instant,
        payloads: &[Payload],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        let pkt = Self::eap_packet(payloads)?;
        if pkt.code == 4 {
            return Err(FailReason::CredentialsRejected);
        }
        if pkt.code != 1 || pkt.data.first() != Some(&EAP_TYPE_MSCHAPV2) {
            return Err(proto("EAP-MSCHAPv2 Success attendu"));
        }
        match MsChapV2::parse(&pkt.data)? {
            MsChapV2::Success { id, message } => {
                let sa = self.sa.as_ref().ok_or_else(|| proto("pas de SA"))?;
                let resp = sa.resp.as_ref().ok_or_else(|| proto("pas de Response"))?;
                if !verify_success(&message, &self.cfg.password, resp, &self.cfg.username) {
                    return Err(FailReason::ServerAuthFailed);
                }
                let reply = EapPacket {
                    code: 2,
                    id: pkt.id,
                    data: MsChapV2::Success {
                        id,
                        message: Vec::new(),
                    }
                    .encode()?,
                }
                .encode()?;
                self.phase = Phase::AwaitEapSuccess;
                self.send_auth_request(now, &[Payload::Eap(reply)], out)
            }
            MsChapV2::Failure { .. } => Err(FailReason::CredentialsRejected),
            _ => Err(proto("opcode MS-CHAPv2 inattendu")),
        }
    }

    fn on_eap_success(
        &mut self,
        now: Instant,
        payloads: &[Payload],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        let pkt = Self::eap_packet(payloads)?;
        match pkt.code {
            3 => {}
            4 => return Err(FailReason::CredentialsRejected),
            _ => return Err(proto("EAP Success attendu")),
        }
        let sa = self.sa.as_mut().ok_or_else(|| proto("pas de SA"))?;
        let nt = sa
            .resp
            .as_ref()
            .ok_or_else(|| proto("pas de Response"))?
            .nt_response;
        let msk = eap_msk(&self.cfg.password, &nt);
        let auth = auth_value(
            sa.suite.prf,
            &msk[..],
            &sa.msg1,
            &sa.nr,
            &sa.keys.sk_pi,
            &sa.idi_body,
        );
        sa.msk = Some(msk);
        self.phase = Phase::AwaitFinal;
        self.send_auth_request(
            now,
            &[Payload::Auth {
                method: AUTH_METHOD_PSK,
                data: auth.to_vec(),
            }],
            out,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn on_final(
        &mut self,
        now: Instant,
        payloads: &[Payload],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        let sa = self.sa.as_ref().ok_or_else(|| proto("pas de SA"))?;
        let msk = sa.msk.as_ref().ok_or_else(|| proto("pas de MSK"))?;
        let mut auth = None;
        let mut cp = None;
        let mut sa_p = None;
        let mut tsi = None;
        let mut tsr = None;
        for p in payloads {
            match p {
                Payload::Auth { method, data } => auth = Some((*method, data)),
                Payload::Cp(c) => cp = Some(c),
                Payload::Sa(v) => sa_p = Some(v),
                Payload::Ts {
                    responder: false,
                    selectors,
                } => tsi = Some(selectors),
                Payload::Ts {
                    responder: true,
                    selectors,
                } => tsr = Some(selectors),
                _ => {}
            }
        }
        let Some((method, auth_data)) = auth else {
            return Err(proto("AUTH final manquant"));
        };
        let expect = auth_value(
            sa.suite.prf,
            &msk[..],
            &sa.msg2,
            &sa.ni,
            &sa.keys.sk_pr,
            &sa.idr_body,
        );
        if method != AUTH_METHOD_PSK || !ct_eq(&expect, auth_data) {
            return Err(FailReason::GatewayAuthFailed);
        }
        let (Some(cp), Some(props), Some(tsi), Some(tsr)) = (cp, sa_p, tsi, tsr) else {
            return Err(proto("réponse finale : CP/SA/TS manquant"));
        };
        if cp.cfg_type != 2 {
            return Err(proto("CP : CFG_REPLY attendu"));
        }
        let ip = cp
            .ip4_address()
            .ok_or_else(|| proto("CP sans adresse IP"))?;
        validate_cp(cp, ip)?;
        if !ts_valid(tsi) || !ts_valid(tsr) {
            return Err(proto("TS invalide"));
        }
        let [prop] = props.as_slice() else {
            return Err(proto("CHILD SA : une proposition attendue"));
        };
        if prop.protocol != 3 || prop.spi.len() != 4 {
            return Err(proto("CHILD SA : proposition ESP invalide"));
        }
        let ch = parse_chosen(prop, 3)?;
        let esp = EspProposal {
            encr: ch.encr,
            integ: ch.integ,
        };
        if !self.cfg.esp_proposals.contains(&esp) {
            return Err(proto("CHILD SA : transforms non proposés"));
        }
        let spi_out = u32::from_be_bytes([prop.spi[0], prop.spi[1], prop.spi[2], prop.spi[3]]);
        let keys = derive_child_keys(
            sa.suite.prf,
            &sa.keys.sk_d,
            &sa.ni,
            &sa.nr,
            esp,
            sa.child_spi_in,
            spi_out,
        )?;
        let config = TunnelConfig {
            ip,
            netmask: cp.ip4_netmask(),
            dns: cp.ip4_dns(),
            subnets: cp.ip4_subnets(),
            dns_domains: cp.dns_domains(),
            ts_local: tsi.clone(),
            ts_remote: tsr.clone(),
        };
        let (suite, spi_r, child_spi_in) = (sa.suite, sa.spi_r, sa.child_spi_in);
        let sa = self.sa.take().ok_or_else(|| proto("pas de SA"))?;
        self.est = Some(Est::new(
            now,
            &self.cfg,
            IkeSa::new(suite, sa.keys, self.spi_i, spi_r, true, self.next_mid),
            established::ChildInfo {
                spi_in: child_spi_in,
                spi_out,
            },
            self.cfg.dh_groups[self.dh_idx],
            (tsi.clone(), tsr.clone()),
        ));
        self.phase = Phase::Established;
        out.push(Output::Event(Event::Established {
            config: Box::new(config),
            child_sa_keys: Box::new(keys),
        }));
        Ok(())
    }
}

/// Adresse unicast utilisable (ni nulle, ni loopback, ni multicast/réservée, ni broadcast).
fn is_unicast(a: [u8; 4]) -> bool {
    a[0] != 0 && a[0] != 127 && a[0] < 224
}

/// Masque contiguë (1...10...0).
fn mask_ok(m: [u8; 4]) -> bool {
    let v = u32::from_be_bytes(m);
    v.leading_ones() + v.trailing_zeros() == 32
}

/// Liste de traffic selectors reçue : non vide, bornée, bien formée.
pub(crate) fn ts_valid(ts: &[TrafficSelector]) -> bool {
    !ts.is_empty() && ts.len() <= 64 && ts.iter().all(TrafficSelector::is_valid)
}

/// Validation des attributs CP reçus (la passerelle est authentifiée, mais on limite la portée
/// d'une passerelle compromise ou bogguée).
fn validate_cp(cp: &Cp, ip: [u8; 4]) -> Result<(), FailReason> {
    if !is_unicast(ip) {
        return Err(proto("CP : adresse IP interne invalide"));
    }
    if let Some(m) = cp.ip4_netmask()
        && (!mask_ok(m) || m == [0; 4])
    {
        return Err(proto("CP : masque de réseau invalide"));
    }
    let dns = cp.ip4_dns();
    if dns.len() > 8 || !dns.iter().all(|d| is_unicast(*d)) {
        return Err(proto("CP : serveur DNS invalide"));
    }
    let subnets = cp.ip4_subnets();
    if subnets.len() > 64 || !subnets.iter().all(|(_, m)| mask_ok(*m)) {
        return Err(proto("CP : sous-réseau invalide"));
    }
    Ok(())
}

fn backoff(base: Duration, sends: u8) -> Duration {
    base * (1u32 << u32::from(sends.saturating_sub(1).min(3)))
}

fn encr_transform(e: Encr) -> Transform {
    let id = if e.is_aead() { 20 } else { 12 };
    Transform {
        ty: 1,
        id,
        key_len: u16::try_from(e.key_len() * 8).ok(),
    }
}

fn integ_id(i: Integ) -> u16 {
    match i {
        Integ::HmacSha1_96 => 2,
        Integ::HmacSha256_128 => 12,
    }
}

/// Première notification d'erreur (type < 16384) d'un message authentifié.
fn error_notify(payloads: &[Payload]) -> Option<FailReason> {
    payloads.iter().find_map(|p| match p {
        Payload::Notify(n) if n.ty < 16384 => Some(match n.ty {
            NO_PROPOSAL_CHOSEN => FailReason::NoProposalChosen,
            t => FailReason::PeerNotify(t),
        }),
        _ => None,
    })
}

struct Chosen {
    encr: Encr,
    prf: Option<Prf>,
    integ: Option<Integ>,
    dh: Option<DhGroup>,
}

/// Interprète la proposition retenue par le pair (un transform par type, ESN = 0).
fn parse_chosen(p: &Proposal, protocol: u8) -> Result<Chosen, FailReason> {
    if p.protocol != protocol {
        return Err(proto("protocole de proposition inattendu"));
    }
    let (mut encr, mut prf, mut integ, mut dh) = (None, None, None, None);
    for t in &p.transforms {
        let dup = match t.ty {
            1 => encr
                .replace(Encr::from_id(t.id, t.key_len.unwrap_or(0))?)
                .is_some(),
            2 => prf.replace(Prf::from_id(t.id)?).is_some(),
            3 => integ.replace(Integ::from_id(t.id)?).is_some(),
            4 => dh.replace(DhGroup::from_id(t.id)?).is_some(),
            5 if t.id == 0 => false,
            _ => return Err(proto("transform inattendu")),
        };
        if dup {
            return Err(proto("transform dupliqué"));
        }
    }
    Ok(Chosen {
        encr: encr.ok_or_else(|| proto("transform ENCR manquant"))?,
        prf,
        integ,
        dh,
    })
}

#[cfg(test)]
mod cp_validation_tests {
    use super::*;
    use crate::wire::{CpAttr, cp_attr};

    fn attr(ty: u16, v: &[u8]) -> CpAttr {
        CpAttr {
            ty,
            value: v.to_vec(),
        }
    }

    fn cp(attrs: Vec<CpAttr>) -> Cp {
        Cp { cfg_type: 2, attrs }
    }

    #[test]
    fn accepts_sane_config() {
        let c = cp(vec![
            attr(cp_attr::INTERNAL_IP4_NETMASK, &[255, 255, 255, 0]),
            attr(cp_attr::INTERNAL_IP4_DNS, &[10, 0, 0, 53]),
            attr(cp_attr::INTERNAL_IP4_SUBNET, &[10, 1, 0, 0, 255, 255, 0, 0]),
        ]);
        assert!(validate_cp(&c, [10, 0, 0, 7]).is_ok());
    }

    #[test]
    fn rejects_bad_values() {
        let ok = cp(vec![]);
        for ip in [[0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
            assert!(validate_cp(&ok, ip).is_err(), "{ip:?}");
        }
        let bad_mask = cp(vec![attr(cp_attr::INTERNAL_IP4_NETMASK, &[255, 0, 255, 0])]);
        assert!(validate_cp(&bad_mask, [10, 0, 0, 7]).is_err());
        let zero_mask = cp(vec![attr(cp_attr::INTERNAL_IP4_NETMASK, &[0; 4])]);
        assert!(validate_cp(&zero_mask, [10, 0, 0, 7]).is_err());
        let bad_dns = cp(vec![attr(cp_attr::INTERNAL_IP4_DNS, &[0, 0, 0, 0])]);
        assert!(validate_cp(&bad_dns, [10, 0, 0, 7]).is_err());
        let bad_sub = cp(vec![attr(
            cp_attr::INTERNAL_IP4_SUBNET,
            &[10, 0, 0, 0, 255, 0, 255, 0],
        )]);
        assert!(validate_cp(&bad_sub, [10, 0, 0, 7]).is_err());
    }

    #[test]
    fn ts_validation() {
        assert!(!ts_valid(&[]));
        assert!(ts_valid(&[TrafficSelector::any()]));
        assert!(!ts_valid(&vec![TrafficSelector::any(); 65]));
    }
}
