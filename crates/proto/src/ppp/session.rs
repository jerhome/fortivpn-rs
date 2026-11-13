//! Automate PPP client « sans I/O » : LCP + IPCP + keepalive (§9.2–§9.8, §11).
//!
//! Entrées : [`PppSession::open`], [`PppSession::close`], [`PppSession::handle_frame`]
//! (trame PPP sortie de [`crate::frame::decode_frame`]) et
//! [`PppSession::handle_timeout`] ; l'instant courant est toujours fourni par l'appelant.
//! Sorties : trames PPP à encapsuler ([`PppSession::poll_transmit`]), événements
//! ([`PppSession::poll_event`]) et prochaine échéance ([`PppSession::poll_timeout`]).
//!
//! Simplifications documentées (§9.3) : un seul compteur de Configure-Request par
//! protocole (retransmissions + renvois après Nak/Reject, plafonné à
//! [`PppConfig::max_configure`]) ; toute renégociation après ouverture est traitée
//! comme une fin de session ([`DownReason::Renegotiation`]).

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use super::options::{ConfigOption, IpcpOption, LcpOption, encode_options};
use super::packet::{Code, ControlPacket, Packet, Protocol};

/// MRU par défaut (`pppd mru 1354` lancé par openfortivpn).
pub const DEFAULT_MRU: u16 = 1354;
/// MRU supposé du pair s'il n'en annonce pas (RFC 1661).
const RFC_DEFAULT_MRU: u16 = 1500;
/// Bornes d'acceptation d'un Nak sur notre MRU (§9.2).
const NAK_MRU_RANGE: std::ops::RangeInclusive<u16> = 576..=1500;

/// Paramètres de l'automate. Défauts : §9.2 et §11.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PppConfig {
    /// MRU proposé (défaut 1354).
    pub mru: u16,
    /// Magic-Number local (aléatoire, fourni par l'appelant pour le déterminisme).
    pub magic: NonZeroU32,
    /// Demander les DNS 129/131 dans IPCP (défaut vrai).
    pub request_dns: bool,
    /// Délai de retransmission des Configure-Request (défaut 3 s).
    pub restart_interval: Duration,
    /// Nombre maximal de Configure-Request par protocole (défaut 10).
    pub max_configure: u32,
    /// Intervalle d'inactivité en réception avant Echo-Request (défaut 30 s ; `None`
    /// désactive le keepalive).
    pub echo_interval: Option<Duration>,
    /// Nombre d'Echo-Request sans réponse avant [`DownReason::DeadPeer`] (défaut 4).
    pub echo_max_failures: u32,
    /// Attente du Terminate-Ack après notre Terminate-Request (défaut 1 s).
    pub terminate_timeout: Duration,
}

impl PppConfig {
    /// Configuration par défaut avec le magic donné.
    pub fn new(magic: NonZeroU32) -> Self {
        Self {
            mru: DEFAULT_MRU,
            magic,
            request_dns: true,
            restart_interval: Duration::from_secs(3),
            max_configure: 10,
            echo_interval: Some(Duration::from_secs(30)),
            echo_max_failures: 4,
            terminate_timeout: Duration::from_secs(1),
        }
    }
}

/// Raison de la fin de session PPP (§12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DownReason {
    /// Nombre maximal de Configure-Request atteint, ou option indispensable refusée
    /// (`PppNegotiationFailed`).
    #[error("échec de la négociation PPP ({0})")]
    NegotiationFailed(Protocol),
    /// Echo-Request sans réponse (`DeadPeer`).
    #[error("la passerelle ne répond plus (LCP echo)")]
    DeadPeer,
    /// Terminate-Request reçu de la passerelle (`ClosedByPeer`).
    #[error("session fermée par la passerelle")]
    ClosedByPeer,
    /// Fermeture demandée localement (Terminate-Ack reçu ou délai écoulé).
    #[error("session fermée localement")]
    LocalClose,
    /// La passerelle a relancé une négociation sur un lien ouvert (traité comme une
    /// coupure, §9.3).
    #[error("renégociation {0} demandée par la passerelle")]
    Renegotiation(Protocol),
    /// La passerelle a rejeté un protocole indispensable (Protocol-Reject d'IPCP).
    #[error("protocole {0} rejeté par la passerelle")]
    ProtocolRejected(Protocol),
}

/// Événement produit par l'automate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PppEvent {
    /// IPCP ouvert : l'interface peut être configurée.
    IpcpUp {
        /// Adresse locale (IPCP fait foi, §5.3).
        local_ip: Ipv4Addr,
        /// DNS obtenus par IPCP (primaire puis secondaire, adresses nulles omises).
        dns: Vec<Ipv4Addr>,
        /// Adresse PPP annoncée par la passerelle (`None` pour la variante vide).
        peer: Option<Ipv4Addr>,
        /// MTU de l'interface : min(MRU du pair, notre MRU).
        mtu: u16,
    },
    /// Datagramme IPv4 reçu (sans en-tête PPP).
    Ipv4(Bytes),
    /// Fin de session ; l'automate est désormais inerte.
    Down(DownReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpState {
    Initial,
    ReqSent,
    AckRcvd,
    AckSent,
    Opened,
}

/// État d'un protocole de contrôle (LCP ou IPCP).
#[derive(Debug)]
struct Cp {
    state: CpState,
    next_id: u8,
    req_id: u8,
    /// Options de notre requête courante, sérialisées (comparées à l'Ack).
    req_opts: Bytes,
    sent: u32,
    deadline: Option<Instant>,
}

impl Cp {
    fn new() -> Self {
        Self {
            state: CpState::Initial,
            next_id: 1,
            req_id: 0,
            req_opts: Bytes::new(),
            sent: 0,
            deadline: None,
        }
    }

    fn alloc_id(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn is_negotiating(&self) -> bool {
        matches!(
            self.state,
            CpState::ReqSent | CpState::AckRcvd | CpState::AckSent
        )
    }

    fn answers_current(&self, p: &ControlPacket) -> bool {
        self.is_negotiating() && p.id() == self.req_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Initial,
    Active,
    Closing,
    Closed,
}

/// Réponse à un Configure-Request du pair.
enum Verdict {
    Ack,
    Nak(Vec<ConfigOption>),
    Reject(Vec<ConfigOption>),
}

fn verdict(rejected: Vec<ConfigOption>, naked: Vec<ConfigOption>) -> Verdict {
    if !rejected.is_empty() {
        Verdict::Reject(rejected)
    } else if !naked.is_empty() {
        Verdict::Nak(naked)
    } else {
        Verdict::Ack
    }
}

/// Automate PPP client (LCP + IPCP + keepalive), piloté par événements.
#[derive(Debug)]
pub struct PppSession {
    cfg: PppConfig,
    phase: Phase,
    lcp: Cp,
    ipcp: Cp,
    // Options LCP locales (`None` = rejetée/abandonnée).
    our_mru: Option<u16>,
    our_magic: Option<u32>,
    peer_mru: u16,
    magic_rng: u32,
    // Options IPCP locales (`None` = non demandée/rejetée).
    local_ip: Ipv4Addr,
    dns1: Option<Ipv4Addr>,
    dns2: Option<Ipv4Addr>,
    peer_ip: Option<Ipv4Addr>,
    // Keepalive.
    echo_deadline: Option<Instant>,
    echo_outstanding: u32,
    // Fermeture locale.
    term_deadline: Option<Instant>,
    transmit: VecDeque<Bytes>,
    events: VecDeque<PppEvent>,
}

impl PppSession {
    /// Taille maximale d'un Code-Reject / Protocol-Reject : bornée par le MRU du pair
    /// **et** par la limite du framing 0x5050 (2 octets de protocole PPP inclus dans
    /// `MAX_PPP_LEN`). Sans la seconde borne, un MRU pair ≥ 65532 produirait une trame
    /// impossible à encoder (bug trouvé par le fuzzing, story 5.2).
    fn reject_room(&self) -> usize {
        usize::from(self.peer_mru).min(crate::frame::MAX_PPP_LEN - 2)
    }

    /// Crée un automate fermé ; appeler [`open`](Self::open) pour démarrer.
    pub fn new(cfg: PppConfig) -> Self {
        let dns = cfg.request_dns.then_some(Ipv4Addr::UNSPECIFIED);
        Self {
            our_mru: Some(cfg.mru),
            our_magic: Some(cfg.magic.get()),
            magic_rng: cfg.magic.get(),
            peer_mru: RFC_DEFAULT_MRU,
            local_ip: Ipv4Addr::UNSPECIFIED,
            dns1: dns,
            dns2: dns,
            peer_ip: None,
            phase: Phase::Initial,
            lcp: Cp::new(),
            ipcp: Cp::new(),
            echo_deadline: None,
            echo_outstanding: 0,
            term_deadline: None,
            transmit: VecDeque::new(),
            events: VecDeque::new(),
            cfg,
        }
    }

    /// Démarre la négociation : émet le LCP Configure-Request (§9.3). Sans effet si
    /// déjà ouvert ou terminé.
    pub fn open(&mut self, now: Instant) {
        if self.phase != Phase::Initial {
            return;
        }
        self.phase = Phase::Active;
        self.lcp.state = CpState::ReqSent;
        self.send_lcp_confreq(now);
    }

    /// Ferme la session : Terminate-Request unique puis attente du Terminate-Ack au plus
    /// [`PppConfig::terminate_timeout`] (§9.8). Produit [`DownReason::LocalClose`].
    pub fn close(&mut self, now: Instant) {
        match self.phase {
            Phase::Initial => self.down(DownReason::LocalClose),
            Phase::Active => {
                let id = self.lcp.alloc_id();
                self.send_control(Protocol::LCP, Code::TerminateRequest, id, Bytes::new());
                self.phase = Phase::Closing;
                self.lcp.deadline = None;
                self.ipcp.deadline = None;
                self.echo_deadline = None;
                self.term_deadline = Some(now + self.cfg.terminate_timeout);
            }
            Phase::Closing | Phase::Closed => {}
        }
    }

    /// Traite une trame PPP reçue (protocole + information, sans en-tête `0x5050`).
    /// Les trames mal formées sont ignorées.
    pub fn handle_frame(&mut self, now: Instant, frame: Bytes) {
        if matches!(self.phase, Phase::Initial | Phase::Closed) {
            return;
        }
        let Ok(packet) = Packet::parse(frame) else {
            return;
        };
        if self.phase == Phase::Closing {
            if let Packet::Lcp(p) = &packet {
                match p.code() {
                    Code::TerminateAck => self.down(DownReason::LocalClose),
                    Code::TerminateRequest => {
                        self.send_control(Protocol::LCP, Code::TerminateAck, p.id(), Bytes::new());
                        self.down(DownReason::LocalClose);
                    }
                    _ => {}
                }
            }
            return;
        }
        // Toute réception prouve que le pair est vivant (§9.7).
        if self.lcp.state == CpState::Opened {
            self.arm_echo(now);
        }
        match packet {
            Packet::Lcp(p) => self.handle_lcp(now, &p),
            Packet::Ipcp(p) => {
                if self.lcp.state == CpState::Opened {
                    self.handle_ipcp(now, &p);
                }
            }
            Packet::Ipv4(ip) => {
                if self.ipcp.state == CpState::Opened {
                    self.events.push_back(PppEvent::Ipv4(ip));
                }
            }
            Packet::Other(f) => {
                if self.lcp.state == CpState::Opened {
                    let id = self.lcp.alloc_id();
                    let rej = ControlPacket::protocol_reject(
                        id,
                        f.protocol,
                        &f.payload,
                        self.reject_room(),
                    );
                    self.transmit.push_back(rej.to_frame(Protocol::LCP));
                }
            }
        }
    }

    /// Traite les échéances atteintes à `now` (retransmissions, keepalive, fermeture).
    pub fn handle_timeout(&mut self, now: Instant) {
        match self.phase {
            Phase::Closing => {
                if self.term_deadline.is_some_and(|d| d <= now) {
                    self.down(DownReason::LocalClose);
                }
            }
            Phase::Active => {
                if self.lcp.deadline.is_some_and(|d| d <= now) {
                    if self.lcp.state == CpState::AckRcvd {
                        self.lcp.state = CpState::ReqSent;
                    }
                    self.send_lcp_confreq(now);
                }
                if self.phase == Phase::Active && self.ipcp.deadline.is_some_and(|d| d <= now) {
                    if self.ipcp.state == CpState::AckRcvd {
                        self.ipcp.state = CpState::ReqSent;
                    }
                    self.send_ipcp_confreq(now);
                }
                if self.phase == Phase::Active && self.echo_deadline.is_some_and(|d| d <= now) {
                    self.echo_tick(now);
                }
            }
            Phase::Initial | Phase::Closed => {}
        }
    }

    /// Prochaine échéance à laquelle appeler [`handle_timeout`](Self::handle_timeout).
    pub fn poll_timeout(&self) -> Option<Instant> {
        match self.phase {
            Phase::Active => [self.lcp.deadline, self.ipcp.deadline, self.echo_deadline]
                .into_iter()
                .flatten()
                .min(),
            Phase::Closing => self.term_deadline,
            Phase::Initial | Phase::Closed => None,
        }
    }

    /// Prochaine trame PPP à émettre (à encapsuler avec [`crate::frame::encode_frame`]).
    pub fn poll_transmit(&mut self) -> Option<Bytes> {
        self.transmit.pop_front()
    }

    /// Prochain événement.
    pub fn poll_event(&mut self) -> Option<PppEvent> {
        self.events.pop_front()
    }

    /// Vrai quand IPCP est ouvert : les datagrammes IPv4 peuvent être émis
    /// (via [`crate::frame::encode_ppp_frame`] avec [`Protocol::IPV4`]).
    pub fn is_ip_up(&self) -> bool {
        self.phase == Phase::Active && self.ipcp.state == CpState::Opened
    }

    /// Vrai une fois la session terminée.
    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    /// MTU de l'interface : min(MRU du pair, notre MRU) (§9.2).
    pub fn mtu(&self) -> u16 {
        self.peer_mru.min(self.our_mru.unwrap_or(RFC_DEFAULT_MRU))
    }

    // ---------------------------------------------------------------- interne

    fn down(&mut self, reason: DownReason) {
        if self.phase == Phase::Closed {
            return;
        }
        self.phase = Phase::Closed;
        self.lcp.deadline = None;
        self.ipcp.deadline = None;
        self.echo_deadline = None;
        self.term_deadline = None;
        self.events.push_back(PppEvent::Down(reason));
    }

    fn send_control(&mut self, protocol: Protocol, code: Code, id: u8, data: Bytes) {
        // Les données construites ici sont toujours bornées (≤ MRU), `new` ne peut échouer.
        if let Ok(p) = ControlPacket::new(code, id, data) {
            self.transmit.push_back(p.to_frame(protocol));
        }
    }

    fn send_configure(&mut self, protocol: Protocol, code: Code, id: u8, opts: &[ConfigOption]) {
        let mut data = BytesMut::new();
        encode_options(opts, &mut data);
        self.send_control(protocol, code, id, data.freeze());
    }

    /// Envoie (ou renvoie) notre Configure-Request avec un nouvel identifiant.
    fn send_confreq(&mut self, which: Protocol, opts: &[ConfigOption], now: Instant) {
        let max = self.cfg.max_configure;
        let restart = self.cfg.restart_interval;
        let cp = if which == Protocol::LCP {
            &mut self.lcp
        } else {
            &mut self.ipcp
        };
        if cp.sent >= max {
            self.down(DownReason::NegotiationFailed(which));
            return;
        }
        let id = cp.alloc_id();
        let mut data = BytesMut::new();
        encode_options(opts, &mut data);
        let data = data.freeze();
        cp.req_id = id;
        cp.req_opts = data.clone();
        cp.sent += 1;
        cp.deadline = Some(now + restart);
        self.send_control(which, Code::ConfigureRequest, id, data);
    }

    fn lcp_request_options(&self) -> Vec<ConfigOption> {
        let mut v = Vec::with_capacity(2);
        if let Some(mru) = self.our_mru {
            v.push(LcpOption::Mru(mru).to_option());
        }
        if let Some(m) = self.our_magic {
            v.push(LcpOption::MagicNumber(m).to_option());
        }
        v
    }

    fn ipcp_request_options(&self) -> Vec<ConfigOption> {
        let mut v = vec![IpcpOption::IpAddress(self.local_ip).to_option()];
        if let Some(d) = self.dns1 {
            v.push(IpcpOption::PrimaryDns(d).to_option());
        }
        if let Some(d) = self.dns2 {
            v.push(IpcpOption::SecondaryDns(d).to_option());
        }
        v
    }

    fn send_lcp_confreq(&mut self, now: Instant) {
        let opts = self.lcp_request_options();
        self.send_confreq(Protocol::LCP, &opts, now);
    }

    fn send_ipcp_confreq(&mut self, now: Instant) {
        let opts = self.ipcp_request_options();
        self.send_confreq(Protocol::IPCP, &opts, now);
    }

    /// Nouveau magic non nul et différent de `avoid` (xorshift32 déterministe).
    fn fresh_magic(&mut self, avoid: u32) -> u32 {
        loop {
            let mut x = self.magic_rng;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.magic_rng = x;
            if x != 0 && x != avoid {
                return x;
            }
        }
    }

    fn arm_echo(&mut self, now: Instant) {
        self.echo_outstanding = 0;
        self.echo_deadline = self.cfg.echo_interval.map(|i| now + i);
    }

    fn echo_tick(&mut self, now: Instant) {
        if self.echo_outstanding >= self.cfg.echo_max_failures {
            self.down(DownReason::DeadPeer);
            return;
        }
        let id = self.lcp.alloc_id();
        let magic = self.our_magic.unwrap_or(0);
        if let Ok(p) = ControlPacket::echo(Code::EchoRequest, id, magic, &[]) {
            self.transmit.push_back(p.to_frame(Protocol::LCP));
        }
        self.echo_outstanding += 1;
        self.echo_deadline = self.cfg.echo_interval.map(|i| now + i);
    }

    // ------------------------------------------------------------------- LCP

    fn handle_lcp(&mut self, now: Instant, p: &ControlPacket) {
        match p.code() {
            Code::ConfigureRequest => self.lcp_rcr(now, p),
            Code::ConfigureAck => {
                if self.lcp.answers_current(p) && *p.data() == self.lcp.req_opts {
                    match self.lcp.state {
                        CpState::ReqSent => self.lcp.state = CpState::AckRcvd,
                        CpState::AckSent => self.lcp_up(now),
                        _ => {}
                    }
                }
            }
            Code::ConfigureNak | Code::ConfigureReject => {
                if self.lcp.answers_current(p) && self.lcp_apply_nak_rej(p) {
                    if self.lcp.state == CpState::AckRcvd {
                        self.lcp.state = CpState::ReqSent;
                    }
                    self.send_lcp_confreq(now);
                }
            }
            Code::TerminateRequest => {
                self.send_control(Protocol::LCP, Code::TerminateAck, p.id(), Bytes::new());
                self.down(DownReason::ClosedByPeer);
            }
            Code::ProtocolReject => {
                if self.lcp.state == CpState::Opened
                    && p.rejected_protocol()
                        .is_some_and(|(proto, _)| proto == Protocol::IPCP)
                {
                    self.down(DownReason::ProtocolRejected(Protocol::IPCP));
                }
            }
            Code::EchoRequest => {
                if self.lcp.state != CpState::Opened {
                    return;
                }
                let Some((magic, data)) = p.magic_and_data() else {
                    return;
                };
                let ours = self.our_magic.unwrap_or(0);
                if ours != 0 && magic == ours {
                    return; // boucle locale
                }
                let room = usize::from(self.peer_mru).saturating_sub(8);
                let data = &data[..data.len().min(room)];
                if let Ok(r) = ControlPacket::echo(Code::EchoReply, p.id(), ours, data) {
                    self.transmit.push_back(r.to_frame(Protocol::LCP));
                }
            }
            // Réception déjà prise en compte pour le keepalive ; rien d'autre à faire.
            Code::TerminateAck | Code::CodeReject | Code::EchoReply | Code::DiscardRequest => {}
            Code::Unknown(_) => {
                let id = self.lcp.alloc_id();
                let rej = ControlPacket::code_reject(id, p, self.reject_room());
                self.transmit.push_back(rej.to_frame(Protocol::LCP));
            }
        }
    }

    fn lcp_rcr(&mut self, now: Instant, p: &ControlPacket) {
        if self.lcp.state == CpState::Opened {
            self.down(DownReason::Renegotiation(Protocol::LCP));
            return;
        }
        let Ok(opts) = p.options() else {
            return;
        };
        let mut rejected = Vec::new();
        let mut naked = Vec::new();
        let mut peer_mru = RFC_DEFAULT_MRU;
        for o in &opts {
            match LcpOption::from_option(o) {
                LcpOption::Mru(v) => peer_mru = v,
                LcpOption::Accm(_) => {}
                LcpOption::MagicNumber(m) => {
                    let ours = self.our_magic.unwrap_or(0);
                    if m == 0 || m == ours {
                        let fresh = self.fresh_magic(ours);
                        naked.push(LcpOption::MagicNumber(fresh).to_option());
                    }
                }
                LcpOption::AuthProtocol(_)
                | LcpOption::Pfc
                | LcpOption::Acfc
                | LcpOption::Other(_) => rejected.push(o.clone()),
            }
        }
        match verdict(rejected, naked) {
            Verdict::Reject(r) => {
                self.send_configure(Protocol::LCP, Code::ConfigureReject, p.id(), &r);
                if self.lcp.state == CpState::AckSent {
                    self.lcp.state = CpState::ReqSent;
                }
            }
            Verdict::Nak(n) => {
                self.send_configure(Protocol::LCP, Code::ConfigureNak, p.id(), &n);
                if self.lcp.state == CpState::AckSent {
                    self.lcp.state = CpState::ReqSent;
                }
            }
            Verdict::Ack => {
                self.peer_mru = peer_mru;
                self.send_control(Protocol::LCP, Code::ConfigureAck, p.id(), p.data().clone());
                match self.lcp.state {
                    CpState::ReqSent => self.lcp.state = CpState::AckSent,
                    CpState::AckRcvd => self.lcp_up(now),
                    _ => {}
                }
            }
        }
    }

    /// Applique un Nak/Reject à nos options LCP ; `false` si le paquet est invalide.
    fn lcp_apply_nak_rej(&mut self, p: &ControlPacket) -> bool {
        let Ok(opts) = p.options() else {
            return false;
        };
        if p.code() == Code::ConfigureReject {
            let sent = self.lcp_request_options();
            if !opts
                .iter()
                .all(|o| sent.iter().any(|s| s.kind() == o.kind()))
            {
                return false;
            }
            for o in &opts {
                match o.kind() {
                    LcpOption::MRU => self.our_mru = None,
                    LcpOption::MAGIC => self.our_magic = None,
                    _ => {}
                }
            }
            return true;
        }
        for o in &opts {
            match LcpOption::from_option(o) {
                LcpOption::Mru(v) if self.our_mru.is_some() => {
                    self.our_mru = NAK_MRU_RANGE.contains(&v).then_some(v);
                }
                LcpOption::MagicNumber(_) if self.our_magic.is_some() => {
                    let ours = self.our_magic.unwrap_or(0);
                    self.our_magic = Some(self.fresh_magic(ours));
                }
                // Options non demandées suggérées par le pair : ignorées.
                _ => {}
            }
        }
        true
    }

    fn lcp_up(&mut self, now: Instant) {
        self.lcp.state = CpState::Opened;
        self.lcp.deadline = None;
        self.arm_echo(now);
        self.ipcp.state = CpState::ReqSent;
        self.send_ipcp_confreq(now);
    }

    // ------------------------------------------------------------------ IPCP

    fn handle_ipcp(&mut self, now: Instant, p: &ControlPacket) {
        match p.code() {
            Code::ConfigureRequest => self.ipcp_rcr(p),
            Code::ConfigureAck => {
                if self.ipcp.answers_current(p) && *p.data() == self.ipcp.req_opts {
                    match self.ipcp.state {
                        CpState::ReqSent => self.ipcp.state = CpState::AckRcvd,
                        CpState::AckSent => self.ipcp_up(),
                        _ => {}
                    }
                }
            }
            Code::ConfigureNak | Code::ConfigureReject => {
                if self.ipcp.answers_current(p) {
                    match self.ipcp_apply_nak_rej(p) {
                        Some(true) => {
                            if self.ipcp.state == CpState::AckRcvd {
                                self.ipcp.state = CpState::ReqSent;
                            }
                            self.send_ipcp_confreq(now);
                        }
                        Some(false) => {}
                        None => self.down(DownReason::NegotiationFailed(Protocol::IPCP)),
                    }
                }
            }
            Code::TerminateRequest => {
                self.send_control(Protocol::IPCP, Code::TerminateAck, p.id(), Bytes::new());
                self.down(DownReason::ClosedByPeer);
            }
            Code::TerminateAck | Code::CodeReject => {}
            Code::ProtocolReject
            | Code::EchoRequest
            | Code::EchoReply
            | Code::DiscardRequest
            | Code::Unknown(_) => {
                let id = self.ipcp.alloc_id();
                let rej = ControlPacket::code_reject(id, p, self.reject_room());
                self.transmit.push_back(rej.to_frame(Protocol::IPCP));
            }
        }
    }

    fn ipcp_rcr(&mut self, p: &ControlPacket) {
        if self.ipcp.state == CpState::Opened {
            self.down(DownReason::Renegotiation(Protocol::IPCP));
            return;
        }
        let Ok(opts) = p.options() else {
            return;
        };
        let mut rejected = Vec::new();
        let mut peer_ip = None;
        for o in &opts {
            match IpcpOption::from_option(o) {
                IpcpOption::IpAddress(a) => peer_ip = Some(a),
                _ => rejected.push(o.clone()),
            }
        }
        // Jamais de Nak sur l'adresse de la passerelle (§9.4).
        match verdict(rejected, Vec::new()) {
            Verdict::Reject(r) => {
                self.send_configure(Protocol::IPCP, Code::ConfigureReject, p.id(), &r);
                if self.ipcp.state == CpState::AckSent {
                    self.ipcp.state = CpState::ReqSent;
                }
            }
            Verdict::Nak(_) | Verdict::Ack => {
                self.peer_ip = peer_ip;
                self.send_control(Protocol::IPCP, Code::ConfigureAck, p.id(), p.data().clone());
                match self.ipcp.state {
                    CpState::ReqSent => self.ipcp.state = CpState::AckSent,
                    CpState::AckRcvd => self.ipcp_up(),
                    _ => {}
                }
            }
        }
    }

    /// Applique un Nak/Reject IPCP : `Some(true)` renvoyer une requête, `Some(false)`
    /// paquet invalide ignoré, `None` adresse IP refusée (échec).
    fn ipcp_apply_nak_rej(&mut self, p: &ControlPacket) -> Option<bool> {
        let Ok(opts) = p.options() else {
            return Some(false);
        };
        if p.code() == Code::ConfigureReject {
            let sent = self.ipcp_request_options();
            if !opts
                .iter()
                .all(|o| sent.iter().any(|s| s.kind() == o.kind()))
            {
                return Some(false);
            }
            for o in &opts {
                match o.kind() {
                    IpcpOption::IP_ADDRESS => return None,
                    IpcpOption::PRIMARY_DNS => self.dns1 = None,
                    IpcpOption::SECONDARY_DNS => self.dns2 = None,
                    _ => {}
                }
            }
            return Some(true);
        }
        for o in &opts {
            match IpcpOption::from_option(o) {
                IpcpOption::IpAddress(a) => self.local_ip = a,
                IpcpOption::PrimaryDns(a) if self.dns1.is_some() => self.dns1 = Some(a),
                IpcpOption::SecondaryDns(a) if self.dns2.is_some() => self.dns2 = Some(a),
                // Options non demandées (VJ, NBNS…) : ignorées.
                _ => {}
            }
        }
        Some(true)
    }

    fn ipcp_up(&mut self) {
        self.ipcp.state = CpState::Opened;
        self.ipcp.deadline = None;
        let dns = [self.dns1, self.dns2]
            .into_iter()
            .flatten()
            .filter(|a| !a.is_unspecified())
            .collect();
        self.events.push_back(PppEvent::IpcpUp {
            local_ip: self.local_ip,
            dns,
            peer: self.peer_ip,
            mtu: self.mtu(),
        });
    }
}
