//! Automate PPP côté passerelle, sans I/O : octets reçus → octets à émettre + sortie.

use std::net::Ipv4Addr;

use bytes::{Bytes, BytesMut};
use proto::frame::{decode_frame, encode_frame, encode_ppp_frame};
use proto::ppp::{Code, ConfigOption, ControlPacket, IpcpOption, LcpOption, Packet, Protocol};
use tokio::time::Instant;

use super::{
    FaultTrigger, GatewayIpcpRequest, IpcpUp, PeerEnd, PeerPhase, PppFault, PppPeerConfig, Shared,
    inc,
};
use crate::config::Ipv4Config;
use crate::icmp::{icmp_echo_reply, ipv4_addrs};

/// MRU supposé du client s'il n'en annonce pas (RFC 1661).
const RFC_DEFAULT_MRU: u16 = 1500;
/// IPV6CP Configure-Request (`lcp.hex:ipv6cp_confreq_gateway`, sans protocole) :
/// id 1, Interface-Identifier `02 00 c0 ff fe 00 00 01`.
const IPV6CP_CONFREQ: [u8; 14] = [
    0x01, 0x01, 0x00, 0x0e, 0x01, 0x0a, 0x02, 0x00, 0xc0, 0xff, 0xfe, 0x00, 0x00, 0x01,
];

/// Fermeture à appliquer au flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseMode {
    /// `shutdown` (`close_notify` en TLS).
    Clean,
    /// Abandon sans `close_notify`.
    Abort,
}

/// Action d'une panne déclenchée par un [`FaultTrigger`].
#[derive(Debug, Clone, Copy)]
enum FaultAction {
    Malformed(&'static [u8]),
    Terminate,
    Abort,
}

/// État d'un protocole de contrôle (vue passerelle).
#[derive(Debug, Default)]
struct Cp {
    /// Configure-Ack envoyé pour la requête courante du client.
    ack_sent: bool,
    /// Configure-Ack reçu pour notre requête courante.
    ack_rcvd: bool,
    next_id: u8,
    req_id: u8,
    req_opts: Bytes,
    sent: u32,
    deadline: Option<Instant>,
}

impl Cp {
    fn opened(&self) -> bool {
        self.ack_sent && self.ack_rcvd
    }

    fn alloc_id(&mut self) -> u8 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    fn reset(&mut self) {
        self.ack_sent = false;
        self.ack_rcvd = false;
        self.sent = 0;
        self.deadline = None;
    }
}

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

pub(crate) struct Machine<'a> {
    cfg: &'a PppPeerConfig,
    shared: &'a Shared,
    conn_id: u64,
    assigned: Ipv4Addr,
    dns1: Option<Ipv4Addr>,
    dns2: Option<Ipv4Addr>,

    out: BytesMut,
    exit: Option<(PeerEnd, CloseMode)>,

    lcp: Cp,
    ipcp: Cp,
    our_magic: Option<u32>,
    our_mru: Option<u16>,
    client_magic: Option<u32>,
    client_mru: u16,
    gateway_ip: Option<Ipv4Addr>,
    client_ip: Option<Ipv4Addr>,
    client_dns: Vec<Ipv4Addr>,
    ipv6cp_offered: bool,

    next_ip_id: u16,
    echo_id: u8,
    echo_deadline: Option<Instant>,
    term: Option<(u8, Instant)>,
    fault: Option<(FaultTrigger, FaultAction)>,
    fault_deadline: Option<Instant>,
}

impl<'a> Machine<'a> {
    pub(crate) fn new(
        cfg: &'a PppPeerConfig,
        shared: &'a Shared,
        ipv4: &Ipv4Config,
        conn_id: u64,
        now: Instant,
    ) -> Self {
        let fault = match cfg.fault {
            PppFault::MalformedFrame { kind, when } => {
                Some((when, FaultAction::Malformed(kind.bytes())))
            }
            PppFault::GatewayTerminate { when } => Some((when, FaultAction::Terminate)),
            PppFault::AbortTls { when } => Some((when, FaultAction::Abort)),
            _ => None,
        };
        let mut m = Self {
            cfg,
            shared,
            conn_id,
            assigned: ipv4.assigned_addr,
            dns1: ipv4.dns.first().map(|d| d.ip),
            dns2: ipv4.dns.get(1).map(|d| d.ip),
            out: BytesMut::new(),
            exit: None,
            lcp: Cp::default(),
            ipcp: Cp::default(),
            our_magic: (cfg.magic != 0).then_some(cfg.magic),
            our_mru: cfg.mru,
            client_magic: None,
            client_mru: RFC_DEFAULT_MRU,
            gateway_ip: match cfg.ipcp_request {
                GatewayIpcpRequest::Address(a) => Some(a),
                GatewayIpcpRequest::Empty => None,
            },
            client_ip: None,
            client_dns: Vec::new(),
            ipv6cp_offered: false,
            next_ip_id: cfg.reply_ip_id,
            echo_id: 0,
            echo_deadline: None,
            term: None,
            fault,
            fault_deadline: None,
        };
        m.milestone(FaultTrigger::Start, now);
        if m.exit.is_none() && m.term.is_none() {
            m.send_lcp_confreq(now);
        }
        m
    }

    pub(crate) fn take_output(&mut self) -> BytesMut {
        self.out.split()
    }

    pub(crate) fn exit(&mut self) -> Option<(PeerEnd, CloseMode)> {
        self.exit.take()
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        if let Some((_, d)) = self.term {
            return Some(d);
        }
        [
            self.lcp.deadline,
            self.ipcp.deadline,
            self.echo_deadline,
            self.fault_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    // ------------------------------------------------------------------ entrées

    /// Consomme toutes les trames complètes de `rx`.
    pub(crate) fn handle_bytes(&mut self, rx: &mut BytesMut, now: Instant) {
        while self.exit.is_none() {
            match decode_frame(rx) {
                Ok(Some(frame)) => {
                    inc(&self.shared.counters.frames_rx);
                    self.handle_frame(frame, now);
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(conn_id = self.conn_id, error = %e, "mock-gw ppp: trame invalide du client");
                    self.finish(PeerEnd::BadFrame(e), CloseMode::Clean);
                }
            }
        }
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        if let Some((_, d)) = self.term {
            if d <= now {
                self.finish(
                    PeerEnd::GatewayTerminated { acked: false },
                    CloseMode::Clean,
                );
            }
            return;
        }
        if self.fault_deadline.is_some_and(|d| d <= now) {
            self.fault_deadline = None;
            self.fire_fault(now);
            if self.exit.is_some() || self.term.is_some() {
                return;
            }
        }
        if self.lcp.deadline.is_some_and(|d| d <= now) {
            self.send_lcp_confreq(now);
        }
        if self.exit.is_none() && self.ipcp.deadline.is_some_and(|d| d <= now) {
            self.send_ipcp_confreq(now);
        }
        if self.exit.is_none() && self.echo_deadline.is_some_and(|d| d <= now) {
            self.echo_id = self.echo_id.wrapping_add(1);
            let magic = self.our_magic.unwrap_or(0);
            if let Ok(p) = ControlPacket::echo(Code::EchoRequest, self.echo_id, magic, &[]) {
                self.send_control(Protocol::LCP, &p);
                inc(&self.shared.counters.lcp_echo_requests_tx);
            }
            self.echo_deadline = self.cfg.echo_interval.map(|i| now + i);
        }
    }

    fn handle_frame(&mut self, frame: Bytes, now: Instant) {
        let Ok(packet) = Packet::parse(frame) else {
            inc(&self.shared.counters.ignored);
            return;
        };
        if self.term.is_some() {
            // En attente du Terminate-Ack : tout le reste est ignoré.
            if let Packet::Lcp(p) = &packet {
                match p.code() {
                    Code::TerminateAck if self.term.is_some_and(|(id, _)| id == p.id()) => {
                        self.finish(PeerEnd::GatewayTerminated { acked: true }, CloseMode::Clean);
                    }
                    Code::TerminateRequest => {
                        self.send_raw_control(
                            Protocol::LCP,
                            Code::TerminateAck,
                            p.id(),
                            Bytes::new(),
                        );
                        self.finish(PeerEnd::GatewayTerminated { acked: true }, CloseMode::Clean);
                    }
                    _ => inc(&self.shared.counters.ignored),
                }
            }
            return;
        }
        match packet {
            Packet::Lcp(p) => self.handle_lcp(&p, now),
            Packet::Ipcp(p) => {
                if self.lcp.opened() {
                    self.handle_ipcp(&p, now);
                } else {
                    inc(&self.shared.counters.ignored);
                }
            }
            Packet::Ipv4(ip) => self.handle_ipv4(&ip),
            Packet::Other(f) => {
                if self.lcp.opened() {
                    let id = self.lcp.alloc_id();
                    let rej = ControlPacket::protocol_reject(
                        id,
                        f.protocol,
                        &f.payload,
                        usize::from(self.client_mru),
                    );
                    self.send_control(Protocol::LCP, &rej);
                    inc(&self.shared.counters.protocol_rejects_tx);
                } else {
                    inc(&self.shared.counters.ignored);
                }
            }
        }
    }

    // ---------------------------------------------------------------------- LCP

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

    fn send_lcp_confreq(&mut self, now: Instant) {
        let opts = self.lcp_request_options();
        self.send_confreq(Protocol::LCP, &opts, now);
    }

    fn handle_lcp(&mut self, p: &ControlPacket, now: Instant) {
        match p.code() {
            Code::ConfigureRequest => self.lcp_rcr(p, now),
            Code::ConfigureAck => {
                if p.id() == self.lcp.req_id && *p.data() == self.lcp.req_opts && !self.lcp.opened()
                {
                    self.lcp.ack_rcvd = true;
                    self.lcp.deadline = None;
                    if self.lcp.ack_sent {
                        self.lcp_up(now);
                    }
                } else {
                    inc(&self.shared.counters.ignored);
                }
            }
            Code::ConfigureNak | Code::ConfigureReject => {
                if p.id() != self.lcp.req_id || self.lcp.ack_rcvd {
                    inc(&self.shared.counters.ignored);
                    return;
                }
                let Ok(opts) = p.options() else {
                    inc(&self.shared.counters.ignored);
                    return;
                };
                let reject = p.code() == Code::ConfigureReject;
                for o in &opts {
                    match (o.kind(), LcpOption::from_option(o)) {
                        (LcpOption::MRU, _) if reject => self.our_mru = None,
                        (LcpOption::MAGIC, _) if reject => self.our_magic = None,
                        (_, LcpOption::Mru(v)) => self.our_mru = Some(v),
                        (_, LcpOption::MagicNumber(_)) => {
                            let m = self.our_magic.unwrap_or(1);
                            self.our_magic = Some((m.rotate_left(7) ^ 0x9e37_79b9) | 1);
                        }
                        _ => {}
                    }
                }
                self.send_lcp_confreq(now);
            }
            Code::TerminateRequest => {
                self.send_raw_control(Protocol::LCP, Code::TerminateAck, p.id(), Bytes::new());
                self.finish(PeerEnd::ClientTerminated, CloseMode::Clean);
            }
            Code::ProtocolReject => {
                inc(&self.shared.counters.protocol_rejects_rx);
                match p.rejected_protocol() {
                    Some((Protocol::IPV6CP, _)) => {
                        self.shared.status.send_modify(|s| s.ipv6cp_rejected = true);
                    }
                    Some((Protocol::IPCP, _)) => {
                        self.finish(PeerEnd::IpcpRejected, CloseMode::Clean);
                    }
                    _ => {}
                }
            }
            Code::EchoRequest => self.lcp_echo_request(p),
            Code::EchoReply => inc(&self.shared.counters.lcp_echo_replies_rx),
            Code::TerminateAck | Code::CodeReject | Code::DiscardRequest => {}
            Code::Unknown(_) => {
                let id = self.lcp.alloc_id();
                let rej = ControlPacket::code_reject(id, p, usize::from(self.client_mru));
                self.send_control(Protocol::LCP, &rej);
            }
        }
    }

    fn lcp_rcr(&mut self, p: &ControlPacket, now: Instant) {
        let Ok(opts) = p.options() else {
            inc(&self.shared.counters.ignored);
            return;
        };
        if self.lcp.opened() {
            // Renégociation (RFC 1661) : IPCP retombe, LCP repart.
            tracing::info!(conn_id = self.conn_id, "mock-gw ppp: renégociation LCP");
            self.lcp.reset();
            self.ipcp.reset();
            self.echo_deadline = None;
            self.set_phase(PeerPhase::Lcp);
            self.send_lcp_confreq(now);
        }
        let mut rejected = Vec::new();
        let mut naked = Vec::new();
        let mut mru = RFC_DEFAULT_MRU;
        let mut magic = None;
        for o in &opts {
            match LcpOption::from_option(o) {
                LcpOption::Mru(v) => mru = v,
                LcpOption::MagicNumber(m) => {
                    if m == 0 || Some(m) == self.our_magic {
                        let other = (m.rotate_left(13) ^ 0x5a5a_5a5a) | 1;
                        naked.push(LcpOption::MagicNumber(other).to_option());
                    } else {
                        magic = Some(m);
                    }
                }
                // Comme FortiOS (openconnect) : asyncmap et compressions refusés.
                LcpOption::Accm(_)
                | LcpOption::Pfc
                | LcpOption::Acfc
                | LcpOption::AuthProtocol(_)
                | LcpOption::Other(_) => rejected.push(o.clone()),
            }
        }
        match verdict(rejected, naked) {
            Verdict::Reject(r) => {
                self.lcp.ack_sent = false;
                self.send_configure(Protocol::LCP, Code::ConfigureReject, p.id(), &r);
            }
            Verdict::Nak(n) => {
                self.lcp.ack_sent = false;
                self.send_configure(Protocol::LCP, Code::ConfigureNak, p.id(), &n);
            }
            Verdict::Ack => {
                self.client_mru = mru;
                self.client_magic = magic;
                self.send_raw_control(Protocol::LCP, Code::ConfigureAck, p.id(), p.data().clone());
                self.lcp.ack_sent = true;
                if self.lcp.ack_rcvd {
                    self.lcp_up(now);
                }
            }
        }
    }

    fn lcp_echo_request(&mut self, p: &ControlPacket) {
        inc(&self.shared.counters.lcp_echo_requests_rx);
        if !self.lcp.opened() || self.cfg.fault == PppFault::IgnoreEchoRequests {
            inc(&self.shared.counters.lcp_echo_requests_ignored);
            return;
        }
        let Some((magic, data)) = p.magic_and_data() else {
            inc(&self.shared.counters.lcp_echo_requests_ignored);
            return;
        };
        let ours = self.our_magic.unwrap_or(0);
        if ours != 0 && magic == ours {
            inc(&self.shared.counters.lcp_echo_requests_ignored);
            return;
        }
        let room = usize::from(self.client_mru).saturating_sub(8);
        let data = &data[..data.len().min(room)];
        if let Ok(r) = ControlPacket::echo(Code::EchoReply, p.id(), ours, data) {
            self.send_control(Protocol::LCP, &r);
            inc(&self.shared.counters.lcp_echo_replies_tx);
        }
    }

    fn lcp_up(&mut self, now: Instant) {
        tracing::debug!(conn_id = self.conn_id, "mock-gw ppp: LCP ouvert");
        self.lcp.deadline = None;
        self.set_phase(PeerPhase::Ipcp);
        if self.cfg.fault != PppFault::IgnoreEchoRequests {
            self.echo_deadline = self.cfg.echo_interval.map(|i| now + i);
        }
        if self.cfg.offer_ipv6cp && !self.ipv6cp_offered {
            self.ipv6cp_offered = true;
            let mut ppp = BytesMut::new();
            ppp.extend_from_slice(&Protocol::IPV6CP.0.to_be_bytes());
            ppp.extend_from_slice(&IPV6CP_CONFREQ);
            self.send_ppp(&ppp);
        }
        self.ipcp.reset();
        self.send_ipcp_confreq(now);
        self.milestone(FaultTrigger::LcpUp, now);
    }

    // --------------------------------------------------------------------- IPCP

    fn ipcp_request_options(&self) -> Vec<ConfigOption> {
        self.gateway_ip
            .map(|a| IpcpOption::IpAddress(a).to_option())
            .into_iter()
            .collect()
    }

    fn send_ipcp_confreq(&mut self, now: Instant) {
        let opts = self.ipcp_request_options();
        self.send_confreq(Protocol::IPCP, &opts, now);
    }

    fn handle_ipcp(&mut self, p: &ControlPacket, now: Instant) {
        match p.code() {
            Code::ConfigureRequest => self.ipcp_rcr(p, now),
            Code::ConfigureAck => {
                if p.id() == self.ipcp.req_id
                    && *p.data() == self.ipcp.req_opts
                    && !self.ipcp.opened()
                {
                    self.ipcp.ack_rcvd = true;
                    self.ipcp.deadline = None;
                    if self.ipcp.ack_sent {
                        self.ipcp_up(now);
                    }
                } else {
                    inc(&self.shared.counters.ignored);
                }
            }
            Code::ConfigureNak | Code::ConfigureReject => {
                if p.id() != self.ipcp.req_id || self.ipcp.ack_rcvd {
                    inc(&self.shared.counters.ignored);
                    return;
                }
                let Ok(opts) = p.options() else {
                    inc(&self.shared.counters.ignored);
                    return;
                };
                for o in &opts {
                    match IpcpOption::from_option(o) {
                        IpcpOption::IpAddress(_) if p.code() == Code::ConfigureReject => {
                            self.gateway_ip = None;
                        }
                        IpcpOption::IpAddress(a) => self.gateway_ip = Some(a),
                        _ => {}
                    }
                }
                self.send_ipcp_confreq(now);
            }
            Code::TerminateRequest => {
                self.send_raw_control(Protocol::IPCP, Code::TerminateAck, p.id(), Bytes::new());
                self.ipcp.reset();
                self.set_phase(PeerPhase::Ipcp);
            }
            Code::TerminateAck | Code::CodeReject => {}
            _ => {
                let id = self.ipcp.alloc_id();
                let rej = ControlPacket::code_reject(id, p, usize::from(self.client_mru));
                self.send_control(Protocol::IPCP, &rej);
            }
        }
    }

    /// Valeur à imposer pour l'adresse demandée `asked`.
    fn wanted_addr(&self, asked: Ipv4Addr) -> Ipv4Addr {
        if self.cfg.fault == PppFault::IpcpNeverConverges && asked == self.assigned {
            // Toujours différente de la demande : la négociation ne converge jamais.
            Ipv4Addr::from(u32::from(self.assigned).wrapping_add(1))
        } else {
            self.assigned
        }
    }

    fn ipcp_rcr(&mut self, p: &ControlPacket, now: Instant) {
        let Ok(opts) = p.options() else {
            inc(&self.shared.counters.ignored);
            return;
        };
        if self.ipcp.opened() {
            tracing::info!(conn_id = self.conn_id, "mock-gw ppp: renégociation IPCP");
            self.ipcp.reset();
            self.set_phase(PeerPhase::Ipcp);
            self.send_ipcp_confreq(now);
        }
        let mut rejected = Vec::new();
        let mut naked = Vec::new();
        let mut ip = None;
        let mut dns = Vec::new();
        for o in &opts {
            match IpcpOption::from_option(o) {
                IpcpOption::IpAddress(a) => {
                    let want = self.wanted_addr(a);
                    if a == want {
                        ip = Some(a);
                    } else {
                        naked.push(IpcpOption::IpAddress(want).to_option());
                    }
                }
                IpcpOption::PrimaryDns(a) => match self.dns1 {
                    Some(d) if d == a => dns.push(a),
                    Some(d) => naked.push(IpcpOption::PrimaryDns(d).to_option()),
                    None => rejected.push(o.clone()),
                },
                IpcpOption::SecondaryDns(a) => match self.dns2 {
                    Some(d) if d == a => dns.push(a),
                    Some(d) => naked.push(IpcpOption::SecondaryDns(d).to_option()),
                    None => rejected.push(o.clone()),
                },
                // VJ, NBNS... : refusés.
                IpcpOption::Other(_) => rejected.push(o.clone()),
            }
        }
        if ip.is_none() && naked.iter().all(|o| o.kind() != IpcpOption::IP_ADDRESS) {
            // Le client n'a pas demandé d'adresse : la lui imposer.
            naked.insert(0, IpcpOption::IpAddress(self.assigned).to_option());
        }
        match verdict(rejected, naked) {
            Verdict::Reject(r) => {
                self.ipcp.ack_sent = false;
                self.send_configure(Protocol::IPCP, Code::ConfigureReject, p.id(), &r);
            }
            Verdict::Nak(n) => {
                self.ipcp.ack_sent = false;
                self.send_configure(Protocol::IPCP, Code::ConfigureNak, p.id(), &n);
            }
            Verdict::Ack => {
                self.client_ip = ip;
                self.client_dns = dns;
                self.send_raw_control(Protocol::IPCP, Code::ConfigureAck, p.id(), p.data().clone());
                self.ipcp.ack_sent = true;
                if self.ipcp.ack_rcvd {
                    self.ipcp_up(now);
                }
            }
        }
    }

    fn ipcp_up(&mut self, now: Instant) {
        self.ipcp.deadline = None;
        let Some(client_ip) = self.client_ip else {
            return;
        };
        let up = IpcpUp {
            conn_id: self.conn_id,
            client_ip,
            dns: self.client_dns.clone(),
            gateway_ip: self.gateway_ip,
            client_magic: self.client_magic,
            client_mru: self.client_mru,
        };
        tracing::info!(
            conn_id = self.conn_id,
            client_ip = %client_ip,
            dns = ?up.dns,
            "mock-gw ppp: IPCP up"
        );
        inc(&self.shared.counters.ipcp_up);
        self.shared.status.send_modify(|s| {
            s.phase = PeerPhase::Up;
            s.ipcp = Some(up);
        });
        self.milestone(FaultTrigger::IpcpUp, now);
    }

    // --------------------------------------------------------------------- IPv4

    fn handle_ipv4(&mut self, ip: &[u8]) {
        let c = &self.shared.counters;
        if !self.ipcp.opened() {
            inc(&c.ipv4_dropped);
            return;
        }
        inc(&c.ipv4_rx);
        let for_target = match (self.cfg.icmp_target, ipv4_addrs(ip)) {
            (None, Some(_)) => true,
            (Some(t), Some((_, dst))) => dst == t,
            (_, None) => false,
        };
        if !for_target {
            inc(&c.ipv4_dropped);
            return;
        }
        match icmp_echo_reply(ip, self.next_ip_id) {
            Ok(reply) => {
                self.next_ip_id = self.next_ip_id.wrapping_add(1);
                if encode_ppp_frame(Protocol::IPV4, &reply, &mut self.out).is_ok() {
                    inc(&c.frames_tx);
                    inc(&c.ipv4_tx);
                    inc(&c.icmp_echo_replied);
                }
            }
            Err(why) => {
                tracing::debug!(conn_id = self.conn_id, ?why, "mock-gw ppp: IPv4 ignoré");
                inc(&c.ipv4_dropped);
            }
        }
    }

    // ------------------------------------------------------------------- pannes

    fn milestone(&mut self, reached: FaultTrigger, now: Instant) {
        let Some((when, _)) = self.fault else {
            return;
        };
        match (when, reached) {
            (FaultTrigger::AfterIpcpUp(d), FaultTrigger::IpcpUp) => {
                self.fault_deadline = Some(now + d);
            }
            (w, r) if w == r => self.fire_fault(now),
            _ => {}
        }
    }

    fn fire_fault(&mut self, now: Instant) {
        let Some((_, action)) = self.fault.take() else {
            return;
        };
        tracing::info!(
            conn_id = self.conn_id,
            ?action,
            "mock-gw ppp: panne déclenchée"
        );
        match action {
            FaultAction::Malformed(bytes) => {
                self.out.extend_from_slice(bytes);
                inc(&self.shared.counters.frames_tx);
            }
            FaultAction::Abort => self.finish(PeerEnd::Aborted, CloseMode::Abort),
            FaultAction::Terminate => {
                let id = self.lcp.alloc_id();
                self.send_raw_control(Protocol::LCP, Code::TerminateRequest, id, Bytes::new());
                self.term = Some((id, now + self.cfg.terminate_timeout));
                self.lcp.deadline = None;
                self.ipcp.deadline = None;
                self.echo_deadline = None;
                self.set_phase(PeerPhase::Terminating);
            }
        }
    }

    // ------------------------------------------------------------------ sorties

    fn finish(&mut self, end: PeerEnd, mode: CloseMode) {
        if self.exit.is_none() {
            self.exit = Some((end, mode));
        }
    }

    fn set_phase(&self, phase: PeerPhase) {
        self.shared.status.send_modify(|s| {
            s.phase = phase;
            if matches!(phase, PeerPhase::Lcp | PeerPhase::Ipcp) {
                // IPCP retombé (renégociation) : plus d'adresse valide.
                s.ipcp = None;
            }
        });
    }

    fn send_confreq(&mut self, which: Protocol, opts: &[ConfigOption], now: Instant) {
        let max = self.cfg.max_configure;
        let restart = self.cfg.restart_interval;
        let cp = if which == Protocol::LCP {
            &mut self.lcp
        } else {
            &mut self.ipcp
        };
        if cp.sent >= max {
            tracing::warn!(conn_id = self.conn_id, %which, "mock-gw ppp: négociation abandonnée");
            self.finish(PeerEnd::NegotiationFailed(which), CloseMode::Clean);
            return;
        }
        let id = cp.alloc_id();
        let Ok(p) = ControlPacket::configure(Code::ConfigureRequest, id, opts) else {
            return;
        };
        cp.req_id = id;
        cp.req_opts = p.data().clone();
        cp.sent += 1;
        cp.deadline = Some(now + restart);
        self.send_control(which, &p);
    }

    fn send_configure(&mut self, protocol: Protocol, code: Code, id: u8, opts: &[ConfigOption]) {
        if let Ok(p) = ControlPacket::configure(code, id, opts) {
            self.send_control(protocol, &p);
        }
    }

    fn send_raw_control(&mut self, protocol: Protocol, code: Code, id: u8, data: Bytes) {
        if let Ok(p) = ControlPacket::new(code, id, data) {
            self.send_control(protocol, &p);
        }
    }

    fn send_control(&mut self, protocol: Protocol, p: &ControlPacket) {
        self.send_ppp(&p.to_frame(protocol));
    }

    fn send_ppp(&mut self, ppp: &[u8]) {
        if encode_frame(ppp, &mut self.out).is_ok() {
            inc(&self.shared.counters.frames_tx);
        }
    }
}
