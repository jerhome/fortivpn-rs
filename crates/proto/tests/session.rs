//! Automate PPP rejoué contre `docs/vectors/*.hex` (§9.2–§9.8, §11).

mod common;

use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use proto::frame::encode_frame;
use proto::ppp::{
    Code, ConfigOption, ControlPacket, DownReason, LcpOption, Packet, PppConfig, PppEvent,
    PppSession, Protocol,
};

const CLIENT_MAGIC: u32 = 0x1a2b_3c4d;

struct Harness {
    s: PppSession,
    now: Instant,
}

impl Harness {
    fn with(cfg: impl FnOnce(&mut PppConfig)) -> Self {
        let mut c = PppConfig::new(NonZeroU32::new(CLIENT_MAGIC).unwrap());
        cfg(&mut c);
        Self {
            s: PppSession::new(c),
            now: Instant::now(),
        }
    }

    fn new() -> Self {
        Self::with(|_| {})
    }

    fn open(&mut self) {
        self.s.open(self.now);
    }

    fn rx(&mut self, name: &str) {
        self.rx_ppp(common::ppp(name));
    }

    fn rx_ppp(&mut self, ppp: Vec<u8>) {
        self.s.handle_frame(self.now, Bytes::from(ppp));
    }

    fn advance(&mut self, d: Duration) {
        self.now += d;
        self.s.handle_timeout(self.now);
    }

    /// Avance jusqu'à la prochaine échéance annoncée.
    fn fire(&mut self) {
        let t = self.s.poll_timeout().expect("échéance attendue");
        assert!(t >= self.now);
        self.now = t;
        self.s.handle_timeout(self.now);
    }

    fn tx(&mut self) -> Bytes {
        self.s.poll_transmit().expect("trame attendue")
    }

    /// Prochaine trame émise == vecteur, octet pour octet sur le fil (0x5050 inclus).
    fn expect_tx(&mut self, name: &str) {
        let ppp = self.tx();
        let mut wire = BytesMut::new();
        encode_frame(&ppp, &mut wire).unwrap();
        assert_eq!(
            &wire[..],
            &common::wire(name)[..],
            "émission attendue : {name}"
        );
    }

    fn tx_packet(&mut self) -> (Protocol, ControlPacket) {
        match Packet::parse(self.tx()).unwrap() {
            Packet::Lcp(p) => (Protocol::LCP, p),
            Packet::Ipcp(p) => (Protocol::IPCP, p),
            other => panic!("paquet de contrôle attendu : {other:?}"),
        }
    }

    fn no_tx(&mut self) {
        assert_eq!(self.s.poll_transmit(), None);
    }

    fn event(&mut self) -> PppEvent {
        self.s.poll_event().expect("événement attendu")
    }

    fn no_event(&mut self) {
        assert_eq!(self.s.poll_event(), None);
    }

    /// Négociation complète du §1 (variante A), vérifiée octet par octet.
    fn negotiate(&mut self) {
        self.open();
        self.expect_tx("lcp_confreq_client");
        self.no_tx();
        self.rx("lcp_confreq_gateway");
        self.expect_tx("lcp_confack_client");
        self.no_tx();
        self.rx("lcp_confack_gateway");
        self.expect_tx("ipcp_confreq_client_1");
        self.no_tx();
        self.rx("ipcp_confreq_gateway");
        self.expect_tx("ipcp_confack_client");
        self.no_tx();
        self.rx("ipcp_confnak_gateway");
        self.expect_tx("ipcp_confreq_client_2");
        self.no_tx();
        self.no_event();
        assert!(!self.s.is_ip_up());
        self.rx("ipcp_confack_gateway");
        self.no_tx();
        assert_eq!(
            self.event(),
            PppEvent::IpcpUp {
                local_ip: Ipv4Addr::new(10, 10, 0, 2),
                dns: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)],
                peer: Some(Ipv4Addr::new(169, 254, 1, 1)),
                mtu: 1354,
            }
        );
        self.no_event();
        assert!(self.s.is_ip_up());
    }
}

fn lcp_frame(code: Code, id: u8, opts: &[LcpOption]) -> Vec<u8> {
    let raw: Vec<ConfigOption> = opts.iter().map(LcpOption::to_option).collect();
    ControlPacket::configure(code, id, &raw)
        .unwrap()
        .to_frame(Protocol::LCP)
        .to_vec()
}

fn ctl_frame(proto: Protocol, code: Code, id: u8, data: &[u8]) -> Vec<u8> {
    ControlPacket::new(code, id, Bytes::copy_from_slice(data))
        .unwrap()
        .to_frame(proto)
        .to_vec()
}

// ------------------------------------------------------------------ scénarios

#[test]
fn full_session_replay() {
    let mut h = Harness::new();
    h.negotiate();

    // Keepalive passerelle.
    h.rx("lcp_echo_request_gateway");
    h.expect_tx("lcp_echo_reply_client");

    // Données.
    h.rx("ipv4_icmp_echo_reply");
    match h.event() {
        PppEvent::Ipv4(ip) => assert_eq!(&ip[..], &common::wire("ipv4_icmp_echo_reply")[8..]),
        e => panic!("{e:?}"),
    }

    // Keepalive client après 30 s sans réception.
    h.advance(Duration::from_secs(29));
    h.no_tx();
    h.advance(Duration::from_secs(1));
    h.expect_tx("lcp_echo_request_client");
    h.rx("lcp_echo_reply_gateway");
    h.no_tx();

    // Fermeture locale.
    h.s.close(h.now);
    h.expect_tx("lcp_terminate_request_client");
    h.no_event();
    h.rx("lcp_terminate_ack_gateway");
    assert_eq!(h.event(), PppEvent::Down(DownReason::LocalClose));
    assert!(h.s.is_closed());
    assert_eq!(h.s.poll_timeout(), None);
    // Inerte ensuite.
    h.rx("lcp_echo_request_gateway");
    h.no_tx();
    h.no_event();
}

#[test]
fn gateway_responses_before_client_ack() {
    // La passerelle acquitte notre requête avant d'envoyer la sienne (AckRcvd -> Opened).
    let mut h = Harness::new();
    h.open();
    h.expect_tx("lcp_confreq_client");
    h.rx("lcp_confack_gateway");
    h.no_tx();
    h.rx("lcp_confreq_gateway");
    h.expect_tx("lcp_confack_client");
    h.expect_tx("ipcp_confreq_client_1");
    // IPCP : Nak puis Ack de notre côté avant la requête (vide) de la passerelle.
    h.rx("ipcp_confnak_gateway");
    h.expect_tx("ipcp_confreq_client_2");
    h.rx("ipcp_confack_gateway");
    h.no_event();
    h.rx("ipcp_confreq_gateway_empty");
    h.expect_tx("ipcp_confack_client_empty");
    match h.event() {
        PppEvent::IpcpUp { local_ip, peer, .. } => {
            assert_eq!(local_ip, Ipv4Addr::new(10, 10, 0, 2));
            assert_eq!(peer, None);
        }
        e => panic!("{e:?}"),
    }
}

#[test]
fn ipv6cp_gets_protocol_reject() {
    let mut h = Harness::new();
    h.negotiate();
    // Deux Echo-Request client (id 2, 3) pour que le Protocol-Reject porte l'id 4.
    h.fire();
    h.expect_tx("lcp_echo_request_client");
    h.fire();
    let (_, p) = h.tx_packet();
    assert_eq!((p.code(), p.id()), (Code::EchoRequest, 3));
    h.rx("ipv6cp_confreq_gateway");
    h.expect_tx("lcp_protocol_reject_ipv6cp_client");
    h.no_event();
    assert!(h.s.is_ip_up());
}

#[test]
fn gateway_terminate_request() {
    let mut h = Harness::new();
    h.negotiate();
    h.rx("lcp_terminate_request_gateway");
    h.expect_tx("lcp_terminate_ack_client");
    assert_eq!(h.event(), PppEvent::Down(DownReason::ClosedByPeer));
    assert!(h.s.is_closed());
}

#[test]
fn gateway_terminate_during_negotiation() {
    let mut h = Harness::new();
    h.open();
    h.expect_tx("lcp_confreq_client");
    h.rx("lcp_terminate_request_gateway");
    h.expect_tx("lcp_terminate_ack_client");
    assert_eq!(h.event(), PppEvent::Down(DownReason::ClosedByPeer));
}

#[test]
fn ipv4_ignored_before_ipcp_up() {
    let mut h = Harness::new();
    h.open();
    h.rx("ipv4_icmp_echo_reply");
    h.rx("ipcp_confreq_gateway"); // IPCP avant LCP Opened : ignoré
    h.expect_tx("lcp_confreq_client");
    h.no_tx();
    h.no_event();
}

#[test]
fn frames_ignored_before_open() {
    let mut h = Harness::new();
    h.rx("lcp_confreq_gateway");
    h.no_tx();
    assert_eq!(h.s.poll_timeout(), None);
}

// ---------------------------------------------------------------- keepalive

#[test]
fn echo_timeout_leads_to_dead_peer() {
    let mut h = Harness::new();
    h.negotiate();
    let start = h.now;
    for i in 0..4u8 {
        h.fire();
        let (proto, p) = h.tx_packet();
        assert_eq!(proto, Protocol::LCP);
        assert_eq!((p.code(), p.id()), (Code::EchoRequest, 2 + i));
        assert_eq!(p.magic_and_data().unwrap().0, CLIENT_MAGIC);
        h.no_event();
    }
    h.fire();
    h.no_tx();
    assert_eq!(h.event(), PppEvent::Down(DownReason::DeadPeer));
    assert_eq!(h.now - start, Duration::from_secs(150));
    assert_eq!(h.s.poll_timeout(), None);
}

#[test]
fn any_reception_resets_echo() {
    let mut h = Harness::new();
    h.negotiate();
    for _ in 0..3 {
        h.fire();
        h.tx();
    }
    // Un paquet IP reçu prouve que le pair est vivant.
    h.rx("ipv4_icmp_echo_reply");
    h.event();
    for _ in 0..4 {
        h.fire();
        h.tx();
    }
    h.no_event();
    h.fire();
    assert_eq!(h.event(), PppEvent::Down(DownReason::DeadPeer));
}

#[test]
fn echo_configurable_and_disableable() {
    let mut h = Harness::with(|c| {
        c.echo_interval = Some(Duration::from_secs(5));
        c.echo_max_failures = 1;
    });
    h.negotiate();
    let t0 = h.now;
    h.fire();
    h.tx();
    h.fire();
    assert_eq!(h.event(), PppEvent::Down(DownReason::DeadPeer));
    assert_eq!(h.now - t0, Duration::from_secs(10));

    let mut h = Harness::with(|c| c.echo_interval = None);
    h.negotiate();
    assert_eq!(h.s.poll_timeout(), None);
}

#[test]
fn echo_request_with_own_magic_is_ignored() {
    let mut h = Harness::new();
    h.negotiate();
    h.rx_ppp(ctl_frame(
        Protocol::LCP,
        Code::EchoRequest,
        5,
        &CLIENT_MAGIC.to_be_bytes(),
    ));
    h.no_tx();
}

#[test]
fn echo_reply_copies_data() {
    let mut h = Harness::new();
    h.negotiate();
    h.rx_ppp(ctl_frame(
        Protocol::LCP,
        Code::EchoRequest,
        8,
        &[0x5e, 0x6f, 0x70, 0x81, 1, 2, 3],
    ));
    let (_, p) = h.tx_packet();
    assert_eq!((p.code(), p.id()), (Code::EchoReply, 8));
    assert_eq!(&p.data()[..], &[0x1a, 0x2b, 0x3c, 0x4d, 1, 2, 3]);
}

#[test]
fn echo_request_before_opened_is_ignored() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.rx("lcp_echo_request_gateway");
    h.no_tx();
}

// ------------------------------------------------------------ retransmission

#[test]
fn lcp_confreq_retransmission_then_failure() {
    let mut h = Harness::new();
    h.open();
    let (_, first) = h.tx_packet();
    assert_eq!(first.id(), 1);
    let t0 = h.now;
    for n in 2..=10u8 {
        h.fire();
        let (proto, p) = h.tx_packet();
        assert_eq!(proto, Protocol::LCP);
        assert_eq!(p.code(), Code::ConfigureRequest);
        assert_eq!(p.id(), n, "nouvel identifiant à chaque renvoi");
        assert_eq!(p.data(), first.data(), "même contenu");
    }
    assert_eq!(h.now - t0, Duration::from_secs(27));
    h.no_event();
    h.fire();
    h.no_tx();
    assert_eq!(
        h.event(),
        PppEvent::Down(DownReason::NegotiationFailed(Protocol::LCP))
    );
    assert_eq!(h.now - t0, Duration::from_secs(30));
}

#[test]
fn ipcp_confreq_retransmission_then_failure() {
    let mut h = Harness::with(|c| {
        c.max_configure = 3;
        c.echo_interval = None;
    });
    h.open();
    h.tx();
    h.rx("lcp_confreq_gateway");
    h.rx("lcp_confack_gateway");
    h.expect_tx("lcp_confack_client");
    h.expect_tx("ipcp_confreq_client_1");
    h.fire();
    let (proto, p) = h.tx_packet();
    assert_eq!((proto, p.id()), (Protocol::IPCP, 2));
    h.fire();
    h.tx();
    h.fire();
    assert_eq!(
        h.event(),
        PppEvent::Down(DownReason::NegotiationFailed(Protocol::IPCP))
    );
}

#[test]
fn ack_with_stale_id_is_ignored() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.fire(); // renvoi id 2
    h.tx();
    h.rx("lcp_confreq_gateway");
    h.tx();
    h.rx("lcp_confack_gateway"); // id 1 : périmé
    h.no_tx();
    h.rx_ppp(lcp_frame(
        Code::ConfigureAck,
        2,
        &[LcpOption::Mru(1354), LcpOption::MagicNumber(CLIENT_MAGIC)],
    ));
    // LCP Opened -> IPCP démarre.
    let (proto, _) = h.tx_packet();
    assert_eq!(proto, Protocol::IPCP);
}

#[test]
fn ack_with_different_options_is_ignored() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.rx("lcp_confreq_gateway");
    h.tx();
    h.rx_ppp(lcp_frame(Code::ConfigureAck, 1, &[LcpOption::Mru(1354)]));
    h.no_tx();
}

// ---------------------------------------------------------- politique LCP §9.2

#[test]
fn gateway_options_pfc_acfc_are_rejected() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    // Requête de la passerelle avec ACCM (accepté), PFC et ACFC (rejetés) ; son magic
    // est égal au nôtre mais seul le Reject est émis (RFC 1661).
    h.rx("lcp_confreq_client_with_accm_pfc_acfc");
    let (_, p) = h.tx_packet();
    assert_eq!((p.code(), p.id()), (Code::ConfigureReject, 2));
    assert_eq!(
        p.options().unwrap(),
        [LcpOption::Pfc.to_option(), LcpOption::Acfc.to_option()]
    );
}

#[test]
fn gateway_auth_and_unknown_options_are_rejected() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    let unknown = ConfigOption::new(13, Bytes::from_static(&[6])).unwrap();
    let raw = vec![
        LcpOption::Mru(1400).to_option(),
        LcpOption::AuthProtocol(Bytes::from_static(&[0xc0, 0x23])).to_option(),
        unknown.clone(),
    ];
    let req = ControlPacket::configure(Code::ConfigureRequest, 4, &raw).unwrap();
    h.rx_ppp(req.to_frame(Protocol::LCP).to_vec());
    let (_, p) = h.tx_packet();
    assert_eq!((p.code(), p.id()), (Code::ConfigureReject, 4));
    assert_eq!(p.options().unwrap(), &raw[1..]);
}

#[test]
fn gateway_magic_loop_is_naked() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.rx_ppp(lcp_frame(
        Code::ConfigureRequest,
        1,
        &[LcpOption::Mru(1354), LcpOption::MagicNumber(CLIENT_MAGIC)],
    ));
    let (_, p) = h.tx_packet();
    assert_eq!((p.code(), p.id()), (Code::ConfigureNak, 1));
    let opts = p.options().unwrap();
    assert_eq!(opts.len(), 1);
    match LcpOption::from_option(&opts[0]) {
        LcpOption::MagicNumber(m) => assert!(m != 0 && m != CLIENT_MAGIC),
        o => panic!("{o:?}"),
    }
}

#[test]
fn peer_mru_sets_mtu() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.rx_ppp(lcp_frame(
        Code::ConfigureRequest,
        1,
        &[LcpOption::Mru(1300)],
    ));
    h.rx("lcp_confack_gateway");
    h.rx("ipcp_confreq_gateway_empty");
    h.rx("ipcp_confack_gateway"); // id 2 : périmé, ignoré
    h.rx("ipcp_confnak_gateway");
    h.rx("ipcp_confack_gateway");
    match h.event() {
        PppEvent::IpcpUp { mtu, .. } => assert_eq!(mtu, 1300),
        e => panic!("{e:?}"),
    }
    assert_eq!(h.s.mtu(), 1300);
}

#[test]
fn lcp_confrej_removes_options_with_new_id() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.rx_ppp(lcp_frame(Code::ConfigureReject, 1, &[LcpOption::Mru(1354)]));
    let (_, p) = h.tx_packet();
    assert_eq!((p.code(), p.id()), (Code::ConfigureRequest, 2));
    assert_eq!(
        p.options().unwrap(),
        [LcpOption::MagicNumber(CLIENT_MAGIC).to_option()]
    );
}

#[test]
fn lcp_confrej_of_unsent_options_is_ignored() {
    // lcp_confrej_gateway rejette ACCM/PFC/ACFC, que nous n'envoyons jamais (et id 2).
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.fire(); // notre requête courante a l'id 2
    h.tx();
    h.rx("lcp_confrej_gateway");
    h.no_tx();
}

#[test]
fn lcp_confnak_mru() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.rx_ppp(lcp_frame(Code::ConfigureNak, 1, &[LcpOption::Mru(1200)]));
    let (_, p) = h.tx_packet();
    assert_eq!(p.id(), 2);
    assert_eq!(
        p.options().unwrap(),
        [
            LcpOption::Mru(1200).to_option(),
            LcpOption::MagicNumber(CLIENT_MAGIC).to_option()
        ]
    );
    // Valeur hors [576, 1500] : on abandonne l'option.
    h.rx_ppp(lcp_frame(Code::ConfigureNak, 2, &[LcpOption::Mru(100)]));
    let (_, p) = h.tx_packet();
    assert_eq!(p.id(), 3);
    assert_eq!(
        p.options().unwrap(),
        [LcpOption::MagicNumber(CLIENT_MAGIC).to_option()]
    );
}

#[test]
fn lcp_confnak_magic_picks_new_value() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.rx_ppp(lcp_frame(
        Code::ConfigureNak,
        1,
        &[LcpOption::MagicNumber(0x1111_1111)],
    ));
    let (_, p) = h.tx_packet();
    let opts: Vec<LcpOption> = p
        .options()
        .unwrap()
        .iter()
        .map(LcpOption::from_option)
        .collect();
    assert_eq!(opts[0], LcpOption::Mru(1354));
    match opts[1] {
        LcpOption::MagicNumber(m) => assert!(m != 0 && m != CLIENT_MAGIC),
        ref o => panic!("{o:?}"),
    }
}

#[test]
fn lcp_renegotiation_when_opened_is_down() {
    let mut h = Harness::new();
    h.negotiate();
    h.rx("lcp_confreq_gateway");
    assert_eq!(
        h.event(),
        PppEvent::Down(DownReason::Renegotiation(Protocol::LCP))
    );
}

#[test]
fn unknown_lcp_code_gets_code_reject() {
    let mut h = Harness::new();
    h.negotiate();
    let bad = ctl_frame(Protocol::LCP, Code::Unknown(42), 7, &[1, 2]);
    h.rx_ppp(bad.clone());
    let (proto, p) = h.tx_packet();
    assert_eq!(proto, Protocol::LCP);
    assert_eq!((p.code(), p.id()), (Code::CodeReject, 2));
    assert_eq!(&p.data()[..], &bad[2..]);
}

#[test]
fn discard_request_is_ignored() {
    let mut h = Harness::new();
    h.negotiate();
    h.rx_ppp(ctl_frame(
        Protocol::LCP,
        Code::DiscardRequest,
        1,
        &[0x5e, 0x6f, 0x70, 0x81],
    ));
    h.no_tx();
    h.no_event();
}

#[test]
fn protocol_reject_of_ipcp_is_down() {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.rx("lcp_confreq_gateway");
    h.rx("lcp_confack_gateway");
    let mut data = BytesMut::new();
    data.put_u16(0x8021);
    data.put_slice(&common::ppp("ipcp_confreq_client_1")[2..]);
    h.rx_ppp(ctl_frame(Protocol::LCP, Code::ProtocolReject, 9, &data));
    assert_eq!(
        h.event(),
        PppEvent::Down(DownReason::ProtocolRejected(Protocol::IPCP))
    );
}

// ------------------------------------------------------------------ IPCP §9.4

fn lcp_opened() -> Harness {
    let mut h = Harness::new();
    h.open();
    h.tx();
    h.rx("lcp_confreq_gateway");
    h.rx("lcp_confack_gateway");
    h.expect_tx("lcp_confack_client");
    h.expect_tx("ipcp_confreq_client_1");
    h
}

#[test]
fn ipcp_dns_reject_continues_without_dns() {
    let mut h = lcp_opened();
    // Reject des DNS 129/131.
    let mut data = BytesMut::new();
    data.put_slice(&[0x81, 6, 0, 0, 0, 0, 0x83, 6, 0, 0, 0, 0]);
    h.rx_ppp(ctl_frame(Protocol::IPCP, Code::ConfigureReject, 1, &data));
    let (proto, p) = h.tx_packet();
    assert_eq!((proto, p.id()), (Protocol::IPCP, 2));
    assert_eq!(&p.data()[..], &[3, 6, 0, 0, 0, 0]);
    h.rx_ppp(ctl_frame(
        Protocol::IPCP,
        Code::ConfigureNak,
        2,
        &[3, 6, 10, 10, 0, 2],
    ));
    let (_, p) = h.tx_packet();
    assert_eq!(&p.data()[..], &[3, 6, 10, 10, 0, 2]);
    h.rx_ppp(ctl_frame(
        Protocol::IPCP,
        Code::ConfigureAck,
        3,
        &[3, 6, 10, 10, 0, 2],
    ));
    h.rx("ipcp_confreq_gateway_empty");
    h.expect_tx("ipcp_confack_client_empty");
    assert_eq!(
        h.event(),
        PppEvent::IpcpUp {
            local_ip: Ipv4Addr::new(10, 10, 0, 2),
            dns: vec![],
            peer: None,
            mtu: 1354
        }
    );
}

#[test]
fn ipcp_address_reject_is_failure() {
    let mut h = lcp_opened();
    h.rx_ppp(ctl_frame(
        Protocol::IPCP,
        Code::ConfigureReject,
        1,
        &[3, 6, 0, 0, 0, 0],
    ));
    assert_eq!(
        h.event(),
        PppEvent::Down(DownReason::NegotiationFailed(Protocol::IPCP))
    );
}

#[test]
fn ipcp_vj_reject_of_unsent_option_is_ignored() {
    let mut h = lcp_opened();
    h.rx("ipcp_confrej_gateway_vj");
    h.no_tx();
    h.no_event();
}

#[test]
fn ipcp_gateway_unknown_options_are_rejected_never_naked() {
    let mut h = lcp_opened();
    // VJ (2) + NBNS (130) + adresse : seules 2 et 130 sont rejetées.
    let data = [
        2, 6, 0, 0x2d, 0x0f, 1, 3, 6, 169, 254, 1, 1, 130, 6, 0, 0, 0, 0,
    ];
    h.rx_ppp(ctl_frame(Protocol::IPCP, Code::ConfigureRequest, 5, &data));
    let (proto, p) = h.tx_packet();
    assert_eq!(
        (proto, p.code(), p.id()),
        (Protocol::IPCP, Code::ConfigureReject, 5)
    );
    assert_eq!(&p.data()[..], &[2, 6, 0, 0x2d, 0x0f, 1, 130, 6, 0, 0, 0, 0]);
    // Adresse quelconque (même 0.0.0.0) : Ack tel quel.
    h.rx_ppp(ctl_frame(
        Protocol::IPCP,
        Code::ConfigureRequest,
        6,
        &[3, 6, 0, 0, 0, 0],
    ));
    let (_, p) = h.tx_packet();
    assert_eq!((p.code(), p.id()), (Code::ConfigureAck, 6));
}

#[test]
fn ipcp_terminate_request_is_down() {
    let mut h = lcp_opened();
    h.rx_ppp(ctl_frame(Protocol::IPCP, Code::TerminateRequest, 3, &[]));
    let (proto, p) = h.tx_packet();
    assert_eq!(
        (proto, p.code(), p.id()),
        (Protocol::IPCP, Code::TerminateAck, 3)
    );
    assert_eq!(h.event(), PppEvent::Down(DownReason::ClosedByPeer));
}

#[test]
fn ipcp_renegotiation_when_opened_is_down() {
    let mut h = Harness::new();
    h.negotiate();
    h.rx("ipcp_confreq_gateway");
    assert_eq!(
        h.event(),
        PppEvent::Down(DownReason::Renegotiation(Protocol::IPCP))
    );
}

// ------------------------------------------------------------------ fermeture

#[test]
fn close_without_terminate_ack_times_out() {
    let mut h = Harness::new();
    h.negotiate();
    h.s.close(h.now);
    let (proto, p) = h.tx_packet();
    assert_eq!(
        (proto, p.code(), p.id()),
        (Protocol::LCP, Code::TerminateRequest, 2)
    );
    let t0 = h.now;
    // Plus de keepalive pendant la fermeture ; trafic ignoré.
    h.rx("lcp_echo_request_gateway");
    h.rx("ipv4_icmp_echo_reply");
    h.no_tx();
    h.no_event();
    h.fire();
    assert_eq!(h.now - t0, Duration::from_secs(1));
    h.no_tx(); // un seul envoi
    assert_eq!(h.event(), PppEvent::Down(DownReason::LocalClose));
}

#[test]
fn close_crossing_gateway_terminate() {
    let mut h = Harness::new();
    h.negotiate();
    h.s.close(h.now);
    h.tx();
    h.rx("lcp_terminate_request_gateway");
    h.expect_tx("lcp_terminate_ack_client");
    assert_eq!(h.event(), PppEvent::Down(DownReason::LocalClose));
}

#[test]
fn close_before_open() {
    let mut h = Harness::new();
    h.s.close(h.now);
    h.no_tx();
    assert_eq!(h.event(), PppEvent::Down(DownReason::LocalClose));
    h.open();
    h.no_tx();
}

#[test]
fn close_vector_id_three() {
    // Séquence produisant exactement lcp_terminate_request_client (id 3).
    let mut h = Harness::new();
    h.negotiate();
    h.fire();
    h.expect_tx("lcp_echo_request_client");
    h.s.close(h.now);
    h.expect_tx("lcp_terminate_request_client");
    h.rx("lcp_terminate_ack_gateway");
    assert_eq!(h.event(), PppEvent::Down(DownReason::LocalClose));
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn arbitrary_frames_never_panic() {
    let mut x: u32 = 0xdead_beef;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    let protos: [[u8; 2]; 5] = [
        [0xc0, 0x21],
        [0x80, 0x21],
        [0x00, 0x21],
        [0x80, 0x57],
        [0xff, 0x03],
    ];
    for _ in 0..200 {
        let mut h = Harness::new();
        h.negotiate();
        for _ in 0..50 {
            let mut f = protos[(next() % 5) as usize].to_vec();
            let len = (next() % 40) as usize;
            f.extend((0..len).map(|_| next() as u8));
            if f.len() >= 6 && next() % 2 == 0 {
                // longueur de contrôle cohérente pour atteindre l'automate
                let l = (f.len() - 2) as u16;
                f[4..6].copy_from_slice(&l.to_be_bytes());
                f[2] = (next() % 12) as u8;
            }
            h.rx_ppp(f);
            while h.s.poll_transmit().is_some() {}
            while h.s.poll_event().is_some() {}
            if next() % 10 == 0 {
                h.advance(Duration::from_secs(u64::from(next() % 40)));
            }
        }
    }
}
