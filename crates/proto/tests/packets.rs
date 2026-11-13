//! Paquets PPP typés contre `docs/vectors/*.hex` (§9).

mod common;

use std::net::Ipv4Addr;

use bytes::Bytes;
use proto::ppp::{
    Code, ConfigOption, ControlPacket, IpcpOption, LcpOption, Packet, PppFrame, Protocol,
};

fn parse(name: &str) -> Packet {
    Packet::parse(Bytes::from(common::ppp(name))).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn lcp(name: &str) -> ControlPacket {
    match parse(name) {
        Packet::Lcp(p) => p,
        other => panic!("{name}: pas LCP : {other:?}"),
    }
}

fn ipcp(name: &str) -> ControlPacket {
    match parse(name) {
        Packet::Ipcp(p) => p,
        other => panic!("{name}: pas IPCP : {other:?}"),
    }
}

fn lcp_opts(p: &ControlPacket) -> Vec<LcpOption> {
    p.options()
        .unwrap()
        .iter()
        .map(LcpOption::from_option)
        .collect()
}

fn ipcp_opts(p: &ControlPacket) -> Vec<IpcpOption> {
    p.options()
        .unwrap()
        .iter()
        .map(IpcpOption::from_option)
        .collect()
}

fn raw(opts: &[LcpOption]) -> Vec<ConfigOption> {
    opts.iter().map(LcpOption::to_option).collect()
}

fn raw_ip(opts: &[IpcpOption]) -> Vec<ConfigOption> {
    opts.iter().map(IpcpOption::to_option).collect()
}

/// Tous les vecteurs valides : parse puis `to_bytes` redonne la trame PPP exacte.
#[test]
fn every_vector_packet_roundtrips() {
    for v in common::all().into_values() {
        if v.name.starts_with("err_")
            || v.name.starts_with("stream_")
            || v.name.ends_with("_raw_ip")
        {
            continue;
        }
        let ppp = Bytes::from(v.bytes[6..].to_vec());
        let p = Packet::parse(ppp.clone()).unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(p.to_bytes(), ppp, "{}", v.name);
        if let Packet::Lcp(c) | Packet::Ipcp(c) = &p {
            if matches!(
                c.code(),
                Code::ConfigureRequest
                    | Code::ConfigureAck
                    | Code::ConfigureNak
                    | Code::ConfigureReject
            ) {
                c.options().unwrap_or_else(|e| panic!("{}: {e}", v.name));
            }
        }
    }
}

#[test]
fn lcp_confreq_client_build() {
    let p = ControlPacket::configure(
        Code::ConfigureRequest,
        1,
        &raw(&[LcpOption::Mru(1354), LcpOption::MagicNumber(0x1a2b_3c4d)]),
    )
    .unwrap();
    assert_eq!(
        &p.to_frame(Protocol::LCP)[..],
        &common::ppp("lcp_confreq_client")[..]
    );
}

#[test]
fn lcp_confreq_gateway_parse() {
    let p = lcp("lcp_confreq_gateway");
    assert_eq!((p.code(), p.id()), (Code::ConfigureRequest, 1));
    assert_eq!(
        lcp_opts(&p),
        [LcpOption::Mru(1354), LcpOption::MagicNumber(0x5e6f_7081)]
    );
}

#[test]
fn lcp_confacks() {
    let ack = lcp("lcp_confack_client");
    let req = lcp("lcp_confreq_gateway");
    assert_eq!((ack.code(), ack.id()), (Code::ConfigureAck, req.id()));
    assert_eq!(ack.data(), req.data());
    let ack = lcp("lcp_confack_gateway");
    assert_eq!(ack.code(), Code::ConfigureAck);
    assert_eq!(ack.data(), lcp("lcp_confreq_client").data());
}

#[test]
fn lcp_confreq_with_accm_pfc_acfc_parse() {
    let p = lcp("lcp_confreq_client_with_accm_pfc_acfc");
    assert_eq!(p.id(), 2);
    assert_eq!(
        lcp_opts(&p),
        [
            LcpOption::Mru(1354),
            LcpOption::Accm(0),
            LcpOption::MagicNumber(0x1a2b_3c4d),
            LcpOption::Pfc,
            LcpOption::Acfc
        ]
    );
}

#[test]
fn lcp_confrej_gateway_parse_and_build() {
    let p = lcp("lcp_confrej_gateway");
    assert_eq!((p.code(), p.id()), (Code::ConfigureReject, 2));
    let opts = [LcpOption::Accm(0), LcpOption::Pfc, LcpOption::Acfc];
    assert_eq!(lcp_opts(&p), opts);
    let built = ControlPacket::configure(Code::ConfigureReject, 2, &raw(&opts)).unwrap();
    assert_eq!(built, p);
}

#[test]
fn lcp_echo_vectors() {
    for (name, code, id, magic) in [
        (
            "lcp_echo_request_gateway",
            Code::EchoRequest,
            7,
            0x5e6f_7081,
        ),
        ("lcp_echo_reply_client", Code::EchoReply, 7, 0x1a2b_3c4d),
        ("lcp_echo_request_client", Code::EchoRequest, 2, 0x1a2b_3c4d),
        ("lcp_echo_reply_gateway", Code::EchoReply, 2, 0x5e6f_7081),
    ] {
        let p = lcp(name);
        assert_eq!((p.code(), p.id()), (code, id), "{name}");
        let (m, data) = p.magic_and_data().unwrap();
        assert_eq!(m, magic, "{name}");
        assert!(data.is_empty());
        let built = ControlPacket::echo(code, id, magic, &[]).unwrap();
        assert_eq!(
            &built.to_frame(Protocol::LCP)[..],
            &common::ppp(name)[..],
            "{name}"
        );
    }
}

#[test]
fn lcp_terminate_vectors() {
    for (name, code, id) in [
        ("lcp_terminate_request_client", Code::TerminateRequest, 3),
        ("lcp_terminate_ack_gateway", Code::TerminateAck, 3),
        ("lcp_terminate_request_gateway", Code::TerminateRequest, 9),
        ("lcp_terminate_ack_client", Code::TerminateAck, 9),
    ] {
        let p = lcp(name);
        assert_eq!((p.code(), p.id()), (code, id), "{name}");
        let built = ControlPacket::new(code, id, Bytes::new()).unwrap();
        assert_eq!(
            &built.to_frame(Protocol::LCP)[..],
            &common::ppp(name)[..],
            "{name}"
        );
    }
}

#[test]
fn ipv6cp_protocol_reject() {
    let Packet::Other(f) = parse("ipv6cp_confreq_gateway") else {
        panic!("IPV6CP attendu en Other");
    };
    assert_eq!(f.protocol, Protocol::IPV6CP);
    let rej = ControlPacket::protocol_reject(4, f.protocol, &f.payload, 1354);
    assert_eq!(
        &rej.to_frame(Protocol::LCP)[..],
        &common::ppp("lcp_protocol_reject_ipv6cp_client")[..]
    );
    let p = lcp("lcp_protocol_reject_ipv6cp_client");
    assert_eq!(p.code(), Code::ProtocolReject);
    let (proto, info) = p.rejected_protocol().unwrap();
    assert_eq!(proto, Protocol::IPV6CP);
    assert_eq!(info, f.payload);
}

#[test]
fn ipcp_client_requests() {
    let zero = Ipv4Addr::UNSPECIFIED;
    let opts1 = [
        IpcpOption::IpAddress(zero),
        IpcpOption::PrimaryDns(zero),
        IpcpOption::SecondaryDns(zero),
    ];
    let p = ControlPacket::configure(Code::ConfigureRequest, 1, &raw_ip(&opts1)).unwrap();
    assert_eq!(
        &p.to_frame(Protocol::IPCP)[..],
        &common::ppp("ipcp_confreq_client_1")[..]
    );
    assert_eq!(ipcp_opts(&ipcp("ipcp_confreq_client_1")), opts1);

    let opts2 = [
        IpcpOption::IpAddress(Ipv4Addr::new(10, 10, 0, 2)),
        IpcpOption::PrimaryDns(Ipv4Addr::new(10, 0, 0, 53)),
        IpcpOption::SecondaryDns(Ipv4Addr::new(10, 0, 0, 54)),
    ];
    let p = ControlPacket::configure(Code::ConfigureRequest, 2, &raw_ip(&opts2)).unwrap();
    assert_eq!(
        &p.to_frame(Protocol::IPCP)[..],
        &common::ppp("ipcp_confreq_client_2")[..]
    );

    let nak = ipcp("ipcp_confnak_gateway");
    assert_eq!((nak.code(), nak.id()), (Code::ConfigureNak, 1));
    assert_eq!(ipcp_opts(&nak), opts2);
    let ack = ipcp("ipcp_confack_gateway");
    assert_eq!((ack.code(), ack.id()), (Code::ConfigureAck, 2));
    assert_eq!(ipcp_opts(&ack), opts2);
}

#[test]
fn ipcp_gateway_variants() {
    let req = ipcp("ipcp_confreq_gateway");
    assert_eq!(
        ipcp_opts(&req),
        [IpcpOption::IpAddress(Ipv4Addr::new(169, 254, 1, 1))]
    );
    let ack = ControlPacket::new(Code::ConfigureAck, req.id(), req.data().clone()).unwrap();
    assert_eq!(
        &ack.to_frame(Protocol::IPCP)[..],
        &common::ppp("ipcp_confack_client")[..]
    );

    let req = ipcp("ipcp_confreq_gateway_empty");
    assert!(req.options().unwrap().is_empty());
    let ack = ControlPacket::configure(Code::ConfigureAck, req.id(), &[]).unwrap();
    assert_eq!(
        &ack.to_frame(Protocol::IPCP)[..],
        &common::ppp("ipcp_confack_client_empty")[..]
    );
}

#[test]
fn ipcp_vj_counterexample() {
    let req = ipcp("ipcp_confreq_client_with_vj");
    let opts = ipcp_opts(&req);
    assert!(matches!(&opts[0], IpcpOption::Other(o) if o.kind() == 2));
    let rej = ipcp("ipcp_confrej_gateway_vj");
    assert_eq!(rej.code(), Code::ConfigureReject);
    let rej_opts = rej.options().unwrap();
    assert_eq!(rej_opts.len(), 1);
    assert_eq!(rej_opts[0].kind(), 2);
    assert_eq!(&rej_opts[0].value()[..], &[0x00, 0x2d, 0x0f, 0x01]);
}

#[test]
fn ipv4_data_vectors() {
    let raw_ip = common::wire("ipv4_icmp_echo_request_raw_ip");
    match parse("ipv4_icmp_echo_request") {
        Packet::Ipv4(ip) => assert_eq!(&ip[..], &raw_ip[..]),
        other => panic!("{other:?}"),
    }
    match parse("ipv4_icmp_echo_reply") {
        Packet::Ipv4(ip) => {
            assert_eq!(ip.len(), 60);
            assert_eq!(ip[0], 0x45);
        }
        other => panic!("{other:?}"),
    }
    let f = PppFrame {
        protocol: Protocol::IPV4,
        payload: Bytes::from(raw_ip),
    };
    assert_eq!(
        &f.to_bytes()[..],
        &common::ppp("ipv4_icmp_echo_request")[..]
    );
}
