//! Client scripté rejouant `lcp.hex`, `ipcp.hex`, `ip.hex`, `framing.hex` contre
//! `PppPeer` : chaque trame émise par la passerelle est comparée à l'octet près.

mod common;

use std::net::Ipv4Addr;
use std::time::Duration;

use common::hex_frame;
use common::ppp::{expect_frame, peer_end, read_wire_frame, spawn_peer};
use mock_gw::{
    GatewayIpcpRequest, IpcpUp, MalformedFrame, PeerEnd, PeerPhase, PppPeer, PppPeerConfig,
    TunnelConfig, icmp_echo_reply,
};
use proto::frame::FrameError;
use tokio::io::{AsyncWrite, AsyncWriteExt, DuplexStream};

fn lcp(name: &str) -> Vec<u8> {
    hex_frame("lcp.hex", name)
}
fn ipcp(name: &str) -> Vec<u8> {
    hex_frame("ipcp.hex", name)
}
fn ip(name: &str) -> Vec<u8> {
    hex_frame("ip.hex", name)
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, bytes: &[u8]) {
    s.write_all(bytes).await.unwrap();
    s.flush().await.unwrap();
}

/// LCP complet selon les vecteurs ; laisse le flux juste après l'émission (par la
/// passerelle) de son IPCP Configure-Request, renvoyé.
async fn lcp_handshake(c: &mut DuplexStream) -> Vec<u8> {
    expect_frame(c, &lcp("lcp_confreq_gateway"), "ConfReq LCP passerelle").await;
    send(c, &lcp("lcp_confreq_client")).await;
    expect_frame(c, &lcp("lcp_confack_gateway"), "ConfAck LCP passerelle").await;
    send(c, &lcp("lcp_confack_client")).await;
    read_wire_frame(c).await.unwrap().expect("IPCP ConfReq")
}

#[tokio::test]
async fn nominal_sequence_matches_vectors() {
    let peer = PppPeer::default();
    let mut obs = peer.observer();
    let (mut c, task) = spawn_peer(&peer, &TunnelConfig::vector_split());

    let req = lcp_handshake(&mut c).await;
    assert_eq!(req, ipcp("ipcp_confreq_gateway"));
    assert_eq!(obs.status().phase, PeerPhase::Ipcp);

    send(&mut c, &ipcp("ipcp_confreq_client_1")).await;
    expect_frame(&mut c, &ipcp("ipcp_confnak_gateway"), "Nak IPCP").await;
    send(&mut c, &ipcp("ipcp_confreq_client_2")).await;
    expect_frame(&mut c, &ipcp("ipcp_confack_gateway"), "Ack IPCP").await;
    assert_eq!(
        obs.status().ipcp,
        None,
        "IPCP pas encore ouvert (Ack non reçu)"
    );
    send(&mut c, &ipcp("ipcp_confack_client")).await;

    let up = tokio::time::timeout(common::TIMEOUT, obs.wait_ipcp_up())
        .await
        .unwrap()
        .expect("IPCP up");
    assert_eq!(
        up,
        IpcpUp {
            conn_id: 7,
            client_ip: Ipv4Addr::new(10, 10, 0, 2),
            dns: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)],
            gateway_ip: Some(Ipv4Addr::new(169, 254, 1, 1)),
            client_magic: Some(0x1a2b_3c4d),
            client_mru: 1354,
        }
    );
    assert_eq!(obs.status().phase, PeerPhase::Up);

    // Données : ICMP Echo Request -> Echo Reply exact (IP id 0xabcd, sommes recalculées).
    send(&mut c, &ip("ipv4_icmp_echo_request")).await;
    expect_frame(&mut c, &ip("ipv4_icmp_echo_reply"), "ICMP Echo Reply").await;

    // Keepalive client.
    send(&mut c, &lcp("lcp_echo_request_client")).await;
    expect_frame(&mut c, &lcp("lcp_echo_reply_gateway"), "LCP Echo-Reply").await;

    // Terminaison par le client.
    send(&mut c, &lcp("lcp_terminate_request_client")).await;
    expect_frame(&mut c, &lcp("lcp_terminate_ack_gateway"), "Terminate-Ack").await;
    assert_eq!(
        read_wire_frame(&mut c).await.unwrap(),
        None,
        "fermeture après l'Ack"
    );
    assert_eq!(peer_end(task).await, PeerEnd::ClientTerminated);

    let st = obs.status();
    assert_eq!(st.phase, PeerPhase::Closed);
    assert_eq!(st.end, Some(PeerEnd::ClientTerminated));
    let n = obs.counters();
    assert_eq!(n.sessions, 1);
    assert_eq!(n.ipcp_up, 1);
    assert_eq!(n.frames_rx, 8);
    assert_eq!(n.frames_tx, 8);
    assert_eq!((n.ipv4_rx, n.ipv4_tx, n.icmp_echo_replied), (1, 1, 1));
    assert_eq!((n.lcp_echo_requests_rx, n.lcp_echo_replies_tx), (1, 1));
    assert_eq!((n.ipv4_dropped, n.ignored), (0, 0));
}

#[tokio::test]
async fn empty_ipcp_variant_b() {
    let peer = PppPeer::new(PppPeerConfig {
        ipcp_request: GatewayIpcpRequest::Empty,
        ..PppPeerConfig::default()
    });
    let mut obs = peer.observer();
    let (mut c, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let req = lcp_handshake(&mut c).await;
    assert_eq!(req, ipcp("ipcp_confreq_gateway_empty"));
    send(&mut c, &ipcp("ipcp_confack_client_empty")).await;
    // Ack reçu avant que le client ait obtenu son adresse : pas encore ouvert.
    send(&mut c, &ipcp("ipcp_confreq_client_1")).await;
    expect_frame(&mut c, &ipcp("ipcp_confnak_gateway"), "Nak IPCP").await;
    send(&mut c, &ipcp("ipcp_confreq_client_2")).await;
    expect_frame(&mut c, &ipcp("ipcp_confack_gateway"), "Ack IPCP").await;
    let up = obs.wait_ipcp_up().await.expect("IPCP up");
    assert_eq!(up.gateway_ip, None);
    assert_eq!(up.client_ip, Ipv4Addr::new(10, 10, 0, 2));
    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
}

#[tokio::test]
async fn rejects_accm_pfc_acfc_and_vj() {
    let peer = PppPeer::default();
    let (mut c, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    expect_frame(&mut c, &lcp("lcp_confreq_gateway"), "ConfReq LCP").await;
    send(&mut c, &lcp("lcp_confreq_client_with_accm_pfc_acfc")).await;
    expect_frame(&mut c, &lcp("lcp_confrej_gateway"), "ConfRej LCP").await;
    // Le client corrige et la négociation reprend.
    send(&mut c, &lcp("lcp_confreq_client")).await;
    expect_frame(&mut c, &lcp("lcp_confack_gateway"), "ConfAck LCP").await;
    send(&mut c, &lcp("lcp_confack_client")).await;
    expect_frame(&mut c, &ipcp("ipcp_confreq_gateway"), "ConfReq IPCP").await;
    send(&mut c, &ipcp("ipcp_confreq_client_with_vj")).await;
    expect_frame(
        &mut c,
        &ipcp("ipcp_confrej_gateway_vj"),
        "ConfRej IPCP (VJ)",
    )
    .await;
    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
}

#[tokio::test]
async fn ipv6cp_offer_and_protocol_rejects() {
    let peer = PppPeer::new(PppPeerConfig {
        offer_ipv6cp: true,
        ..PppPeerConfig::default()
    });
    let obs = peer.observer();
    let (mut c, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let first = lcp_handshake(&mut c).await;
    assert_eq!(
        first,
        lcp("ipv6cp_confreq_gateway"),
        "IPV6CP proposé après LCP"
    );
    expect_frame(&mut c, &ipcp("ipcp_confreq_gateway"), "ConfReq IPCP").await;
    send(&mut c, &lcp("lcp_protocol_reject_ipv6cp_client")).await;

    // Dans l'autre sens : la passerelle rejette un protocole qu'elle ne gère pas.
    send(&mut c, &lcp("ipv6cp_confreq_gateway")).await;
    let mut expected = lcp("lcp_protocol_reject_ipv6cp_client");
    expected[9] = 2; // identifiant LCP suivant de la passerelle (vecteur : 4)
    expect_frame(&mut c, &expected, "Protocol-Reject IPV6CP").await;

    // Code LCP inconnu -> Code-Reject (id 3) recopiant le paquet.
    send(
        &mut c,
        &[
            0x00, 0x0c, 0x50, 0x50, 0x00, 0x06, 0xc0, 0x21, 0x0c, 0x05, 0x00, 0x04,
        ],
    )
    .await;
    expect_frame(
        &mut c,
        &[
            0x00, 0x10, 0x50, 0x50, 0x00, 0x0a, 0xc0, 0x21, 0x07, 0x03, 0x00, 0x08, 0x0c, 0x05,
            0x00, 0x04,
        ],
        "Code-Reject",
    )
    .await;

    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
    assert!(obs.status().ipv6cp_rejected);
    let n = obs.counters();
    assert_eq!((n.protocol_rejects_rx, n.protocol_rejects_tx), (1, 1));
}

#[tokio::test]
async fn gateway_echo_requests_and_ipcp_before_lcp_ignored() {
    let peer = PppPeer::new(PppPeerConfig {
        echo_interval: Some(Duration::from_millis(20)),
        ..PppPeerConfig::default()
    });
    let obs = peer.observer();
    let (mut c, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    expect_frame(&mut c, &lcp("lcp_confreq_gateway"), "ConfReq LCP").await;
    // IPCP avant LCP ouvert : ignoré (§9.3).
    send(&mut c, &ipcp("ipcp_confreq_client_1")).await;
    // IPv4 avant IPCP ouvert : ignoré.
    send(&mut c, &ip("ipv4_icmp_echo_request")).await;
    send(&mut c, &lcp("lcp_confreq_client")).await;
    expect_frame(&mut c, &lcp("lcp_confack_gateway"), "ConfAck LCP").await;
    send(&mut c, &lcp("lcp_confack_client")).await;
    expect_frame(&mut c, &ipcp("ipcp_confreq_gateway"), "ConfReq IPCP").await;
    // Echo-Request de la passerelle (magic passerelle) ; seul l'id diffère du vecteur.
    let mut expected = lcp("lcp_echo_request_gateway");
    expected[9] = 1;
    expect_frame(&mut c, &expected, "Echo-Request passerelle").await;
    let mut reply = lcp("lcp_echo_reply_client");
    reply[9] = 1;
    send(&mut c, &reply).await;
    expected[9] = 2;
    expect_frame(&mut c, &expected, "2e Echo-Request").await;
    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
    let n = obs.counters();
    assert_eq!(n.ignored, 1, "IPCP avant LCP");
    assert_eq!(n.ipv4_dropped, 1, "IPv4 avant IPCP");
    assert_eq!(n.lcp_echo_replies_rx, 1);
    assert!(n.lcp_echo_requests_tx >= 2);
}

#[tokio::test]
async fn frames_split_at_every_byte_and_coalesced() {
    let peer = PppPeer::default();
    let mut obs = peer.observer();
    let (mut c, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    expect_frame(&mut c, &lcp("lcp_confreq_gateway"), "ConfReq LCP").await;
    // Requête et Ack LCP du client dans une seule écriture.
    let mut both = lcp("lcp_confreq_client");
    both.extend(lcp("lcp_confack_client"));
    send(&mut c, &both).await;
    expect_frame(&mut c, &lcp("lcp_confack_gateway"), "ConfAck LCP").await;
    expect_frame(&mut c, &ipcp("ipcp_confreq_gateway"), "ConfReq IPCP").await;
    // IPCP octet par octet.
    let mut script = ipcp("ipcp_confreq_client_1");
    script.extend(ipcp("ipcp_confreq_client_2"));
    script.extend(ipcp("ipcp_confack_client"));
    for b in &script {
        send(&mut c, std::slice::from_ref(b)).await;
    }
    expect_frame(&mut c, &ipcp("ipcp_confnak_gateway"), "Nak IPCP").await;
    expect_frame(&mut c, &ipcp("ipcp_confack_gateway"), "Ack IPCP").await;
    assert!(obs.wait_ipcp_up().await.is_some());
    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
}

#[tokio::test]
async fn bad_frames_from_client_end_session() {
    for (name, err) in [
        ("err_bad_magic", FrameError::BadMagic([0x50, 0x51])),
        (
            "err_inconsistent_lengths",
            FrameError::InconsistentLength {
                total: 23,
                ppp_len: 16,
            },
        ),
        ("err_total_too_small", FrameError::TotalTooSmall(6)),
        (
            "err_http_instead_of_ppp",
            FrameError::HttpResponse { status: Some(403) },
        ),
    ] {
        let peer = PppPeer::default();
        let (mut c, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
        expect_frame(&mut c, &lcp("lcp_confreq_gateway"), "ConfReq LCP").await;
        send(&mut c, &hex_frame("framing.hex", name)).await;
        assert_eq!(read_wire_frame(&mut c).await.unwrap(), None, "{name}");
        assert_eq!(peer_end(task).await, PeerEnd::BadFrame(err), "{name}");
    }
}

#[test]
fn malformed_frame_bytes_match_vectors() {
    for (kind, name) in [
        (MalformedFrame::BadMagic, "err_bad_magic"),
        (
            MalformedFrame::InconsistentLengths,
            "err_inconsistent_lengths",
        ),
        (MalformedFrame::TotalTooSmall, "err_total_too_small"),
    ] {
        assert_eq!(kind.bytes(), hex_frame("framing.hex", name), "{name}");
    }
}

#[test]
fn icmp_reply_function_matches_vector() {
    let req = ip("ipv4_icmp_echo_request_raw_ip");
    assert_eq!(req, ip("ipv4_icmp_echo_request")[8..]);
    let reply = icmp_echo_reply(&req, 0xabcd).unwrap();
    assert_eq!(reply, ip("ipv4_icmp_echo_reply")[8..]);
    // Bourrage au-delà de la longueur IP : ignoré.
    let mut padded = req.clone();
    padded.extend([0u8; 6]);
    assert_eq!(icmp_echo_reply(&padded, 0xabcd).unwrap(), reply);
    // Sommes de contrôle corrompues, fragment, pas un Echo Request.
    let mut bad = req.clone();
    bad[10] ^= 1;
    assert_eq!(
        icmp_echo_reply(&bad, 1),
        Err(mock_gw::IcmpDrop::MalformedIp)
    );
    let mut bad = req.clone();
    bad[30] ^= 1;
    assert_eq!(
        icmp_echo_reply(&bad, 1),
        Err(mock_gw::IcmpDrop::MalformedIcmp)
    );
    let reply_as_req = &ip("ipv4_icmp_echo_reply")[8..];
    assert_eq!(
        icmp_echo_reply(reply_as_req, 1),
        Err(mock_gw::IcmpDrop::NotEchoRequest)
    );
    let mut frag = req.clone();
    frag[6] = 0x20; // MF
    frag[10..12].fill(0);
    let sum = mock_gw::internet_checksum(&frag[..20]);
    frag[10..12].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(icmp_echo_reply(&frag, 1), Err(mock_gw::IcmpDrop::Fragment));
}
