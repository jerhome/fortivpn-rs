//! Interopérabilité : automate client `proto::ppp::PppSession` (piloté à la main, sans
//! `core`) contre le pair PPP indépendant de mock-gw, en mémoire et à travers TLS ;
//! chaque `PppFault`.

mod common;

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use common::ppp::{ClientEnd, PppClient, client_config, peer_end, spawn_peer};
use common::{connect, hex_frame, login, tunnel_request};
use mock_gw::{
    DnsServer, FaultTrigger, GatewayIpcpRequest, MalformedFrame, MockGateway, PeerEnd, PeerPhase,
    PppFault, PppPeer, PppPeerConfig, TunnelConfig, internet_checksum,
};
use proto::frame::FrameError;
use proto::ppp::{DownReason, PppEvent, Protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn echo_request() -> Vec<u8> {
    hex_frame("ip.hex", "ipv4_icmp_echo_request_raw_ip")
}
fn echo_reply() -> Vec<u8> {
    hex_frame("ip.hex", "ipv4_icmp_echo_reply")[8..].to_vec()
}

fn ipcp_up_split() -> PppEvent {
    PppEvent::IpcpUp {
        local_ip: Ipv4Addr::new(10, 10, 0, 2),
        dns: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)],
        peer: Some(Ipv4Addr::new(169, 254, 1, 1)),
        mtu: 1354,
    }
}

fn is_ipv4(e: &PppEvent) -> bool {
    matches!(e, PppEvent::Ipv4(_))
}

#[tokio::test]
async fn handshake_ping_and_client_close() {
    let peer = PppPeer::default();
    let mut obs = peer.observer();
    let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let mut c = PppClient::new(stream, client_config());

    assert_eq!(c.connect().await.unwrap(), ipcp_up_split());
    let up = obs.wait_ipcp_up().await.unwrap();
    assert_eq!(up.client_ip, Ipv4Addr::new(10, 10, 0, 2));
    assert_eq!(up.client_magic, Some(0x1a2b_3c4d));

    for _ in 0..3 {
        c.send_ipv4(&echo_request()).await.unwrap();
        let PppEvent::Ipv4(ip) = c.run_until(is_ipv4).await.unwrap() else {
            unreachable!()
        };
        // Seul l'identifiant IP (incrémenté) et donc la somme IP changent.
        assert_eq!(ip[..4], echo_reply()[..4]);
        assert_eq!(ip[6..10], echo_reply()[6..10]);
        assert_eq!(ip[12..], echo_reply()[12..]);
        assert_eq!(internet_checksum(&ip[..20]), 0);
    }

    c.session.close(std::time::Instant::now());
    assert_eq!(
        c.run_until(|e| matches!(e, PppEvent::Down(_))).await,
        Ok(PppEvent::Down(DownReason::LocalClose))
    );
    assert_eq!(c.drain().await, ClientEnd::Eof);
    assert_eq!(peer_end(task).await, PeerEnd::ClientTerminated);
    let n = obs.counters();
    assert_eq!((n.icmp_echo_replied, n.ipv4_tx), (3, 3));
    assert_eq!(n.ignored, 0);
}

#[tokio::test]
async fn empty_variant_single_dns_rejects_secondary() {
    let peer = PppPeer::new(PppPeerConfig {
        ipcp_request: GatewayIpcpRequest::Empty,
        ..PppPeerConfig::default()
    });
    let mut obs = peer.observer();
    let cfg = TunnelConfig::full_tunnel(
        Ipv4Addr::new(10, 212, 134, 200),
        vec![DnsServer::new(Ipv4Addr::new(10, 0, 0, 53))],
    );
    let (stream, task) = spawn_peer(&peer, &cfg);
    let mut c = PppClient::new(stream, client_config());
    assert_eq!(
        c.connect().await.unwrap(),
        PppEvent::IpcpUp {
            local_ip: Ipv4Addr::new(10, 212, 134, 200),
            dns: vec![Ipv4Addr::new(10, 0, 0, 53)],
            peer: None,
            mtu: 1354,
        }
    );
    let up = obs.wait_ipcp_up().await.unwrap();
    assert_eq!(up.dns, [Ipv4Addr::new(10, 0, 0, 53)]);
    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
}

#[tokio::test]
async fn icmp_target_filters_destinations() {
    let target = Ipv4Addr::new(10, 20, 0, 10); // destination du vecteur
    let peer = PppPeer::new(PppPeerConfig {
        icmp_target: Some(target),
        ..PppPeerConfig::default()
    });
    let obs = peer.observer();
    let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let mut c = PppClient::new(stream, client_config());
    c.connect().await.unwrap();

    // Même requête vers une autre destination : pas de réponse.
    let mut other = echo_request();
    other[19] = 11;
    other[10..12].fill(0);
    let sum = internet_checksum(&other[..20]);
    other[10..12].copy_from_slice(&sum.to_be_bytes());
    c.send_ipv4(&other).await.unwrap();
    c.send_ipv4(&echo_request()).await.unwrap();
    let PppEvent::Ipv4(ip) = c.run_until(is_ipv4).await.unwrap() else {
        unreachable!()
    };
    assert_eq!(
        ip,
        echo_reply(),
        "première réponse : IP id 0xabcd comme le vecteur"
    );
    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
    let n = obs.counters();
    assert_eq!((n.ipv4_rx, n.ipv4_dropped, n.icmp_echo_replied), (2, 1, 1));
}

#[tokio::test]
async fn ignored_echoes_lead_to_dead_peer() {
    let peer = PppPeer::with_fault(PppFault::IgnoreEchoRequests);
    let obs = peer.observer();
    let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let mut cfg = client_config();
    cfg.echo_interval = Some(Duration::from_millis(30));
    cfg.echo_max_failures = 4;
    let mut c = PppClient::new(stream, cfg);
    c.connect().await.unwrap();
    assert_eq!(
        c.run_until(|_| false).await,
        Err(ClientEnd::Down(DownReason::DeadPeer))
    );
    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
    let n = obs.counters();
    assert_eq!(n.lcp_echo_requests_rx, 4);
    assert_eq!(n.lcp_echo_requests_ignored, 4);
    assert_eq!(n.lcp_echo_replies_tx, 0);
}

#[tokio::test]
async fn answered_echoes_keep_session_alive() {
    let peer = PppPeer::default();
    let obs = peer.observer();
    let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let mut cfg = client_config();
    cfg.echo_interval = Some(Duration::from_millis(60));
    let mut c = PppClient::new(stream, cfg);
    c.connect().await.unwrap();
    // 600 ms = 10 intervalles : sans réponses, DeadPeer serait atteint (4 échecs, 240 ms).
    // Marges larges : la suite tourne en parallèle.
    let r = tokio::time::timeout(Duration::from_millis(600), c.run_until(|_| false)).await;
    assert!(r.is_err(), "la session doit rester ouverte : {r:?}");
    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
    let n = obs.counters();
    assert!(n.lcp_echo_replies_tx >= 4, "{n:?}");
    assert_eq!(n.lcp_echo_requests_rx, n.lcp_echo_replies_tx);
}

#[tokio::test]
async fn malformed_frames_are_fatal_for_client() {
    let cases = [
        (MalformedFrame::BadMagic, FrameError::BadMagic([0x50, 0x51])),
        (
            MalformedFrame::InconsistentLengths,
            FrameError::InconsistentLength {
                total: 23,
                ppp_len: 16,
            },
        ),
        (MalformedFrame::TotalTooSmall, FrameError::TotalTooSmall(6)),
    ];
    for when in [
        FaultTrigger::Start,
        FaultTrigger::LcpUp,
        FaultTrigger::IpcpUp,
    ] {
        for (kind, err) in cases.clone() {
            let peer = PppPeer::with_fault(PppFault::MalformedFrame { kind, when });
            let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
            let mut c = PppClient::new(stream, client_config());
            let r = if when == FaultTrigger::IpcpUp {
                c.connect().await.unwrap();
                c.run_until(|_| false).await
            } else {
                c.connect().await
            };
            assert_eq!(r, Err(ClientEnd::Frame(err)), "{kind:?} {when:?}");
            drop(c);
            assert_eq!(peer_end(task).await, PeerEnd::Eof);
        }
    }
}

#[tokio::test]
async fn gateway_terminate_is_acked() {
    for when in [
        FaultTrigger::IpcpUp,
        FaultTrigger::AfterIpcpUp(Duration::from_millis(50)),
    ] {
        let peer = PppPeer::with_fault(PppFault::GatewayTerminate { when });
        let mut obs = peer.observer();
        let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
        let mut c = PppClient::new(stream, client_config());
        c.connect().await.unwrap();
        assert_eq!(
            c.run_until(|_| false).await,
            Err(ClientEnd::Down(DownReason::ClosedByPeer)),
            "{when:?}"
        );
        assert_eq!(c.drain().await, ClientEnd::Eof, "close_notify après l'Ack");
        assert_eq!(
            peer_end(task).await,
            PeerEnd::GatewayTerminated { acked: true }
        );
        assert_eq!(
            obs.wait_end().await,
            PeerEnd::GatewayTerminated { acked: true }
        );
    }
}

#[tokio::test]
async fn gateway_terminate_without_ack_times_out() {
    let peer = PppPeer::new(PppPeerConfig {
        fault: PppFault::GatewayTerminate {
            when: FaultTrigger::IpcpUp,
        },
        terminate_timeout: Duration::from_millis(50),
        ..PppPeerConfig::default()
    });
    let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let mut c = PppClient::new(stream, client_config());
    c.connect().await.unwrap();
    // Client muet ensuite : il ne lit plus le flux, le Terminate-Request reste sans Ack.
    assert_eq!(
        peer_end(task).await,
        PeerEnd::GatewayTerminated { acked: false }
    );
}

#[tokio::test]
async fn ipcp_never_converges() {
    let peer = PppPeer::with_fault(PppFault::IpcpNeverConverges);
    let obs = peer.observer();
    let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let mut c = PppClient::new(stream, client_config());
    assert_eq!(
        c.connect().await,
        Err(ClientEnd::Down(DownReason::NegotiationFailed(
            Protocol::IPCP
        )))
    );
    assert_eq!(obs.status().phase, PeerPhase::Ipcp);
    drop(c);
    assert_eq!(peer_end(task).await, PeerEnd::Eof);
    assert_eq!(obs.counters().ipcp_up, 0);
}

#[tokio::test]
async fn gateway_gives_up_on_silent_client() {
    let peer = PppPeer::new(PppPeerConfig {
        restart_interval: Duration::from_millis(10),
        max_configure: 3,
        ..PppPeerConfig::default()
    });
    let (mut stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let mut ids = Vec::new();
    while let Some(f) = common::ppp::read_wire_frame(&mut stream).await.unwrap() {
        assert_eq!(&f[6..9], &[0xc0, 0x21, 0x01], "LCP Configure-Request");
        ids.push(f[9]);
    }
    assert_eq!(ids, [1, 2, 3], "retransmissions avec un nouvel identifiant");
    assert_eq!(
        peer_end(task).await,
        PeerEnd::NegotiationFailed(Protocol::LCP)
    );
}

// --------------------------------------------------------------------- à travers TLS

/// Login + `GET /remote/sslvpn-tunnel` sur une passerelle servant `peer`.
async fn tls_tunnel(peer: &PppPeer) -> (mock_gw::RunningGateway, common::Client) {
    let gw = MockGateway::builder()
        .tunnel_handler(peer.clone())
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let cookie = login(&mut s).await;
    s.write_all(&tunnel_request(&cookie)).await.unwrap();
    s.flush().await.unwrap();
    (gw, s)
}

#[tokio::test]
async fn tls_end_to_end_nominal() {
    let peer = PppPeer::default();
    let mut obs = peer.observer();
    let (gw, s) = tls_tunnel(&peer).await;
    let mut c = PppClient::new(s, client_config());
    assert_eq!(c.connect().await.unwrap(), ipcp_up_split());
    let up = obs.wait_ipcp_up().await.unwrap();
    assert_eq!(up.conn_id, 1);
    c.send_ipv4(&echo_request()).await.unwrap();
    assert_eq!(
        c.run_until(is_ipv4).await.unwrap(),
        PppEvent::Ipv4(echo_reply().into())
    );
    c.session.close(std::time::Instant::now());
    assert_eq!(
        c.run_until(|e| matches!(e, PppEvent::Down(_))).await,
        Ok(PppEvent::Down(DownReason::LocalClose))
    );
    assert_eq!(c.drain().await, ClientEnd::Eof, "close_notify reçu");
    assert_eq!(obs.wait_end().await, PeerEnd::ClientTerminated);
    gw.shutdown().await;
}

#[tokio::test]
async fn tls_abort_without_close_notify() {
    for when in [FaultTrigger::Start, FaultTrigger::IpcpUp] {
        let peer = PppPeer::with_fault(PppFault::AbortTls { when });
        let mut obs = peer.observer();
        let (gw, s) = tls_tunnel(&peer).await;
        let mut c = PppClient::new(s, client_config());
        let r = if when == FaultTrigger::IpcpUp {
            c.connect().await.unwrap();
            c.run_until(|_| false).await
        } else {
            // Ne rien écrire : des données non lues côté passerelle transformeraient le
            // FIN en RST.
            Err(c.drain().await)
        };
        assert_eq!(
            r,
            Err(ClientEnd::Io(io::ErrorKind::UnexpectedEof)),
            "{when:?}"
        );
        assert_eq!(obs.wait_end().await, PeerEnd::Aborted);
        gw.shutdown().await;
    }
}

#[tokio::test]
async fn tls_http_instead_of_ppp() {
    let peer = PppPeer::with_fault(PppFault::HttpInsteadOfPpp { status: 403 });
    let mut obs = peer.observer();
    let (gw, mut s) = tls_tunnel(&peer).await;
    let mut raw = Vec::new();
    tokio::time::timeout(common::TIMEOUT, s.read_to_end(&mut raw))
        .await
        .unwrap()
        .expect("fermeture propre (close_notify)");
    let line = hex_frame("framing.hex", "err_http_instead_of_ppp");
    assert!(raw.starts_with(&line), "{}", String::from_utf8_lossy(&raw));
    let mut dec = proto::frame::FrameDecoder::new();
    dec.push(&raw);
    assert_eq!(
        dec.next_frame(),
        Err(FrameError::HttpResponse { status: Some(403) })
    );
    assert_eq!(obs.wait_end().await, PeerEnd::HttpSent(403));
    gw.shutdown().await;
}

#[tokio::test]
async fn tls_reconnect_new_session() {
    let peer = PppPeer::default();
    let mut obs = peer.observer();
    let gw = MockGateway::builder()
        .tunnel_handler(peer.clone())
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let cookie = login(&mut s).await;
    for conn in 0..2 {
        let mut s = connect(&gw).await;
        s.write_all(&tunnel_request(&cookie)).await.unwrap();
        let mut c = PppClient::new(s, client_config());
        assert_eq!(
            c.connect().await.unwrap(),
            ipcp_up_split(),
            "connexion {conn}"
        );
        // Coupure brutale côté client (sans Terminate ni close_notify).
        drop(c);
        let end = obs.wait_end().await;
        assert!(
            matches!(end, PeerEnd::Eof | PeerEnd::Io(_)),
            "connexion {conn}: {end:?}"
        );
    }
    assert_eq!(obs.counters().sessions, 2);
    assert_eq!(obs.counters().ipcp_up, 2);
    gw.shutdown().await;
}
