//! Tunnel contre une passerelle PPP simulée sur `tokio::io::duplex`, en rejouant les
//! vecteurs `docs/vectors/{lcp,ipcp,ip,framing}.hex`.

use std::collections::HashMap;
use std::path::PathBuf;

use bytes::Bytes;
use proto::ppp::{Code, ControlPacket, Packet};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

use super::*;

const CLIENT_MAGIC: u32 = 0x1a2b_3c4d;
/// Garde-fou des attentes en temps réel (les tests à horloge figée n'en dépendent pas).
const STEP: Duration = Duration::from_secs(5);

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectors")
}

/// Vecteurs `@frame` (format : `docs/vectors/README.md`), indexés par nom.
fn vectors() -> HashMap<String, Vec<u8>> {
    let mut map = HashMap::new();
    for file in ["framing.hex", "lcp.hex", "ipcp.hex", "ip.hex"] {
        let text = std::fs::read_to_string(vectors_dir().join(file)).unwrap();
        let mut current: Option<(String, usize, Vec<u8>)> = None;
        let mut flush = |cur: Option<(String, usize, Vec<u8>)>| {
            if let Some((name, len, bytes)) = cur {
                assert_eq!(bytes.len(), len, "{name}");
                assert!(map.insert(name, bytes).is_none());
            }
        };
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("@frame") {
                flush(current.take());
                let mut parts = rest.split_whitespace();
                let name = parts.next().unwrap().to_owned();
                let len = parts
                    .find_map(|kv| kv.strip_prefix("len="))
                    .unwrap()
                    .parse()
                    .unwrap();
                current = Some((name, len, Vec::new()));
                continue;
            }
            let (_, _, bytes) = current.as_mut().unwrap();
            bytes.extend(
                line.split_whitespace()
                    .map(|t| u8::from_str_radix(t, 16).unwrap()),
            );
        }
        flush(current);
    }
    map
}

pub(crate) fn wire(name: &str) -> Vec<u8> {
    vectors()
        .remove(name)
        .unwrap_or_else(|| panic!("vecteur {name} introuvable"))
}

/// Message d'un vecteur `.http` (commentaires retirés, CRLF sur le fil).
fn http_vector(file: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(vectors_dir().join(file)).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .skip_while(|l| l.is_empty())
        .take_while(|l| !l.is_empty())
        .collect();
    format!("{}\r\n\r\n", lines.join("\r\n")).into_bytes()
}

pub(crate) fn options() -> TunnelOptions {
    TunnelOptions::with_magic(NonZeroU32::new(CLIENT_MAGIC).unwrap())
}

/// Passerelle simulée : côté serveur du duplex.
pub(crate) struct Gateway {
    io: DuplexStream,
    dec: FrameDecoder,
}

impl Gateway {
    pub(crate) fn new(io: DuplexStream) -> Self {
        Self {
            io,
            dec: FrameDecoder::new(),
        }
    }

    pub(crate) async fn send_raw(&mut self, bytes: &[u8]) {
        self.io.write_all(bytes).await.unwrap();
    }

    pub(crate) async fn send(&mut self, name: &str) {
        self.send_raw(&wire(name)).await;
    }

    /// Prochaine trame PPP émise par le client ; `None` à la fin du flux.
    async fn next_frame(&mut self) -> Option<Bytes> {
        loop {
            if let Some(f) = self.dec.next_frame().unwrap() {
                return Some(f);
            }
            let mut buf = [0u8; 4096];
            let n = self.io.read(&mut buf).await.unwrap();
            if n == 0 {
                assert!(self.dec.buffered().is_empty(), "trame tronquée");
                return None;
            }
            self.dec.push(&buf[..n]);
        }
    }

    pub(crate) async fn recv(&mut self) -> Bytes {
        tokio::time::timeout(STEP, self.next_frame())
            .await
            .expect("trame attendue")
            .expect("flux fermé")
    }

    /// La prochaine trame émise == vecteur (octets exacts sur le fil).
    pub(crate) async fn expect(&mut self, name: &str) {
        let ppp = self.recv().await;
        let mut on_wire = BytesMut::new();
        frame::encode_frame(&ppp, &mut on_wire).unwrap();
        assert_eq!(&on_wire[..], &wire(name)[..], "attendu : {name}");
    }

    pub(crate) async fn recv_lcp(&mut self) -> ControlPacket {
        match Packet::parse(self.recv().await).unwrap() {
            Packet::Lcp(p) => p,
            other => panic!("LCP attendu, reçu {other:?}"),
        }
    }

    pub(crate) async fn expect_eof(&mut self) {
        let next = tokio::time::timeout(STEP, self.next_frame())
            .await
            .expect("fin de flux attendue");
        assert!(next.is_none(), "trame inattendue : {next:?}");
    }
}

/// Négociation complète (§1, vecteurs lcp/ipcp), côté passerelle.
pub(crate) async fn negotiate(gw: &mut Gateway) {
    gw.expect("lcp_confreq_client").await;
    gw.send("lcp_confreq_gateway").await;
    gw.expect("lcp_confack_client").await;
    gw.send("lcp_confack_gateway").await;
    gw.expect("ipcp_confreq_client_1").await;
    gw.send("ipcp_confreq_gateway").await;
    gw.expect("ipcp_confack_client").await;
    gw.send("ipcp_confnak_gateway").await;
    gw.expect("ipcp_confreq_client_2").await;
    gw.send("ipcp_confack_gateway").await;
}

async fn open_negotiated() -> (Tunnel, Gateway) {
    let (client, server) = duplex(64 * 1024);
    let mut gw = Gateway::new(server);
    let opening = tokio::spawn(open(client, options()));
    negotiate(&mut gw).await;
    let tunnel = opening.await.unwrap().expect("tunnel ouvert");
    (tunnel, gw)
}

fn expected_params() -> TunnelParams {
    TunnelParams {
        local_ip: Ipv4Addr::new(10, 10, 0, 2),
        peer: Some(Ipv4Addr::new(169, 254, 1, 1)),
        dns: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)],
        mtu: 1354,
    }
}

async fn end_error(tunnel: &mut Tunnel) -> TunnelError {
    match tokio::time::timeout(STEP, tunnel.end.wait()).await.unwrap() {
        Err(TransportError::Tunnel(e)) => e,
        other => panic!("erreur de tunnel attendue : {other:?}"),
    }
}

// ------------------------------------------------------------------ succès

#[tokio::test]
async fn full_negotiation_yields_ipcp_params() {
    let (tunnel, _gw) = open_negotiated().await;
    assert_eq!(tunnel.params, expected_params());
}

#[tokio::test]
async fn icmp_round_trip() {
    let (mut tunnel, mut gw) = open_negotiated().await;
    let request = wire("ipv4_icmp_echo_request_raw_ip");
    tunnel.packets.send(Bytes::from(request)).await.unwrap();
    gw.expect("ipv4_icmp_echo_request").await;

    gw.send("ipv4_icmp_echo_reply").await;
    let reply = tokio::time::timeout(STEP, tunnel.packets.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..], &wire("ipv4_icmp_echo_reply")[8..]);
}

#[tokio::test]
async fn frames_received_with_ipcp_ack_are_delivered() {
    let (client, server) = duplex(64 * 1024);
    let mut gw = Gateway::new(server);
    let opening = tokio::spawn(open(client, options()));
    gw.expect("lcp_confreq_client").await;
    gw.send("lcp_confreq_gateway").await;
    gw.expect("lcp_confack_client").await;
    gw.send("lcp_confack_gateway").await;
    gw.expect("ipcp_confreq_client_1").await;
    gw.send("ipcp_confreq_gateway").await;
    gw.expect("ipcp_confack_client").await;
    gw.send("ipcp_confnak_gateway").await;
    gw.expect("ipcp_confreq_client_2").await;
    // Ack final et premier datagramme dans la même écriture TLS.
    let mut both = wire("ipcp_confack_gateway");
    both.extend(wire("ipv4_icmp_echo_reply"));
    gw.send_raw(&both).await;

    let mut tunnel = opening.await.unwrap().unwrap();
    let reply = tokio::time::timeout(STEP, tunnel.packets.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..], &wire("ipv4_icmp_echo_reply")[8..]);
}

#[tokio::test]
async fn answers_gateway_echo_request() {
    let (_tunnel, mut gw) = open_negotiated().await;
    gw.send("lcp_echo_request_gateway").await;
    gw.expect("lcp_echo_reply_client").await;
}

#[tokio::test]
async fn unbounded_echo_requests_without_tcp_ack_end_as_dead_peer() {
    let (mut tunnel, mut gw) = open_negotiated().await;
    // La passerelle envoie des Echo-Request sans jamais lire : `out` sature.
    let one = wire("lcp_echo_request_gateway");
    let batch: Vec<u8> = one.iter().copied().cycle().take(one.len() * 1000).collect();
    let sender = tokio::spawn(async move {
        for _ in 0..(OUT_HARD_LIMIT / 12 + 4 * MAX_IGNORED_CONTROL as usize) / 1000 + 10 {
            gw.send_raw(&batch).await;
        }
        gw
    });
    assert!(matches!(
        end_error(&mut tunnel).await,
        TunnelError::DeadPeer
    ));
    drop(sender);
}

#[tokio::test]
async fn ipv6cp_is_protocol_rejected() {
    let (_tunnel, mut gw) = open_negotiated().await;
    gw.send("ipv6cp_confreq_gateway").await;
    // id LCP suivant : 0x02 (0x01 = Configure-Request initial).
    let p = gw.recv_lcp().await;
    assert_eq!(p.code(), Code::ProtocolReject);
    assert_eq!(p.rejected_protocol().unwrap().0, Protocol(0x8057));
}

#[tokio::test]
async fn send_tunnel_request_matches_vector() {
    let expected = http_vector("sslvpn_tunnel_request.http");
    let text = String::from_utf8(expected.clone()).unwrap();
    let value = text
        .split("SVPNCOOKIE=")
        .nth(1)
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap();
    let cookie = SessionCookie::new(value).unwrap();
    let mut out = Vec::new();
    send_tunnel_request(&mut out, &cookie).await.unwrap();
    assert_eq!(out, expected);
}

// ------------------------------------------------------------- fermetures

#[tokio::test]
async fn local_close_sends_terminate_then_closes_tls() {
    let (mut tunnel, mut gw) = open_negotiated().await;
    let closing = tokio::spawn(tunnel.handle.close());
    let req = gw.recv_lcp().await;
    assert_eq!(req.code(), Code::TerminateRequest);
    let ack = ControlPacket::new(Code::TerminateAck, req.id(), Bytes::new()).unwrap();
    gw.send_raw(&frame::frame_to_bytes(&ack.to_frame(Protocol::LCP)).unwrap())
        .await;
    gw.expect_eof().await;
    closing.await.unwrap();
    assert!(tunnel.end.wait().await.is_ok());
    assert!(tunnel.packets.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn local_close_without_ack_times_out() {
    let (mut tunnel, mut gw) = open_negotiated().await;
    let start = Instant::now();
    tunnel.handle.request_close();
    assert_eq!(gw.recv_lcp().await.code(), Code::TerminateRequest);
    gw.expect_eof().await;
    assert!(tunnel.end.wait().await.is_ok());
    assert!(start.elapsed() >= Duration::from_secs(1));
}

#[tokio::test]
async fn dropping_packet_channel_closes_tunnel() {
    let (tunnel, mut gw) = open_negotiated().await;
    let Tunnel {
        packets,
        mut end,
        handle,
        ..
    } = tunnel;
    drop(packets);
    assert_eq!(gw.recv_lcp().await.code(), Code::TerminateRequest);
    gw.send("lcp_terminate_ack_gateway").await;
    gw.expect_eof().await;
    handle.join().await;
    assert!(end.wait().await.is_ok());
}

#[tokio::test]
async fn gateway_terminate_request() {
    let (mut tunnel, mut gw) = open_negotiated().await;
    gw.send("lcp_terminate_request_gateway").await;
    gw.expect("lcp_terminate_ack_client").await;
    gw.expect_eof().await;
    assert!(matches!(
        end_error(&mut tunnel).await,
        TunnelError::ClosedByPeer
    ));
    assert!(tunnel.packets.recv().await.is_none());
}

#[tokio::test]
async fn gateway_eof_is_closed_by_peer() {
    let (mut tunnel, gw) = open_negotiated().await;
    drop(gw);
    assert!(matches!(
        end_error(&mut tunnel).await,
        TunnelError::ClosedByPeer
    ));
}

#[tokio::test(start_paused = true)]
async fn echo_timeout_is_dead_peer() {
    let (mut tunnel, mut gw) = open_negotiated().await;
    let start = Instant::now();
    // La passerelle se tait : 4 Echo-Request sans réponse (30 s chacun) puis DeadPeer.
    assert!(matches!(
        tunnel.end.wait().await,
        Err(TransportError::Tunnel(TunnelError::DeadPeer))
    ));
    assert!(start.elapsed() >= Duration::from_secs(150));
    for _ in 0..4 {
        let p = gw.recv_lcp().await;
        assert_eq!(p.code(), Code::EchoRequest);
    }
    gw.expect_eof().await;
}

#[tokio::test(start_paused = true)]
async fn echo_reply_keeps_session_alive() {
    let (tunnel, mut gw) = open_negotiated().await;
    for _ in 0..6 {
        // Sans garde-fou : l'horloge figée avance jusqu'au prochain keepalive (30 s).
        let p = match Packet::parse(gw.next_frame().await.unwrap()).unwrap() {
            Packet::Lcp(p) => p,
            other => panic!("LCP attendu, reçu {other:?}"),
        };
        assert_eq!(p.code(), Code::EchoRequest);
        let magic = 0x5e6f_7081;
        let reply = ControlPacket::echo(Code::EchoReply, p.id(), magic, &[]).unwrap();
        gw.send_raw(&frame::frame_to_bytes(&reply.to_frame(Protocol::LCP)).unwrap())
            .await;
    }
    assert!(!tunnel.handle.is_finished());
}

// ------------------------------------------------------------------ échecs

#[tokio::test]
async fn http_403_is_tunnel_refused() {
    let (client, server) = duplex(4096);
    let mut gw = Gateway::new(server);
    let opening = tokio::spawn(open(client, options()));
    gw.expect("lcp_confreq_client").await;
    gw.send_raw(&http_vector("sslvpn_tunnel_403.http")).await;
    let err = opening.await.unwrap().unwrap_err();
    assert!(matches!(
        err,
        TunnelError::TunnelRefused { status: Some(403) }
    ));
    assert!(err.requires_reauth());
}

#[tokio::test]
async fn split_http_status_line_is_read() {
    let (client, server) = duplex(4096);
    let mut gw = Gateway::new(server);
    let opening = tokio::spawn(open(client, options()));
    gw.expect("lcp_confreq_client").await;
    gw.send_raw(b"HTTP/1").await;
    tokio::task::yield_now().await;
    gw.send_raw(b".1 403 Forbidden\r\n\r\n").await;
    let err = opening.await.unwrap().unwrap_err();
    assert!(matches!(
        err,
        TunnelError::TunnelRefused { status: Some(403) }
    ));
}

#[tokio::test]
async fn framing_vector_http_is_tunnel_refused() {
    let (client, server) = duplex(4096);
    let mut gw = Gateway::new(server);
    let opening = tokio::spawn(open(client, options()));
    gw.send("err_http_instead_of_ppp").await;
    assert!(matches!(
        opening.await.unwrap(),
        Err(TunnelError::TunnelRefused { status: Some(403) })
    ));
}

#[tokio::test]
async fn invalid_frames_are_bad_frame() {
    for name in [
        "err_bad_magic",
        "err_inconsistent_lengths",
        "err_total_too_small",
    ] {
        let (client, server) = duplex(4096);
        let mut gw = Gateway::new(server);
        let opening = tokio::spawn(open(client, options()));
        gw.send(name).await;
        assert!(
            matches!(opening.await.unwrap(), Err(TunnelError::BadFrame(_))),
            "{name}"
        );
    }
}

#[tokio::test]
async fn invalid_frame_after_up_ends_tunnel() {
    let (mut tunnel, mut gw) = open_negotiated().await;
    gw.send("err_bad_magic").await;
    assert!(matches!(
        end_error(&mut tunnel).await,
        TunnelError::BadFrame(FrameError::BadMagic(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn silent_gateway_is_first_frame_timeout() {
    let (client, mut server) = duplex(4096);
    let start = Instant::now();
    let err = open(client, options()).await.unwrap_err();
    assert!(matches!(err, TunnelError::FirstFrameTimeout(d) if d == FIRST_FRAME_TIMEOUT));
    assert!(start.elapsed() >= FIRST_FRAME_TIMEOUT);
    // Configure-Request émis (et retransmis toutes les 3 s) pendant l'attente.
    let mut buf = vec![0u8; 4096];
    let n = server.read(&mut buf).await.unwrap();
    assert!(n >= 22);
}

#[tokio::test(start_paused = true)]
async fn unanswered_lcp_is_negotiation_failure() {
    let (client, server) = duplex(64 * 1024);
    let mut gw = Gateway::new(server);
    let mut opts = options();
    opts.first_frame_timeout = Duration::from_secs(3600);
    let opening = tokio::spawn(open(client, opts));
    // Une trame quelconque (Echo-Request avant ouverture, ignoré) désarme le délai de
    // première trame ; ensuite les Configure-Request restent sans réponse.
    gw.expect("lcp_confreq_client").await;
    gw.send("lcp_echo_request_gateway").await;
    assert!(matches!(
        opening.await.unwrap(),
        Err(TunnelError::PppNegotiationFailed(Protocol::LCP))
    ));
}

#[tokio::test]
async fn gateway_closing_during_negotiation() {
    let (client, server) = duplex(4096);
    let mut gw = Gateway::new(server);
    let opening = tokio::spawn(open(client, options()));
    gw.expect("lcp_confreq_client").await;
    gw.send("lcp_terminate_request_gateway").await;
    gw.expect("lcp_terminate_ack_client").await;
    assert!(matches!(
        opening.await.unwrap(),
        Err(TunnelError::ClosedByPeer)
    ));
}

// --------------------------------------------------------------- fusion

#[test]
fn params_feed_sslvpn_config_merge() {
    let n: crate::sslvpn::NegotiatedIpv4 = expected_params().into();
    assert_eq!(n.address, Ipv4Addr::new(10, 10, 0, 2));
    assert_eq!(n.peer, Some(Ipv4Addr::new(169, 254, 1, 1)));
    assert_eq!(n.mtu, 1354);
    assert_eq!(n.dns, expected_params().dns);
}

#[tokio::test]
async fn already_buffered_bytes_are_processed_first() {
    // Le Configure-Request de la passerelle était déjà dans le reliquat HTTP.
    let (client, server) = duplex(64 * 1024);
    let mut gw = Gateway::new(server);
    let prefix = wire("lcp_confreq_gateway");
    let opening = tokio::spawn(async move { open_with_buffered(client, &prefix, options()).await });
    gw.expect("lcp_confreq_client").await;
    gw.expect("lcp_confack_client").await;
    gw.send("lcp_confack_gateway").await;
    gw.expect("ipcp_confreq_client_1").await;
    gw.send("ipcp_confreq_gateway").await;
    gw.expect("ipcp_confack_client").await;
    gw.send("ipcp_confnak_gateway").await;
    gw.expect("ipcp_confreq_client_2").await;
    gw.send("ipcp_confack_gateway").await;
    assert_eq!(opening.await.unwrap().unwrap().params, expected_params());
}

#[tokio::test]
async fn buffered_http_refusal() {
    let (client, _server) = duplex(4096);
    let refusal = http_vector("sslvpn_tunnel_403.http");
    assert!(matches!(
        open_with_buffered(client, &refusal, options()).await,
        Err(TunnelError::TunnelRefused { status: Some(403) })
    ));
}

#[test]
fn random_magic_is_nonzero_and_varies() {
    let a = random_magic();
    let b = random_magic();
    assert_ne!(a, b);
}

// ------------------------------------------------- stabilité (story 2.6)

/// Flux dont l'écriture reste en tampon jusqu'à `flush` (comme TLS/TCP : rien ne part
/// sans `flush`), pour vérifier que les trames de contrôle sont bien vidées.
struct FlushOnly {
    inner: DuplexStream,
    pending: Vec<u8>,
}

impl tokio::io::AsyncRead for FlushOnly {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FlushOnly {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.pending.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        while !this.pending.is_empty() {
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.pending) {
                std::task::Poll::Ready(Ok(n)) => {
                    this.pending.drain(..n);
                }
                other => return other.map(|r| r.map(|_| ())),
            }
        }
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn control_frames_are_flushed_without_ip_traffic() {
    let (client, server) = duplex(64 * 1024);
    let mut gw = Gateway::new(server);
    let stream = FlushOnly {
        inner: client,
        pending: Vec::new(),
    };
    let opening = tokio::spawn(open(stream, options()));
    negotiate(&mut gw).await;
    let _tunnel = opening.await.unwrap().expect("tunnel ouvert");
    // Aucun trafic IP : seule la réponse de contrôle peut sortir, et elle doit l'être.
    gw.send("lcp_echo_request_gateway").await;
    gw.expect("lcp_echo_reply_client").await;
    // Echo-Request avec données : recopiées, notre magic, même id.
    let mut req = BytesMut::new();
    let echo = ControlPacket::echo(Code::EchoRequest, 0x42, 0x5e6f_7081, b"abcd").unwrap();
    frame::encode_frame(&echo.to_frame(Protocol::LCP), &mut req).unwrap();
    gw.send_raw(&req).await;
    let reply = gw.recv_lcp().await;
    assert_eq!((reply.code(), reply.id()), (Code::EchoReply, 0x42));
    let (magic, data) = reply.magic_and_data().unwrap();
    assert_eq!((magic, &data[..]), (CLIENT_MAGIC, &b"abcd"[..]));
}

#[tokio::test]
async fn discard_request_and_ccp_get_no_fatal_reaction() {
    let (tunnel, mut gw) = open_negotiated().await;
    let discard = ControlPacket::echo(Code::DiscardRequest, 9, 0x5e6f_7081, b"xx").unwrap();
    let mut buf = BytesMut::new();
    frame::encode_frame(&discard.to_frame(Protocol::LCP), &mut buf).unwrap();
    // CCP Configure-Request (0x80fd) : Protocol-Reject, pas de coupure.
    frame::encode_frame(&[0x80, 0xfd, 1, 1, 0, 4], &mut buf).unwrap();
    gw.send_raw(&buf).await;
    let p = gw.recv_lcp().await;
    assert_eq!(p.code(), Code::ProtocolReject);
    assert_eq!(p.rejected_protocol().unwrap().0, Protocol(0x80fd));
    gw.send("lcp_echo_request_gateway").await;
    gw.expect("lcp_echo_reply_client").await;
    assert!(!tunnel.handle.is_finished());
}

#[tokio::test]
async fn non_ipv4_packets_from_tun_are_not_sent_as_ppp_ipv4() {
    let (tunnel, mut gw) = open_negotiated().await;
    // Paquet IPv6 (RS/MLD émis par l'OS sur la TUN) puis datagramme tronqué : écartés.
    let mut v6 = vec![0u8; 48];
    v6[0] = 0x60;
    tunnel.packets.send(Bytes::from(v6)).await.unwrap();
    tunnel
        .packets
        .send(Bytes::from_static(&[0x45, 0, 0, 40]))
        .await
        .unwrap();
    let request = wire("ipv4_icmp_echo_request_raw_ip");
    tunnel.packets.send(Bytes::from(request)).await.unwrap();
    // La première trame sortante est l'ICMP IPv4 valide.
    gw.expect("ipv4_icmp_echo_request").await;
}

#[test]
fn ipv4_datagram_check() {
    assert!(is_ipv4_datagram(&wire("ipv4_icmp_echo_request_raw_ip")));
    assert!(!is_ipv4_datagram(&[0x60; 40]));
    assert!(!is_ipv4_datagram(&[0x45; 19]));
    let mut p = vec![0x45, 0, 0, 100];
    p.resize(40, 0);
    assert!(!is_ipv4_datagram(&p), "longueur totale > paquet");
}
