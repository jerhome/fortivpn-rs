//! Interopérabilité de la boucle tunnel `fortivpn_core::tunnel` avec le pair PPP
//! indépendant de `tools/mock-gw` (`mock_gw::PppPeer`), story 5.4 (1re partie).
//!
//! - En mémoire (`tokio::io::duplex`, horloge tokio figée et avancée automatiquement) :
//!   négociation, IPCP, pings ICMP aller-retour, fermeture locale, et chaque
//!   `PppFault` avec son mappage vers `TunnelError`.
//! - À travers TLS (`MockGateway` réel sur 127.0.0.1, certificat épinglé par SHA-256) :
//!   login fait à la main (POST `/remote/logincheck`), puis `send_tunnel_request` +
//!   `open_with_buffered`. N'utilise pas `fortivpn_core::sslvpn`.
//!
//! Aucune vraie passerelle n'est contactée ; aucun secret réel (identifiants fictifs de
//! `docs/vectors/README.md`, cookie aléatoire de mock-gw jamais affiché).

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fortivpn_core::TransportError;
use fortivpn_core::tunnel::{self, Tunnel, TunnelError, TunnelOptions, TunnelParams};
use mock_gw::{
    DEFAULT_GATEWAY_PPP_ADDR, DEFAULT_REPLY_IP_ID, DnsServer, FaultTrigger, GatewayIpcpRequest,
    MalformedFrame, MockGateway, PeerEnd, PppFault, PppPeer, PppPeerConfig, RunningGateway,
    Scenario, TunnelConfig, icmp_echo_reply, internet_checksum,
};
use proto::auth::SessionCookie;
use proto::frame::FrameError;
use proto::ppp::Protocol;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Magic-Number LCP du client (`lcp.hex:lcp_confreq_client`).
const CLIENT_MAGIC: u32 = 0x1a2b_3c4d;
/// Garde-fou en horloge virtuelle (tests en mémoire, `start_paused`).
const VIRTUAL_GUARD: Duration = Duration::from_secs(3600);
/// Garde-fou en temps réel (tests TLS).
const REAL_GUARD: Duration = Duration::from_secs(10);
/// SNI présent dans le certificat auto-signé de mock-gw.
const SNI: &str = "vpn.example.com";

// ------------------------------------------------------------------- vecteurs

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectors")
}

/// Octets du vecteur `@frame name` de `file` (format `docs/vectors/README.md`).
fn vector(file: &str, name: &str) -> Vec<u8> {
    let path = vectors_dir().join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::new();
    let mut len = None;
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("@frame ") {
            if len.is_some() {
                break;
            }
            let mut parts = rest.split_whitespace();
            if parts.next() == Some(name) {
                len = parts
                    .find_map(|p| p.strip_prefix("len="))
                    .map(|l| l.parse::<usize>().unwrap());
            }
        } else if len.is_some() && !line.is_empty() && !line.starts_with('#') {
            out.extend(
                line.split_whitespace()
                    .map(|h| u8::from_str_radix(h, 16).unwrap()),
            );
        }
    }
    let len = len.unwrap_or_else(|| panic!("{file}:{name} absent"));
    assert_eq!(out.len(), len, "{file}:{name} len=");
    out
}

/// ICMP Echo Request `ip.hex:ipv4_icmp_echo_request_raw_ip` (10.10.0.2 → 10.20.0.10)
/// avec la séquence ICMP `seq` et l'identifiant IP `0x1234 + seq - 1` ; sommes
/// recalculées. `seq == 1` redonne exactement le vecteur.
fn echo_request(seq: u16) -> Vec<u8> {
    let mut p = vector("ip.hex", "ipv4_icmp_echo_request_raw_ip");
    p[4..6].copy_from_slice(&(0x1234 + seq - 1).to_be_bytes());
    p[10..12].fill(0);
    let ip_sum = internet_checksum(&p[..20]);
    p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    p[22..24].fill(0);
    let icmp_sum = internet_checksum(&p[20..]);
    p[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    p
}

// --------------------------------------------------------------- utilitaires

fn options() -> TunnelOptions {
    TunnelOptions::with_magic(NonZeroU32::new(CLIENT_MAGIC).unwrap())
}

/// Paramètres attendus pour `TunnelConfig::vector_split()` et le pair par défaut.
fn split_params() -> TunnelParams {
    TunnelParams {
        local_ip: Ipv4Addr::new(10, 10, 0, 2),
        peer: Some(DEFAULT_GATEWAY_PPP_ADDR),
        dns: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)],
        mtu: 1354,
    }
}

/// Lance `peer` sur l'extrémité « passerelle » d'un `duplex` ; renvoie l'extrémité client.
fn spawn_peer(peer: &PppPeer, cfg: &TunnelConfig) -> (DuplexStream, JoinHandle<PeerEnd>) {
    let (client, gateway) = duplex(64 * 1024);
    let peer = peer.clone();
    let ipv4 = cfg.ipv4.clone();
    let task = tokio::spawn(async move { peer.serve(gateway, &ipv4, 1).await });
    (client, task)
}

async fn peer_end(task: JoinHandle<PeerEnd>, guard: Duration) -> PeerEnd {
    timeout(guard, task)
        .await
        .expect("fin du pair PPP")
        .expect("tâche du pair PPP")
}

fn tunnel_error(e: TransportError) -> TunnelError {
    match e {
        TransportError::Tunnel(t) => t,
        other => panic!("erreur de transport inattendue : {other:?}"),
    }
}

/// Issue d'un tunnel : `open` a-t-il réussi, et résultat final.
#[derive(Debug)]
struct Outcome {
    opened: bool,
    result: Result<(), TunnelError>,
}

/// Ouvre le tunnel puis attend sa fin (sans rien envoyer) ; le canal de paquets reste
/// ouvert jusqu'à la fin.
async fn run_to_end<S>(stream: S, buffered: &[u8], opts: TunnelOptions, guard: Duration) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let opened = timeout(guard, tunnel::open_with_buffered(stream, buffered, opts))
        .await
        .expect("open : délai dépassé");
    match opened {
        Err(e) => Outcome {
            opened: false,
            result: Err(e),
        },
        Ok(mut t) => {
            let result = timeout(guard, t.end.wait())
                .await
                .expect("fin du tunnel : délai dépassé")
                .map_err(tunnel_error);
            timeout(guard, t.handle.join())
                .await
                .expect("fin de la tâche du tunnel");
            Outcome {
                opened: true,
                result,
            }
        }
    }
}

/// Envoie trois pings et vérifie les réponses (la première octet pour octet contre
/// `ip.hex:ipv4_icmp_echo_reply`).
async fn ping3(t: &mut Tunnel, guard: Duration) {
    for seq in 1..=3u16 {
        let req = echo_request(seq);
        t.packets.send(Bytes::from(req.clone())).await.unwrap();
        let reply = timeout(guard, t.packets.recv())
            .await
            .expect("réponse ICMP : délai dépassé")
            .expect("canal de paquets fermé");
        if seq == 1 {
            assert_eq!(
                reply[..],
                vector("ip.hex", "ipv4_icmp_echo_reply")[8..],
                "vecteur ip.hex"
            );
        }
        let expected = icmp_echo_reply(&req, DEFAULT_REPLY_IP_ID + seq - 1).unwrap();
        assert_eq!(reply[..], expected[..], "réponse au ping {seq}");
        assert_eq!(internet_checksum(&reply[..20]), 0, "somme IP");
        assert_eq!(internet_checksum(&reply[20..]), 0, "somme ICMP");
    }
}

// ============================================================ 1. en mémoire

#[tokio::test(start_paused = true)]
async fn nominal_handshake_ping_and_local_close() {
    let peer = PppPeer::default();
    let mut obs = peer.observer();
    let cfg = TunnelConfig::vector_split();
    let (stream, task) = spawn_peer(&peer, &cfg);

    let mut t = tunnel::open(stream, options()).await.unwrap();
    assert_eq!(t.params, split_params());
    let up = obs
        .wait_ipcp_up()
        .await
        .expect("IPCP ouvert côté passerelle");
    assert_eq!(up.client_ip, cfg.ipv4.assigned_addr);
    assert_eq!(
        up.dns,
        cfg.ipv4.dns.iter().map(|d| d.ip).collect::<Vec<_>>()
    );
    assert_eq!(up.client_magic, Some(CLIENT_MAGIC));
    assert_eq!(up.client_mru, 1354);
    assert_eq!(up.gateway_ip, Some(DEFAULT_GATEWAY_PPP_ADDR));

    ping3(&mut t, VIRTUAL_GUARD).await;

    let Tunnel {
        mut packets,
        mut end,
        handle,
        ..
    } = t;
    timeout(VIRTUAL_GUARD, handle.close()).await.unwrap();
    assert!(
        matches!(end.wait().await, Ok(())),
        "fermeture locale propre"
    );
    assert!(packets.recv().await.is_none(), "canal fermé après la fin");
    assert_eq!(
        peer_end(task, VIRTUAL_GUARD).await,
        PeerEnd::ClientTerminated
    );

    let n = obs.counters();
    assert_eq!((n.sessions, n.ipcp_up), (1, 1), "{n:?}");
    assert_eq!(
        (n.ipv4_rx, n.ipv4_tx, n.icmp_echo_replied),
        (3, 3, 3),
        "{n:?}"
    );
    assert_eq!((n.ipv4_dropped, n.ignored), (0, 0), "{n:?}");
    assert_eq!(
        (n.protocol_rejects_rx, n.protocol_rejects_tx),
        (0, 0),
        "{n:?}"
    );
    assert!(n.frames_rx >= 3 + 3, "{n:?}");
    assert!(n.frames_tx >= 3 + 3, "{n:?}");
}

#[tokio::test(start_paused = true)]
async fn dropping_packet_channel_closes_cleanly() {
    let peer = PppPeer::default();
    let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let t = tunnel::open(stream, options()).await.unwrap();
    let Tunnel {
        packets,
        mut end,
        handle,
        ..
    } = t;
    drop(packets);
    assert!(matches!(
        timeout(VIRTUAL_GUARD, end.wait()).await.unwrap(),
        Ok(())
    ));
    handle.join().await;
    assert_eq!(
        peer_end(task, VIRTUAL_GUARD).await,
        PeerEnd::ClientTerminated
    );
}

#[tokio::test(start_paused = true)]
async fn open_with_buffered_first_frame() {
    let peer = PppPeer::default();
    let (mut stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    // Lit la première trame de la passerelle (LCP Configure-Request) avant `open`,
    // comme le reliquat d'une lecture HTTP.
    let mut first = vec![0u8; 2];
    stream.read_exact(&mut first).await.unwrap();
    let total = usize::from(u16::from_be_bytes([first[0], first[1]]));
    first.resize(total, 0);
    stream.read_exact(&mut first[2..]).await.unwrap();
    assert_eq!(first, vector("lcp.hex", "lcp_confreq_gateway"));

    let mut t = tunnel::open_with_buffered(stream, &first, options())
        .await
        .unwrap();
    assert_eq!(t.params, split_params());
    ping3(&mut t, VIRTUAL_GUARD).await;
    t.handle.close().await;
    assert_eq!(
        peer_end(task, VIRTUAL_GUARD).await,
        PeerEnd::ClientTerminated
    );
}

#[tokio::test(start_paused = true)]
async fn empty_ipcp_variant_and_single_dns() {
    let peer = PppPeer::new(PppPeerConfig {
        ipcp_request: GatewayIpcpRequest::Empty,
        ..PppPeerConfig::default()
    });
    let cfg = TunnelConfig::full_tunnel(
        Ipv4Addr::new(10, 212, 134, 200),
        vec![DnsServer::new(Ipv4Addr::new(10, 0, 0, 53))],
    );
    let (stream, task) = spawn_peer(&peer, &cfg);
    let t = tunnel::open(stream, options()).await.unwrap();
    assert_eq!(
        t.params,
        TunnelParams {
            local_ip: Ipv4Addr::new(10, 212, 134, 200),
            peer: None,
            dns: vec![Ipv4Addr::new(10, 0, 0, 53)],
            mtu: 1354,
        }
    );
    t.handle.close().await;
    assert_eq!(
        peer_end(task, VIRTUAL_GUARD).await,
        PeerEnd::ClientTerminated
    );
}

#[tokio::test(start_paused = true)]
async fn ipv6cp_offer_is_protocol_rejected() {
    let peer = PppPeer::new(PppPeerConfig {
        offer_ipv6cp: true,
        ..PppPeerConfig::default()
    });
    let mut obs = peer.observer();
    let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let mut t = tunnel::open(stream, options()).await.unwrap();
    assert_eq!(t.params, split_params());
    ping3(&mut t, VIRTUAL_GUARD).await;
    let st = obs.wait_for(|s| s.ipv6cp_rejected).await;
    assert!(st.ipv6cp_rejected);
    assert!(obs.counters().protocol_rejects_rx >= 1);
    t.handle.close().await;
    assert_eq!(
        peer_end(task, VIRTUAL_GUARD).await,
        PeerEnd::ClientTerminated
    );
}

#[tokio::test(start_paused = true)]
async fn keepalive_both_directions_keeps_session_up() {
    let peer = PppPeer::new(PppPeerConfig {
        echo_interval: Some(Duration::from_secs(10)),
        ..PppPeerConfig::default()
    });
    let obs = peer.observer();
    let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
    let mut opts = options();
    opts.ppp.echo_interval = Some(Duration::from_secs(5));
    let mut t = tunnel::open(stream, opts).await.unwrap();
    // 10 min virtuelles : sans réponses, DeadPeer serait atteint bien avant.
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert!(t.end.try_result().is_none(), "le tunnel doit rester ouvert");
    assert!(!t.handle.is_finished());
    let n = obs.counters();
    assert!(n.lcp_echo_requests_tx >= 50, "{n:?}");
    assert_eq!(n.lcp_echo_replies_rx, n.lcp_echo_requests_tx, "{n:?}");
    assert_eq!(n.lcp_echo_requests_rx, n.lcp_echo_replies_tx, "{n:?}");
    ping3(&mut t, VIRTUAL_GUARD).await;
    t.handle.close().await;
    assert_eq!(
        peer_end(task, VIRTUAL_GUARD).await,
        PeerEnd::ClientTerminated
    );
}

// ======================================================== 2. pannes en mémoire

const ALL_TRIGGERS: [FaultTrigger; 4] = [
    FaultTrigger::Start,
    FaultTrigger::LcpUp,
    FaultTrigger::IpcpUp,
    FaultTrigger::AfterIpcpUp(Duration::from_secs(5)),
];

/// `open` doit réussir si la panne est déclenchée une fois IPCP ouvert.
fn opens_before(when: FaultTrigger) -> bool {
    matches!(when, FaultTrigger::IpcpUp | FaultTrigger::AfterIpcpUp(_))
}

async fn fault_outcome(peer: &PppPeer, opts: TunnelOptions) -> (Outcome, PeerEnd) {
    let (stream, task) = spawn_peer(peer, &TunnelConfig::vector_split());
    let outcome = run_to_end(stream, &[], opts, VIRTUAL_GUARD).await;
    (outcome, peer_end(task, VIRTUAL_GUARD).await)
}

#[tokio::test(start_paused = true)]
async fn ignored_echo_requests_give_dead_peer() {
    let peer = PppPeer::with_fault(PppFault::IgnoreEchoRequests);
    let obs = peer.observer();
    let opts = options();
    let echo = opts.ppp.echo_interval.unwrap();
    let failures = opts.ppp.echo_max_failures;
    let start = Instant::now();
    let (o, end) = fault_outcome(&peer, opts).await;
    let elapsed = start.elapsed();
    assert!(o.opened);
    assert!(
        matches!(o.result, Err(TunnelError::DeadPeer)),
        "{:?}",
        o.result
    );
    assert!(
        matches!(end, PeerEnd::Eof | PeerEnd::ClientTerminated),
        "{end:?}"
    );
    let n = obs.counters();
    assert_eq!(n.lcp_echo_requests_rx, u64::from(failures), "{n:?}");
    assert_eq!(n.lcp_echo_requests_ignored, u64::from(failures), "{n:?}");
    assert_eq!(n.lcp_echo_replies_tx, 0, "{n:?}");
    // Détection en horloge virtuelle : au moins `echo_max_failures` intervalles.
    assert!(elapsed >= echo * failures, "{elapsed:?}");
    assert!(elapsed <= echo * (failures + 2), "{elapsed:?}");
}

#[tokio::test(start_paused = true)]
async fn gateway_terminate_gives_closed_by_peer() {
    for when in ALL_TRIGGERS {
        let peer = PppPeer::with_fault(PppFault::GatewayTerminate { when });
        let (o, end) = fault_outcome(&peer, options()).await;
        assert_eq!(o.opened, opens_before(when), "{when:?}: {o:?}");
        assert!(
            matches!(o.result, Err(TunnelError::ClosedByPeer)),
            "{when:?}: {o:?}"
        );
        assert_eq!(end, PeerEnd::GatewayTerminated { acked: true }, "{when:?}");
    }
}

/// `duplex` n'a pas de `close_notify` : l'abandon du flux est vu comme une fin propre
/// (EOF) et donne `ClosedByPeer` ; si une écriture du client est en attente au même
/// moment, le `select!` peut aussi retenir son échec (`Io(BrokenPipe)`) — les deux sont
/// acceptables pour une coupure brutale. Le mappage vers `Io` est vérifié à travers TLS
/// (`tls_abort_gives_io_error`).
#[tokio::test(start_paused = true)]
async fn abort_in_memory_gives_closed_by_peer() {
    for when in ALL_TRIGGERS {
        let peer = PppPeer::with_fault(PppFault::AbortTls { when });
        let (o, end) = fault_outcome(&peer, options()).await;
        assert_eq!(o.opened, opens_before(when), "{when:?}: {o:?}");
        assert!(
            match &o.result {
                Err(TunnelError::ClosedByPeer) => true,
                Err(TunnelError::Io(e)) => e.kind() == io::ErrorKind::BrokenPipe,
                _ => false,
            },
            "{when:?}: {o:?}"
        );
        assert_eq!(end, PeerEnd::Aborted, "{when:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn malformed_frames_give_bad_frame() {
    let kinds = [
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
    for when in ALL_TRIGGERS {
        for (kind, expected) in kinds.clone() {
            let peer = PppPeer::with_fault(PppFault::MalformedFrame { kind, when });
            let (o, end) = fault_outcome(&peer, options()).await;
            assert_eq!(o.opened, opens_before(when), "{kind:?} {when:?}: {o:?}");
            match o.result {
                Err(TunnelError::BadFrame(e)) => assert_eq!(e, expected, "{kind:?} {when:?}"),
                other => panic!("{kind:?} {when:?}: {other:?}"),
            }
            assert!(
                matches!(end, PeerEnd::Eof | PeerEnd::ClientTerminated),
                "{kind:?} {when:?}: {end:?}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn http_instead_of_ppp_gives_tunnel_refused() {
    for status in [403u16, 401, 503] {
        let peer = PppPeer::with_fault(PppFault::HttpInsteadOfPpp { status });
        let (o, end) = fault_outcome(&peer, options()).await;
        assert!(!o.opened, "{status}");
        match &o.result {
            Err(e @ TunnelError::TunnelRefused { status: s }) => {
                assert_eq!(*s, Some(status));
                assert!(e.requires_reauth());
            }
            other => panic!("{status}: {other:?}"),
        }
        assert_eq!(end, PeerEnd::HttpSent(status));
    }
}

#[tokio::test(start_paused = true)]
async fn ipcp_never_converging_gives_negotiation_failed() {
    let peer = PppPeer::with_fault(PppFault::IpcpNeverConverges);
    let obs = peer.observer();
    let (o, end) = fault_outcome(&peer, options()).await;
    assert!(!o.opened);
    assert!(
        matches!(
            o.result,
            Err(TunnelError::PppNegotiationFailed(Protocol::IPCP))
        ),
        "{o:?}"
    );
    assert!(!matches!(&o.result, Err(e) if e.requires_reauth()));
    assert!(
        matches!(end, PeerEnd::Eof | PeerEnd::ClientTerminated),
        "{end:?}"
    );
    assert_eq!(obs.counters().ipcp_up, 0);
}

#[tokio::test(start_paused = true)]
async fn no_fault_error_requires_reauth_except_refusal() {
    // Seule `TunnelRefused` impose une ré-authentification (cookie consommé/expiré).
    let peer = PppPeer::with_fault(PppFault::GatewayTerminate {
        when: FaultTrigger::IpcpUp,
    });
    let (o, _) = fault_outcome(&peer, options()).await;
    assert!(!o.result.unwrap_err().requires_reauth());
    let peer = PppPeer::with_fault(PppFault::IgnoreEchoRequests);
    let (o, _) = fault_outcome(&peer, options()).await;
    assert!(!o.result.unwrap_err().requires_reauth());
}

// ============================================================== 3. TLS réel

/// Vérificateur par épinglage SHA-256 du certificat feuille (DER).
#[derive(Debug)]
struct Pinned {
    sha256_hex: String,
    provider: Arc<CryptoProvider>,
}

fn sha256_hex(der: &[u8]) -> String {
    use std::fmt::Write as _;
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if sha256_hex(end_entity.as_ref()).eq_ignore_ascii_case(&self.sha256_hex) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("empreinte non épinglée".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn tls_connect(addr: SocketAddr, pin: &str) -> io::Result<TlsStream<TcpStream>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            sha256_hex: pin.to_owned(),
            provider,
        }))
        .with_no_client_auth();
    let tcp = timeout(REAL_GUARD, TcpStream::connect(addr)).await??;
    let name = ServerName::try_from(SNI).map_err(io::Error::other)?;
    timeout(
        REAL_GUARD,
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await?
}

fn url_encode(s: &str) -> String {
    use std::fmt::Write as _;
    s.bytes().fold(String::new(), |mut out, b| {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
        out
    })
}

/// Réponse HTTP minimale : statut, en-têtes, corps (`Content-Length`).
#[derive(Debug)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
}

async fn read_response<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Response> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = timeout(REAL_GUARD, s.read(&mut chunk)).await??;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(io::Error::other)?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::other("ligne de statut"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map_or(Ok(0), |(_, v)| v.parse())
        .map_err(io::Error::other)?;
    while buf.len() < head_end + len {
        let n = timeout(REAL_GUARD, s.read(&mut chunk)).await??;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(buf.len(), head_end + len, "octets en trop après la réponse");
    Ok(Response { status, headers })
}

/// POST `/remote/logincheck` fait à la main (identifiants fictifs par défaut de mock-gw)
/// sur une connexion dédiée ; renvoie le `SVPNCOOKIE`.
async fn login(gw: &RunningGateway) -> SessionCookie {
    let mut s = tls_connect(gw.addr(), gw.cert().sha256_hex())
        .await
        .expect("connexion TLS épinglée");
    let body = format!(
        "username={}&credential={}&realm=&ajax=1",
        url_encode(mock_gw::DEFAULT_USERNAME),
        url_encode(mock_gw::DEFAULT_PASSWORD)
    );
    let req = format!(
        "POST /remote/logincheck HTTP/1.1\r\nHost: {SNI}:443\r\nUser-Agent: Mozilla/5.0 SV1\r\n\
         Accept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    s.flush().await.unwrap();
    let resp = read_response(&mut s).await.expect("réponse logincheck");
    assert_eq!(resp.status, 200);
    let value = resp
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .find_map(|(_, v)| v.strip_prefix("SVPNCOOKIE="))
        .and_then(|v| v.split(';').next())
        .filter(|v| !v.is_empty())
        .expect("SVPNCOOKIE non vide");
    let cookie = SessionCookie::new(value).expect("cookie valide");
    let _ = s.shutdown().await;
    cookie
}

/// Passerelle servant `peer` ; nouvelle connexion TLS, login, `GET sslvpn-tunnel`.
async fn tls_tunnel(peer: &PppPeer, scenario: Scenario) -> (RunningGateway, TlsStream<TcpStream>) {
    let gw = MockGateway::builder()
        .scenario(scenario)
        .tunnel_handler(peer.clone())
        .start()
        .await
        .unwrap();
    let cookie = login(&gw).await;
    let mut s = tls_connect(gw.addr(), gw.cert().sha256_hex())
        .await
        .expect("connexion TLS épinglée");
    tunnel::send_tunnel_request(&mut s, &cookie).await.unwrap();
    (gw, s)
}

#[tokio::test]
async fn tls_pin_mismatch_is_rejected() {
    let gw = MockGateway::builder().start().await.unwrap();
    let wrong = "00".repeat(32);
    let r = tls_connect(gw.addr(), &wrong).await;
    assert!(r.is_err(), "certificat non épinglé accepté");
    assert!(tls_connect(gw.addr(), gw.cert().sha256_hex()).await.is_ok());
    gw.shutdown().await;
}

#[tokio::test]
async fn tls_end_to_end_ping_and_close() {
    let peer = PppPeer::default();
    let mut obs = peer.observer();
    let (gw, s) = tls_tunnel(&peer, Scenario::Nominal).await;
    let mut t = timeout(REAL_GUARD, tunnel::open_with_buffered(s, &[], options()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t.params, split_params());
    let up = obs.wait_ipcp_up().await.unwrap();
    assert_eq!(up.client_magic, Some(CLIENT_MAGIC));
    ping3(&mut t, REAL_GUARD).await;
    let Tunnel {
        mut end, handle, ..
    } = t;
    timeout(REAL_GUARD, handle.close()).await.unwrap();
    assert!(matches!(end.wait().await, Ok(())));
    assert_eq!(
        timeout(REAL_GUARD, obs.wait_end()).await.unwrap(),
        PeerEnd::ClientTerminated
    );
    let n = obs.counters();
    assert_eq!(
        (n.sessions, n.ipcp_up, n.icmp_echo_replied),
        (1, 1, 3),
        "{n:?}"
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn tls_abort_gives_io_error() {
    for when in ALL_TRIGGERS {
        let when = match when {
            FaultTrigger::AfterIpcpUp(_) => FaultTrigger::AfterIpcpUp(Duration::from_millis(50)),
            w => w,
        };
        let peer = PppPeer::with_fault(PppFault::AbortTls { when });
        let mut obs = peer.observer();
        let (gw, s) = tls_tunnel(&peer, Scenario::Nominal).await;
        let o = run_to_end(s, &[], options(), REAL_GUARD).await;
        assert_eq!(o.opened, opens_before(when), "{when:?}: {o:?}");
        match &o.result {
            Err(TunnelError::Io(e)) => assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                ),
                "{when:?}: {e:?}"
            ),
            other => panic!("{when:?}: {other:?}"),
        }
        assert_eq!(
            timeout(REAL_GUARD, obs.wait_end()).await.unwrap(),
            PeerEnd::Aborted
        );
        gw.shutdown().await;
    }
}

#[tokio::test]
async fn tls_gateway_terminate_gives_closed_by_peer() {
    let when = FaultTrigger::AfterIpcpUp(Duration::from_millis(50));
    let peer = PppPeer::with_fault(PppFault::GatewayTerminate { when });
    let mut obs = peer.observer();
    let (gw, s) = tls_tunnel(&peer, Scenario::Nominal).await;
    let o = run_to_end(s, &[], options(), REAL_GUARD).await;
    assert!(o.opened);
    assert!(matches!(o.result, Err(TunnelError::ClosedByPeer)), "{o:?}");
    assert_eq!(
        timeout(REAL_GUARD, obs.wait_end()).await.unwrap(),
        PeerEnd::GatewayTerminated { acked: true }
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn tls_http_instead_of_ppp_gives_tunnel_refused() {
    let peer = PppPeer::with_fault(PppFault::HttpInsteadOfPpp { status: 403 });
    let (gw, s) = tls_tunnel(&peer, Scenario::Nominal).await;
    let o = run_to_end(s, &[], options(), REAL_GUARD).await;
    assert!(!o.opened);
    assert!(
        matches!(
            o.result,
            Err(TunnelError::TunnelRefused { status: Some(403) })
        ),
        "{o:?}"
    );
    gw.shutdown().await;
}

/// Cookie refusé par la passerelle elle-même (`Scenario::CookieRejected`) : 403 HTTP
/// réel de mock-gw sur `GET /remote/sslvpn-tunnel`.
#[tokio::test]
async fn tls_rejected_cookie_requires_reauth() {
    let peer = PppPeer::default();
    let obs = peer.observer();
    let (gw, s) = tls_tunnel(&peer, Scenario::CookieRejected).await;
    let o = run_to_end(s, &[], options(), REAL_GUARD).await;
    assert!(!o.opened);
    match &o.result {
        Err(e @ TunnelError::TunnelRefused { status: Some(403) }) => {
            assert!(e.requires_reauth());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        obs.counters().sessions,
        0,
        "le pair PPP ne doit pas être appelé"
    );
    gw.shutdown().await;
}

// ================================================================ bugs connus

/// Régression (`core::tunnel`, `Driver::establish`, corrigé) : si la passerelle a déjà répondu en HTTP et
/// fermé le flux avant la première écriture du client, le `select!` tire au hasard entre
/// la lecture (réponse HTTP disponible → `TunnelRefused`) et l'écriture du
/// Configure-Request LCP (→ `BrokenPipe`). Dans ~30 % des cas, `open` renvoie
/// `TunnelError::Io(BrokenPipe)` : `requires_reauth()` est alors faux et une
/// reconnexion réessaierait avec un cookie refusé. Attendu : une erreur d'écriture
/// ne doit pas masquer une réponse déjà reçue (vider la lecture avant de conclure).
#[tokio::test(start_paused = true)]
async fn bug_http_refusal_masked_by_write_error() {
    let mut io_errors = Vec::new();
    for i in 0..64 {
        let peer = PppPeer::with_fault(PppFault::HttpInsteadOfPpp { status: 403 });
        let (stream, task) = spawn_peer(&peer, &TunnelConfig::vector_split());
        // La passerelle a répondu `403` et fermé avant que le client n'écrive.
        assert_eq!(peer_end(task, VIRTUAL_GUARD).await, PeerEnd::HttpSent(403));
        match tunnel::open(stream, options()).await {
            Err(TunnelError::TunnelRefused { status: Some(403) }) => {}
            Err(TunnelError::Io(e)) => io_errors.push((i, e.kind())),
            other => panic!("essai {i}: {other:?}"),
        }
    }
    assert!(
        io_errors.is_empty(),
        "{} essais sur 64 donnent Io au lieu de TunnelRefused : {io_errors:?}",
        io_errors.len()
    );
}
