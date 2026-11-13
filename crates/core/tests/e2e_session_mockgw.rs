//! Tunnel complet de bout en bout (story 5.4) : `Session<SslVpnTransport,
//! FakeNetBackend>` contre `mock_gw::MockGateway` + `PppPeer`, en TLS réel sur
//! 127.0.0.1 (certificat auto-signé épinglé). Pas de TUN réelle : la TUN est le
//! canal en mémoire du `FakeNetBackend`.
//!
//! Identifiants : valeurs fictives par défaut de mock-gw (`docs/vectors/README.md`).

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;
use std::time::Duration;

use bytes::Bytes;
use fortivpn_core::fake::{FakeNetBackend, NetOp, RouteVia};
use fortivpn_core::sslvpn::{CertFingerprint, SslVpnOptions, SslVpnTransport, TlsOptions};
use fortivpn_core::{
    Credentials, DisconnectReason, ReconnectPolicy, RoutingMode, Session, SessionEvent,
    SessionEvents, SessionOptions, SessionState, Transport, TransportError, TunnelError,
    TunnelOptions,
};
use ipnet::IpNet;
use mock_gw::{
    CookieCheck, DEFAULT_PASSWORD, DEFAULT_REPLY_IP_ID, DEFAULT_USERNAME, DropPoint, FaultTrigger,
    LoginFailure, MockGatewayBuilder, PeerEnd, PppFault, PppPeer, RunningGateway, Scenario,
    icmp_echo_reply, internet_checksum,
};
use tokio::time::timeout;

/// Garde-fou en temps réel.
const GUARD: Duration = Duration::from_secs(15);
/// Magic-Number LCP fixe du client (tests déterministes).
const CLIENT_MAGIC: u32 = 0x1a2b_3c4d;
/// Adresse attribuée par `TunnelConfig::vector_split()`.
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 2);
/// Hôte interne joint par les pings (dans 10.0.0.0/8, route split).
const PING_DST: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 10);

// --------------------------------------------------------------- utilitaires

fn tunnel_options() -> TunnelOptions {
    TunnelOptions::with_magic(NonZeroU32::new(CLIENT_MAGIC).unwrap())
}

fn creds() -> Credentials {
    Credentials::new(DEFAULT_USERNAME, DEFAULT_PASSWORD)
}

fn bad_creds() -> Credentials {
    Credentials::new(DEFAULT_USERNAME, "pas-le-bon")
}

async fn start(builder: MockGatewayBuilder, peer: &PppPeer) -> RunningGateway {
    builder
        .tunnel_handler(peer.clone())
        .start()
        .await
        .expect("démarrage de mock-gw")
}

/// Options client épinglant le certificat de `gw` (pas de racines système).
fn client_options(gw: &RunningGateway) -> SslVpnOptions {
    let mut o = SslVpnOptions::new("127.0.0.1", gw.addr().port());
    let fp: CertFingerprint = gw.cert().sha256_hex().parse().expect("empreinte");
    o.tls = TlsOptions {
        use_system_roots: false,
        pinned: vec![fp],
        ..TlsOptions::default()
    };
    o
}

fn transport(gw: &RunningGateway, opts: TunnelOptions) -> SslVpnTransport {
    SslVpnTransport::new(&client_options(gw))
        .expect("transport")
        .with_tunnel_options(opts)
}

type E2eSession = Session<SslVpnTransport, FakeNetBackend>;

/// Session sans reconnexion automatique.
fn session(
    gw: &RunningGateway,
    opts: TunnelOptions,
    credentials: Credentials,
) -> (
    E2eSession,
    FakeNetBackend,
    fortivpn_core::SessionHandle,
    SessionEvents,
) {
    session_with(gw, opts, credentials, ReconnectPolicy::disabled())
}

fn session_with(
    gw: &RunningGateway,
    opts: TunnelOptions,
    credentials: Credentials,
    policy: ReconnectPolicy,
) -> (
    E2eSession,
    FakeNetBackend,
    fortivpn_core::SessionHandle,
    SessionEvents,
) {
    let backend = FakeNetBackend::new();
    let (s, h, ev) = Session::new(
        transport(gw, opts),
        backend.clone(),
        credentials,
        SessionOptions::new("fvpn0").with_reconnect(policy),
    );
    (s, backend, h, ev)
}

async fn next_event(ev: &mut SessionEvents) -> SessionEvent {
    timeout(GUARD, ev.recv())
        .await
        .expect("événement : délai dépassé")
        .expect("flux d'événements fermé")
}

fn drain(ev: &mut SessionEvents) -> Vec<SessionState> {
    std::iter::from_fn(|| ev.try_recv())
        .map(|e| e.state)
        .collect()
}

/// ICMP Echo Request `LOCAL_IP` → `PING_DST` (sommes calculées).
fn echo_request(seq: u16) -> Vec<u8> {
    let payload = b"fortivpn-rs e2e!";
    let total = 20 + 8 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p.extend_from_slice(&(0x1234 + seq).to_be_bytes());
    p.extend_from_slice(&[0x40, 0, 64, 1, 0, 0]);
    p.extend_from_slice(&LOCAL_IP.octets());
    p.extend_from_slice(&PING_DST.octets());
    let sum = internet_checksum(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p.extend_from_slice(&[8, 0, 0, 0, 0x42, 0x42]);
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(payload);
    let sum = internet_checksum(&p[20..]);
    p[22..24].copy_from_slice(&sum.to_be_bytes());
    p
}

fn count(gw: &RunningGateway, path: &str) -> usize {
    gw.log().for_path(path).len()
}

fn logged_out(gw: &RunningGateway) -> bool {
    gw.log()
        .for_path("/remote/logout")
        .iter()
        .any(|r| r.cookie == CookieCheck::Valid)
}

fn connect_error(reason: &DisconnectReason) -> &TransportError {
    match reason {
        DisconnectReason::ConnectFailed(e) => e,
        other => panic!("ConnectFailed attendu : {other:?}"),
    }
}

fn teardown_done(backend: &FakeNetBackend) {
    assert!(backend.is_clean(), "configuration réseau non annulée");
    assert!(
        backend
            .ops()
            .contains(&NetOp::TeardownStart { blocking: false }),
        "{:?}",
        backend.ops()
    );
}

// ================================================================ nominal

#[tokio::test]
async fn full_tunnel_up_ping_and_shutdown() {
    let peer = PppPeer::default();
    let mut obs = peer.observer();
    let gw = start(MockGatewayBuilder::default(), &peer).await;
    let (mut session, backend, handle, mut ev) = session(&gw, tunnel_options(), creds());
    let run = tokio::spawn(async move { session.run().await });

    // Événements horodatés, dans l'ordre.
    let mut seen = Vec::new();
    let up = loop {
        let e = next_event(&mut ev).await;
        if let Some(prev) = seen.last().map(|p: &SessionEvent| p.elapsed) {
            assert!(e.elapsed >= prev, "horodatage non monotone");
        }
        let done = matches!(e.state, SessionState::TunnelUp { .. });
        seen.push(e);
        if done {
            break seen.last().cloned().unwrap();
        }
    };
    let names: Vec<_> = seen
        .iter()
        .map(|e| match e.state {
            SessionState::Connecting => "Connecting",
            SessionState::Authenticated => "Authenticated",
            SessionState::ConfigReceived => "ConfigReceived",
            SessionState::TunnelUp { .. } => "TunnelUp",
            _ => "autre",
        })
        .collect();
    assert_eq!(
        names,
        ["Connecting", "Authenticated", "ConfigReceived", "TunnelUp"]
    );
    assert!(up.elapsed > Duration::ZERO);

    // Configuration appliquée (vector_split + IPCP).
    let SessionState::TunnelUp { config, interface } = up.state else {
        unreachable!()
    };
    assert_eq!(interface.name, "fvpn0");
    assert_eq!(config.ipv4.address, "10.10.0.2/32".parse().unwrap());
    assert_eq!(config.mtu, 1354);
    assert_eq!(config.gateway, IpAddr::from(Ipv4Addr::LOCALHOST));
    let dns: Vec<IpAddr> = vec![
        Ipv4Addr::new(10, 0, 0, 53).into(),
        Ipv4Addr::new(10, 0, 0, 54).into(),
    ];
    assert_eq!(config.dns.servers, dns);
    for d in ["corp.example.com", "lab.example.net"] {
        assert!(config.dns.search_domains.iter().any(|s| s == d), "{d}");
    }
    let RoutingMode::Split { include } = &config.routing else {
        panic!("split attendu : {:?}", config.routing)
    };
    for r in ["172.16.0.0/12", "192.0.2.128/25", "198.51.100.7/32"] {
        assert!(include.contains(&r.parse::<IpNet>().unwrap()), "{r}");
    }
    let covers = |ip: Ipv4Addr| include.iter().any(|n| n.contains(&IpAddr::from(ip)));
    assert!(covers(PING_DST));
    assert!(!covers(Ipv4Addr::new(10, 99, 1, 1)), "exclusion negate=1");
    let ops = backend.ops();
    assert!(ops.contains(&NetOp::SetMtu(1354)), "{ops:?}");
    assert!(ops.contains(&NetOp::SetDns(config.dns.clone())), "{ops:?}");
    let routes = backend.installed_routes();
    assert_eq!(routes.len(), include.len() + 1, "{routes:?}");
    assert!(
        routes.iter().any(|r| r.via == RouteVia::Underlay
            && r.dest == IpNet::from(IpAddr::from(Ipv4Addr::LOCALHOST)))
    );

    // Pings via la TUN fictive.
    let mut tun = backend.take_tun_peer().expect("TUN fictive");
    for seq in 1..=3u16 {
        let req = echo_request(seq);
        tun.send(Bytes::from(req.clone())).await.unwrap();
        let reply = timeout(GUARD, tun.recv())
            .await
            .expect("réponse ICMP : délai dépassé")
            .expect("TUN fermée");
        let expected = icmp_echo_reply(&req, DEFAULT_REPLY_IP_ID + seq - 1).unwrap();
        assert_eq!(reply[..], expected[..], "ping {seq}");
    }

    // Arrêt demandé : Terminate PPP, teardown réseau, logout.
    handle.shutdown();
    let reason = timeout(GUARD, run).await.unwrap().unwrap();
    assert!(matches!(reason, DisconnectReason::Requested), "{reason:?}");
    teardown_done(&backend);
    assert_eq!(
        timeout(GUARD, obs.wait_end()).await.unwrap(),
        PeerEnd::ClientTerminated
    );
    assert!(logged_out(&gw), "{:?}", gw.log().paths());
    let n = obs.counters();
    assert_eq!((n.sessions, n.icmp_echo_replied), (1, 3), "{n:?}");
    let last = drain(&mut ev);
    assert!(
        matches!(last.last(), Some(SessionState::Disconnected { .. })),
        "{last:?}"
    );
    gw.shutdown().await;
}

// ============================================== réutilisation du cookie

#[tokio::test]
async fn tunnel_reconnect_reuses_cookie_then_reauths_when_refused() {
    let cookie = "c0ffee".repeat(8);
    let peer = PppPeer::default();
    let gw = start(MockGatewayBuilder::default().session_cookie(&cookie), &peer).await;
    let mut t = transport(&gw, tunnel_options());
    let s = timeout(GUARD, t.connect(&creds())).await.unwrap().unwrap();
    drop(s);
    t.close_tunnel().await;
    assert!(t.has_session_cookie());

    // 1. Cookie encore valide : pas de nouveau logincheck.
    let s = timeout(GUARD, t.connect(&creds())).await.unwrap().unwrap();
    drop(s);
    t.close_tunnel().await;
    assert_eq!(
        count(&gw, "/remote/logincheck"),
        1,
        "{:?}",
        gw.log().paths()
    );
    assert_eq!(count(&gw, "/remote/sslvpn-tunnel"), 2);

    // 2. Session fermée côté passerelle : le cookie est refusé, ré-authentification.
    let other = fortivpn_core::sslvpn::SslVpnClient::new(&client_options(&gw)).unwrap();
    other
        .logout(&fortivpn_core::sslvpn::SessionCookie::new(cookie.as_str()).unwrap())
        .await
        .unwrap();
    let s = timeout(GUARD, t.connect(&creds())).await.unwrap().unwrap();
    drop(s);
    assert_eq!(
        count(&gw, "/remote/logincheck"),
        2,
        "{:?}",
        gw.log().paths()
    );
    timeout(GUARD, t.disconnect()).await.unwrap().unwrap();
    assert!(!t.has_session_cookie());
    // Idempotent.
    t.disconnect().await.unwrap();
    gw.shutdown().await;
}

// ================================================================ échecs

async fn connect_fails(
    builder: MockGatewayBuilder,
    credentials: Credentials,
) -> (
    RunningGateway,
    DisconnectReason,
    FakeNetBackend,
    Vec<SessionState>,
) {
    let peer = PppPeer::default();
    let gw = start(builder, &peer).await;
    let (mut s, backend, _h, mut ev) = session(&gw, tunnel_options(), credentials);
    let reason = timeout(GUARD, s.run()).await.expect("run : délai dépassé");
    assert!(backend.ops().is_empty(), "aucune opération réseau attendue");
    assert_eq!(peer.observer().counters().sessions, 0);
    (gw, reason, backend, drain(&mut ev))
}

#[tokio::test]
async fn wrong_password_ret0_and_405() {
    for mode in [LoginFailure::Ret0, LoginFailure::Status405] {
        let (gw, reason, _, states) = connect_fails(
            MockGatewayBuilder::default().login_failure(mode),
            bad_creds(),
        )
        .await;
        assert!(
            matches!(connect_error(&reason), TransportError::AuthFailed),
            "{mode:?}: {reason:?}"
        );
        assert!(
            !states
                .iter()
                .any(|s| matches!(s, SessionState::Authenticated)),
            "{states:?}"
        );
        assert_eq!(count(&gw, "/remote/fortisslvpn_xml"), 0);
        gw.shutdown().await;
    }
}

#[tokio::test]
async fn second_factor_required_gives_clear_error() {
    let (gw, reason, _, _) = connect_fails(
        MockGatewayBuilder::default().scenario(Scenario::SecondFactorRequired),
        creds(),
    )
    .await;
    let msg = connect_error(&reason).to_string();
    assert!(msg.contains("deux facteurs"), "{msg}");
    gw.shutdown().await;
}

#[tokio::test]
async fn drop_after_auth_fails_without_network_changes() {
    for point in [
        DropPoint::AfterLoginResponse,
        DropPoint::BeforeConfig,
        DropPoint::BeforeTunnel,
    ] {
        let (gw, reason, _, _) = connect_fails(
            MockGatewayBuilder::default().scenario(Scenario::DropAfterAuth(point)),
            creds(),
        )
        .await;
        let e = connect_error(&reason);
        assert!(
            matches!(
                e,
                TransportError::Io(_)
                    | TransportError::Protocol(_)
                    | TransportError::Tunnel(TunnelError::ClosedByPeer | TunnelError::Io(_))
            ),
            "{point:?}: {e:?}"
        );
        if point == DropPoint::BeforeTunnel {
            // Cookie obtenu : logout fait au nettoyage (§10.1).
            assert!(logged_out(&gw), "{:?}", gw.log().paths());
        }
        gw.shutdown().await;
    }
}

async fn tunnel_fails(
    fault: PppFault,
    opts: TunnelOptions,
) -> (std::sync::Arc<TransportError>, PeerEnd) {
    let peer = PppPeer::with_fault(fault);
    let mut obs = peer.observer();
    let gw = start(MockGatewayBuilder::default(), &peer).await;
    let (mut s, backend, _h, mut ev) = session(&gw, opts, creds());
    let reason = timeout(GUARD, s.run()).await.expect("run : délai dépassé");
    let states = drain(&mut ev);
    assert!(
        states
            .iter()
            .any(|s| matches!(s, SessionState::TunnelUp { .. })),
        "{states:?}"
    );
    teardown_done(&backend);
    assert!(logged_out(&gw), "{:?}", gw.log().paths());
    let end = timeout(GUARD, obs.wait_end()).await.unwrap();
    gw.shutdown().await;
    match reason {
        DisconnectReason::TransportFailed(e) => (e, end),
        other => panic!("TransportFailed attendu : {other:?}"),
    }
}

#[tokio::test]
async fn dead_peer_tears_down() {
    let mut opts = tunnel_options();
    opts.ppp.echo_interval = Some(Duration::from_millis(100));
    opts.ppp.echo_max_failures = 3;
    let (e, _) = tunnel_fails(PppFault::IgnoreEchoRequests, opts).await;
    assert!(
        matches!(*e, TransportError::Tunnel(TunnelError::DeadPeer)),
        "{e:?}"
    );
}

#[tokio::test]
async fn gateway_terminate_tears_down() {
    let when = FaultTrigger::AfterIpcpUp(Duration::from_millis(300));
    let (e, end) = tunnel_fails(PppFault::GatewayTerminate { when }, tunnel_options()).await;
    assert!(
        matches!(*e, TransportError::Tunnel(TunnelError::ClosedByPeer)),
        "{e:?}"
    );
    assert_eq!(end, PeerEnd::GatewayTerminated { acked: true });
}

// ============================================== reconnexion automatique

/// Reconnexion rapide et déterministe (pas de jitter).
fn fast_reconnect(initial: Duration) -> ReconnectPolicy {
    let mut p = ReconnectPolicy::default();
    p.initial_delay = initial;
    p.jitter = 0.0;
    p.max_attempts = std::num::NonZeroU32::new(3);
    p
}

/// Attend `n` événements `TunnelUp` ; appelle `on_reconnecting` à chaque
/// `Reconnecting`. Retourne les états vus.
async fn until_up<F, Fut>(
    ev: &mut SessionEvents,
    n: usize,
    mut on_reconnecting: F,
) -> Vec<SessionState>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut seen = Vec::new();
    let mut ups = 0;
    while ups < n {
        let e = next_event(ev).await;
        match &e.state {
            SessionState::TunnelUp { .. } => ups += 1,
            SessionState::Reconnecting { .. } => on_reconnecting().await,
            SessionState::Disconnected { reason } => panic!("fin inattendue : {reason:?}"),
            _ => {}
        }
        seen.push(e.state);
    }
    seen
}

#[tokio::test]
async fn dead_peer_reconnects_with_same_cookie() {
    let peer = PppPeer::with_fault(PppFault::IgnoreEchoRequests);
    let obs = peer.observer();
    let gw = start(MockGatewayBuilder::default(), &peer).await;
    let mut opts = tunnel_options();
    opts.ppp.echo_interval = Some(Duration::from_millis(100));
    opts.ppp.echo_max_failures = 3;
    let (mut s, backend, handle, mut ev) = session_with(
        &gw,
        opts,
        creds(),
        fast_reconnect(Duration::from_millis(50)),
    );
    let run = tokio::spawn(async move { s.run().await });

    let seen = until_up(&mut ev, 2, || async {}).await;
    handle.shutdown();
    let reason = timeout(GUARD, run).await.unwrap().unwrap();
    assert!(matches!(reason, DisconnectReason::Requested), "{reason:?}");

    let cause = seen
        .iter()
        .find_map(|s| match s {
            SessionState::Reconnecting {
                attempt: 1, cause, ..
            } => Some(cause.clone()),
            _ => None,
        })
        .expect("Reconnecting");
    assert!(
        matches!(&cause, DisconnectReason::TransportFailed(e)
            if matches!(**e, TransportError::Tunnel(TunnelError::DeadPeer))),
        "{cause:?}"
    );
    // Cookie réutilisé : un seul login, une seule étape `Authenticated`.
    assert_eq!(
        count(&gw, "/remote/logincheck"),
        1,
        "{:?}",
        gw.log().paths()
    );
    assert_eq!(
        seen.iter()
            .filter(|s| matches!(s, SessionState::Authenticated))
            .count(),
        1
    );
    assert_eq!(count(&gw, "/remote/sslvpn-tunnel"), 2);
    assert_eq!(obs.counters().sessions, 2, "{:?}", obs.counters());
    teardown_done(&backend);
    assert!(logged_out(&gw), "{:?}", gw.log().paths());
    gw.shutdown().await;
}

#[tokio::test]
async fn reconnect_reauthenticates_when_cookie_refused() {
    let cookie = "c0ffee".repeat(8);
    let when = FaultTrigger::AfterIpcpUp(Duration::from_millis(200));
    let peer = PppPeer::with_fault(PppFault::GatewayTerminate { when });
    let obs = peer.observer();
    let gw = start(MockGatewayBuilder::default().session_cookie(&cookie), &peer).await;
    let (mut s, backend, handle, mut ev) = session_with(
        &gw,
        tunnel_options(),
        creds(),
        fast_reconnect(Duration::from_millis(500)),
    );
    let run = tokio::spawn(async move { s.run().await });

    // Pendant l'attente du backoff, la session est fermée côté passerelle.
    let other = fortivpn_core::sslvpn::SslVpnClient::new(&client_options(&gw)).unwrap();
    let mut expired = false;
    let seen = until_up(&mut ev, 2, || {
        let fire = !expired;
        expired = true;
        let other = &other;
        let cookie = cookie.as_str();
        async move {
            if fire {
                other
                    .logout(&fortivpn_core::sslvpn::SessionCookie::new(cookie).unwrap())
                    .await
                    .unwrap();
            }
        }
    })
    .await;
    handle.shutdown();
    let reason = timeout(GUARD, run).await.unwrap().unwrap();
    assert!(matches!(reason, DisconnectReason::Requested), "{reason:?}");

    assert!(
        seen.iter().any(|s| matches!(
            s,
            SessionState::Reconnecting { cause: DisconnectReason::TransportFailed(e), .. }
                if matches!(**e, TransportError::Tunnel(TunnelError::ClosedByPeer))
        )),
        "{seen:?}"
    );
    // Cookie refusé à la reconnexion : ré-authentification complète.
    assert_eq!(
        count(&gw, "/remote/logincheck"),
        2,
        "{:?}",
        gw.log().paths()
    );
    assert_eq!(
        seen.iter()
            .filter(|s| matches!(s, SessionState::Authenticated))
            .count(),
        2
    );
    assert_eq!(obs.counters().sessions, 2, "{:?}", obs.counters());
    teardown_done(&backend);
    gw.shutdown().await;
}
