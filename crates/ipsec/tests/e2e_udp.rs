//! e2e : `Session<IpsecTransport, FakeNetBackend>` contre la passerelle simulée
//! (`ipsec::testutil::SimGateway`) servie sur de vraies sockets UDP 127.0.0.1.
//! Sans privilèges, sans strongSwan (interop : story 6.4).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use fortivpn_core::fake::{FakeNetBackend, RouteVia};
use fortivpn_core::session::{DisconnectReason, SessionEvents, SessionHandle, SessionOptions};
use fortivpn_core::{
    Credentials, PacketChannel, ReconnectPolicy, RoutingMode, Session, SessionState, TunnelConfig,
};
use ipsec::esp::{self, Datagram};
use ipsec::ike::Lifetimes;
use ipsec::testutil::{PASS, PSK, SimGateway, USER, icmp_echo_reply, icmp_echo_request};
use ipsec::{IpsecOptions, IpsecTransport};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const T: Duration = Duration::from_secs(10);
const CLIENT_IP: [u8; 4] = [10, 10, 2, 7];
const TARGET: [u8; 4] = [10, 20, 0, 5];

fn lock<X>(m: &Mutex<X>) -> MutexGuard<'_, X> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

enum Cmd {
    DeleteIke,
}

struct Gw {
    state: Arc<Mutex<SimGateway>>,
    cmd: mpsc::UnboundedSender<Cmd>,
    silent: Arc<AtomicBool>,
    keepalives: Arc<AtomicU32>,
    ike_port: u16,
    natt_port: u16,
    _task: JoinHandle<()>,
}

impl Gw {
    async fn start() -> Self {
        let ike = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let natt = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (ike_port, natt_port) = (
            ike.local_addr().unwrap().port(),
            natt.local_addr().unwrap().port(),
        );
        let state = Arc::new(Mutex::new(SimGateway::new()));
        let silent = Arc::new(AtomicBool::new(false));
        let keepalives = Arc::new(AtomicU32::new(0));
        let (cmd, mut cmd_rx) = mpsc::unbounded_channel();
        let (st, si, ka) = (state.clone(), silent.clone(), keepalives.clone());
        let task = tokio::spawn(async move {
            let (mut b1, mut b2) = (vec![0u8; 65_536], vec![0u8; 65_536]);
            let mut client: Option<SocketAddr> = None;
            loop {
                tokio::select! {
                    Ok((n, from)) = ike.recv_from(&mut b1) => {
                        if si.load(Ordering::SeqCst) { continue; }
                        let replies = lock(&st).handle_ike(&b1[..n]);
                        for r in replies { let _ = ike.send_to(&r, from).await; }
                    }
                    Ok((n, from)) = natt.recv_from(&mut b2) => {
                        client = Some(from);
                        if si.load(Ordering::SeqCst) { continue; }
                        let data = &b2[..n];
                        let out: Vec<Vec<u8>> = match esp::classify(data) {
                            Ok(Datagram::Keepalive) => { ka.fetch_add(1, Ordering::SeqCst); vec![] }
                            Ok(Datagram::Ike(m)) => lock(&st).handle_ike(m),
                            Ok(Datagram::Esp(m)) => {
                                let mut g = lock(&st);
                                g.open_esp(m)
                                    .and_then(|p| icmp_echo_reply(&p))
                                    .map(|r| vec![g.seal_esp(&r)])
                                    .unwrap_or_default()
                            }
                            Err(_) => vec![],
                        };
                        for r in out { let _ = natt.send_to(&r, from).await; }
                    }
                    Some(c) = cmd_rx.recv() => {
                        if let (Some(to), Cmd::DeleteIke) = (client, c) {
                            let d = lock(&st).delete_ike();
                            let _ = natt.send_to(&d, to).await;
                        }
                    }
                }
            }
        });
        Self {
            state,
            cmd,
            silent,
            keepalives,
            ike_port,
            natt_port,
            _task: task,
        }
    }
}

struct Harness {
    gw: Gw,
    backend: FakeNetBackend,
    handle: SessionHandle,
    events: SessionEvents,
    run: JoinHandle<DisconnectReason>,
    tun: PacketChannel,
    config: TunnelConfig,
}

async fn start(tune: impl FnOnce(&mut IpsecOptions)) -> Harness {
    let gw = Gw::start().await;
    let mut o = IpsecOptions::new("127.0.0.1", PSK);
    o.ike_port = gw.ike_port;
    o.natt_port = gw.natt_port;
    tune(&mut o);
    let backend = FakeNetBackend::new();
    let (mut session, handle, mut events) = Session::new(
        IpsecTransport::new(o),
        backend.clone(),
        Credentials::new(USER, PASS),
        SessionOptions::new("fvpn0").with_reconnect(ReconnectPolicy::disabled()),
    );
    let run = tokio::spawn(async move { session.run().await });
    let config = timeout(T, async {
        loop {
            let ev = events.recv().await.expect("session terminée trop tôt");
            if let SessionState::TunnelUp { config, .. } = ev.state {
                return config;
            }
        }
    })
    .await
    .expect("TunnelUp attendu");
    let tun = backend.take_tun_peer().expect("TUN");
    Harness {
        gw,
        backend,
        handle,
        events,
        run,
        tun,
        config,
    }
}

impl Harness {
    async fn ping(&mut self, seq: u16) {
        let req = icmp_echo_request(CLIENT_IP, TARGET, 0x4242, seq);
        self.tun.send(Bytes::from(req.clone())).await.unwrap();
        let rep = timeout(Duration::from_secs(2), self.tun.recv())
            .await
            .unwrap_or_else(|_| panic!("pas de réponse au ping {seq}"))
            .expect("TUN fermée");
        assert_eq!(&rep[..], &icmp_echo_reply(&req).unwrap()[..], "ping {seq}");
    }
}

#[tokio::test]
async fn tunnel_up_config_ping_dpd_and_keepalive() {
    let mut h = start(|o| {
        o.dpd_idle = Some(Duration::from_millis(300));
        o.keepalive = Duration::from_millis(200);
    })
    .await;
    let c = &h.config;
    assert_eq!(c.ipv4.address.to_string(), "10.10.2.7/32");
    assert_eq!(c.gateway.to_string(), "127.0.0.1");
    assert_eq!(c.dns.servers[0].to_string(), "10.20.0.53");
    assert_eq!(c.dns.search_domains, vec!["corp.example.test".to_owned()]);
    let RoutingMode::Split { include } = &c.routing else {
        panic!("split attendu");
    };
    assert_eq!(include[0].to_string(), "10.20.0.0/24");
    assert!(
        h.backend
            .installed_routes()
            .iter()
            .any(|r| r.dest.to_string() == "10.20.0.0/24" && r.via == RouteVia::Tunnel)
    );
    for seq in 1..=5 {
        h.ping(seq).await;
    }
    // Silence : le client émet des DPD (répondus) et des keepalives NAT-T.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(lock(&h.gw.state).dpd_received >= 1, "DPD du client attendu");
    assert!(
        h.gw.keepalives.load(Ordering::SeqCst) >= 1,
        "keepalive attendu"
    );
    h.ping(6).await;

    // Arrêt demandé : Delete(IKE) propre vers la passerelle.
    h.handle.shutdown();
    let reason = timeout(T, &mut h.run).await.unwrap().unwrap();
    assert!(matches!(reason, DisconnectReason::Requested), "{reason:?}");
    // Le datagramme UDP est traité de façon asynchrone par la passerelle.
    let mut closed = false;
    for _ in 0..50 {
        closed = lock(&h.gw.state).closed;
        if closed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(closed, "Delete(IKE) attendu");
    assert!(h.backend.is_clean());
}

#[tokio::test]
async fn peer_delete_ends_session() {
    let mut h = start(|_| {}).await;
    h.ping(1).await;
    h.gw.cmd.send(Cmd::DeleteIke).unwrap();
    let reason = timeout(T, &mut h.run).await.unwrap().unwrap();
    assert!(
        matches!(&reason, DisconnectReason::TransportFailed(e) if e.is_transient()),
        "{reason:?}"
    );
    assert!(h.backend.is_clean());
    drop(h.events);
}

#[tokio::test]
async fn dead_peer_ends_session() {
    let mut h = start(|o| {
        o.dpd_idle = Some(Duration::from_millis(200));
        o.retransmit_base = Some(Duration::from_millis(100));
        o.max_sends = Some(3);
    })
    .await;
    h.ping(1).await;
    h.gw.silent.store(true, Ordering::SeqCst);
    let reason = timeout(T, &mut h.run).await.unwrap().unwrap();
    assert!(
        matches!(&reason, DisconnectReason::TransportFailed(e) if e.is_transient()),
        "{reason:?}"
    );
}

#[tokio::test]
async fn child_rekey_is_lossless() {
    let mut h = start(|o| {
        o.lifetimes = Some(Lifetimes {
            child_soft: Duration::from_millis(800),
            child_hard: Duration::from_secs(60),
            ..Lifetimes::default()
        });
    })
    .await;
    // ~3 s de trafic continu (sans perte tolérée) à cheval sur le rekey.
    for seq in 1..=100u16 {
        h.ping(seq).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(lock(&h.gw.state).rekeys >= 1, "rekey CHILD attendu");
    h.handle.shutdown();
    timeout(T, &mut h.run).await.unwrap().unwrap();
}
