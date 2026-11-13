//! E2E du mode proxy sans admin (story 7.2) : `Session<SslVpnTransport, ProxyBackend>`
//! contre `mock_gw::MockGateway` (TLS réel sur 127.0.0.1, certificat épinglé). Derrière le
//! pair PPP de mock-gw, un pair smoltcp « passerelle » (écho TCP 10.10.0.5:7, DNS
//! 10.10.0.53:53) branché via `PppPeer::with_ip_bridge`. Pas de TUN, pas de sudo,
//! ports éphémères. Identifiants : valeurs fictives de mock-gw.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fortivpn_core::sslvpn::{CertFingerprint, SslVpnOptions, SslVpnTransport, TlsOptions};
use fortivpn_core::{
    Credentials, DisconnectReason, ReconnectPolicy, Session, SessionEvents, SessionHandle,
    SessionOptions, SessionState, TunnelOptions,
};
use mock_gw::{
    DEFAULT_PASSWORD, DEFAULT_USERNAME, DnsServer, IpBridge, IpLink, MockGatewayBuilder, PppFault,
    PppPeer, RunningGateway, TunnelConfig,
};
use netproxy::{Forward, Host, ProxyBackend, ProxyConfig, Target};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Cidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const ECHO: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 5);
const DNS: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 53);
const T: Duration = Duration::from_secs(15);

// --- Pair « passerelle » ---------------------------------------------------------

struct Queues {
    rx: VecDeque<Bytes>,
    tx: VecDeque<Bytes>,
}

struct Rx(Bytes);
struct Tx<'a>(&'a mut VecDeque<Bytes>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0; len];
        let r = f(&mut buf);
        self.0.push_back(Bytes::from(buf));
        r
    }
}

impl Device for Queues {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1354;
        c
    }
}

/// Réponse DNS : `echo.corp` → ECHO, sinon NXDOMAIN.
fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*query.get(i)?);
        i += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(query.get(i..i + len)?).into_owned());
        i += len;
    }
    let question_end = i + 4;
    let question = query.get(12..question_end)?;
    let found = labels.join(".") == "echo.corp";
    let mut r = Vec::new();
    r.extend_from_slice(&query[..2]);
    r.extend_from_slice(if found { &[0x81, 0x80] } else { &[0x81, 0x83] });
    r.extend_from_slice(&[0, 1, 0, u8::from(found), 0, 0, 0, 0]);
    r.extend_from_slice(question);
    if found {
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        r.extend_from_slice(&ECHO.octets());
    }
    Some(r)
}

/// Pile du pair : écho TCP (8 écoutes sur le port 7) et serveur DNS.
async fn gateway_peer(link: IpLink) {
    let tx = link.downlink;
    let mut rx = link.uplink;
    let mut dev = Queues {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let start = tokio::time::Instant::now();
    let now =
        || smoltcp::time::Instant::from_micros(i64::try_from(start.elapsed().as_micros()).unwrap());
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
    iface.update_ip_addrs(|a| {
        a.push(IpCidr::Ipv4(Ipv4Cidr::new(ECHO, 32))).unwrap();
        a.push(IpCidr::Ipv4(Ipv4Cidr::new(DNS, 32))).unwrap();
    });
    iface.routes_mut().add_default_ipv4_route(ECHO).unwrap();
    let mut sockets = SocketSet::new(Vec::new());
    let mut tcps = Vec::new();
    for _ in 0..8 {
        let mut s = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 65536]),
            tcp::SocketBuffer::new(vec![0; 65536]),
        );
        s.listen(7).unwrap();
        tcps.push(sockets.add(s));
    }
    let mut u = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]),
    );
    u.bind((IpAddress::Ipv4(DNS), 53)).unwrap();
    let udp_h = sockets.add(u);
    let mut buf = vec![0u8; 65536];
    loop {
        iface.poll(now(), &mut dev, &mut sockets);
        for &h in &tcps {
            let s = sockets.get_mut::<tcp::Socket>(h);
            while s.can_recv() && s.can_send() {
                let room = s.send_capacity() - s.send_queue();
                let lim = room.min(buf.len());
                let n = s.recv_slice(&mut buf[..lim]).unwrap();
                if n == 0 {
                    break;
                }
                assert_eq!(s.send_slice(&buf[..n]).unwrap(), n);
            }
            if s.state() == tcp::State::CloseWait && s.recv_queue() == 0 {
                s.close();
            }
        }
        let u = sockets.get_mut::<udp::Socket>(udp_h);
        while let Ok((n, meta)) = u.recv_slice(&mut buf) {
            if let Some(resp) = dns_answer(&buf[..n]) {
                u.send_slice(&resp, meta.endpoint).unwrap();
            }
        }
        iface.poll(now(), &mut dev, &mut sockets);
        while let Some(p) = dev.tx.pop_front() {
            if tx.send(p).is_err() {
                return;
            }
        }
        let delay = iface
            .poll_delay(now(), &sockets)
            .map_or(Duration::from_millis(50), |d| {
                Duration::from_micros(d.total_micros())
            })
            .min(Duration::from_millis(50));
        tokio::select! {
            p = rx.recv() => match p {
                Some(p) => dev.rx.push_back(p),
                None => return,
            },
            () = tokio::time::sleep(delay) => {}
        }
    }
}
// --- Passerelle + session -----------------------------------------------------------

/// Passerelle dont chaque connexion tunnel est servie par un `PppPeer` relié au pair
/// smoltcp. `faulty_first` : la 1re connexion ignore les LCP Echo-Request (`DeadPeer`).
async fn start_gateway(faulty_first: bool) -> RunningGateway {
    let tc = TunnelConfig::split(
        Ipv4Addr::new(10, 10, 0, 2),
        vec![DnsServer::new(DNS)],
        vec!["10.10.0.0/24".parse().unwrap()],
    );
    let count = Arc::new(AtomicUsize::new(0));
    let bridge = IpBridge::new(|link| {
        tokio::spawn(gateway_peer(link));
    });
    MockGatewayBuilder::default()
        .tunnel_config(tc)
        .tunnel_handler(
            move |stream: mock_gw::TunnelStream, ctx: mock_gw::TunnelContext| {
                let n = count.fetch_add(1, Ordering::SeqCst);
                let peer = if faulty_first && n == 0 {
                    PppPeer::with_fault(PppFault::IgnoreEchoRequests)
                } else {
                    PppPeer::default()
                }
                .with_ip_bridge(bridge.clone());
                async move {
                    peer.serve(stream, &ctx.config.ipv4, ctx.conn_id).await;
                }
            },
        )
        .start()
        .await
        .expect("démarrage de mock-gw")
}

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

struct Env {
    gw: RunningGateway,
    socks: SocketAddr,
    forward: SocketAddr,
    handle: SessionHandle,
    events: SessionEvents,
    run: tokio::task::JoinHandle<DisconnectReason>,
}

async fn setup(faulty_first: bool, opts: TunnelOptions, policy: ReconnectPolicy) -> Env {
    let gw = start_gateway(faulty_first).await;
    let backend = ProxyBackend::new(ProxyConfig::new(
        Some("127.0.0.1:0".parse().unwrap()),
        vec![Forward {
            listen: "127.0.0.1:0".parse().unwrap(),
            target: Target {
                host: Host::Domain("echo.corp".into()),
                port: 7,
            },
        }],
    ))
    .unwrap();
    let socks = backend.socks_addr().unwrap();
    let forward = backend.forwards()[0].0;
    let transport = SslVpnTransport::new(&client_options(&gw))
        .expect("transport")
        .with_tunnel_options(opts);
    let (mut session, handle, events) = Session::new(
        transport,
        backend,
        Credentials::new(DEFAULT_USERNAME, DEFAULT_PASSWORD),
        SessionOptions::new("proxy").with_reconnect(policy),
    );
    let run = tokio::spawn(async move { session.run().await });
    Env {
        gw,
        socks,
        forward,
        handle,
        events,
        run,
    }
}

fn tunnel_options() -> TunnelOptions {
    TunnelOptions::with_magic(NonZeroU32::new(0x1a2b_3c4d).unwrap())
}

/// Attend `n` `TunnelUp` ; retourne tous les états vus.
async fn until_up(ev: &mut SessionEvents, n: usize) -> Vec<SessionState> {
    let mut seen = Vec::new();
    let mut ups = 0;
    while ups < n {
        let e = timeout(T, ev.recv())
            .await
            .expect("événement : délai dépassé")
            .expect("flux d'événements fermé");
        ups += usize::from(matches!(e.state, SessionState::TunnelUp { .. }));
        seen.push(e.state);
    }
    seen
}

// --- Clients ----------------------------------------------------------------------

async fn socks_connect(proxy: SocketAddr, request: &[u8]) -> (u8, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, request[0], 0];
    req.extend_from_slice(&request[1..]);
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 5);
    (reply[1], s)
}

fn ipv4_req(ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut r = vec![1, 1];
    r.extend_from_slice(&ip.octets());
    r.extend_from_slice(&port.to_be_bytes());
    r
}

fn domain_req(name: &str, port: u16) -> Vec<u8> {
    let mut r = vec![1, 3, u8::try_from(name.len()).unwrap()];
    r.extend_from_slice(name.as_bytes());
    r.extend_from_slice(&port.to_be_bytes());
    r
}

async fn check_echo(stream: TcpStream, data: Vec<u8>) {
    let (mut rd, mut wr) = stream.into_split();
    let expected = data.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    rd.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();
    assert_eq!(got.len(), expected.len());
    assert!(got == expected, "contenu de l'écho différent");
}

fn payload_100k() -> Vec<u8> {
    (0..100_000u32).map(|i| (i % 251) as u8).collect()
}

/// IP, nom (DNS du tunnel) et redirection : 100 Ko chacun.
async fn exercise_all(env: &Env) {
    let (code, s) = timeout(T, socks_connect(env.socks, &ipv4_req(ECHO, 7)))
        .await
        .unwrap();
    assert_eq!(code, 0, "CONNECT par IP");
    timeout(T, check_echo(s, payload_100k())).await.unwrap();

    let (code, s) = timeout(T, socks_connect(env.socks, &domain_req("echo.corp", 7)))
        .await
        .unwrap();
    assert_eq!(code, 0, "CONNECT par nom");
    timeout(T, check_echo(s, payload_100k())).await.unwrap();

    let s = TcpStream::connect(env.forward).await.unwrap();
    timeout(T, check_echo(s, payload_100k())).await.unwrap();
}

// --- Tests ------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks_forward_and_clean_shutdown() {
    timeout(Duration::from_secs(90), async {
        let mut env = setup(false, tunnel_options(), ReconnectPolicy::disabled()).await;
        until_up(&mut env.events, 1).await;
        exercise_all(&env).await;

        let (code, _) = timeout(T, socks_connect(env.socks, &domain_req("nope.corp", 7)))
            .await
            .unwrap();
        assert_eq!(code, 4, "hôte injoignable (NXDOMAIN)");

        env.handle.shutdown();
        let reason = timeout(T, env.run).await.unwrap().unwrap();
        assert!(matches!(reason, DisconnectReason::Requested), "{reason:?}");
        // Backend détruit avec la session : les écoutes sont fermées.
        let mut closed = false;
        for _ in 0..50 {
            if TcpStream::connect(env.socks).await.is_err() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(closed, "écoute SOCKS encore ouverte après l'arrêt");
        let mut fwd_closed = false;
        for _ in 0..50 {
            if TcpStream::connect(env.forward).await.is_err() {
                fwd_closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            fwd_closed,
            "écoute de redirection encore ouverte après l'arrêt"
        );
        let logout = env.gw.log().for_path("/remote/logout");
        assert!(!logout.is_empty(), "{:?}", env.gw.log().paths());
        env.gw.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_peer_reconnects_and_listeners_survive() {
    timeout(Duration::from_secs(90), async {
        let mut opts = tunnel_options();
        opts.ppp.echo_interval = Some(Duration::from_millis(100));
        opts.ppp.echo_max_failures = 3;
        let mut policy = ReconnectPolicy::default();
        policy.initial_delay = Duration::from_millis(50);
        policy.jitter = 0.0;
        policy.max_attempts = NonZeroU32::new(3);
        let mut env = setup(true, opts, policy).await;

        // 1re session : DeadPeer ; les écoutes restent ouvertes pendant la coupure.
        let first = until_up(&mut env.events, 1).await;
        assert!(
            first
                .iter()
                .any(|s| matches!(s, SessionState::TunnelUp { .. }))
        );
        // 2e TunnelUp = après reconnexion.
        let seen = until_up(&mut env.events, 1).await;
        assert!(
            seen.iter()
                .any(|s| matches!(s, SessionState::Reconnecting { .. })),
            "{seen:?}"
        );
        // Les écoutes acceptent toujours ; nouvelles connexions OK après TunnelUp.
        exercise_all(&env).await;

        env.handle.shutdown();
        let reason = timeout(T, env.run).await.unwrap().unwrap();
        assert!(matches!(reason, DisconnectReason::Requested), "{reason:?}");
        assert_eq!(env.gw.log().for_path("/remote/sslvpn-tunnel").len(), 2);
        env.gw.shutdown().await;
    })
    .await
    .unwrap();
}
