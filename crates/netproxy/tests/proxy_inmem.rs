//! Test d'intégration en mémoire du mode proxy : `ProxyBackend` relié par son
//! `PacketChannel` à un pair smoltcp « passerelle » simulé (écho TCP sur
//! 10.10.0.5:7, DNS sur 10.10.0.53:53), clients réels sur 127.0.0.1.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use fortivpn_core::{
    DnsConfig, Ipv4Config, NetBackend, PacketChannel, RoutingMode, TunOptions, TunnelConfig,
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
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 100);
const T: Duration = Duration::from_secs(10);

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
        c.max_transmission_unit = 1400;
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
async fn gateway_peer(channel: PacketChannel) {
    let (tx, mut rx) = channel.split();
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
            if tx.send(p).await.is_err() {
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

// --- Clients ----------------------------------------------------------------------

fn tunnel_config() -> TunnelConfig {
    TunnelConfig {
        ipv4: Ipv4Config {
            address: ipnet::Ipv4Net::new(LOCAL, 32).unwrap(),
            peer: Some(Ipv4Addr::new(169, 254, 2, 1)),
        },
        ipv6: None,
        mtu: 1400,
        dns: DnsConfig {
            servers: vec![IpAddr::V4(DNS)],
            search_domains: vec!["corp".into()],
        },
        routing: RoutingMode::Split {
            include: vec!["10.10.0.0/24".parse().unwrap()],
        },
        gateway: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
    }
}

/// Négociation SOCKS5 ; retourne le code de réponse et le flux.
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
    if reply[1] == 0 {
        assert_eq!(&reply[3..8], &[1, 10, 10, 0, 100], "adresse liée");
    }
    (reply[1], s)
}

fn ipv4_req(cmd: u8, ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut r = vec![cmd, 1];
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

/// Envoie `data` et vérifie l'écho intégral, puis la fin de flux après FIN.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks_and_forward_through_inmemory_tunnel() {
    timeout(Duration::from_secs(60), scenario()).await.unwrap();
}

async fn scenario() {
    let config = ProxyConfig::new(
        Some("127.0.0.1:0".parse().unwrap()),
        vec![Forward {
            listen: "127.0.0.1:0".parse().unwrap(),
            target: Target {
                host: Host::Domain("echo.corp".into()),
                port: 7,
            },
        }],
    );
    let backend = ProxyBackend::new(config).unwrap();
    let proxy = backend.socks_addr().unwrap();
    let forward = backend.forwards()[0].0;
    assert!(proxy.ip().is_loopback() && proxy.port() != 0);

    // Avant le tunnel : écoutes non servies (pas de runtime) → rien n'est accepté
    // tant que create_tun n'a pas eu lieu ; on ne teste qu'après.
    let tun = backend.create_tun(&TunOptions::new("proxy")).await.unwrap();
    assert_eq!(tun.info.index, None);
    let peer = tokio::spawn(gateway_peer(tun.packets));
    let mut guard = backend.apply(&tun.info, &tunnel_config()).await.unwrap();

    // 1. SOCKS5 CONNECT IPv4 : petit écho puis gros volume (contrôle de flux).
    let (code, s) = timeout(T, socks_connect(proxy, &ipv4_req(1, ECHO, 7)))
        .await
        .unwrap();
    assert_eq!(code, 0);
    timeout(T, check_echo(s, b"bonjour le tunnel".to_vec()))
        .await
        .unwrap();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let (code, s) = timeout(T, socks_connect(proxy, &ipv4_req(1, ECHO, 7)))
        .await
        .unwrap();
    assert_eq!(code, 0);
    timeout(T, check_echo(s, big)).await.unwrap();

    // 2. SOCKS5 CONNECT par nom (DNS du tunnel).
    let (code, s) = timeout(T, socks_connect(proxy, &domain_req("echo.corp", 7)))
        .await
        .unwrap();
    assert_eq!(code, 0);
    timeout(T, check_echo(s, b"par nom".to_vec()))
        .await
        .unwrap();

    // 3. Redirection de port 127.0.0.1:X → echo.corp:7.
    let s = TcpStream::connect(forward).await.unwrap();
    timeout(T, check_echo(s, b"redirection".to_vec()))
        .await
        .unwrap();

    // 4. Refus : nom inconnu, port fermé (RST), BIND, UDP ASSOCIATE.
    let (code, _) = timeout(T, socks_connect(proxy, &domain_req("nope.corp", 7)))
        .await
        .unwrap();
    assert_eq!(code, 4, "hôte injoignable");
    let (code, _) = timeout(T, socks_connect(proxy, &ipv4_req(1, ECHO, 9)))
        .await
        .unwrap();
    assert_eq!(code, 5, "connexion refusée");
    for cmd in [2, 3] {
        let (code, _) = timeout(T, socks_connect(proxy, &ipv4_req(cmd, ECHO, 7)))
            .await
            .unwrap();
        assert_eq!(code, 7, "commande {cmd} non prise en charge");
    }

    // 5. Après le teardown : tunnel coupé → réseau injoignable, écoute conservée.
    guard.teardown().await.unwrap();
    let (code, _) = timeout(T, socks_connect(proxy, &ipv4_req(1, ECHO, 7)))
        .await
        .unwrap();
    assert_eq!(code, 3, "réseau injoignable");
    drop(backend);
    peer.abort();
}

#[test]
fn non_loopback_and_busy_port_refused() {
    let c = ProxyConfig::new(Some("0.0.0.0:0".parse().unwrap()), vec![]);
    assert!(matches!(
        ProxyBackend::new(c),
        Err(netproxy::ProxyError::Config(
            netproxy::ProxyConfigError::NonLoopback(_)
        ))
    ));
    let first = ProxyBackend::new(ProxyConfig::new(
        Some("127.0.0.1:0".parse().unwrap()),
        vec![],
    ))
    .unwrap();
    let taken = first.socks_addr().unwrap();
    assert!(matches!(
        ProxyBackend::new(ProxyConfig::new(Some(taken), vec![])),
        Err(netproxy::ProxyError::Bind { .. })
    ));
}
