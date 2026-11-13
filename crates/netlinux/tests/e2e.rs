//! Tests e2e réels de `LinuxNetBackend` : TUN, adresses, routes, DNS.
//!
//! Chaque test s'exécute sur un thread placé dans un **netns jetable**
//! (`unshare(CLONE_NEWNET)`) : l'hôte (WSL) n'est jamais modifié, et le netns
//! disparaît avec le thread. Un « underlay » y est simulé par une paire veth
//! (`ul0` 192.0.2.10/24, route par défaut via 192.0.2.1).
//!
//! Nécessitent `CAP_SYS_ADMIN` (pour `unshare`) et `CAP_NET_ADMIN` ; ignorés
//! par défaut. Sans privilèges, dans un userns + netns jetables (recommandé,
//! aucune élévation) :
//!
//! ```text
//! cargo test -p netlinux --test e2e --no-run
//! unshare -rn target/debug/deps/e2e-<hash> --ignored
//! ```
//!
//! Ou, avec l'accord de l'utilisateur uniquement : `sudo -E cargo test -p netlinux -- --ignored`.
#![cfg(target_os = "linux")]

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use fortivpn_core::{
    DnsConfig, Ipv4Config, NetBackend, PacketChannel, RoutingMode, TunOptions, TunnelConfig,
};
use futures_util::TryStreamExt;
use ipnet::{Ipv4Net, Ipv6Net};
use netlinux::{DnsStrategy, LinuxNetBackend};
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteType};
use rtnetlink::{Handle, LinkUnspec, LinkVeth, RouteMessageBuilder};

const UNDERLAY_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const UNDERLAY_GW: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const VPN_GATEWAY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 212, 134, 200);
const PEER: Ipv4Addr = Ipv4Addr::new(169, 254, 2, 1);
const TIMEOUT: Duration = Duration::from_secs(3);
/// Passerelle IPv6 de l'underlay (lien local) : route par défaut `::/0`.
const UNDERLAY_GW6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
/// Destination IPv6 globale sondée pour la fuite (E2).
const PROBE6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);

/// Exécute `f` dans un netns neuf, sur un thread dédié avec son runtime.
fn in_netns<F, Fut>(f: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let res = std::thread::spawn(move || {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).expect(
            "unshare(CLONE_NEWNET) : lancer avec `sudo -E cargo test -p netlinux -- --ignored`",
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(f());
    })
    .join();
    if let Err(panic) = res {
        std::panic::resume_unwind(panic);
    }
}

fn handle() -> Handle {
    let (conn, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(conn);
    handle
}

async fn link_index(h: &Handle, name: &str) -> Option<u32> {
    h.link()
        .get()
        .match_name(name)
        .execute()
        .try_next()
        .await
        .ok()
        .flatten()
        .map(|l| l.header.index)
}

async fn set_up(h: &Handle, index: u32) {
    h.link()
        .set(LinkUnspec::new_with_index(index).up().build())
        .execute()
        .await
        .unwrap();
}

/// `lo` up + veth `ul0`/`ul1` + 192.0.2.10/24 + route par défaut via 192.0.2.1.
/// Retourne l'index de `ul0`.
async fn setup_underlay(h: &Handle) -> u32 {
    let lo = link_index(h, "lo").await.unwrap();
    set_up(h, lo).await;
    h.link()
        .add(LinkVeth::new("ul0", "ul1").build())
        .execute()
        .await
        .unwrap();
    let ul0 = link_index(h, "ul0").await.unwrap();
    let ul1 = link_index(h, "ul1").await.unwrap();
    set_up(h, ul0).await;
    set_up(h, ul1).await;
    h.address()
        .add(ul0, UNDERLAY_ADDR.into(), 24)
        .execute()
        .await
        .unwrap();
    h.route()
        .add(
            RouteMessageBuilder::<Ipv4Addr>::new()
                .gateway(UNDERLAY_GW)
                .output_interface(ul0)
                .build(),
        )
        .execute()
        .await
        .unwrap();
    // IPv6 de l'hôte : route par défaut via un routeur en lien local.
    h.route()
        .add(
            RouteMessageBuilder::<Ipv6Addr>::new()
                .gateway(UNDERLAY_GW6)
                .output_interface(ul0)
                .build(),
        )
        .execute()
        .await
        .unwrap();
    ul0
}

/// Routes IPv6 de la table `main` : (destination, type), hors `fe80::/64`
/// (ajoutées par le noyau à la montée de chaque interface, dont la TUN).
async fn main_routes6(h: &Handle) -> Vec<(Ipv6Net, RouteType)> {
    let msgs: Vec<RouteMessage> = h
        .route()
        .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
        .execute()
        .try_collect()
        .await
        .unwrap();
    msgs.into_iter()
        .filter(|m| m.header.table == 254)
        .map(|m| {
            let dest = m
                .attributes
                .iter()
                .find_map(|a| match a {
                    RouteAttribute::Destination(RouteAddress::Inet6(d)) => Some(*d),
                    _ => None,
                })
                .unwrap_or(Ipv6Addr::UNSPECIFIED);
            (
                Ipv6Net::new(dest, m.header.destination_prefix_length).unwrap(),
                m.header.kind,
            )
        })
        .filter(|(dest, _)| dest.network().segments()[0] & 0xffc0 != 0xfe80)
        .collect()
}

/// Route effective vers `dst` (`RTM_GETROUTE`, interface imposée si `oif`) :
/// (type, interface) ; `None` si le noyau refuse (pas de route).
async fn resolve6(h: &Handle, dst: Ipv6Addr, oif: Option<u32>) -> Option<(RouteType, Option<u32>)> {
    let mut builder = RouteMessageBuilder::<Ipv6Addr>::new().destination_prefix(dst, 128);
    if let Some(index) = oif {
        builder = builder.output_interface(index);
    }
    let reply = h
        .route()
        .get(builder.build())
        .execute()
        .try_next()
        .await
        .ok()??;
    let out = reply.attributes.iter().find_map(|a| match a {
        RouteAttribute::Oif(i) => Some(*i),
        _ => None,
    });
    Some((reply.header.kind, out))
}

fn blackholes6() -> [(Ipv6Net, RouteType); 2] {
    [
        ("::/1".parse().unwrap(), RouteType::BlackHole),
        ("8000::/1".parse().unwrap(), RouteType::BlackHole),
    ]
}

/// Route de la table `main` : (destination, interface, passerelle).
type MainRoute = (Ipv4Net, Option<u32>, Option<Ipv4Addr>);

async fn main_routes(h: &Handle) -> Vec<MainRoute> {
    let msgs: Vec<_> = h
        .route()
        .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute()
        .try_collect()
        .await
        .unwrap();
    msgs.into_iter()
        .filter(|m| m.header.table == 254)
        .map(|m| {
            let mut dest = Ipv4Addr::UNSPECIFIED;
            let mut oif = None;
            let mut gw = None;
            for a in &m.attributes {
                match a {
                    RouteAttribute::Destination(RouteAddress::Inet(d)) => dest = *d,
                    RouteAttribute::Oif(i) => oif = Some(*i),
                    RouteAttribute::Gateway(RouteAddress::Inet(g)) => gw = Some(*g),
                    _ => {}
                }
            }
            (
                Ipv4Net::new(dest, m.header.destination_prefix_length).unwrap(),
                oif,
                gw,
            )
        })
        .collect()
}

async fn addresses(h: &Handle, index: u32) -> Vec<IpAddr> {
    let msgs: Vec<_> = h
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .try_collect()
        .await
        .unwrap();
    msgs.iter()
        .flat_map(|m| m.attributes.iter())
        .filter_map(|a| match a {
            AddressAttribute::Local(ip) => Some(*ip),
            _ => None,
        })
        .collect()
}

async fn mtu(h: &Handle, index: u32) -> Option<u32> {
    let link = h
        .link()
        .get()
        .match_index(index)
        .execute()
        .try_next()
        .await
        .unwrap()?;
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Mtu(m) => Some(*m),
        _ => None,
    })
}

fn net(s: &str) -> Ipv4Net {
    s.parse().unwrap()
}

fn config(routing: RoutingMode) -> TunnelConfig {
    TunnelConfig {
        ipv4: Ipv4Config {
            address: Ipv4Net::from(LOCAL),
            peer: Some(PEER),
        },
        ipv6: None,
        mtu: 1354,
        dns: DnsConfig {
            servers: vec!["10.0.0.53".parse().unwrap()],
            search_domains: vec!["corp.example".into()],
        },
        routing,
        gateway: IpAddr::V4(VPN_GATEWAY),
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("netlinux-e2e-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Le backend refuse un dossier resolv inscriptible par le groupe/les autres.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// En-tête IPv4 + UDP minimal (somme de contrôle UDP à 0, autorisée en IPv4).
fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Bytes {
    let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (src, dst) else {
        panic!("IPv4 uniquement");
    };
    let total = u16::try_from(20 + 8 + payload.len()).unwrap();
    let mut p = Vec::with_capacity(usize::from(total));
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    p.extend_from_slice(&src.ip().octets());
    p.extend_from_slice(&dst.ip().octets());
    let mut sum: u32 = p
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !u16::try_from(sum).unwrap();
    p[10..12].copy_from_slice(&csum.to_be_bytes());
    p.extend_from_slice(&src.port().to_be_bytes());
    p.extend_from_slice(&dst.port().to_be_bytes());
    p.extend_from_slice(&(8 + u16::try_from(payload.len()).unwrap()).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    Bytes::from(p)
}

/// Prochain paquet IPv4 de la TUN (ignore l'IPv6 éventuel du noyau).
async fn next_ipv4(chan: &mut PacketChannel) -> Bytes {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let p = chan.recv().await.expect("canal TUN fermé");
            if p.first().map(|b| b >> 4) == Some(4) {
                return p;
            }
        }
    })
    .await
    .expect("aucun paquet IPv4 sur la TUN")
}

// sudo -E cargo test -p netlinux -- --ignored
#[test]
#[ignore = "root + netns : sudo -E cargo test -p netlinux -- --ignored"]
fn e2e_split_tunnel_apply_and_teardown() {
    in_netns(|| async {
        let h = handle();
        let ul0 = setup_underlay(&h).await;
        let dir = temp_dir("split");
        let resolv = dir.join("resolv.conf");
        let backend = LinuxNetBackend::new().with_dns(DnsStrategy::ResolvFile(resolv.clone()));

        let tun = backend
            .create_tun(&TunOptions::new("fvpn-e2e"))
            .await
            .unwrap();
        let idx = tun.info.index.unwrap();
        assert_eq!(link_index(&h, "fvpn-e2e").await, Some(idx));

        let routing = RoutingMode::Split {
            include: vec!["10.0.0.0/8".parse().unwrap()],
        };
        let mut cfg = config(routing);
        // M2 : chaque DNS a sa /32 via le tunnel, couvert ou non par 10.0.0.0/8.
        cfg.dns.servers.push("172.16.0.53".parse().unwrap());
        let before6 = main_routes6(&h).await;
        let mut guard = backend.apply(&tun.info, &cfg).await.unwrap();

        assert_eq!(mtu(&h, idx).await, Some(1354));
        assert_eq!(addresses(&h, idx).await, vec![IpAddr::V4(LOCAL)]);
        let routes = main_routes(&h).await;
        assert!(
            routes.contains(&(Ipv4Net::from(VPN_GATEWAY), Some(ul0), Some(UNDERLAY_GW))),
            "{routes:?}"
        );
        assert!(
            routes.contains(&(net("10.0.0.0/8"), Some(idx), None)),
            "{routes:?}"
        );
        for dns in ["172.16.0.53/32", "10.0.0.53/32"] {
            assert!(
                routes.contains(&(net(dns), Some(idx), None)),
                "{dns} via le tunnel attendue : {routes:?}"
            );
        }
        // Split : pas de blackhole IPv6.
        assert_eq!(main_routes6(&h).await, before6);
        let content = std::fs::read_to_string(&resolv).unwrap();
        assert!(content.contains("nameserver 10.0.0.53\n"));
        assert!(content.contains("search corp.example\n"));

        guard.teardown().await.unwrap();
        assert!(!guard.is_active());
        let routes = main_routes(&h).await;
        assert!(
            !routes.iter().any(|r| r.0 == Ipv4Net::from(VPN_GATEWAY)),
            "{routes:?}"
        );
        assert!(
            !routes
                .iter()
                .any(|r| r.0 == net("10.0.0.0/8") || r.0 == net("172.16.0.53/32")),
            "{routes:?}"
        );
        assert!(addresses(&h, idx).await.is_empty());
        assert!(!resolv.exists());
        // La route par défaut d'origine est intacte.
        assert!(routes.contains(&(net("0.0.0.0/0"), Some(ul0), Some(UNDERLAY_GW))));
        drop(tun);
        std::fs::remove_dir_all(dir).unwrap();
    });
}

// sudo -E cargo test -p netlinux -- --ignored
#[test]
#[ignore = "root + netns : sudo -E cargo test -p netlinux -- --ignored"]
fn e2e_full_tunnel_and_blocking_drop() {
    in_netns(|| async {
        let h = handle();
        let ul0 = setup_underlay(&h).await;
        let backend = LinuxNetBackend::new();
        let tun = backend
            .create_tun(&TunOptions::new("fvpn-e2e"))
            .await
            .unwrap();
        let idx = tun.info.index.unwrap();
        let excluded = net("203.0.113.0/24");
        let lan = net("192.0.2.0/24");
        let routing = RoutingMode::Full {
            exclude: vec![excluded.into(), lan.into()],
        };
        let mut cfg = config(routing);
        // M2 : un DNS dans une exclusion doit quand même passer par le tunnel.
        let dns_in_exclusion = net("203.0.113.53/32");
        cfg.dns.servers.push(IpAddr::V4(dns_in_exclusion.addr()));
        // E2 : avant, l'IPv6 global sort par l'underlay.
        assert_eq!(
            resolve6(&h, PROBE6, None).await,
            Some((RouteType::Unicast, Some(ul0)))
        );
        let guard = backend.apply(&tun.info, &cfg).await.unwrap();

        let routes6 = main_routes6(&h).await;
        for bh in blackholes6() {
            assert!(routes6.contains(&bh), "{bh:?} absent de {routes6:?}");
        }
        let probe = resolve6(&h, PROBE6, None).await;
        assert!(
            matches!(probe, None | Some((RouteType::BlackHole, _))),
            "l'IPv6 global doit être bloqué (blackhole) : {probe:?}"
        );
        // Le lien local (routeur IPv6 de l'underlay) reste joignable.
        assert_eq!(
            resolve6(&h, UNDERLAY_GW6, Some(ul0)).await,
            Some((RouteType::Unicast, Some(ul0)))
        );

        let routes = main_routes(&h).await;
        for expected in [
            (Ipv4Net::from(VPN_GATEWAY), Some(ul0), Some(UNDERLAY_GW)),
            (excluded, Some(ul0), Some(UNDERLAY_GW)),
            (dns_in_exclusion, Some(idx), None),
            (net("10.0.0.53/32"), Some(idx), None),
            (net("0.0.0.0/1"), Some(idx), None),
            (net("128.0.0.0/1"), Some(idx), None),
            (net("0.0.0.0/0"), Some(ul0), Some(UNDERLAY_GW)),
        ] {
            assert!(
                routes.contains(&expected),
                "{expected:?} absent de {routes:?}"
            );
        }
        // Le LAN directement connecté existait déjà (EEXIST) : présent une seule fois.
        assert_eq!(
            routes.iter().filter(|r| r.0 == lan).count(),
            1,
            "{routes:?}"
        );

        // Chemin Drop (bloquant) depuis l'intérieur du runtime.
        drop(guard);
        let routes = main_routes(&h).await;
        for gone in [
            Ipv4Net::from(VPN_GATEWAY),
            excluded,
            dns_in_exclusion,
            net("10.0.0.53/32"),
            net("0.0.0.0/1"),
            net("128.0.0.0/1"),
        ] {
            assert!(
                !routes.iter().any(|r| r.0 == gone),
                "{gone} toujours là : {routes:?}"
            );
        }
        let routes6 = main_routes6(&h).await;
        assert!(
            !routes6.iter().any(|r| r.1 == RouteType::BlackHole),
            "blackhole IPv6 toujours là : {routes6:?}"
        );
        assert_eq!(
            resolve6(&h, PROBE6, None).await,
            Some((RouteType::Unicast, Some(ul0)))
        );
        assert!(
            routes.iter().any(|r| r.0 == lan),
            "la route du LAN (non installée par nous) doit rester"
        );
        assert!(addresses(&h, idx).await.is_empty());
        drop(tun);
    });
}

// sudo -E cargo test -p netlinux -- --ignored
#[test]
#[ignore = "root + netns : sudo -E cargo test -p netlinux -- --ignored"]
fn e2e_tun_packet_round_trip() {
    in_netns(|| async {
        let h = handle();
        setup_underlay(&h).await;
        let backend = LinuxNetBackend::new();
        let mut tun = backend
            .create_tun(&TunOptions::new("fvpn-e2e"))
            .await
            .unwrap();
        let routing = RoutingMode::Split {
            include: vec!["10.0.0.0/8".parse().unwrap()],
        };
        let mut guard = backend.apply(&tun.info, &config(routing)).await.unwrap();

        // OS -> tunnel.
        let remote: SocketAddr = "10.1.2.3:9999".parse().unwrap();
        let out = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        out.send_to(b"ping-out", remote).await.unwrap();
        let p = next_ipv4(&mut tun.packets).await;
        assert_eq!(p[9], 17, "UDP");
        assert_eq!(&p[12..16], &LOCAL.octets(), "source = adresse du tunnel");
        assert_eq!(&p[16..20], &[10, 1, 2, 3]);
        assert!(p.ends_with(b"ping-out"));

        // Tunnel -> OS.
        let local: SocketAddr = SocketAddr::new(IpAddr::V4(LOCAL), 5555);
        let sock = tokio::net::UdpSocket::bind(local).await.unwrap();
        tun.packets
            .send(udp_packet(remote, local, b"pong-in"))
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(TIMEOUT, sock.recv_from(&mut buf))
            .await
            .expect("paquet injecté non reçu")
            .unwrap();
        assert_eq!(&buf[..n], b"pong-in");
        assert_eq!(from, remote);

        guard.teardown().await.unwrap();
    });
}

// sudo -E cargo test -p netlinux -- --ignored
#[test]
#[ignore = "root + netns : sudo -E cargo test -p netlinux -- --ignored"]
fn e2e_tun_removed_when_channel_dropped() {
    in_netns(|| async {
        let h = handle();
        let backend = LinuxNetBackend::new();
        let tun = backend
            .create_tun(&TunOptions::new("fvpn-e2e"))
            .await
            .unwrap();
        assert!(link_index(&h, "fvpn-e2e").await.is_some());
        drop(tun);
        tokio::time::timeout(TIMEOUT, async {
            while link_index(&h, "fvpn-e2e").await.is_some() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("l'interface TUN doit disparaître quand le canal est libéré");
    });
}

// sudo -E cargo test -p netlinux -- --ignored
#[test]
#[ignore = "root + netns : sudo -E cargo test -p netlinux -- --ignored"]
fn e2e_failed_apply_leaves_no_state() {
    in_netns(|| async {
        let h = handle();
        setup_underlay(&h).await;
        let before = main_routes(&h).await;
        let before6 = main_routes6(&h).await;
        // Le fichier resolv est la dernière étape : son échec force le rollback
        // de l'adresse et des routes déjà installées.
        let missing = temp_dir("fail").join("absent").join("resolv.conf");
        let backend = LinuxNetBackend::new().with_dns(DnsStrategy::ResolvFile(missing));
        let tun = backend
            .create_tun(&TunOptions::new("fvpn-e2e"))
            .await
            .unwrap();
        let idx = tun.info.index.unwrap();
        let routing = RoutingMode::Full { exclude: vec![] };
        assert!(backend.apply(&tun.info, &config(routing)).await.is_err());
        assert!(addresses(&h, idx).await.is_empty());
        assert_eq!(main_routes(&h).await, before);
        assert_eq!(
            main_routes6(&h).await,
            before6,
            "blackholes retirés au rollback"
        );
        drop(tun);
    });
}

/// F1 de bout en bout : un fichier resolv lien symbolique (ou un dossier
/// inscriptible par tous) fait échouer `apply` avec rollback complet (routes
/// IPv4, blackholes IPv6, adresse) et la cible du lien reste intacte.
// unshare -rn target/debug/deps/e2e-<hash> --ignored
#[test]
#[ignore = "root + netns : sudo -E cargo test -p netlinux -- --ignored"]
fn e2e_unsafe_resolv_path_is_refused_and_rolled_back() {
    in_netns(|| async {
        let h = handle();
        setup_underlay(&h).await;
        let dir = temp_dir("unsafe");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"victim\n").unwrap();
        let link = dir.join("resolv.conf");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let open = temp_dir("unsafe-open").join("world");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();

        for path in [link.clone(), open.join("resolv.conf")] {
            let before = main_routes(&h).await;
            let before6 = main_routes6(&h).await;
            let backend = LinuxNetBackend::new().with_dns(DnsStrategy::ResolvFile(path.clone()));
            let tun = backend
                .create_tun(&TunOptions::new("fvpn-e2e"))
                .await
                .unwrap();
            let idx = tun.info.index.unwrap();
            let routing = RoutingMode::Full { exclude: vec![] };
            let r = backend.apply(&tun.info, &config(routing)).await;
            assert!(r.is_err(), "{}", path.display());
            assert!(addresses(&h, idx).await.is_empty());
            assert_eq!(main_routes(&h).await, before);
            assert_eq!(main_routes6(&h).await, before6);
            drop(tun);
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim\n");
        assert!(!open.join("resolv.conf").exists());
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(open.parent().unwrap()).unwrap();
    });
}

// sudo -E cargo test -p netlinux -- --ignored
#[test]
#[ignore = "root + netns : sudo -E cargo test -p netlinux -- --ignored"]
fn e2e_unreachable_gateway_is_refused() {
    in_netns(|| async {
        // Pas d'underlay : aucune route vers la passerelle.
        let backend = LinuxNetBackend::new();
        let tun = backend
            .create_tun(&TunOptions::new("fvpn-e2e"))
            .await
            .unwrap();
        let routing = RoutingMode::Split { include: vec![] };
        assert!(backend.apply(&tun.info, &config(routing)).await.is_err());
        drop(tun);
    });
}
