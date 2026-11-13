//! Calcul pur (sans I/O) du plan d'opérations à appliquer pour une
//! [`TunnelConfig`], à partir des routes d'origine déjà résolues.
//!
//! Ordre du plan (l'annulation se fait dans l'ordre inverse) :
//!
//! 1. lien TUN : MTU + `up` (non annulé : appartient au cycle de vie de la TUN) ;
//! 2. adresse IPv4 locale (+ pair point-à-point éventuel) ;
//! 3. route `/32` vers la passerelle via la route d'origine (underlay) ;
//! 4. split : réseaux inclus via la TUN ;
//!    full : exclusions via leur route d'origine, **puis** `0.0.0.0/1` et
//!    `128.0.0.0/1` via la TUN (les exclusions sont en place avant que le
//!    trafic ne bascule dans le tunnel) ;
//! 5. `/32` via la TUN pour chaque serveur DNS IPv4 du tunnel (sauf DNS ==
//!    passerelle) — revue 5.3, M2, voir [`dns_host_routes`] ;
//! 6. full : routes `blackhole` IPv6 `::/1` + `8000::/1` (le tunnel est IPv4
//!    seulement : sans elles, l'IPv6 de l'hôte sortirait en clair) — revue
//!    5.3, E2 ;
//! 7. DNS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use fortivpn_core::{NetError, RoutingMode, TunnelConfig};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::dns::DnsUndo;

/// Route d'origine (underlay) vers une adresse, telle que résolue par le noyau
/// (`RTM_GETROUTE`) **avant** toute modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OriginRoute {
    /// Passerelle (`via`), absente si la destination est sur un lien direct.
    pub(crate) gateway: Option<Ipv4Addr>,
    /// Interface de sortie.
    pub(crate) oif: u32,
    /// Vrai si la destination est une adresse locale de l'hôte.
    pub(crate) local: bool,
}

/// Route IPv4 à installer (table `main`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RouteSpec {
    /// Destination (bits d'hôte à zéro).
    pub(crate) dest: Ipv4Net,
    /// Interface de sortie.
    pub(crate) oif: u32,
    /// Passerelle ; `None` : route directe (`scope link`).
    pub(crate) gateway: Option<Ipv4Addr>,
}

/// Adresse IPv4 à poser sur la TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddrSpec {
    /// Index de l'interface.
    pub(crate) index: u32,
    /// Adresse locale et préfixe.
    pub(crate) address: Ipv4Net,
    /// Pair point-à-point (`IFA_ADDRESS`), si connu.
    pub(crate) peer: Option<Ipv4Addr>,
}

/// Fichier resolv à écrire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsWrite {
    /// Chemin absolu du fichier.
    pub(crate) path: PathBuf,
    /// Contenu complet.
    pub(crate) content: String,
}

/// Opération élémentaire du plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Op {
    /// MTU + lien `up`.
    Link {
        /// Index de l'interface.
        index: u32,
        /// MTU.
        mtu: u16,
    },
    /// Pose d'une adresse.
    Address(AddrSpec),
    /// Ajout d'une route.
    Route(RouteSpec),
    /// Ajout d'une route IPv6 `blackhole` (table `main`). Ignorée avec un
    /// avertissement si l'hôte n'a pas IPv6.
    Blackhole6(Ipv6Net),
    /// Écriture du fichier resolv.
    Dns(DnsWrite),
}

/// Annulation d'une opération effectivement réalisée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Undo {
    /// Retrait de l'adresse.
    Address(AddrSpec),
    /// Retrait de la route.
    Route(RouteSpec),
    /// Retrait de la route IPv6 `blackhole`.
    Blackhole6(Ipv6Net),
    /// Restauration du fichier resolv par son descripteur (contenu antérieur,
    /// ou suppression s'il n'existait pas).
    Dns(DnsUndo),
}

/// Résultat des résolutions de routes d'origine nécessaires au plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lookups {
    /// Route d'origine vers la passerelle.
    pub(crate) gateway: OriginRoute,
    /// Route d'origine de chaque exclusion (full-tunnel) ; `None` : aucune.
    pub(crate) exclusions: Vec<(Ipv4Net, Option<OriginRoute>)>,
}

/// Moitiés de l'espace IPv4 utilisées en full-tunnel (plus spécifiques que la
/// route par défaut d'origine, qu'elles n'ont donc pas besoin de modifier).
pub(crate) const FULL_TUNNEL_HALVES: [Ipv4Net; 2] = [
    Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 1),
    Ipv4Net::new_assert(Ipv4Addr::new(128, 0, 0, 0), 1),
];

/// Routes IPv6 `blackhole` du full-tunnel : couvrent tout l'espace IPv6 global
/// et sont plus spécifiques que toute route par défaut (`::/0`) ; les routes
/// plus spécifiques de l'hôte (lien local `fe80::/64`, préfixes on-link)
/// restent prioritaires, la table `local` aussi.
pub(crate) const FULL_TUNNEL_V6_BLACKHOLES: [Ipv6Net; 2] = [
    Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 1),
    Ipv6Net::new_assert(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1),
];

/// Réseaux IPv4 (normalisés) listés par la politique de routage.
pub(crate) fn v4_networks(routing: &RoutingMode) -> Vec<Ipv4Net> {
    routing
        .networks()
        .iter()
        .filter_map(|n| match n {
            IpNet::V4(v4) => Some(v4.trunc()),
            IpNet::V6(_) => None,
        })
        .collect()
}

fn through_tunnel_error(what: &str) -> NetError {
    NetError::Os {
        op: "plan_routes",
        reason: format!("la route d'origine de {what} passe déjà par l'interface du tunnel"),
    }
}

/// Serveurs DNS IPv4 du tunnel qui reçoivent une `/32` via la TUN (revue
/// 5.3, M2), sinon leurs requêtes (noms internes) pourraient partir en clair
/// sur l'underlay : serveur hors inclusions (split), dans une exclusion
/// (full), **ou** dans un réseau on-link plus spécifique de l'underlay (un LAN
/// `10.1.0.0/16` l'emporte sur une inclusion `10.0.0.0/8` comme sur les
/// moitiés `/1`). La `/32` est donc ajoutée **toujours**, comme dans netwin.
///
/// Exceptions (avertissement, pas de route) : serveur égal à la passerelle VPN
/// (la `/32` d'underlay de la passerelle doit primer) ; adresse non routable
/// (non spécifiée, boucle locale, multicast, diffusion, lien local) ou égale
/// à l'adresse locale du tunnel. Les serveurs IPv6 sont ignorés (bloqués par
/// les `blackhole` en full). Dédupliqués, dans l'ordre de la configuration.
pub(crate) fn dns_host_routes(config: &TunnelConfig, gateway: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for server in &config.dns.servers {
        let IpAddr::V4(s) = *server else {
            continue;
        };
        if out.contains(&s) {
            continue;
        }
        if s == gateway {
            tracing::warn!(
                server = %s,
                "serveur DNS = passerelle VPN : requêtes DNS hors tunnel (non chiffrées par le VPN)"
            );
            continue;
        }
        if s.is_unspecified()
            || s.is_loopback()
            || s.is_multicast()
            || s.is_broadcast()
            || s.is_link_local()
            || s == config.ipv4.address.addr()
        {
            tracing::warn!(server = %s, "serveur DNS non routable : pas de route dédiée");
            continue;
        }
        out.push(s);
    }
    out
}

/// Construit le plan. `config` doit avoir été validée (IPv4 uniquement).
pub(crate) fn build(
    tun_index: u32,
    config: &TunnelConfig,
    gateway: Ipv4Addr,
    lookups: &Lookups,
    dns: Option<DnsWrite>,
) -> Result<Vec<Op>, NetError> {
    let mut ops = vec![
        Op::Link {
            index: tun_index,
            mtu: config.mtu,
        },
        Op::Address(AddrSpec {
            index: tun_index,
            address: config.ipv4.address,
            peer: config.ipv4.peer,
        }),
    ];

    let gw = lookups.gateway;
    if gw.local {
        // La passerelle est une adresse de cet hôte (ex. mock-gw sur 127.0.0.1) :
        // la table `local` est prioritaire sur toutes nos routes, pas de boucle
        // possible, rien à préserver.
        tracing::debug!(%gateway, "passerelle locale : pas de route de préservation");
    } else if gw.oif == tun_index {
        return Err(through_tunnel_error("la passerelle"));
    } else {
        ops.push(Op::Route(RouteSpec {
            dest: Ipv4Net::from(gateway),
            oif: gw.oif,
            gateway: gw.gateway,
        }));
    }

    let dns_routes: Vec<RouteSpec> = dns_host_routes(config, gateway)
        .into_iter()
        .map(|s| RouteSpec {
            dest: Ipv4Net::from(s),
            oif: tun_index,
            gateway: None,
        })
        .collect();

    match &config.routing {
        RoutingMode::Split { .. } => {
            let includes = v4_networks(&config.routing);
            ops.extend(includes.iter().map(|&dest| {
                Op::Route(RouteSpec {
                    dest,
                    oif: tun_index,
                    gateway: None,
                })
            }));
            ops.extend(
                dns_routes
                    .into_iter()
                    .filter(|r| !includes.contains(&r.dest))
                    .map(Op::Route),
            );
        }
        RoutingMode::Full { exclude } => {
            if exclude.iter().any(|n| matches!(n, IpNet::V6(_))) {
                tracing::warn!(
                    "exclusions IPv6 ignorées : tout l'IPv6 est bloqué (blackhole) en full-tunnel"
                );
            }
            for &(dest, origin) in &lookups.exclusions {
                if dns_routes.iter().any(|r| r.dest == dest.trunc()) {
                    tracing::warn!(
                        %dest,
                        "exclusion du serveur DNS ignorée : DNS via le tunnel"
                    );
                    continue;
                }
                match origin {
                    None => {
                        tracing::warn!(%dest, "exclusion sans route d'origine : ignorée");
                    }
                    Some(o) if o.local => {
                        tracing::debug!(%dest, "exclusion locale : déjà hors tunnel");
                    }
                    Some(o) if o.oif == tun_index => {
                        return Err(through_tunnel_error(&format!("l'exclusion {dest}")));
                    }
                    Some(o) => ops.push(Op::Route(RouteSpec {
                        dest: dest.trunc(),
                        oif: o.oif,
                        gateway: o.gateway,
                    })),
                }
            }
            ops.extend(dns_routes.into_iter().map(Op::Route));
            ops.extend(FULL_TUNNEL_HALVES.iter().map(|&dest| {
                Op::Route(RouteSpec {
                    dest,
                    oif: tun_index,
                    gateway: None,
                })
            }));
            ops.extend(FULL_TUNNEL_V6_BLACKHOLES.into_iter().map(Op::Blackhole6));
        }
    }

    if let Some(dns) = dns {
        ops.push(Op::Dns(dns));
    }
    Ok(ops)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::IpAddr;

    use fortivpn_core::{DnsConfig, Ipv4Config};

    use super::*;

    pub(crate) const TUN: u32 = 7;
    pub(crate) const UNDERLAY: u32 = 2;
    pub(crate) const UNDERLAY_GW: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    /// Même configuration que `fortivpn_core::config::tests::sample`.
    pub(crate) fn sample() -> TunnelConfig {
        TunnelConfig {
            ipv4: Ipv4Config {
                address: "10.212.134.200/32".parse().unwrap(),
                peer: Some(Ipv4Addr::new(169, 254, 2, 1)),
            },
            ipv6: None,
            mtu: 1354,
            dns: DnsConfig {
                servers: vec!["10.0.0.53".parse().unwrap()],
                search_domains: vec!["corp.example".into()],
            },
            routing: RoutingMode::Split {
                include: vec!["10.0.0.0/8".parse().unwrap()],
            },
            gateway: "203.0.113.10".parse().unwrap(),
        }
    }

    pub(crate) fn default_origin() -> OriginRoute {
        OriginRoute {
            gateway: Some(UNDERLAY_GW),
            oif: UNDERLAY,
            local: false,
        }
    }

    fn gw(config: &TunnelConfig) -> Ipv4Addr {
        match config.gateway {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => unreachable!(),
        }
    }

    fn lookups(exclusions: Vec<(Ipv4Net, Option<OriginRoute>)>) -> Lookups {
        Lookups {
            gateway: default_origin(),
            exclusions,
        }
    }

    fn routes(ops: &[Op]) -> Vec<RouteSpec> {
        ops.iter()
            .filter_map(|op| match op {
                Op::Route(r) => Some(*r),
                _ => None,
            })
            .collect()
    }

    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    #[test]
    fn split_plan_order_and_content() {
        let c = sample();
        let dns = DnsWrite {
            path: "/tmp/x".into(),
            content: "nameserver 10.0.0.53\n".into(),
        };
        let ops = build(TUN, &c, gw(&c), &lookups(vec![]), Some(dns.clone())).unwrap();
        assert_eq!(
            ops,
            vec![
                Op::Link {
                    index: TUN,
                    mtu: 1354
                },
                Op::Address(AddrSpec {
                    index: TUN,
                    address: net("10.212.134.200/32"),
                    peer: Some(Ipv4Addr::new(169, 254, 2, 1)),
                }),
                Op::Route(RouteSpec {
                    dest: net("203.0.113.10/32"),
                    oif: UNDERLAY,
                    gateway: Some(UNDERLAY_GW),
                }),
                Op::Route(RouteSpec {
                    dest: net("10.0.0.0/8"),
                    oif: TUN,
                    gateway: None,
                }),
                Op::Route(RouteSpec {
                    dest: net("10.0.0.53/32"),
                    oif: TUN,
                    gateway: None,
                }),
                Op::Dns(dns),
            ]
        );
    }

    #[test]
    fn full_plan_installs_exclusions_before_halves() {
        let mut c = sample();
        let lan = net("192.168.1.0/24");
        let remote = net("198.51.100.0/24");
        c.routing = RoutingMode::Full {
            exclude: vec![lan.into(), remote.into()],
        };
        let lan_origin = OriginRoute {
            gateway: None,
            oif: 3,
            local: false,
        };
        let ops = build(
            TUN,
            &c,
            gw(&c),
            &lookups(vec![
                (lan, Some(lan_origin)),
                (remote, Some(default_origin())),
            ]),
            None,
        )
        .unwrap();
        assert_eq!(
            routes(&ops),
            vec![
                RouteSpec {
                    dest: net("203.0.113.10/32"),
                    oif: UNDERLAY,
                    gateway: Some(UNDERLAY_GW),
                },
                RouteSpec {
                    dest: lan,
                    oif: 3,
                    gateway: None,
                },
                RouteSpec {
                    dest: remote,
                    oif: UNDERLAY,
                    gateway: Some(UNDERLAY_GW),
                },
                RouteSpec {
                    dest: net("10.0.0.53/32"),
                    oif: TUN,
                    gateway: None,
                },
                RouteSpec {
                    dest: net("0.0.0.0/1"),
                    oif: TUN,
                    gateway: None,
                },
                RouteSpec {
                    dest: net("128.0.0.0/1"),
                    oif: TUN,
                    gateway: None,
                },
            ]
        );
        assert!(!ops.iter().any(|op| matches!(op, Op::Dns(_))));
        assert_eq!(blackholes(&ops), FULL_TUNNEL_V6_BLACKHOLES.to_vec());
    }

    #[test]
    fn exclusion_without_origin_or_local_is_skipped() {
        let mut c = sample();
        let a = net("100.64.0.0/10");
        let b = net("192.0.2.10/32");
        c.routing = RoutingMode::Full {
            exclude: vec![a.into(), b.into()],
        };
        let local = OriginRoute {
            gateway: None,
            oif: 1,
            local: true,
        };
        let ops = build(
            TUN,
            &c,
            gw(&c),
            &lookups(vec![(a, None), (b, Some(local))]),
            None,
        )
        .unwrap();
        let dests: Vec<_> = routes(&ops).iter().map(|r| r.dest).collect();
        assert_eq!(
            dests,
            vec![
                net("203.0.113.10/32"),
                net("10.0.0.53/32"),
                net("0.0.0.0/1"),
                net("128.0.0.0/1")
            ]
        );
    }

    #[test]
    fn origin_through_tunnel_is_refused() {
        let c = sample();
        let mut l = lookups(vec![]);
        l.gateway.oif = TUN;
        assert!(matches!(
            build(TUN, &c, gw(&c), &l, None),
            Err(NetError::Os { .. })
        ));

        let mut c = sample();
        let x = net("198.51.100.0/24");
        c.routing = RoutingMode::Full {
            exclude: vec![x.into()],
        };
        let bad = OriginRoute {
            gateway: None,
            oif: TUN,
            local: false,
        };
        assert!(build(TUN, &c, gw(&c), &lookups(vec![(x, Some(bad))]), None).is_err());
    }

    #[test]
    fn local_gateway_gets_no_preservation_route() {
        let mut c = sample();
        c.gateway = "127.0.0.1".parse().unwrap();
        let l = Lookups {
            gateway: OriginRoute {
                gateway: None,
                oif: 1,
                local: true,
            },
            exclusions: vec![],
        };
        let ops = build(TUN, &c, gw(&c), &l, None).unwrap();
        assert_eq!(
            routes(&ops),
            vec![tun_route("10.0.0.0/8"), tun_route("10.0.0.53/32")]
        );
    }

    #[test]
    fn networks_are_normalized() {
        let mut c = sample();
        c.routing = RoutingMode::Split {
            include: vec!["10.1.2.3/8".parse().unwrap()],
        };
        let ops = build(TUN, &c, gw(&c), &lookups(vec![]), None).unwrap();
        assert!(routes(&ops).iter().any(|r| r.dest == net("10.0.0.0/8")));
        assert_eq!(v4_networks(&c.routing), vec![net("10.0.0.0/8")]);
    }

    #[test]
    fn halves_cover_ipv4_space() {
        assert_eq!(FULL_TUNNEL_HALVES[0], net("0.0.0.0/1"));
        assert_eq!(FULL_TUNNEL_HALVES[1], net("128.0.0.0/1"));
    }

    fn blackholes(ops: &[Op]) -> Vec<Ipv6Net> {
        ops.iter()
            .filter_map(|op| match op {
                Op::Blackhole6(n) => Some(*n),
                _ => None,
            })
            .collect()
    }

    fn tun_route(s: &str) -> RouteSpec {
        RouteSpec {
            dest: net(s),
            oif: TUN,
            gateway: None,
        }
    }

    fn with_dns(mut c: TunnelConfig, servers: &[&str]) -> TunnelConfig {
        c.dns.servers = servers.iter().map(|s| s.parse().unwrap()).collect();
        c
    }

    #[test]
    fn full_plan_blackholes_ipv6_after_halves_and_before_dns() {
        let mut c = sample();
        c.routing = RoutingMode::Full { exclude: vec![] };
        let dns = DnsWrite {
            path: "/tmp/x".into(),
            content: String::new(),
        };
        let ops = build(TUN, &c, gw(&c), &lookups(vec![]), Some(dns)).unwrap();
        assert_eq!(
            blackholes(&ops),
            vec![
                "::/1".parse::<Ipv6Net>().unwrap(),
                "8000::/1".parse().unwrap()
            ]
        );
        let pos = |pred: &dyn Fn(&Op) -> bool| ops.iter().position(pred).unwrap();
        let last_half = pos(&|op| matches!(op, Op::Route(r) if r.dest == net("128.0.0.0/1")));
        let first_bh = pos(&|op| matches!(op, Op::Blackhole6(_)));
        let dns_pos = pos(&|op| matches!(op, Op::Dns(_)));
        assert!(last_half < first_bh && first_bh < dns_pos, "{ops:?}");
        // Les deux moitiés couvrent tout l'espace IPv6.
        let [a, b] = FULL_TUNNEL_V6_BLACKHOLES;
        for probe in ["::1", "2001:db8::1", "fe80::1", "ffff::1", "8000::"] {
            let ip: Ipv6Addr = probe.parse().unwrap();
            assert!(a.contains(&ip) ^ b.contains(&ip), "{probe}");
        }
    }

    #[test]
    fn split_plan_has_no_blackhole() {
        let c = sample();
        let ops = build(TUN, &c, gw(&c), &lookups(vec![]), None).unwrap();
        assert!(blackholes(&ops).is_empty());
    }

    #[test]
    fn full_plan_with_ipv6_exclusion_still_blackholes() {
        let mut c = sample();
        c.routing = RoutingMode::Full {
            exclude: vec!["2001:db8::/32".parse().unwrap()],
        };
        let ops = build(TUN, &c, gw(&c), &lookups(vec![]), None).unwrap();
        assert_eq!(blackholes(&ops).len(), 2);
    }

    /// Même couvert par une inclusion, le DNS reçoit sa `/32` : un réseau
    /// on-link plus spécifique de l'underlay l'emporterait sinon.
    #[test]
    fn split_dns_covered_by_include_still_gets_host_route() {
        let c = sample(); // DNS 10.0.0.53 dans 10.0.0.0/8
        assert_eq!(
            dns_host_routes(&c, gw(&c)),
            vec![Ipv4Addr::new(10, 0, 0, 53)]
        );
        let ops = build(TUN, &c, gw(&c), &lookups(vec![]), None).unwrap();
        assert!(routes(&ops).contains(&tun_route("10.0.0.53/32")));
    }

    #[test]
    fn split_include_equal_to_dns_host_is_not_duplicated() {
        let mut c = sample();
        c.routing = RoutingMode::Split {
            include: vec!["10.0.0.53/32".parse().unwrap()],
        };
        let ops = build(TUN, &c, gw(&c), &lookups(vec![]), None).unwrap();
        let n = routes(&ops)
            .iter()
            .filter(|r| r.dest == net("10.0.0.53/32"))
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn split_dns_outside_includes_gets_host_route_via_tunnel() {
        let c = with_dns(
            sample(),
            &[
                "172.16.0.53",
                "10.0.0.53",
                "fd00::53",
                "172.16.0.53",
                "192.168.5.5",
            ],
        );
        let ops = build(TUN, &c, gw(&c), &lookups(vec![]), None).unwrap();
        assert_eq!(
            routes(&ops),
            vec![
                RouteSpec {
                    dest: net("203.0.113.10/32"),
                    oif: UNDERLAY,
                    gateway: Some(UNDERLAY_GW),
                },
                tun_route("10.0.0.0/8"),
                tun_route("172.16.0.53/32"),
                tun_route("10.0.0.53/32"),
                tun_route("192.168.5.5/32"),
            ]
        );
    }

    #[test]
    fn split_without_includes_routes_every_dns() {
        let mut c = with_dns(sample(), &["10.0.0.53", "10.0.0.54"]);
        c.routing = RoutingMode::Split { include: vec![] };
        assert_eq!(
            dns_host_routes(&c, gw(&c)),
            vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)]
        );
    }

    #[test]
    fn full_dns_in_exclusion_gets_host_route_via_tunnel() {
        let lan = net("192.168.1.0/24");
        let mut c = with_dns(sample(), &["192.168.1.53", "10.0.0.53"]);
        c.routing = RoutingMode::Full {
            exclude: vec![lan.into()],
        };
        let lan_origin = OriginRoute {
            gateway: None,
            oif: 3,
            local: false,
        };
        let ops = build(
            TUN,
            &c,
            gw(&c),
            &lookups(vec![(lan, Some(lan_origin))]),
            None,
        )
        .unwrap();
        assert_eq!(
            routes(&ops),
            vec![
                RouteSpec {
                    dest: net("203.0.113.10/32"),
                    oif: UNDERLAY,
                    gateway: Some(UNDERLAY_GW),
                },
                RouteSpec {
                    dest: lan,
                    oif: 3,
                    gateway: None,
                },
                tun_route("192.168.1.53/32"),
                tun_route("10.0.0.53/32"),
                tun_route("0.0.0.0/1"),
                tun_route("128.0.0.0/1"),
            ]
        );
    }

    #[test]
    fn full_dns_outside_exclusions_still_gets_host_route() {
        let mut c = with_dns(sample(), &["10.0.0.53"]);
        c.routing = RoutingMode::Full {
            exclude: vec!["192.168.1.0/24".parse().unwrap()],
        };
        assert_eq!(
            dns_host_routes(&c, gw(&c)),
            vec![Ipv4Addr::new(10, 0, 0, 53)]
        );
    }

    #[test]
    fn full_exclusion_equal_to_dns_host_is_dropped() {
        let x = net("192.168.1.53/32");
        let mut c = with_dns(sample(), &["192.168.1.53"]);
        c.routing = RoutingMode::Full {
            exclude: vec![x.into()],
        };
        let ops = build(
            TUN,
            &c,
            gw(&c),
            &lookups(vec![(x, Some(default_origin()))]),
            None,
        )
        .unwrap();
        let r: Vec<_> = routes(&ops).into_iter().filter(|r| r.dest == x).collect();
        assert_eq!(r, vec![tun_route("192.168.1.53/32")]);
    }

    #[test]
    fn dns_equal_to_gateway_or_unroutable_gets_no_route() {
        // Split : passerelle hors inclusions.
        let c = with_dns(
            sample(),
            &[
                "203.0.113.10",
                "127.0.0.53",
                "0.0.0.0",
                "224.0.0.251",
                "255.255.255.255",
            ],
        );
        assert!(dns_host_routes(&c, gw(&c)).is_empty());
        let ops = build(TUN, &c, gw(&c), &lookups(vec![]), None).unwrap();
        let gw_routes: Vec<_> = routes(&ops)
            .into_iter()
            .filter(|r| r.dest == net("203.0.113.10/32"))
            .collect();
        assert_eq!(gw_routes.len(), 1);
        assert_eq!(
            gw_routes[0].oif, UNDERLAY,
            "la /32 de la passerelle reste sur l'underlay"
        );

        // Full : passerelle dans une exclusion.
        let mut c = with_dns(sample(), &["203.0.113.10"]);
        c.routing = RoutingMode::Full {
            exclude: vec!["203.0.113.0/24".parse().unwrap()],
        };
        assert!(dns_host_routes(&c, gw(&c)).is_empty());
    }
}
