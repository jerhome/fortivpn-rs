//! [`LinuxNetBackend`] : assemblage TUN + plan + exécution.

use std::future::Future;
use std::net::IpAddr;

use fortivpn_core::{
    NetBackend, NetCleanup, NetError, NetGuard, RoutingMode, TunDevice, TunInfo, TunOptions,
    TunnelConfig,
};

use crate::dns::{self, DnsStrategy};
use crate::netlink::LinuxSystem;
use crate::plan::{self, Lookups};
use crate::system::{Rollback, System, install};

/// `NetBackend` Linux : TUN via `/dev/net/tun`, adresses/MTU/routes via
/// rtnetlink, DNS selon une [`DnsStrategy`] (par défaut : aucune action).
///
/// Nécessite `CAP_NET_ADMIN` (root, ou netns utilisateur).
#[derive(Debug, Clone, Default)]
pub struct LinuxNetBackend {
    dns: DnsStrategy,
}

impl LinuxNetBackend {
    /// Backend avec [`DnsStrategy::Ignore`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Choisit la stratégie DNS.
    #[must_use]
    pub fn with_dns(mut self, dns: DnsStrategy) -> Self {
        self.dns = dns;
        self
    }

    /// Stratégie DNS courante.
    pub fn dns_strategy(&self) -> &DnsStrategy {
        &self.dns
    }
}

impl NetBackend for LinuxNetBackend {
    type Cleanup = LinuxCleanup;

    fn create_tun(
        &self,
        options: &TunOptions,
    ) -> impl Future<Output = Result<TunDevice, NetError>> + Send {
        let options = options.clone();
        async move { crate::tun::create(&LinuxSystem, &options).await }
    }

    fn apply(
        &self,
        tun: &TunInfo,
        config: &TunnelConfig,
    ) -> impl Future<Output = Result<NetGuard<LinuxCleanup>, NetError>> + Send {
        let tun = tun.clone();
        let config = config.clone();
        let dns = self.dns.clone();
        async move {
            let inner = apply_with(&LinuxSystem, &dns, &tun, &config).await?;
            Ok(NetGuard::new(LinuxCleanup { inner }))
        }
    }
}

/// Annulation de [`LinuxNetBackend::apply`] : retire exactement ce qui a été
/// installé (adresse, routes, fichier resolv), dans l'ordre inverse. Les
/// éléments déjà absents (ex. routes de la TUN détruites avec elle) sont
/// ignorés. La MTU et l'état `up` de la TUN ne sont pas restaurés (ils
/// disparaissent avec l'interface).
#[derive(Debug)]
pub struct LinuxCleanup {
    inner: Rollback<LinuxSystem>,
}

impl NetCleanup for LinuxCleanup {
    fn cleanup(&mut self) -> impl Future<Output = Result<(), NetError>> + Send {
        self.inner.cleanup()
    }

    fn cleanup_blocking(&mut self) -> Result<(), NetError> {
        self.inner.cleanup_blocking()
    }
}

/// `apply` générique sur le [`System`] (testable avec un système fictif).
///
/// Toutes les vérifications et résolutions (route d'origine de la passerelle
/// et des exclusions) ont lieu **avant** la première modification.
pub(crate) async fn apply_with<S: System>(
    sys: &S,
    dns_strategy: &DnsStrategy,
    tun: &TunInfo,
    config: &TunnelConfig,
) -> Result<Rollback<S>, NetError> {
    config.validate()?;
    if config.ipv6.is_some() {
        return Err(NetError::Unsupported("IPv6"));
    }
    let IpAddr::V4(gateway) = config.gateway else {
        return Err(NetError::Unsupported("passerelle IPv6"));
    };
    let dns_write = dns::plan(dns_strategy, &config.dns)?;
    let index = match tun.index {
        Some(i) => i,
        None => sys.link_index(&tun.name).await?,
    };

    let gateway_origin = sys
        .lookup_route(gateway)
        .await?
        .ok_or_else(|| NetError::Os {
            op: "lookup_route",
            reason: format!("aucune route vers la passerelle {gateway}"),
        })?;
    let mut exclusions = Vec::new();
    if let RoutingMode::Full { .. } = config.routing {
        for net in plan::v4_networks(&config.routing) {
            exclusions.push((net, sys.lookup_route(net.network()).await?));
        }
    }
    let lookups = Lookups {
        gateway: gateway_origin,
        exclusions,
    };

    let ops = plan::build(index, config, gateway, &lookups, dns_write)?;
    tracing::debug!(?ops, "plan réseau");
    install(sys, &ops).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    use fortivpn_core::Ipv6Config;
    use fortivpn_core::fake::{FakeNetBackend, RouteVia};
    use ipnet::{IpNet, Ipv4Net};

    use super::*;
    use crate::plan::tests::{TUN, UNDERLAY, default_origin, sample};
    use crate::plan::{Op, OriginRoute, RouteSpec};
    use crate::system::mock::{Event, MockSystem};

    fn tun_info() -> TunInfo {
        TunInfo {
            name: "fvpn0".into(),
            index: Some(TUN),
        }
    }

    fn mock() -> MockSystem {
        let sys = MockSystem::default();
        sys.state().default_origin = Some(default_origin());
        sys
    }

    fn execs(sys: &MockSystem) -> Vec<Op> {
        sys.state()
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Exec(op) => Some(op.clone()),
                Event::Revert(_) => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn apply_and_teardown_split() {
        let sys = mock();
        let dir = std::env::temp_dir().join(format!("netlinux-backend-{}", std::process::id()));
        let strategy = DnsStrategy::ResolvFile(dir.join("resolv.conf"));
        let rb = apply_with(&sys, &strategy, &tun_info(), &sample())
            .await
            .unwrap();
        let mut guard = NetGuard::new(rb);
        {
            let s = sys.state();
            assert_eq!(s.addresses.len(), 1);
            assert_eq!(s.routes.len(), 3, "passerelle, 10.0.0.0/8, /32 DNS");
            assert!(s.dns);
            assert_eq!(s.lookups, vec![Ipv4Addr::new(203, 0, 113, 10)]);
        }
        guard.teardown().await.unwrap();
        assert!(sys.is_clean());
    }

    #[tokio::test]
    async fn lookups_happen_before_any_change() {
        let sys = mock();
        let mut c = sample();
        c.routing = RoutingMode::Full {
            exclude: vec!["198.51.100.0/24".parse().unwrap()],
        };
        let _rb = apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &c)
            .await
            .unwrap();
        assert_eq!(
            sys.state().lookups,
            vec![
                Ipv4Addr::new(203, 0, 113, 10),
                Ipv4Addr::new(198, 51, 100, 0)
            ]
        );
    }

    #[tokio::test]
    async fn resolves_index_by_name_when_missing() {
        let sys = mock();
        sys.state().links.insert("fvpn0".into(), 42);
        let tun = TunInfo {
            name: "fvpn0".into(),
            index: None,
        };
        let _rb = apply_with(&sys, &DnsStrategy::Ignore, &tun, &sample())
            .await
            .unwrap();
        assert_eq!(
            execs(&sys)[0],
            Op::Link {
                index: 42,
                mtu: 1354
            }
        );
    }

    #[tokio::test]
    async fn rejects_before_touching_anything() {
        let cases: Vec<(TunnelConfig, DnsStrategy, &str)> = vec![
            {
                let mut c = sample();
                c.mtu = 100;
                (c, DnsStrategy::Ignore, "mtu")
            },
            {
                let mut c = sample();
                c.ipv6 = Some(Ipv6Config {
                    address: "fd00::2/64".parse().unwrap(),
                    peer: None,
                });
                (c, DnsStrategy::Ignore, "ipv6")
            },
            {
                let mut c = sample();
                c.gateway = "2001:db8::1".parse().unwrap();
                (c, DnsStrategy::Ignore, "gateway v6")
            },
            {
                let mut c = sample();
                c.dns.search_domains = vec!["x\nnameserver 6.6.6.6".into()];
                (
                    c,
                    DnsStrategy::ResolvFile("/tmp/netlinux-never-written".into()),
                    "dns",
                )
            },
            (
                sample(),
                DnsStrategy::ResolvFile("/etc/resolv.conf".into()),
                "system resolv",
            ),
        ];
        for (c, strategy, what) in cases {
            let sys = mock();
            let r = apply_with(&sys, &strategy, &tun_info(), &c).await;
            assert!(r.is_err(), "{what}");
            assert!(sys.state().events.is_empty(), "{what}");
        }

        let sys = mock();
        let mut c = sample();
        c.ipv6 = Some(Ipv6Config {
            address: "fd00::2/64".parse().unwrap(),
            peer: None,
        });
        assert!(matches!(
            apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &c).await,
            Err(NetError::Unsupported(_))
        ));
        let mut c = sample();
        c.mtu = 1;
        assert!(matches!(
            apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &c).await,
            Err(NetError::InvalidConfig(_))
        ));
    }

    #[tokio::test]
    async fn unreachable_gateway_is_an_error() {
        let sys = MockSystem::default(); // aucune route d'origine
        assert!(
            apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &sample())
                .await
                .is_err()
        );
        assert!(sys.state().events.is_empty());
    }

    #[tokio::test]
    async fn failure_mid_apply_rolls_back() {
        for step in 0..4 {
            let sys = mock();
            sys.state().fail_exec_at = Some(step);
            assert!(
                apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &sample())
                    .await
                    .is_err()
            );
            assert!(sys.is_clean(), "étape {step}");
        }
    }

    /// Le fake de `core` est la référence : mêmes destinations, même chemin
    /// (tunnel / underlay) pour split et full, **plus** la `/32` via le tunnel
    /// de chaque serveur DNS (M2), que le fake ne modélise pas encore ; les
    /// `blackhole` IPv6 (E2) sont tenus à part (`State::blackholes`).
    #[tokio::test]
    async fn same_routes_as_reference_fake() {
        let mut full = sample();
        full.routing = RoutingMode::Full {
            exclude: vec!["192.168.1.0/24".parse().unwrap()],
        };
        for config in [sample(), full] {
            let fake = FakeNetBackend::new();
            let ftun = fake.create_tun(&TunOptions::new("fvpn0")).await.unwrap();
            let _fguard = fake.apply(&ftun.info, &config).await.unwrap();
            let mut expected: HashSet<(IpNet, bool)> = fake
                .installed_routes()
                .iter()
                .map(|r| (r.dest, r.via == RouteVia::Tunnel))
                .collect();
            // Écart au fake (M2) : /32 du DNS 10.0.0.53 via le tunnel.
            expected.insert(("10.0.0.53/32".parse().unwrap(), true));

            let sys = mock();
            let _rb = apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &config)
                .await
                .unwrap();
            let ours: HashSet<(IpNet, bool)> = sys
                .state()
                .routes
                .iter()
                .map(|r: &RouteSpec| (IpNet::V4(r.dest), r.oif == TUN))
                .collect();
            assert_eq!(ours, expected, "{:?}", config.routing);
            assert!(
                sys.state()
                    .routes
                    .iter()
                    .filter(|r| r.oif != TUN)
                    .all(|r| r.oif == UNDERLAY)
            );
        }
    }

    #[tokio::test]
    async fn local_gateway_skips_preservation_route() {
        let sys = mock();
        let lo = Ipv4Addr::LOCALHOST;
        sys.state().origins.insert(
            lo,
            OriginRoute {
                gateway: None,
                oif: 1,
                local: true,
            },
        );
        let mut c = sample();
        c.gateway = IpAddr::V4(lo);
        let _rb = apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &c)
            .await
            .unwrap();
        let dests: Vec<Ipv4Net> = sys.state().routes.iter().map(|r| r.dest).collect();
        assert_eq!(
            dests,
            vec![
                "10.0.0.0/8".parse::<Ipv4Net>().unwrap(),
                "10.0.0.53/32".parse().unwrap()
            ]
        );
    }

    /// Revue 5.3 E2 + M2 au niveau `apply` : blackholes IPv6 et `/32` DNS
    /// installés puis retirés.
    #[tokio::test]
    async fn full_tunnel_blackholes_ipv6_and_routes_excluded_dns() {
        let sys = mock();
        let mut c = sample();
        c.dns.servers = vec!["192.168.1.53".parse().unwrap()];
        c.routing = RoutingMode::Full {
            exclude: vec!["192.168.1.0/24".parse().unwrap()],
        };
        let rb = apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &c)
            .await
            .unwrap();
        let mut guard = NetGuard::new(rb);
        {
            let s = sys.state();
            assert_eq!(
                s.blackholes,
                crate::plan::FULL_TUNNEL_V6_BLACKHOLES.to_vec()
            );
            assert!(s.routes.contains(&RouteSpec {
                dest: "192.168.1.53/32".parse().unwrap(),
                oif: TUN,
                gateway: None,
            }));
        }
        guard.teardown().await.unwrap();
        assert!(sys.is_clean());
    }

    #[tokio::test]
    async fn split_tunnel_routes_uncovered_dns_without_blackhole() {
        let sys = mock();
        let mut c = sample();
        c.dns.servers = vec!["172.16.0.53".parse().unwrap()];
        let _rb = apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &c)
            .await
            .unwrap();
        let s = sys.state();
        assert!(s.blackholes.is_empty());
        assert!(s.routes.contains(&RouteSpec {
            dest: "172.16.0.53/32".parse().unwrap(),
            oif: TUN,
            gateway: None,
        }));
    }

    #[tokio::test]
    async fn failure_on_blackhole_rolls_back_everything() {
        let mut c = sample();
        c.routing = RoutingMode::Full { exclude: vec![] };
        // Link, Address, gw /32, 0/1, 128/1, ::/1 (index 5), 8000::/1 (6).
        for step in [5, 6] {
            let sys = mock();
            sys.state().fail_exec_at = Some(step);
            assert!(
                apply_with(&sys, &DnsStrategy::Ignore, &tun_info(), &c)
                    .await
                    .is_err()
            );
            assert!(sys.is_clean(), "étape {step}");
        }
    }
}
