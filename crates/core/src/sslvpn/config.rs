//! Conversion de la configuration XML (`proto::config::VpnConfig`) + résultat IPCP en
//! [`TunnelConfig`] neutre (`docs/protocol.md` §5.3, §9.4).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};
use proto::config::VpnConfig;

use crate::config::{DnsConfig, Ipv4Config, RoutingMode, TunnelConfig};
use crate::error::ConfigError;

/// Paramètres négociés par PPP (IPCP fait foi pour l'adresse, §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedIpv4 {
    /// Adresse locale obtenue par IPCP.
    pub address: Ipv4Addr,
    /// Adresse du pair PPP, si annoncée.
    pub peer: Option<Ipv4Addr>,
    /// MTU de l'interface (min(MRU pair, notre MRU), §9.2).
    pub mtu: u16,
    /// DNS obtenus par IPCP (options 129/131), complément du XML.
    pub dns: Vec<Ipv4Addr>,
}

/// Nombre maximal de préfixes produits par la soustraction des exclusions (M1).
pub(crate) const MAX_SPLIT_ROUTES: usize = 1024;

/// Retire `excl` de `net` (préfixes : soit disjoints, soit emboîtés). Échoue si la
/// sortie dépasse [`MAX_SPLIT_ROUTES`].
fn subtract(net: Ipv4Net, excl: Ipv4Net, out: &mut Vec<Ipv4Net>) -> Result<(), ConfigError> {
    if excl.contains(&net) {
        return Ok(());
    }
    if !net.contains(&excl) {
        out.push(net);
        return check_len(out.len());
    }
    // `net` contient strictement `excl` : on le coupe en deux et on recommence.
    match net.subnets(net.prefix_len() + 1) {
        Ok(halves) => {
            for half in halves {
                subtract(half, excl, out)?;
            }
        }
        Err(_) => {
            out.push(net);
            check_len(out.len())?;
        }
    }
    Ok(())
}

fn check_len(n: usize) -> Result<(), ConfigError> {
    if n > MAX_SPLIT_ROUTES {
        Err(ConfigError::TooManyRoutes(MAX_SPLIT_ROUTES))
    } else {
        Ok(())
    }
}

/// Routes incluses moins les routes exclues (split-tunnel avec `negate="1"`).
fn include_minus_exclude(
    include: &[Ipv4Net],
    exclude: &[Ipv4Net],
) -> Result<Vec<Ipv4Net>, ConfigError> {
    check_len(include.len())?;
    let mut current: Vec<Ipv4Net> = include.to_vec();
    for &excl in exclude {
        let mut next = Vec::with_capacity(current.len());
        for net in current {
            subtract(net, excl, &mut next)?;
        }
        current = next;
    }
    Ok(current)
}

/// Construit la [`TunnelConfig`] :
///
/// - adresse = IPCP (une divergence avec `<assigned-addr>` est journalisée) ;
/// - DNS = serveurs XML puis IPCP en complément ; domaines = `@domain` puis domaines
///   de `<split-dns>`, dédupliqués ;
/// - split-tunnel si au moins une route incluse : routes incluses **moins** les
///   exclusions `negate="1"` (le modèle `RoutingMode::Split` n'a pas d'exclusions),
///   sans la route /32 égale à l'IP de la passerelle (comme openfortivpn) ;
/// - sinon full-tunnel avec les exclusions `negate="1"`.
///
/// La section IPv6 est ignorée (hors MVP).
pub fn tunnel_config(
    xml: &VpnConfig,
    gateway: IpAddr,
    ppp: &NegotiatedIpv4,
) -> Result<TunnelConfig, ConfigError> {
    if let Some(assigned) = xml.ipv4.assigned_addr {
        if assigned != ppp.address {
            tracing::warn!(
                %assigned,
                ipcp = %ppp.address,
                "adresse IPCP différente de <assigned-addr> : IPCP fait foi"
            );
        }
    }

    let mut servers: Vec<IpAddr> = xml.ipv4.dns_servers.iter().map(|&a| a.into()).collect();
    let mut ipcp_extra = false;
    for &d in &ppp.dns {
        let d = IpAddr::V4(d);
        if !servers.contains(&d) {
            ipcp_extra |= !xml.ipv4.dns_servers.is_empty();
            servers.push(d);
        }
    }
    if ipcp_extra {
        tracing::debug!("DNS IPCP différents de ceux du XML : ajoutés en complément");
    }
    let mut search_domains: Vec<String> = Vec::new();
    let mut seen_domains: BTreeSet<String> = BTreeSet::new();
    for d in xml
        .ipv4
        .dns_suffixes
        .iter()
        .chain(xml.ipv4.split_dns.iter().flat_map(|s| s.domains.iter()))
    {
        if seen_domains.insert(d.to_ascii_lowercase()) {
            search_domains.push(d.clone());
        }
    }

    let routing = if xml.is_split_tunnel() {
        let include = include_minus_exclude(&xml.ipv4.include_routes, &xml.ipv4.exclude_routes)?
            .into_iter()
            .filter(|n| !(n.prefix_len() == 32 && IpAddr::V4(n.addr()) == gateway))
            .map(IpNet::V4)
            .collect();
        RoutingMode::Split { include }
    } else {
        RoutingMode::Full {
            exclude: xml
                .ipv4
                .exclude_routes
                .iter()
                .map(|&n| IpNet::V4(n))
                .collect(),
        }
    };

    let config = TunnelConfig {
        ipv4: Ipv4Config {
            address: Ipv4Net::from(ppp.address),
            peer: ppp.peer,
        },
        ipv6: None,
        mtu: ppp.mtu,
        dns: DnsConfig {
            servers,
            search_domains,
        },
        routing,
        gateway,
    };
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::config::parse_config;

    fn vector(name: &str) -> VpnConfig {
        let path = format!("{}/../../docs/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        parse_config(&std::fs::read(path).unwrap()).unwrap()
    }

    fn ppp() -> NegotiatedIpv4 {
        NegotiatedIpv4 {
            address: Ipv4Addr::new(10, 10, 0, 2),
            peer: Some(Ipv4Addr::new(169, 254, 2, 1)),
            mtu: 1354,
            dns: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 99)],
        }
    }

    fn nets(v: &[&str]) -> Vec<IpNet> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn split_vector_maps() {
        let gw: IpAddr = "198.51.100.7".parse().unwrap();
        let c = tunnel_config(&vector("config_split.xml"), gw, &ppp()).unwrap();
        assert_eq!(c.ipv4.address, "10.10.0.2/32".parse().unwrap());
        assert_eq!(c.mtu, 1354);
        assert_eq!(
            c.dns.servers,
            ["10.0.0.53", "10.0.0.54", "10.0.0.99"]
                .map(|s| s.parse::<IpAddr>().unwrap())
                .to_vec()
        );
        assert_eq!(
            c.dns.search_domains,
            ["corp.example.com", "lab.example.net"]
        );
        let RoutingMode::Split { include } = &c.routing else {
            panic!("{:?}", c.routing);
        };
        // 10.0.0.0/8 moins 10.99.0.0/16 ; 198.51.100.7/32 = passerelle -> retirée.
        let expected = nets(&[
            "10.0.0.0/10",
            "10.64.0.0/11",
            "10.96.0.0/15",
            "10.98.0.0/16",
            "10.100.0.0/14",
            "10.104.0.0/13",
            "10.112.0.0/12",
            "10.128.0.0/9",
            "172.16.0.0/12",
            "192.0.2.128/25",
        ]);
        assert_eq!(include, &expected);
    }

    #[test]
    fn full_tunnel_vector_maps() {
        let gw: IpAddr = "203.0.113.10".parse().unwrap();
        let c = tunnel_config(&vector("config_full_tunnel.xml"), gw, &ppp()).unwrap();
        assert_eq!(c.routing, RoutingMode::Full { exclude: vec![] });
        assert_eq!(c.gateway, gw);
        assert!(c.dns.search_domains.is_empty());
    }

    #[test]
    fn subtraction_edge_cases() {
        let n = |s: &str| s.parse::<Ipv4Net>().unwrap();
        assert_eq!(
            include_minus_exclude(&[n("10.0.0.0/8")], &[n("0.0.0.0/0")]).unwrap(),
            vec![]
        );
        assert_eq!(
            include_minus_exclude(&[n("10.0.0.0/8")], &[n("192.168.0.0/16")]).unwrap(),
            vec![n("10.0.0.0/8")]
        );
        assert_eq!(
            include_minus_exclude(&[n("10.0.0.0/31")], &[n("10.0.0.1/32")]).unwrap(),
            vec![n("10.0.0.0/32")]
        );
    }

    #[test]
    fn subtraction_output_is_bounded() {
        let n = |s: &str| s.parse::<Ipv4Net>().unwrap();
        // 0.0.0.0/0 moins 100 /32 dispersés : ~32 préfixes chacun -> dépasse 1024.
        let excl: Vec<Ipv4Net> = (0..100u32)
            .map(|i| Ipv4Net::new(Ipv4Addr::from(i.wrapping_mul(40_000_000)), 32).unwrap())
            .collect();
        assert_eq!(
            include_minus_exclude(&[n("0.0.0.0/0")], &excl),
            Err(ConfigError::TooManyRoutes(MAX_SPLIT_ROUTES))
        );
        let few = &excl[..10];
        assert!(include_minus_exclude(&[n("0.0.0.0/0")], few).unwrap().len() <= 1024);
    }

    #[test]
    fn domains_deduplicated_case_insensitively() {
        let mut xml = vector("config_split.xml");
        let d = xml.ipv4.dns_suffixes.clone();
        xml.ipv4
            .dns_suffixes
            .extend(d.iter().map(|s| s.to_uppercase()));
        let gw: IpAddr = "198.51.100.7".parse().unwrap();
        let c = tunnel_config(&xml, gw, &ppp()).unwrap();
        assert_eq!(c.dns.search_domains.len(), 2);
    }

    #[test]
    fn rejects_bad_ipcp_address() {
        let mut p = ppp();
        p.address = Ipv4Addr::UNSPECIFIED;
        let gw: IpAddr = "203.0.113.10".parse().unwrap();
        assert!(tunnel_config(&vector("config_full_tunnel.xml"), gw, &p).is_err());
    }
}
