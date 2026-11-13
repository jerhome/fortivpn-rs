//! Configuration réseau du tunnel, neutre vis-à-vis du transport.
//!
//! Produite par un [`Transport`](crate::Transport) (XML `fortisslvpn_xml` + IPCP pour
//! SSL-VPN, mode-config IKE pour IPsec) et consommée par un
//! [`NetBackend`](crate::NetBackend).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::error::ConfigError;

/// MTU minimale acceptée (minimum IPv4 garanti, RFC 791).
pub const MIN_MTU: u16 = 576;

/// Configuration réseau complète à appliquer sur l'interface TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    /// Adressage IPv4 local du tunnel.
    pub ipv4: Ipv4Config,
    /// Adressage IPv6 local (prévu, pas encore pris en charge par les backends).
    pub ipv6: Option<Ipv6Config>,
    /// MTU de l'interface TUN.
    pub mtu: u16,
    /// DNS à associer au tunnel.
    pub dns: DnsConfig,
    /// Politique de routage (split ou full-tunnel).
    pub routing: RoutingMode,
    /// Adresse publique de la passerelle : sa route doit rester hors tunnel
    /// (via la route par défaut d'origine) pour éviter une boucle.
    pub gateway: IpAddr,
}

/// Adressage IPv4 local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Config {
    /// Adresse locale et longueur de préfixe (souvent `/32` en PPP).
    pub address: Ipv4Net,
    /// Adresse du pair point-à-point, si le transport en fournit une.
    pub peer: Option<Ipv4Addr>,
}

/// Adressage IPv6 local (non implémenté pour l'instant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Config {
    /// Adresse locale et longueur de préfixe.
    pub address: Ipv6Net,
    /// Adresse du pair point-à-point éventuelle.
    pub peer: Option<Ipv6Addr>,
}

/// Configuration DNS du tunnel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsConfig {
    /// Serveurs DNS, par ordre de préférence.
    pub servers: Vec<IpAddr>,
    /// Domaines de recherche / domaines internes (NRPT sous Windows).
    pub search_domains: Vec<String>,
}

/// Politique de routage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingMode {
    /// Split-tunnel : seuls ces réseaux passent par le tunnel.
    Split {
        /// Réseaux routés via le tunnel.
        include: Vec<IpNet>,
    },
    /// Full-tunnel : tout le trafic passe par le tunnel, sauf ces réseaux
    /// (qui restent sur la route d'origine).
    Full {
        /// Réseaux exclus du tunnel.
        exclude: Vec<IpNet>,
    },
}

impl RoutingMode {
    /// Réseaux listés par la politique (inclusions ou exclusions).
    pub fn networks(&self) -> &[IpNet] {
        match self {
            Self::Split { include } => include,
            Self::Full { exclude } => exclude,
        }
    }
}

impl TunnelConfig {
    /// Vérifie la cohérence de la configuration (à appeler par le transport
    /// avant de la remettre, et par les backends avant de l'appliquer).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.mtu < MIN_MTU {
            return Err(ConfigError::InvalidMtu(self.mtu));
        }
        let addr = self.ipv4.address.addr();
        if addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast() {
            return Err(ConfigError::InvalidAddress(IpAddr::V4(addr)));
        }
        if self.gateway.is_unspecified() {
            return Err(ConfigError::InvalidAddress(self.gateway));
        }
        if let Some(net) = self
            .routing
            .networks()
            .iter()
            .find(|n| matches!(n, IpNet::V6(_)) && self.ipv6.is_none())
        {
            return Err(ConfigError::RouteFamilyMismatch(*net));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Configuration de référence pour les tests du crate.
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

    #[test]
    fn sample_is_valid() {
        assert_eq!(sample().validate(), Ok(()));
    }

    #[test]
    fn rejects_small_mtu() {
        let mut c = sample();
        c.mtu = 500;
        assert_eq!(c.validate(), Err(ConfigError::InvalidMtu(500)));
    }

    #[test]
    fn rejects_unspecified_addresses() {
        let mut c = sample();
        c.ipv4.address = "0.0.0.0/32".parse().unwrap();
        assert!(matches!(c.validate(), Err(ConfigError::InvalidAddress(_))));

        let mut c = sample();
        c.gateway = "0.0.0.0".parse().unwrap();
        assert!(matches!(c.validate(), Err(ConfigError::InvalidAddress(_))));
    }

    #[test]
    fn rejects_ipv6_route_without_ipv6_config() {
        let mut c = sample();
        let v6: IpNet = "fd00::/8".parse().unwrap();
        c.routing = RoutingMode::Full { exclude: vec![v6] };
        assert_eq!(c.validate(), Err(ConfigError::RouteFamilyMismatch(v6)));

        c.ipv6 = Some(Ipv6Config {
            address: "fd00::2/64".parse().unwrap(),
            peer: None,
        });
        assert_eq!(c.validate(), Ok(()));
    }
}
