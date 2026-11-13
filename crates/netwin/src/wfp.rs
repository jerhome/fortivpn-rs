//! Plan des filtres WFP (Windows Filtering Platform) : logique **pure**.
//!
//! Choix des filtres selon le mode de routage, conditions, poids. Le FFI
//! (`win::wfp`) ne fait que traduire ces descriptions en structures WFP.
//!
//! Les filtres vivent dans une session WFP **dynamique** : retirés par le
//! système quand le handle de session est fermé ou que le processus meurt
//! (kill-switch sans résidu, aucun journal nécessaire). Revue 5.3, E2 / F4.

use std::net::IpAddr;

use fortivpn_core::{RoutingMode, TunnelConfig};

/// GUID constant de notre sous-couche WFP (`"fortivpn-rs-wfp"` en ASCII, 16 octets).
pub(crate) const SUBLAYER_GUID: u128 = 0x666f_7274_6976_706e_2d72_732d_7766_7000;

/// GUID de la sous-couche de **protection pendant la reconnexion** (`"fortivpn-rs-hold"`).
/// Distincte de [`SUBLAYER_GUID`] : la protection est installée (nouvelle session)
/// avant le retrait des filtres du tunnel, sans fenêtre de fuite ni conflit.
pub(crate) const HOLD_SUBLAYER_GUID: u128 = 0x666f_7274_6976_706e_2d72_732d_686f_6c64;

/// Poids de la sous-couche (élevé : évalué avant la plupart des autres).
pub(crate) const SUBLAYER_WEIGHT: u16 = 0xFFF0;

/// Poids (0..=15) des filtres `permit` : l'emportent sur les `block` de la
/// sous-couche.
pub(crate) const WEIGHT_PERMIT: u8 = 15;
/// Poids (0..=15) des filtres `block`.
pub(crate) const WEIGHT_BLOCK: u8 = 10;

/// Ports UDP à ne pas laisser sortir hors tunnel : NBT-NS, mDNS, LLMNR.
pub(crate) const NAME_RESOLUTION_PORTS: [u16; 3] = [137, 5353, 5355];

/// Protocole IP UDP.
pub(crate) const PROTO_UDP: u8 = 17;

/// Couche ALE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    ConnectV4,
    RecvAcceptV4,
    ConnectV6,
    RecvAcceptV6,
}

/// Verdict du filtre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Permit,
    Block,
}

/// Condition d'un filtre (toutes combinées par ET).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Condition {
    /// Interface locale différente de ce LUID (`FWPM_CONDITION_IP_LOCAL_INTERFACE`).
    LocalInterfaceNot(u64),
    /// Trafic de bouclage (`FWP_CONDITION_FLAG_IS_LOOPBACK`).
    Loopback,
    /// Protocole IP.
    Protocol(u8),
    /// Port distant (couche connect).
    RemotePort(u16),
    /// Port local (couche recv/accept).
    LocalPort(u16),
    /// Adresse distante exacte (couche connect).
    RemoteAddr(IpAddr),
}

/// Description d'un filtre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterSpec {
    pub(crate) name: String,
    pub(crate) layer: Layer,
    pub(crate) verdict: Verdict,
    pub(crate) weight: u8,
    pub(crate) conditions: Vec<Condition>,
}

fn permit_loopback(layer: Layer) -> FilterSpec {
    FilterSpec {
        name: format!("fortivpn-rs permit loopback {layer:?}"),
        layer,
        verdict: Verdict::Permit,
        weight: WEIGHT_PERMIT,
        conditions: vec![Condition::Loopback],
    }
}

/// Ports `DHCPv4` : serveur (connect) et client (recv/accept).
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

/// Filtres de **protection pendant la reconnexion** (revue 5.3 passe 2, M2) :
/// tant que la session est en `Reconnecting`, tout est bloqué (IPv4 et IPv6,
/// connect et recv/accept) sauf le bouclage, la passerelle VPN (pour se
/// reconnecter) et `DHCPv4` (changement de réseau). Le nouveau tunnel est autorisé
/// en remplaçant cette protection par les filtres de [`plan_filters`] à
/// l'`apply` suivant. Vide hors full-tunnel ou si `enabled` est faux.
pub(crate) fn plan_hold_filters(config: &TunnelConfig, enabled: bool) -> Vec<FilterSpec> {
    if !enabled || !matches!(config.routing, RoutingMode::Full { .. }) {
        return Vec::new();
    }
    let mut out = vec![
        permit_loopback(Layer::ConnectV4),
        permit_loopback(Layer::RecvAcceptV4),
        permit_loopback(Layer::ConnectV6),
        permit_loopback(Layer::RecvAcceptV6),
    ];
    let gateway_layer = if config.gateway.is_ipv4() {
        Layer::ConnectV4
    } else {
        Layer::ConnectV6
    };
    out.push(FilterSpec {
        name: "fortivpn-rs hold permit gateway".into(),
        layer: gateway_layer,
        verdict: Verdict::Permit,
        weight: WEIGHT_PERMIT,
        conditions: vec![Condition::RemoteAddr(config.gateway)],
    });
    out.push(FilterSpec {
        name: "fortivpn-rs hold permit DHCPv4 out".into(),
        layer: Layer::ConnectV4,
        verdict: Verdict::Permit,
        weight: WEIGHT_PERMIT,
        conditions: vec![
            Condition::Protocol(PROTO_UDP),
            Condition::RemotePort(DHCP_SERVER_PORT),
        ],
    });
    out.push(FilterSpec {
        name: "fortivpn-rs hold permit DHCPv4 in".into(),
        layer: Layer::RecvAcceptV4,
        verdict: Verdict::Permit,
        weight: WEIGHT_PERMIT,
        conditions: vec![
            Condition::Protocol(PROTO_UDP),
            Condition::LocalPort(DHCP_CLIENT_PORT),
        ],
    });
    for layer in [
        Layer::ConnectV4,
        Layer::RecvAcceptV4,
        Layer::ConnectV6,
        Layer::RecvAcceptV6,
    ] {
        out.push(FilterSpec {
            name: format!("fortivpn-rs hold block all {layer:?}"),
            layer,
            verdict: Verdict::Block,
            weight: WEIGHT_BLOCK,
            conditions: Vec::new(),
        });
    }
    out
}

/// Filtres à installer. Vide hors full-tunnel ou si `enabled` est faux.
///
/// Full-tunnel : permit loopback (4 couches) ; block de tout l'IPv6 hors
/// interface tunnel (connect + recv/accept) ; block UDP 137/5353/5355 hors
/// tunnel en IPv4 (port distant en connect, port local en recv/accept).
pub(crate) fn plan_filters(
    config: &TunnelConfig,
    tunnel_luid: u64,
    enabled: bool,
) -> Vec<FilterSpec> {
    if !enabled || !matches!(config.routing, RoutingMode::Full { .. }) {
        return Vec::new();
    }
    let not_tunnel = Condition::LocalInterfaceNot(tunnel_luid);
    let mut out = vec![
        permit_loopback(Layer::ConnectV4),
        permit_loopback(Layer::RecvAcceptV4),
        permit_loopback(Layer::ConnectV6),
        permit_loopback(Layer::RecvAcceptV6),
    ];
    for layer in [Layer::ConnectV6, Layer::RecvAcceptV6] {
        out.push(FilterSpec {
            name: format!("fortivpn-rs block IPv6 off-tunnel {layer:?}"),
            layer,
            verdict: Verdict::Block,
            weight: WEIGHT_BLOCK,
            conditions: vec![not_tunnel],
        });
    }
    for port in NAME_RESOLUTION_PORTS {
        for (layer, port_cond) in [
            (Layer::ConnectV4, Condition::RemotePort(port)),
            (Layer::RecvAcceptV4, Condition::LocalPort(port)),
        ] {
            out.push(FilterSpec {
                name: format!("fortivpn-rs block UDP {port} off-tunnel {layer:?}"),
                layer,
                verdict: Verdict::Block,
                weight: WEIGHT_BLOCK,
                conditions: vec![not_tunnel, Condition::Protocol(PROTO_UDP), port_cond],
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::tests::sample;

    const LUID: u64 = 0x0006_0000_1234_0000;

    fn full() -> TunnelConfig {
        let mut c = sample();
        c.routing = RoutingMode::Full {
            exclude: Vec::new(),
        };
        c
    }

    fn split() -> TunnelConfig {
        let mut c = sample();
        c.routing = RoutingMode::Split {
            include: Vec::new(),
        };
        c
    }

    #[test]
    fn nothing_in_split_or_when_disabled() {
        assert!(plan_filters(&split(), LUID, true).is_empty());
        assert!(plan_filters(&full(), LUID, false).is_empty());
    }

    #[test]
    fn full_tunnel_filter_set() {
        let f = plan_filters(&full(), LUID, true);
        assert_eq!(f.len(), 4 + 2 + 6);
        let blocks = || f.iter().filter(|x| x.verdict == Verdict::Block);
        // IPv6 : bloqué dans les deux sens, sur toute interface autre que le tunnel.
        for layer in [Layer::ConnectV6, Layer::RecvAcceptV6] {
            assert!(
                blocks()
                    .any(|x| x.layer == layer
                        && x.conditions == [Condition::LocalInterfaceNot(LUID)])
            );
        }
        // Chaque port de résolution de noms, en UDP, hors tunnel.
        for port in NAME_RESOLUTION_PORTS {
            assert!(blocks().any(|x| x.layer == Layer::ConnectV4
                && x.conditions.contains(&Condition::RemotePort(port))
                && x.conditions.contains(&Condition::Protocol(PROTO_UDP))));
            assert!(blocks().any(|x| x.layer == Layer::RecvAcceptV4
                && x.conditions.contains(&Condition::LocalPort(port))));
        }
        // Tout block exclut le tunnel lui-même.
        assert!(blocks().all(|x| x.conditions.contains(&Condition::LocalInterfaceNot(LUID))));
    }

    #[test]
    fn loopback_permits_outweigh_blocks_on_every_layer() {
        let f = plan_filters(&full(), LUID, true);
        for layer in [
            Layer::ConnectV4,
            Layer::RecvAcceptV4,
            Layer::ConnectV6,
            Layer::RecvAcceptV6,
        ] {
            let p = f
                .iter()
                .find(|x| x.layer == layer && x.verdict == Verdict::Permit)
                .expect("permit loopback");
            assert_eq!(p.conditions, [Condition::Loopback]);
            assert!(
                f.iter()
                    .filter(|x| x.verdict == Verdict::Block)
                    .all(|b| b.weight < p.weight)
            );
        }
    }

    #[test]
    fn hold_nothing_in_split_or_when_disabled() {
        assert!(plan_hold_filters(&split(), true).is_empty());
        assert!(plan_hold_filters(&full(), false).is_empty());
    }

    #[test]
    fn hold_blocks_everything_but_loopback_gateway_and_dhcp() {
        let c = full();
        let f = plan_hold_filters(&c, true);
        let blocks: Vec<_> = f.iter().filter(|x| x.verdict == Verdict::Block).collect();
        // Un bloc sans condition par couche : rien ne passe hors permits.
        assert_eq!(blocks.len(), 4);
        assert!(
            blocks
                .iter()
                .all(|b| b.conditions.is_empty() && b.weight == WEIGHT_BLOCK)
        );
        let permits: Vec<_> = f.iter().filter(|x| x.verdict == Verdict::Permit).collect();
        assert!(
            permits
                .iter()
                .all(|p| p.weight == WEIGHT_PERMIT && p.weight > WEIGHT_BLOCK)
        );
        // Passerelle autorisée, et elle seule comme adresse.
        let gw: Vec<_> = permits
            .iter()
            .filter(|p| p.conditions.contains(&Condition::RemoteAddr(c.gateway)))
            .collect();
        assert_eq!(gw.len(), 1);
        assert_eq!(gw[0].layer, Layer::ConnectV4);
        // Bouclage sur les 4 couches ; DHCP en IPv4 seulement.
        assert_eq!(
            permits
                .iter()
                .filter(|p| p.conditions == [Condition::Loopback])
                .count(),
            4
        );
        assert!(
            permits.iter().any(|p| p.layer == Layer::RecvAcceptV4
                && p.conditions.contains(&Condition::LocalPort(68)))
        );
        assert_eq!(permits.len(), 4 + 1 + 2);
    }

    #[test]
    fn hold_gateway_permit_follows_address_family() {
        let mut c = full();
        c.gateway = "2001:db8::1".parse().unwrap();
        let f = plan_hold_filters(&c, true);
        assert!(
            f.iter().any(|x| x.layer == Layer::ConnectV6
                && x.conditions == [Condition::RemoteAddr(c.gateway)])
        );
    }

    #[test]
    fn weights_fit_wfp_uint8_range() {
        const { assert!(WEIGHT_PERMIT <= 15 && WEIGHT_BLOCK < WEIGHT_PERMIT) };
    }
}
