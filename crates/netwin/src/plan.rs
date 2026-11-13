//! Calculs purs (sans appel système) : plan de routes, plan DNS / NRPT,
//! encodages de chaînes Windows.
//!
//! Compilé et testé sur toutes les plateformes (`cargo test -p netwin`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use fortivpn_core::{NetError, RoutingMode, TunnelConfig};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Métrique d'interface du tunnel (basse : préférée aux interfaces physiques,
/// dont la métrique automatique vaut typiquement 25 à 55).
pub(crate) const TUNNEL_INTERFACE_METRIC: u32 = 1;

/// Métrique des routes installées (s'ajoute à la métrique d'interface).
pub(crate) const ROUTE_METRIC: u32 = 0;

/// Préfixe des noms de règles NRPT créées par fortivpn-rs.
///
/// Les règles NRPT locales sont des sous-clés de
/// `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`,
/// conventionnellement nommées par un GUID entre accolades (c'est ce que crée
/// `Add-DnsClientNrptRule`). On garde cette forme pour la compatibilité, avec
/// un préfixe fixe reconnaissable : `666f7274-6976-706e-2d72-73` est l'ASCII
/// hexadécimal de `fortivpn-rs`. Le suffixe est un index sur 10 chiffres hexa.
pub const NRPT_RULE_PREFIX: &str = "{666f7274-6976-706e-2d72-73";

/// Valeur `DisplayName` / `Comment` posée sur nos règles NRPT.
pub(crate) const NRPT_DISPLAY_NAME: &str = "fortivpn-rs";

/// Nombre maximal d'espaces de noms par règle NRPT (au-delà : règles multiples).
pub(crate) const NRPT_MAX_NAMESPACES_PER_RULE: usize = 50;

/// Espace de noms NRPT « tous les noms ».
pub(crate) const NRPT_ANY_NAMESPACE: &str = ".";

/// Nom de la DLL Wintun, à livrer à côté de l'exécutable.
pub const WINTUN_DLL_NAME: &str = "wintun.dll";

/// Longueur maximale d'un nom d'adaptateur Wintun (`MAX_ADAPTER_NAME` - 1, en
/// unités UTF-16).
const MAX_ADAPTER_NAME_LEN: usize = 127;

/// Chemin de `wintun.dll` à côté de l'exécutable `exe`.
pub(crate) fn wintun_path_next_to(exe: &Path) -> PathBuf {
    exe.parent()
        .unwrap_or_else(|| Path::new(""))
        .join(WINTUN_DLL_NAME)
}

/// Vérifie un nom d'adaptateur Wintun.
pub(crate) fn check_adapter_name(name: &str) -> Result<(), NetError> {
    let len = name.encode_utf16().count();
    if len == 0 || len > MAX_ADAPTER_NAME_LEN || name.contains('\0') {
        return Err(NetError::Os {
            op: "create_tun",
            reason: format!("nom d'interface invalide (1 à {MAX_ADAPTER_NAME_LEN} caractères)"),
        });
    }
    Ok(())
}

/// Chemin d'une route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    /// Via l'interface du tunnel (on-link).
    Tunnel,
    /// Via la route d'origine (interface physique + passerelle d'origine),
    /// résolue par `GetBestRoute2` avant toute installation de route tunnel.
    Underlay,
}

/// Route à installer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlannedRoute {
    pub(crate) dest: Ipv4Net,
    pub(crate) via: Via,
}

/// Rejette ce que ce backend ne sait pas appliquer.
pub(crate) fn check_supported(config: &TunnelConfig) -> Result<(), NetError> {
    config.validate()?;
    if config.ipv6.is_some() {
        return Err(NetError::Unsupported("IPv6"));
    }
    if config.gateway.is_ipv6() {
        return Err(NetError::Unsupported("passerelle IPv6"));
    }
    Ok(())
}

fn v4(net: &IpNet) -> Result<Ipv4Net, NetError> {
    match net {
        IpNet::V4(n) => Ok(n.trunc()),
        IpNet::V6(_) => Err(NetError::Unsupported("route IPv6")),
    }
}

/// Les deux moitiés de l'espace IPv4 : plus spécifiques que la route par
/// défaut d'origine, qu'elles masquent sans la supprimer.
fn halves() -> [Ipv4Net; 2] {
    [
        Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 1),
        Ipv4Net::new_assert(Ipv4Addr::new(128, 0, 0, 0), 1),
    ]
}

/// Plan de routes, dans l'ordre d'installation :
///
/// 1. `/32` vers la passerelle via la route d'origine (toujours) ;
/// 2. full-tunnel : exclusions via la route d'origine, **avant** les routes
///    tunnel (pas de fenêtre où le trafic exclu partirait dans le tunnel) ;
/// 3. routes tunnel : inclusions (split) ou `0.0.0.0/1` + `128.0.0.0/1` (full).
///    Une inclusion `0.0.0.0/0` est remplacée par les deux moitiés ;
/// 4. `/32` via le tunnel vers chaque serveur DNS IPv4 du tunnel (revue 5.3,
///    M2) : sans elle, une inclusion manquante, une exclusion, ou un réseau
///    on-link plus spécifique de la carte physique enverrait les requêtes DNS
///    internes en clair. Ajoutée **toujours** (et non seulement hors
///    inclusion) car une inclusion `10.0.0.0/8` ne l'emporte pas sur un réseau
///    local `10.1.0.0/16` on-link. Une exclusion `/32` identique est retirée.
///    Exception : serveur DNS = passerelle VPN (sa `/32` doit rester hors
///    tunnel) → avertissement ; adresses non routables ignorées.
///
/// Les préfixes sont normalisés (bits d'hôte à zéro) et dédupliqués.
pub(crate) fn plan_routes(config: &TunnelConfig) -> Result<Vec<PlannedRoute>, NetError> {
    let IpAddr::V4(gateway) = config.gateway else {
        return Err(NetError::Unsupported("passerelle IPv6"));
    };
    let mut plan = vec![PlannedRoute {
        dest: Ipv4Net::from(gateway),
        via: Via::Underlay,
    }];
    match &config.routing {
        RoutingMode::Split { include } => {
            for net in include {
                let net = v4(net)?;
                if net.prefix_len() == 0 {
                    plan.extend(halves().map(|dest| PlannedRoute {
                        dest,
                        via: Via::Tunnel,
                    }));
                } else {
                    plan.push(PlannedRoute {
                        dest: net,
                        via: Via::Tunnel,
                    });
                }
            }
        }
        RoutingMode::Full { exclude } => {
            for net in exclude {
                plan.push(PlannedRoute {
                    dest: v4(net)?,
                    via: Via::Underlay,
                });
            }
            plan.extend(halves().map(|dest| PlannedRoute {
                dest,
                via: Via::Tunnel,
            }));
        }
    }
    for server in dns_servers_v4(config) {
        if server == gateway {
            tracing::warn!(
                %server,
                "serveur DNS = passerelle VPN : requêtes DNS hors tunnel (non chiffrées par le VPN)"
            );
            continue;
        }
        if !is_routable_unicast(server) || server == config.ipv4.address.addr() {
            tracing::warn!(%server, "serveur DNS non routable : pas de route dédiée");
            continue;
        }
        let dest = Ipv4Net::from(server);
        let before = plan.len();
        plan.retain(|r| !(r.dest == dest && r.via == Via::Underlay));
        if plan.len() != before {
            tracing::warn!(%server, "exclusion du serveur DNS ignorée : DNS via le tunnel");
        }
        plan.push(PlannedRoute {
            dest,
            via: Via::Tunnel,
        });
    }
    let mut seen = Vec::with_capacity(plan.len());
    plan.retain(|r| {
        if seen.contains(&r.dest) {
            false
        } else {
            seen.push(r.dest);
            true
        }
    });
    Ok(plan)
}

/// Serveurs DNS IPv4 du tunnel, dédupliqués, dans l'ordre.
fn dns_servers_v4(config: &TunnelConfig) -> Vec<Ipv4Addr> {
    let mut servers = Vec::new();
    for s in &config.dns.servers {
        if let IpAddr::V4(a) = s {
            if !servers.contains(a) {
                servers.push(*a);
            }
        }
    }
    servers
}

/// Adresse unicast routable (ni non spécifiée, ni loopback, ni multicast,
/// ni diffusion, ni lien-local).
fn is_routable_unicast(a: Ipv4Addr) -> bool {
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_link_local())
}

/// Routes IPv6 à installer sur l'interface du tunnel (revue 5.3, E2,
/// variante minimale) : en full-tunnel, `::/1` + `8000::/1` (plus spécifiques
/// que toute route par défaut IPv6, y compris annoncée par un faux RA) ; les
/// paquets IPv6 qui y arrivent sont abandonnés par le relais Wintun (le
/// tunnel ne transporte que de l'IPv4). Rien en split-tunnel.
///
/// Limites : un préfixe on-link IPv6 de la carte physique (plus spécifique)
/// reste joignable hors tunnel, comme le réseau local IPv4. Le blocage
/// complet passe par des filtres WFP (story à proposer).
pub(crate) fn plan_ipv6_block(config: &TunnelConfig) -> Vec<Ipv6Net> {
    match config.routing {
        RoutingMode::Split { .. } => Vec::new(),
        RoutingMode::Full { .. } => vec![
            Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 1),
            Ipv6Net::new_assert(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1),
        ],
    }
}

/// Règle NRPT à créer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NrptRule {
    /// Nom de la sous-clé de registre (préfixé par [`NRPT_RULE_PREFIX`]).
    pub(crate) name: String,
    /// Espaces de noms (`corp.example` exact, `.corp.example` suffixe, `.` tout).
    pub(crate) namespaces: Vec<String>,
    /// Serveurs DNS du tunnel.
    pub(crate) servers: Vec<Ipv4Addr>,
}

/// Plan DNS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DnsPlan {
    /// Serveurs DNS IPv4 posés sur l'interface du tunnel.
    pub(crate) servers: Vec<Ipv4Addr>,
    /// Liste de recherche posée sur l'interface du tunnel.
    pub(crate) search: Vec<String>,
    /// Règles NRPT.
    pub(crate) nrpt: Vec<NrptRule>,
}

impl DnsPlan {
    /// Vrai si quelque chose est à poser sur l'interface.
    pub(crate) fn has_interface_settings(&self) -> bool {
        !self.servers.is_empty() || !self.search.is_empty()
    }
}

/// Normalise un nom de domaine (minuscules, sans point initial/final) et
/// rejette tout ce qui n'est pas un nom DNS ASCII plausible : ces chaînes
/// finissent dans des listes séparées par `,`/`;` et des `REG_MULTI_SZ`.
pub(crate) fn normalize_domain(raw: &str) -> Option<String> {
    let d = raw.trim().trim_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 {
        return None;
    }
    let ok = d.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then_some(d)
}

/// Nom de la `index`-ième règle NRPT.
pub(crate) fn nrpt_rule_name(index: usize) -> String {
    format!("{NRPT_RULE_PREFIX}{index:010x}}}")
}

/// Vrai si `name` est une règle NRPT créée par fortivpn-rs (insensible à la
/// casse, forme complète vérifiée : jamais de suppression d'une règle tierce).
pub(crate) fn is_our_nrpt_rule(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix(NRPT_RULE_PREFIX) else {
        return false;
    };
    let Some(hex) = rest.strip_suffix('}') else {
        return false;
    };
    hex.len() == 10 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Plan DNS :
///
/// - serveurs IPv4 et domaines de recherche toujours posés sur l'interface
///   (les serveurs IPv6 sont ignorés : IPv6 non pris en charge) ;
/// - split-tunnel avec domaines : règles NRPT (nom exact + suffixe) vers les
///   serveurs du tunnel, pour que les noms internes ne partent jamais vers le
///   DNS de l'interface physique ;
/// - full-tunnel : règle NRPT `.` (tous les noms) vers les serveurs du tunnel,
///   contre les fuites DNS de la résolution multi-interface de Windows.
pub(crate) fn plan_dns(config: &TunnelConfig) -> DnsPlan {
    for s in config.dns.servers.iter().filter(|s| s.is_ipv6()) {
        tracing::warn!(server = %s, "serveur DNS IPv6 ignoré");
    }
    let servers = dns_servers_v4(config);
    let mut search: Vec<String> = Vec::new();
    for raw in &config.dns.search_domains {
        match normalize_domain(raw) {
            Some(d) if !search.contains(&d) => search.push(d),
            Some(_) => {}
            None => tracing::warn!(domain = %raw, "domaine DNS invalide ignoré"),
        }
    }

    let namespaces: Vec<String> = if servers.is_empty() {
        Vec::new()
    } else {
        match config.routing {
            RoutingMode::Split { .. } => search
                .iter()
                .flat_map(|d| [d.clone(), format!(".{d}")])
                .collect(),
            RoutingMode::Full { .. } => vec![NRPT_ANY_NAMESPACE.to_owned()],
        }
    };
    let nrpt = namespaces
        .chunks(NRPT_MAX_NAMESPACES_PER_RULE)
        .enumerate()
        .map(|(i, chunk)| NrptRule {
            name: nrpt_rule_name(i),
            namespaces: chunk.to_vec(),
            servers: servers.clone(),
        })
        .collect();

    DnsPlan {
        servers,
        search,
        nrpt,
    }
}

fn join<T: ToString>(items: &[T], sep: &str) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(sep)
}

/// `NameServer` de `DNS_INTERFACE_SETTINGS` : adresses séparées par des virgules.
pub(crate) fn interface_servers_value(servers: &[Ipv4Addr]) -> String {
    join(servers, ",")
}

/// `SearchList` de `DNS_INTERFACE_SETTINGS` : domaines séparés par des virgules.
pub(crate) fn interface_search_value(domains: &[String]) -> String {
    join(domains, ",")
}

/// `GenericDNSServers` d'une règle NRPT : adresses séparées par `;`.
pub(crate) fn nrpt_servers_value(servers: &[Ipv4Addr]) -> String {
    join(servers, ";")
}

/// Chaîne UTF-16 terminée par un NUL (`PCWSTR`, `REG_SZ`).
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `REG_MULTI_SZ` : chaînes terminées par NUL, liste terminée par un NUL
/// supplémentaire. Liste vide : deux NUL.
pub(crate) fn to_multi_sz<S: AsRef<str>>(items: &[S]) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for s in items {
        out.extend(s.as_ref().encode_utf16());
        out.push(0);
    }
    if out.is_empty() {
        out.push(0);
    }
    out.push(0);
    out
}

/// Octets little-endian d'une chaîne UTF-16 (données de `RegSetValueExW`).
pub(crate) fn wide_bytes(wide: &[u16]) -> Vec<u8> {
    wide.iter().flat_map(|c| c.to_le_bytes()).collect()
}

/// GUID déterministe de l'adaptateur Wintun pour un nom donné : Windows
/// rattache le profil réseau au GUID, un GUID stable évite d'accumuler des
/// « Réseau 2, 3… ». Hachage FNV-1a 128 bits, bits version (8, « custom »,
/// RFC 9562) et variante posés.
pub(crate) fn adapter_guid(name: &str) -> u128 {
    const OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    let mut h = OFFSET;
    for b in "fortivpn-rs:".bytes().chain(name.bytes()) {
        h ^= u128::from(b);
        h = h.wrapping_mul(PRIME);
    }
    // Version (bits 76..80) = 8, variante (bits 62..64) = 0b10.
    h = (h & !(0xf << 76)) | (0x8 << 76);
    (h & !(0b11 << 62)) | (0b10 << 62)
}

#[cfg(test)]
pub(crate) mod tests {
    use fortivpn_core::{DnsConfig, Ipv4Config, Ipv6Config};

    use super::*;

    /// Configuration de référence (même forme que celle de `core`).
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

    fn r(dest: &str, via: Via) -> PlannedRoute {
        PlannedRoute {
            dest: dest.parse().unwrap(),
            via,
        }
    }

    #[test]
    fn split_plan_starts_with_gateway_route() {
        assert_eq!(
            plan_routes(&sample()).unwrap(),
            vec![
                r("203.0.113.10/32", Via::Underlay),
                r("10.0.0.0/8", Via::Tunnel),
                r("10.0.0.53/32", Via::Tunnel),
            ]
        );
    }

    #[test]
    fn full_plan_installs_exclusions_before_halves() {
        let mut c = sample();
        c.routing = RoutingMode::Full {
            exclude: vec!["192.168.1.0/24".parse().unwrap()],
        };
        assert_eq!(
            plan_routes(&c).unwrap(),
            vec![
                r("203.0.113.10/32", Via::Underlay),
                r("192.168.1.0/24", Via::Underlay),
                r("0.0.0.0/1", Via::Tunnel),
                r("128.0.0.0/1", Via::Tunnel),
                r("10.0.0.53/32", Via::Tunnel),
            ]
        );
    }

    #[test]
    fn split_default_route_becomes_halves_and_prefixes_are_normalized() {
        let mut c = sample();
        c.routing = RoutingMode::Split {
            include: vec![
                "0.0.0.0/0".parse().unwrap(),
                "10.1.2.3/16".parse().unwrap(),
                "10.1.0.0/16".parse().unwrap(),
                "203.0.113.10/32".parse().unwrap(),
            ],
        };
        assert_eq!(
            plan_routes(&c).unwrap(),
            vec![
                r("203.0.113.10/32", Via::Underlay),
                r("0.0.0.0/1", Via::Tunnel),
                r("128.0.0.0/1", Via::Tunnel),
                r("10.1.0.0/16", Via::Tunnel),
                r("10.0.0.53/32", Via::Tunnel),
            ],
            "doublons retirés, la route passerelle (underlay) l'emporte"
        );
    }

    #[test]
    fn dns_servers_always_get_a_tunnel_route() {
        // Split : serveur hors des inclusions.
        let mut c = sample();
        c.dns.servers = vec![
            "172.16.0.53".parse().unwrap(),
            "fd00::53".parse().unwrap(),
            "172.16.0.53".parse().unwrap(),
        ];
        assert_eq!(
            plan_routes(&c).unwrap(),
            vec![
                r("203.0.113.10/32", Via::Underlay),
                r("10.0.0.0/8", Via::Tunnel),
                r("172.16.0.53/32", Via::Tunnel),
            ]
        );

        // Split : inclusion /32 identique → pas de doublon.
        let mut c = sample();
        c.routing = RoutingMode::Split {
            include: vec!["10.0.0.53/32".parse().unwrap()],
        };
        assert_eq!(
            plan_routes(&c).unwrap(),
            vec![
                r("203.0.113.10/32", Via::Underlay),
                r("10.0.0.53/32", Via::Tunnel),
            ]
        );

        // Full : serveur dans une exclusion, et exclusion /32 identique retirée.
        let mut c = sample();
        c.dns.servers = vec!["192.168.1.53".parse().unwrap(), "10.9.9.9".parse().unwrap()];
        c.routing = RoutingMode::Full {
            exclude: vec![
                "192.168.1.0/24".parse().unwrap(),
                "10.9.9.9/32".parse().unwrap(),
            ],
        };
        assert_eq!(
            plan_routes(&c).unwrap(),
            vec![
                r("203.0.113.10/32", Via::Underlay),
                r("192.168.1.0/24", Via::Underlay),
                r("0.0.0.0/1", Via::Tunnel),
                r("128.0.0.0/1", Via::Tunnel),
                r("192.168.1.53/32", Via::Tunnel),
                r("10.9.9.9/32", Via::Tunnel),
            ]
        );
    }

    #[test]
    fn dns_server_equal_to_gateway_or_unroutable_gets_no_route() {
        let mut c = sample();
        c.dns.servers = vec![
            "203.0.113.10".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            "224.0.0.251".parse().unwrap(),
            "169.254.1.1".parse().unwrap(),
            "10.212.134.200".parse().unwrap(),
        ];
        assert_eq!(
            plan_routes(&c).unwrap(),
            vec![
                r("203.0.113.10/32", Via::Underlay),
                r("10.0.0.0/8", Via::Tunnel),
            ],
            "la /32 passerelle reste hors tunnel"
        );
    }

    #[test]
    fn ipv6_block_only_in_full_tunnel() {
        assert!(plan_ipv6_block(&sample()).is_empty());
        let mut c = sample();
        c.routing = RoutingMode::Full { exclude: vec![] };
        assert_eq!(
            plan_ipv6_block(&c),
            vec![
                "::/1".parse::<Ipv6Net>().unwrap(),
                "8000::/1".parse().unwrap()
            ]
        );
    }

    #[test]
    fn ipv6_is_unsupported() {
        let mut c = sample();
        c.ipv6 = Some(Ipv6Config {
            address: "fd00::2/64".parse().unwrap(),
            peer: None,
        });
        assert!(matches!(check_supported(&c), Err(NetError::Unsupported(_))));

        let mut c = sample();
        c.gateway = "2001:db8::1".parse().unwrap();
        assert!(matches!(check_supported(&c), Err(NetError::Unsupported(_))));
        assert!(matches!(plan_routes(&c), Err(NetError::Unsupported(_))));

        let mut c = sample();
        c.mtu = 100;
        assert!(matches!(
            check_supported(&c),
            Err(NetError::InvalidConfig(_))
        ));
        assert!(check_supported(&sample()).is_ok());
    }

    #[test]
    fn domains_are_normalized_and_validated() {
        assert_eq!(
            normalize_domain(" .Corp.Example. "),
            Some("corp.example".into())
        );
        assert_eq!(normalize_domain("a_b.example"), Some("a_b.example".into()));
        for bad in ["", ".", "a..b", "a,b", "a;b", "a\0b", "é.fr", "a b"] {
            assert_eq!(normalize_domain(bad), None, "{bad:?}");
        }
        assert_eq!(normalize_domain(&"a".repeat(64)), None);
    }

    #[test]
    fn split_dns_plan_uses_nrpt_for_domains() {
        let mut c = sample();
        c.dns.servers.push("fd00::53".parse().unwrap());
        c.dns.servers.push("10.0.0.53".parse().unwrap());
        c.dns.search_domains = vec!["Corp.Example".into(), "corp.example.".into(), "x;y".into()];
        let plan = plan_dns(&c);
        assert_eq!(plan.servers, vec![Ipv4Addr::new(10, 0, 0, 53)]);
        assert_eq!(plan.search, vec!["corp.example".to_owned()]);
        assert_eq!(
            plan.nrpt,
            vec![NrptRule {
                name: nrpt_rule_name(0),
                namespaces: vec!["corp.example".into(), ".corp.example".into()],
                servers: vec![Ipv4Addr::new(10, 0, 0, 53)],
            }]
        );
        assert!(plan.has_interface_settings());
    }

    #[test]
    fn full_dns_plan_uses_catch_all_rule() {
        let mut c = sample();
        c.routing = RoutingMode::Full { exclude: vec![] };
        let plan = plan_dns(&c);
        assert_eq!(plan.nrpt.len(), 1);
        assert_eq!(plan.nrpt[0].namespaces, vec![".".to_owned()]);
    }

    #[test]
    fn no_servers_means_no_nrpt() {
        let mut c = sample();
        c.dns.servers.clear();
        let plan = plan_dns(&c);
        assert!(plan.nrpt.is_empty());
        assert!(plan.has_interface_settings(), "domaines de recherche seuls");
        c.dns.search_domains.clear();
        assert!(!plan_dns(&c).has_interface_settings());
    }

    #[test]
    fn many_domains_are_split_across_rules() {
        let mut c = sample();
        c.dns.search_domains = (0..30).map(|i| format!("d{i}.example")).collect();
        let plan = plan_dns(&c);
        assert_eq!(plan.nrpt.len(), 2);
        assert_eq!(plan.nrpt[0].namespaces.len(), NRPT_MAX_NAMESPACES_PER_RULE);
        assert_eq!(plan.nrpt[1].namespaces.len(), 10);
        assert_eq!(plan.nrpt[1].name, nrpt_rule_name(1));
    }

    #[test]
    fn nrpt_rule_names_are_recognized() {
        let name = nrpt_rule_name(3);
        assert_eq!(name, "{666f7274-6976-706e-2d72-730000000003}");
        assert_eq!(name.len(), 38, "forme GUID {{8-4-4-4-12}}");
        assert!(is_our_nrpt_rule(&name));
        assert!(is_our_nrpt_rule(&name.to_ascii_uppercase()));
        assert!(!is_our_nrpt_rule("{12345678-1234-1234-1234-123456789abc}"));
        assert!(!is_our_nrpt_rule(&format!("{NRPT_RULE_PREFIX}0000000003")));
        assert!(!is_our_nrpt_rule(&format!(
            "{NRPT_RULE_PREFIX}00000000zz}}"
        )));
        assert!(!is_our_nrpt_rule(&format!("{NRPT_RULE_PREFIX}0}}")));
    }

    #[test]
    fn value_encodings() {
        let s = [Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)];
        assert_eq!(interface_servers_value(&s), "10.0.0.53,10.0.0.54");
        assert_eq!(nrpt_servers_value(&s), "10.0.0.53;10.0.0.54");
        assert_eq!(
            interface_search_value(&["a.example".into(), "b.example".into()]),
            "a.example,b.example"
        );
        assert_eq!(to_wide("ab"), vec![97, 98, 0]);
        assert_eq!(to_multi_sz(&["a", "bc"]), vec![97, 0, 98, 99, 0, 0]);
        assert_eq!(to_multi_sz::<&str>(&[]), vec![0, 0]);
        assert_eq!(wide_bytes(&[0x0061, 0x0100]), vec![0x61, 0, 0, 1]);
    }

    #[test]
    fn adapter_name_and_dll_path() {
        assert!(check_adapter_name("fortivpn").is_ok());
        assert!(check_adapter_name("").is_err());
        assert!(check_adapter_name("a\0b").is_err());
        assert!(check_adapter_name(&"x".repeat(127)).is_ok());
        assert!(check_adapter_name(&"x".repeat(128)).is_err());
        assert_eq!(
            wintun_path_next_to(Path::new("/opt/fortivpn/fortivpn.exe")),
            PathBuf::from("/opt/fortivpn/wintun.dll")
        );
    }

    #[test]
    fn adapter_guid_is_stable_and_well_formed() {
        let g = adapter_guid("fortivpn");
        assert_eq!(g, adapter_guid("fortivpn"));
        assert_ne!(g, adapter_guid("fortivpn2"));
        assert_eq!((g >> 76) & 0xf, 0x8, "version");
        assert_eq!((g >> 62) & 0b11, 0b10, "variante");
    }
}
