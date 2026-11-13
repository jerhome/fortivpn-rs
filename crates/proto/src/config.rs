//! Configuration XML `GET /remote/fortisslvpn_xml` (`docs/protocol.md` §5).
//!
//! Parseur `quick-xml` tolérant (éléments et attributs inconnus ignorés) mais strict sur
//! les valeurs des attributs connus de la section IPv4 (adresses, masques contigus,
//! noms de domaine) : une valeur invalide fait échouer l'analyse plutôt que de produire
//! une configuration réseau partielle. La section `<ipv6>` (hors MVP) est analysée de
//! façon permissive : une entrée invalide y est ignorée.
//!
//! Aucune entité externe n'est résolue : seules les entités prédéfinies XML et les
//! références numériques sont acceptées ; une DTD éventuelle est ignorée.
//!
//! Écarts volontaires avec openfortivpn (§5.3) : **tous** les blocs
//! `<split-tunnel-info>` sont lus (et pas seulement le premier), et l'attribut
//! `negate="1"` est respecté (préfixes à exclure du tunnel) ; tous les `@domain` sont
//! agrégés ; pas de limite de 255 caractères.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};

/// Erreur d'analyse de la configuration XML.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum XmlConfigError {
    /// Le document n'est pas en UTF-8.
    #[error("configuration XML : encodage non UTF-8")]
    NotUtf8,
    /// XML mal formé.
    #[error("configuration XML mal formée : {0}")]
    Xml(String),
    /// La racine n'est pas `<sslvpn-tunnel>` (ex. page HTML de login : cookie expiré).
    #[error("la réponse n'est pas une configuration <sslvpn-tunnel>")]
    NotSslvpnTunnel,
    /// Valeur d'attribut invalide.
    #[error("configuration XML : valeur invalide pour <{element} {attribute}>")]
    InvalidValue {
        /// Élément concerné.
        element: String,
        /// Attribut concerné.
        attribute: &'static str,
    },
    /// Trop d'entrées (routes, domaines ou DNS) : configuration hostile ou aberrante.
    #[error("configuration XML : trop de {what} (maximum {max})")]
    TooMany {
        /// Nature des entrées.
        what: &'static str,
        /// Maximum accepté.
        max: usize,
    },
}

/// Nombre maximal de routes (include + exclude, IPv4 + IPv6).
pub const MAX_ROUTES: usize = 1024;
/// Nombre maximal de domaines (suffixes + split-dns, IPv4 + IPv6).
pub const MAX_DOMAINS: usize = 64;
/// Nombre maximal de serveurs DNS par famille d'adresses.
pub const MAX_DNS: usize = 8;

/// Configuration de session extraite du XML.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VpnConfig {
    /// Attribut `dtls` de la racine (DTLS proposé par la passerelle, hors périmètre).
    pub dtls: bool,
    /// Valeurs des `<tunnel-method value>` (`ppp`, `tun`).
    pub tunnel_methods: Vec<String>,
    /// Version FortiOS annoncée (`<fos>`), à titre informatif.
    pub fos: Option<FosVersion>,
    /// `<auth-ses>` : reconnexion sans ré-authentification (§10.3).
    pub auth_session: Option<AuthSession>,
    /// Section `<ipv4>`.
    pub ipv4: Ipv4Settings,
    /// Section `<ipv6>` (hors MVP), si présente.
    pub ipv6: Option<Ipv6Settings>,
    /// `<idle-timeout val>` en secondes.
    pub idle_timeout: Option<u32>,
    /// `<auth-timeout val>` en secondes.
    pub auth_timeout: Option<u32>,
}

impl VpnConfig {
    /// Split-tunnel si au moins une route **incluse** IPv4 est annoncée (§5.3) ; sinon
    /// full-tunnel.
    pub fn is_split_tunnel(&self) -> bool {
        !self.ipv4.include_routes.is_empty()
    }
}

/// Version FortiOS (`<fos>`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FosVersion {
    /// `@platform`.
    pub platform: String,
    /// `@major`.
    pub major: String,
    /// `@minor`.
    pub minor: String,
    /// `@patch`.
    pub patch: String,
    /// `@build`.
    pub build: String,
}

/// `<auth-ses>` (§5.2, §10.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthSession {
    /// `@check-src-ip`.
    pub check_src_ip: bool,
    /// `@tun-connect-without-reauth`.
    pub tun_connect_without_reauth: bool,
    /// `@tun-user-ses-timeout` en secondes.
    pub tun_user_ses_timeout: Option<u32>,
}

/// `<split-dns>` : domaines résolus par des serveurs dédiés.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SplitDns {
    /// `@domains` (liste séparée par `,`).
    pub domains: Vec<String>,
    /// `@dnsserver1..9`, dans l'ordre.
    pub servers: Vec<IpAddr>,
}

/// Section `<ipv4>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ipv4Settings {
    /// `<assigned-addr ipv4>` (contrôle de cohérence ; IPCP fait foi).
    pub assigned_addr: Option<Ipv4Addr>,
    /// `<dns ip>` dans l'ordre (priorité), dédupliqués.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Tous les `<dns domain>`, dédupliqués, ordre d'apparition.
    pub dns_suffixes: Vec<String>,
    /// `<split-dns>`.
    pub split_dns: Vec<SplitDns>,
    /// Préfixes des `<split-tunnel-info>` sans `negate="1"` (via le tunnel).
    pub include_routes: Vec<Ipv4Net>,
    /// Préfixes des `<split-tunnel-info negate="1">` (exclus du tunnel).
    pub exclude_routes: Vec<Ipv4Net>,
}

/// Section `<ipv6>` (hors MVP).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ipv6Settings {
    /// `<assigned-addr ipv6 prefix-len>`.
    pub assigned_addr: Option<Ipv6Net>,
    /// `<dns ipv6>`.
    pub dns_servers: Vec<Ipv6Addr>,
    /// `<dns domain>`.
    pub dns_suffixes: Vec<String>,
    /// Routes incluses.
    pub include_routes: Vec<Ipv6Net>,
    /// Routes exclues (`negate="1"`).
    pub exclude_routes: Vec<Ipv6Net>,
}

type Attrs = Vec<(String, String)>;

fn get<'a>(attrs: &'a Attrs, key: &str) -> Option<&'a str> {
    attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.trim())
}

fn invalid(element: &str, attribute: &'static str) -> XmlConfigError {
    XmlConfigError::InvalidValue {
        element: element.to_owned(),
        attribute,
    }
}

fn parse_bool(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "1" | "on" | "true" | "yes")
}

fn parse_u32(
    attrs: &Attrs,
    element: &str,
    key: &'static str,
) -> Result<Option<u32>, XmlConfigError> {
    get(attrs, key)
        .map(|v| v.parse::<u32>().map_err(|_| invalid(element, key)))
        .transpose()
}

/// Masque pointé contigu -> longueur de préfixe (§5.3 : masques non contigus refusés).
fn mask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let m = u32::from(mask);
    let ones = m.leading_ones();
    (ones + m.trailing_zeros() >= 32)
        .then(|| u8::try_from(ones).ok())
        .flatten()
}

/// Valide un nom de domaine (évite toute injection dans resolv.conf / NRPT).
fn valid_domain(d: &str) -> bool {
    let d = d.strip_suffix('.').unwrap_or(d);
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
}

/// Découpe une liste de domaines (`,`, `;` ou blancs, §5.3 [NV]) et l'ajoute à `out`
/// sans doublon (insensible à la casse).
fn push_domains(
    out: &mut Vec<String>,
    list: &str,
    element: &str,
    attribute: &'static str,
    strict: bool,
) -> Result<(), XmlConfigError> {
    let mut seen: std::collections::HashSet<String> =
        out.iter().map(|x| x.to_ascii_lowercase()).collect();
    for d in list
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        if !valid_domain(d) {
            if strict {
                return Err(invalid(element, attribute));
            }
            continue;
        }
        let d = d.strip_suffix('.').unwrap_or(d);
        if seen.insert(d.to_ascii_lowercase()) {
            if out.len() >= MAX_DOMAINS {
                return Err(XmlConfigError::TooMany {
                    what: "domaines",
                    max: MAX_DOMAINS,
                });
            }
            out.push(d.to_owned());
        }
    }
    Ok(())
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, x: T) {
    if !v.contains(&x) {
        v.push(x);
    }
}

#[derive(Debug, Default)]
struct Builder {
    cfg: VpnConfig,
    /// `negate` du `<split-tunnel-info>` ouvert.
    negate: bool,
}

impl Builder {
    fn element(
        &mut self,
        name: &str,
        path: &[String],
        attrs: &Attrs,
    ) -> Result<(), XmlConfigError> {
        let parent = path.last().map(String::as_str);
        let grandparent = path
            .len()
            .checked_sub(2)
            .and_then(|i| path.get(i))
            .map(String::as_str);
        let at_root = path.len() == 1;
        match (name, parent, grandparent) {
            ("tunnel-method", _, _) if at_root => {
                if let Some(v) = get(attrs, "value") {
                    self.cfg.tunnel_methods.push(v.to_owned());
                }
            }
            ("fos", _, _) if at_root => {
                let g = |k| get(attrs, k).unwrap_or_default().to_owned();
                self.cfg.fos = Some(FosVersion {
                    platform: g("platform"),
                    major: g("major"),
                    minor: g("minor"),
                    patch: g("patch"),
                    build: g("build"),
                });
            }
            ("auth-ses", _, _) if at_root => {
                self.cfg.auth_session = Some(AuthSession {
                    check_src_ip: get(attrs, "check-src-ip").is_some_and(parse_bool),
                    tun_connect_without_reauth: get(attrs, "tun-connect-without-reauth")
                        .is_some_and(parse_bool),
                    tun_user_ses_timeout: parse_u32(attrs, name, "tun-user-ses-timeout")?,
                });
            }
            ("idle-timeout", _, _) if at_root => {
                self.cfg.idle_timeout = parse_u32(attrs, name, "val")?;
            }
            ("auth-timeout", _, _) if at_root => {
                self.cfg.auth_timeout = parse_u32(attrs, name, "val")?;
            }
            ("ipv6", _, _) if at_root => {
                self.cfg.ipv6.get_or_insert_with(Ipv6Settings::default);
            }
            ("split-tunnel-info", Some("ipv4" | "ipv6"), _) => {
                self.negate = get(attrs, "negate").is_some_and(parse_bool);
            }
            ("dns", Some("ipv4"), _) => self.ipv4_dns(attrs)?,
            ("split-dns", Some("ipv4"), _) => self.ipv4_split_dns(attrs)?,
            ("assigned-addr", Some("ipv4"), _) => {
                if let Some(v) = get(attrs, "ipv4") {
                    let a = v.parse().map_err(|_| invalid(name, "ipv4"))?;
                    self.cfg.ipv4.assigned_addr = Some(a);
                }
            }
            ("addr", Some("split-tunnel-info"), Some("ipv4")) => self.ipv4_route(attrs)?,
            ("dns", Some("ipv6"), _) => self.ipv6_dns(attrs)?,
            ("assigned-addr", Some("ipv6"), _) => {
                let v6 = self.cfg.ipv6.get_or_insert_with(Ipv6Settings::default);
                if let Some(net) = ipv6_prefix(attrs) {
                    v6.assigned_addr = Some(net);
                }
            }
            ("addr", Some("split-tunnel-info"), Some("ipv6")) => {
                let negate = self.negate;
                let v6 = self.cfg.ipv6.get_or_insert_with(Ipv6Settings::default);
                if let Some(net) = ipv6_prefix(attrs) {
                    let net = net.trunc();
                    if negate {
                        push_unique(&mut v6.exclude_routes, net);
                    } else {
                        push_unique(&mut v6.include_routes, net);
                    }
                }
            }
            _ => {}
        }
        self.check_limits()
    }

    /// Bornes globales (M1) : appelé après chaque élément, donc la croissance reste bornée.
    fn check_limits(&self) -> Result<(), XmlConfigError> {
        let v4 = &self.cfg.ipv4;
        let mut routes = v4.include_routes.len() + v4.exclude_routes.len();
        let mut v6_dns = 0;
        let mut domains =
            v4.dns_suffixes.len() + v4.split_dns.iter().map(|s| s.domains.len()).sum::<usize>();
        if let Some(v6) = &self.cfg.ipv6 {
            routes += v6.include_routes.len() + v6.exclude_routes.len();
            v6_dns = v6.dns_servers.len();
            domains += v6.dns_suffixes.len();
        }
        let fail = |what, max| Err(XmlConfigError::TooMany { what, max });
        if routes > MAX_ROUTES {
            return fail("routes", MAX_ROUTES);
        }
        if domains > MAX_DOMAINS {
            return fail("domaines", MAX_DOMAINS);
        }
        if v4.dns_servers.len() > MAX_DNS || v6_dns > MAX_DNS {
            return fail("serveurs DNS", MAX_DNS);
        }
        Ok(())
    }

    fn ipv4_dns(&mut self, attrs: &Attrs) -> Result<(), XmlConfigError> {
        if let Some(ip) = get(attrs, "ip") {
            let ip: Ipv4Addr = ip.parse().map_err(|_| invalid("dns", "ip"))?;
            push_unique(&mut self.cfg.ipv4.dns_servers, ip);
        }
        if let Some(d) = get(attrs, "domain") {
            push_domains(&mut self.cfg.ipv4.dns_suffixes, d, "dns", "domain", true)?;
        }
        Ok(())
    }

    fn ipv4_split_dns(&mut self, attrs: &Attrs) -> Result<(), XmlConfigError> {
        const SERVERS: [&str; 9] = [
            "dnsserver1",
            "dnsserver2",
            "dnsserver3",
            "dnsserver4",
            "dnsserver5",
            "dnsserver6",
            "dnsserver7",
            "dnsserver8",
            "dnsserver9",
        ];
        let mut entry = SplitDns::default();
        if let Some(d) = get(attrs, "domains") {
            push_domains(&mut entry.domains, d, "split-dns", "domains", true)?;
        }
        for key in SERVERS {
            if let Some(v) = get(attrs, key).filter(|v| !v.is_empty()) {
                let ip: IpAddr = v.parse().map_err(|_| invalid("split-dns", key))?;
                push_unique(&mut entry.servers, ip);
            }
        }
        if !entry.domains.is_empty() {
            self.cfg.ipv4.split_dns.push(entry);
        }
        Ok(())
    }

    fn ipv4_route(&mut self, attrs: &Attrs) -> Result<(), XmlConfigError> {
        let ip: Ipv4Addr = get(attrs, "ip")
            .ok_or_else(|| invalid("addr", "ip"))?
            .parse()
            .map_err(|_| invalid("addr", "ip"))?;
        let mask: Ipv4Addr = get(attrs, "mask")
            .ok_or_else(|| invalid("addr", "mask"))?
            .parse()
            .map_err(|_| invalid("addr", "mask"))?;
        let prefix = mask_to_prefix(mask).ok_or_else(|| invalid("addr", "mask"))?;
        let net = Ipv4Net::new(ip, prefix)
            .map_err(|_| invalid("addr", "mask"))?
            .trunc();
        if self.negate {
            push_unique(&mut self.cfg.ipv4.exclude_routes, net);
        } else {
            push_unique(&mut self.cfg.ipv4.include_routes, net);
        }
        Ok(())
    }

    fn ipv6_dns(&mut self, attrs: &Attrs) -> Result<(), XmlConfigError> {
        let v6 = self.cfg.ipv6.get_or_insert_with(Ipv6Settings::default);
        if let Some(ip) = get(attrs, "ipv6").and_then(|v| v.parse().ok()) {
            push_unique(&mut v6.dns_servers, ip);
        }
        if let Some(d) = get(attrs, "domain") {
            // Section permissive : seule la borne peut échouer en mode non strict.
            push_domains(&mut v6.dns_suffixes, d, "dns", "domain", false)?;
        }
        Ok(())
    }
}

fn ipv6_prefix(attrs: &Attrs) -> Option<Ipv6Net> {
    let ip: Ipv6Addr = get(attrs, "ipv6")?.parse().ok()?;
    let len: u8 = get(attrs, "prefix-len")?.parse().ok()?;
    Ipv6Net::new(ip, len).ok()
}

fn collect_attrs(e: &BytesStart<'_>) -> Result<Attrs, XmlConfigError> {
    let mut out = Vec::new();
    for a in e.attributes() {
        let a = a.map_err(|err| XmlConfigError::Xml(err.to_string()))?;
        let key = a.key.as_ref().to_owned();
        let value = a
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| XmlConfigError::Xml(err.to_string()))?
            .into_owned();
        out.push((key, value));
    }
    Ok(out)
}

/// Analyse le corps de la réponse `fortisslvpn_xml`.
pub fn parse_config(body: &[u8]) -> Result<VpnConfig, XmlConfigError> {
    let text = std::str::from_utf8(body).map_err(|_| XmlConfigError::NotUtf8)?;
    let mut reader = quick_xml::Reader::from_str(text);
    let mut b = Builder::default();
    let mut path: Vec<String> = Vec::new();
    let mut seen_root = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|e| XmlConfigError::Xml(e.to_string()))?;
        let (start, empty) = match &event {
            Event::Start(e) => (e, false),
            Event::Empty(e) => (e, true),
            Event::End(_) => {
                if path.pop().as_deref() == Some("split-tunnel-info") {
                    b.negate = false;
                }
                continue;
            }
            Event::Eof => break,
            _ => continue,
        };
        let name = start.name().as_ref().to_owned();
        if path.is_empty() {
            if seen_root || name != "sslvpn-tunnel" {
                return Err(XmlConfigError::NotSslvpnTunnel);
            }
            seen_root = true;
            let attrs = collect_attrs(start)?;
            b.cfg.dtls = get(&attrs, "dtls").is_some_and(parse_bool);
        } else {
            let attrs = collect_attrs(start)?;
            b.element(&name, &path, &attrs)?;
        }
        if !empty {
            path.push(name);
        } else if path.is_empty() {
            // Racine vide `<sslvpn-tunnel/>` : document terminé.
            break;
        }
    }
    if !seen_root {
        return Err(XmlConfigError::NotSslvpnTunnel);
    }
    if !path.is_empty() {
        return Err(XmlConfigError::Xml("document tronqué".into()));
    }
    Ok(b.cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpResponse, vectors};

    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn split_vector() {
        let c = parse_config(vectors::raw("config_split.xml").as_bytes()).unwrap();
        assert!(c.dtls);
        assert_eq!(c.tunnel_methods, ["ppp", "tun"]);
        assert_eq!(c.fos.as_ref().unwrap().platform, "FGVM64");
        assert_eq!(c.fos.as_ref().unwrap().build, "1639");
        assert_eq!(
            c.auth_session,
            Some(AuthSession {
                check_src_ip: true,
                tun_connect_without_reauth: true,
                tun_user_ses_timeout: Some(240),
            })
        );
        assert_eq!(c.ipv4.assigned_addr, Some(ip("10.10.0.2")));
        assert_eq!(c.ipv4.dns_servers, [ip("10.0.0.53"), ip("10.0.0.54")]);
        assert_eq!(c.ipv4.dns_suffixes, ["corp.example.com"]);
        assert_eq!(
            c.ipv4.split_dns,
            [SplitDns {
                domains: vec!["corp.example.com".into(), "lab.example.net".into()],
                servers: vec!["10.0.0.53".parse().unwrap(), "10.0.0.54".parse().unwrap()],
            }]
        );
        assert_eq!(
            c.ipv4.include_routes,
            [
                net("10.0.0.0/8"),
                net("172.16.0.0/12"),
                net("192.0.2.128/25"),
                net("198.51.100.7/32"),
            ]
        );
        // Bug openfortivpn n°2 (negate ignoré) non reproduit.
        assert_eq!(c.ipv4.exclude_routes, [net("10.99.0.0/16")]);
        assert!(c.is_split_tunnel());
        assert_eq!(c.idle_timeout, Some(3600));
        assert_eq!(c.auth_timeout, Some(28800));
        assert!(c.ipv6.is_none());
    }

    #[test]
    fn response_vector_body_equals_split_without_comments() {
        let r = HttpResponse::from_bytes(&vectors::http("fortisslvpn_xml_response.http"));
        let from_response = parse_config(r.body()).unwrap();
        let from_file = parse_config(vectors::raw("config_split.xml").as_bytes()).unwrap();
        assert_eq!(from_response, from_file);
    }

    #[test]
    fn full_tunnel_vector() {
        let c = parse_config(vectors::raw("config_full_tunnel.xml").as_bytes()).unwrap();
        assert!(!c.dtls);
        assert!(!c.is_split_tunnel());
        assert!(c.ipv4.include_routes.is_empty());
        assert!(c.ipv4.exclude_routes.is_empty());
        assert_eq!(c.ipv4.dns_servers, [ip("10.0.0.53")]);
        assert!(c.ipv4.dns_suffixes.is_empty());
        assert_eq!(c.ipv4.assigned_addr, Some(ip("10.10.0.2")));
        assert_eq!(c.idle_timeout, Some(300));
        let s = c.auth_session.unwrap();
        assert!(!s.check_src_ip && !s.tun_connect_without_reauth);
        assert_eq!(s.tun_user_ses_timeout, Some(30));
        assert_eq!(c.fos.unwrap().major, "6");
    }

    #[test]
    fn dual_stack_vector() {
        let c = parse_config(vectors::raw("config_dual_stack.xml").as_bytes()).unwrap();
        assert_eq!(c.ipv4.include_routes, [net("10.0.0.0/8")]);
        assert_eq!(c.ipv4.dns_suffixes, ["corp.example.com"]);
        let v6 = c.ipv6.unwrap();
        assert_eq!(v6.dns_servers, ["fd00:10::53".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(v6.assigned_addr, Some("fd00:10:0:1::2/64".parse().unwrap()));
        assert_eq!(
            v6.include_routes,
            ["fd00:10::/48".parse::<Ipv6Net>().unwrap()]
        );
        assert_eq!(
            v6.exclude_routes,
            ["2001:db8:dead::/48".parse::<Ipv6Net>().unwrap()]
        );
    }

    #[test]
    fn reads_every_split_tunnel_block() {
        // Bug openfortivpn n°1 (seul le premier bloc lu) non reproduit.
        let xml = r#"<sslvpn-tunnel><ipv4>
            <split-tunnel-info negate="1"><addr ip="10.1.0.0" mask="255.255.0.0"/></split-tunnel-info>
            <split-tunnel-info><addr ip='10.2.3.4' mask='255.255.0.0'/></split-tunnel-info>
            <split-tunnel-info><addr ip="10.3.0.0" mask="255.255.0.0"/><addr ip="10.3.0.0" mask="255.255.0.0"/></split-tunnel-info>
            <split-tunnel-info/>
        </ipv4></sslvpn-tunnel>"#;
        let c = parse_config(xml.as_bytes()).unwrap();
        assert_eq!(c.ipv4.exclude_routes, [net("10.1.0.0/16")]);
        // hôte tronqué au réseau, doublon retiré
        assert_eq!(
            c.ipv4.include_routes,
            [net("10.2.0.0/16"), net("10.3.0.0/16")]
        );
    }

    #[test]
    fn aggregates_domains() {
        let xml = r#"<sslvpn-tunnel><ipv4>
            <dns ip="10.0.0.1" domain="a.example"/>
            <dns domain="b.example;c.example d.example"/>
            <dns ip="10.0.0.1" domain="A.EXAMPLE."/>
        </ipv4></sslvpn-tunnel>"#;
        let c = parse_config(xml.as_bytes()).unwrap();
        assert_eq!(c.ipv4.dns_servers, [ip("10.0.0.1")]);
        assert_eq!(
            c.ipv4.dns_suffixes,
            ["a.example", "b.example", "c.example", "d.example"]
        );
    }

    #[test]
    fn rejects_invalid_values() {
        for xml in [
            r#"<sslvpn-tunnel><ipv4><split-tunnel-info><addr ip="10.0.0.0" mask="255.0.255.0"/></split-tunnel-info></ipv4></sslvpn-tunnel>"#,
            r#"<sslvpn-tunnel><ipv4><split-tunnel-info><addr ip="10.0.0.0"/></split-tunnel-info></ipv4></sslvpn-tunnel>"#,
            r#"<sslvpn-tunnel><ipv4><dns ip="10.0.0.300"/></ipv4></sslvpn-tunnel>"#,
            r#"<sslvpn-tunnel><ipv4><dns domain="ev!l.example"/></ipv4></sslvpn-tunnel>"#,
            r#"<sslvpn-tunnel><ipv4><assigned-addr ipv4="x"/></ipv4></sslvpn-tunnel>"#,
            r#"<sslvpn-tunnel><idle-timeout val="-1"/></sslvpn-tunnel>"#,
        ] {
            assert!(
                matches!(
                    parse_config(xml.as_bytes()),
                    Err(XmlConfigError::InvalidValue { .. })
                ),
                "{xml}"
            );
        }
    }

    #[test]
    fn rejects_non_config_documents() {
        assert_eq!(
            parse_config(b"<html><body>login</body></html>"),
            Err(XmlConfigError::NotSslvpnTunnel)
        );
        assert_eq!(parse_config(b""), Err(XmlConfigError::NotSslvpnTunnel));
        assert_eq!(parse_config(b"\xff\xfe"), Err(XmlConfigError::NotUtf8));
        assert!(matches!(
            parse_config(b"<sslvpn-tunnel><ipv4>"),
            Err(XmlConfigError::Xml(_))
        ));
        assert!(matches!(
            parse_config(b"<sslvpn-tunnel></ipv4>"),
            Err(XmlConfigError::Xml(_))
        ));
    }

    #[test]
    fn no_external_entities() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY ext SYSTEM "file:///etc/passwd">]>
<sslvpn-tunnel><ipv4><dns ip="10.0.0.1" domain="&ext;"/></ipv4></sslvpn-tunnel>"#;
        assert!(matches!(
            parse_config(xml.as_bytes()),
            Err(XmlConfigError::Xml(_))
        ));
    }

    #[test]
    fn ignores_unknown_and_tolerates_bad_ipv6() {
        let xml = r#"<sslvpn-tunnel ver="2" foo="bar"><unknown a="1"><dns ip="bad"/></unknown>
            <ipv6><dns ipv6="nope"/><split-tunnel-info><addr ipv6="zz" prefix-len="1"/></split-tunnel-info></ipv6>
            <ipv4><dns ip="10.0.0.1"/></ipv4></sslvpn-tunnel>"#;
        let c = parse_config(xml.as_bytes()).unwrap();
        assert_eq!(c.ipv4.dns_servers, [ip("10.0.0.1")]);
        assert_eq!(c.ipv6, Some(Ipv6Settings::default()));
    }

    #[test]
    fn mask_conversion() {
        assert_eq!(mask_to_prefix(ip("0.0.0.0")), Some(0));
        assert_eq!(mask_to_prefix(ip("255.255.255.255")), Some(32));
        assert_eq!(mask_to_prefix(ip("255.240.0.0")), Some(12));
        assert_eq!(mask_to_prefix(ip("255.0.0.255")), None);
        assert_eq!(mask_to_prefix(ip("0.255.255.255")), None);
    }

    #[test]
    fn rejects_too_many_routes_domains_dns() {
        let wrap = |inner: String| format!("<sslvpn-tunnel>{inner}</sslvpn-tunnel>");
        let addrs: String = (0..1025u32)
            .map(|i| {
                format!(
                    "<addr ip=\"10.{}.{}.0\" mask=\"255.255.255.0\"/>",
                    i / 256,
                    i % 256
                )
            })
            .collect();
        let xml = wrap(format!(
            "<ipv4><split-tunnel-info>{addrs}</split-tunnel-info></ipv4>"
        ));
        assert!(matches!(
            parse_config(xml.as_bytes()),
            Err(XmlConfigError::TooMany { what: "routes", .. })
        ));
        let doms: Vec<String> = (0..65).map(|i| format!("d{i}.example.com")).collect();
        let xml = wrap(format!("<ipv4><dns domain=\"{}\"/></ipv4>", doms.join(",")));
        assert!(matches!(
            parse_config(xml.as_bytes()),
            Err(XmlConfigError::TooMany {
                what: "domaines",
                ..
            })
        ));
        let dns: String = (1..=9)
            .map(|i| format!("<dns ip=\"10.0.0.{i}\"/>"))
            .collect();
        let xml = wrap(format!("<ipv4>{dns}</ipv4>"));
        assert!(matches!(
            parse_config(xml.as_bytes()),
            Err(XmlConfigError::TooMany {
                what: "serveurs DNS",
                ..
            })
        ));
        // Limites exactes acceptées, doublons de domaines non comptés.
        let doms: Vec<String> = (0..64).map(|i| format!("d{i}.example.com")).collect();
        let xml = wrap(format!(
            "<ipv4><dns domain=\"{0},D0.EXAMPLE.COM\"/></ipv4>",
            doms.join(",")
        ));
        assert_eq!(
            parse_config(xml.as_bytes())
                .unwrap()
                .ipv4
                .dns_suffixes
                .len(),
            64
        );
    }
}
