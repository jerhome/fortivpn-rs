//! Configuration tunnel renvoyée par `GET /remote/fortisslvpn_xml` (docs/protocol.md §5).
//!
//! Le XML produit reprend la mise en forme d'une vraie passerelle telle que reconstituée
//! dans `docs/vectors/fortisslvpn_xml_response.http` (y compris le mélange de guillemets
//! simples et doubles), de sorte que [`TunnelConfig::vector_split`] produit **exactement**
//! le corps de ce vecteur.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

/// Paramètres DTLS (`<dtls-config>`), informatifs : la fausse passerelle ne fait pas de DTLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtlsConfig {
    pub heartbeat_interval: u32,
    pub heartbeat_fail_count: u32,
    pub heartbeat_idle_timeout: u32,
    pub client_hello_timeout: u32,
}

/// Version FortiOS annoncée (`<fos>`), informative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FosVersion {
    pub platform: String,
    pub major: String,
    pub minor: String,
    pub patch: String,
    pub build: String,
    pub branch: String,
}

/// Reconnexion sans ré-authentification (`<auth-ses>`, docs/protocol.md §10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthSession {
    pub check_src_ip: bool,
    pub tun_connect_without_reauth: bool,
    pub tun_user_ses_timeout: u32,
}

/// Préférences FortiClient (`<client-config>`), informatives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientConfig {
    pub save_password: bool,
    pub keep_alive: bool,
    pub auto_connect: bool,
}

/// Serveur DNS IPv4, avec suffixe de recherche optionnel (`<dns ip=.. domain=..>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServer {
    pub ip: Ipv4Addr,
    pub domain: Option<String>,
}

impl DnsServer {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self { ip, domain: None }
    }

    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }
}

/// Split-DNS (`<split-dns domains=.. dnsserver1=..>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitDns {
    pub domains: Vec<String>,
    /// Au plus 9 serveurs (`dnsserver1..9`) ; les suivants sont ignorés.
    pub servers: Vec<Ipv4Addr>,
}

/// Section `<ipv4>`.
///
/// `include_routes` vide => full-tunnel (aucun `<split-tunnel-info>` d'inclusion émis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Config {
    pub assigned_addr: Ipv4Addr,
    pub dns: Vec<DnsServer>,
    pub split_dns: Vec<SplitDns>,
    pub include_routes: Vec<Ipv4Net>,
    /// Routes exclues du tunnel (`<split-tunnel-info negate="1">`).
    pub exclude_routes: Vec<Ipv4Net>,
}

/// Section `<ipv6>` (hors MVP) : n'est émise que si la requête contient `dual_stack=1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Config {
    pub assigned_addr: Ipv6Net,
    pub dns: Vec<Ipv6Addr>,
    pub include_routes: Vec<Ipv6Net>,
    pub exclude_routes: Vec<Ipv6Net>,
}

/// Configuration tunnel complète servie par la fausse passerelle.
///
/// Elle est aussi transmise au [`crate::TunnelHandler`] ([`crate::PppPeer`] : adresse et
/// DNS attribués par IPCP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    /// Attribut `dtls` de la racine.
    pub dtls: bool,
    pub dtls_config: Option<DtlsConfig>,
    /// Valeurs de `<tunnel-method value=..>` (`ppp`, `tun`).
    pub tunnel_methods: Vec<String>,
    pub fos: Option<FosVersion>,
    pub auth_ses: Option<AuthSession>,
    pub client_config: Option<ClientConfig>,
    pub ipv4: Ipv4Config,
    pub ipv6: Option<Ipv6Config>,
    /// `<idle-timeout val=..>` en secondes.
    pub idle_timeout: Option<u32>,
    /// `<auth-timeout val=..>` en secondes.
    pub auth_timeout: Option<u32>,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self::vector_split()
    }
}

impl TunnelConfig {
    /// Configuration minimale en full-tunnel : adresse attribuée + DNS, aucune route.
    pub fn full_tunnel(assigned_addr: Ipv4Addr, dns: Vec<DnsServer>) -> Self {
        Self {
            dtls: false,
            dtls_config: None,
            tunnel_methods: vec!["ppp".into()],
            fos: None,
            auth_ses: None,
            client_config: None,
            ipv4: Ipv4Config {
                assigned_addr,
                dns,
                split_dns: Vec::new(),
                include_routes: Vec::new(),
                exclude_routes: Vec::new(),
            },
            ipv6: None,
            idle_timeout: None,
            auth_timeout: None,
        }
    }

    /// Configuration minimale en split-tunnel.
    pub fn split(assigned_addr: Ipv4Addr, dns: Vec<DnsServer>, routes: Vec<Ipv4Net>) -> Self {
        let mut cfg = Self::full_tunnel(assigned_addr, dns);
        cfg.ipv4.include_routes = routes;
        cfg
    }

    /// Reproduit `docs/vectors/config_split.xml` (et le corps de
    /// `fortisslvpn_xml_response.http`, à l'octet près).
    pub fn vector_split() -> Self {
        Self {
            dtls: true,
            dtls_config: Some(DtlsConfig {
                heartbeat_interval: 10,
                heartbeat_fail_count: 10,
                heartbeat_idle_timeout: 10,
                client_hello_timeout: 10,
            }),
            tunnel_methods: vec!["ppp".into(), "tun".into()],
            fos: Some(FosVersion {
                platform: "FGVM64".into(),
                major: "7".into(),
                minor: "02".into(),
                patch: "8".into(),
                build: "1639".into(),
                branch: "1639".into(),
            }),
            auth_ses: Some(AuthSession {
                check_src_ip: true,
                tun_connect_without_reauth: true,
                tun_user_ses_timeout: 240,
            }),
            client_config: Some(ClientConfig {
                save_password: false,
                keep_alive: true,
                auto_connect: false,
            }),
            ipv4: Ipv4Config {
                assigned_addr: Ipv4Addr::new(10, 10, 0, 2),
                dns: vec![
                    DnsServer::new(Ipv4Addr::new(10, 0, 0, 53)),
                    DnsServer::new(Ipv4Addr::new(10, 0, 0, 54)).with_domain("corp.example.com"),
                ],
                split_dns: vec![SplitDns {
                    domains: vec!["corp.example.com".into(), "lab.example.net".into()],
                    servers: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)],
                }],
                include_routes: vec![
                    net4([10, 0, 0, 0], 8),
                    net4([172, 16, 0, 0], 12),
                    net4([192, 0, 2, 128], 25),
                    net4([198, 51, 100, 7], 32),
                ],
                exclude_routes: vec![net4([10, 99, 0, 0], 16)],
            },
            ipv6: None,
            idle_timeout: Some(3600),
            auth_timeout: Some(28800),
        }
    }

    /// Reproduit `docs/vectors/config_full_tunnel.xml`.
    pub fn vector_full_tunnel() -> Self {
        let mut cfg = Self::full_tunnel(
            Ipv4Addr::new(10, 10, 0, 2),
            vec![DnsServer::new(Ipv4Addr::new(10, 0, 0, 53))],
        );
        cfg.fos = Some(FosVersion {
            platform: "FG100F".into(),
            major: "6".into(),
            minor: "04".into(),
            patch: "15".into(),
            build: "2095".into(),
            branch: "2095".into(),
        });
        cfg.auth_ses = Some(AuthSession {
            check_src_ip: false,
            tun_connect_without_reauth: false,
            tun_user_ses_timeout: 30,
        });
        cfg.client_config = Some(ClientConfig {
            save_password: false,
            keep_alive: false,
            auto_connect: false,
        });
        cfg.idle_timeout = Some(300);
        cfg.auth_timeout = Some(28800);
        cfg
    }

    /// Reproduit `docs/vectors/config_dual_stack.xml` (section `<ipv6>` servie seulement
    /// sur `GET /remote/fortisslvpn_xml?dual_stack=1`).
    pub fn vector_dual_stack() -> Self {
        let mut cfg = Self::split(
            Ipv4Addr::new(10, 10, 0, 2),
            vec![DnsServer::new(Ipv4Addr::new(10, 0, 0, 53)).with_domain("corp.example.com")],
            vec![net4([10, 0, 0, 0], 8)],
        );
        cfg.dtls = true;
        cfg.auth_ses = Some(AuthSession {
            check_src_ip: true,
            tun_connect_without_reauth: true,
            tun_user_ses_timeout: 240,
        });
        cfg.ipv6 = Some(Ipv6Config {
            assigned_addr: net6("fd00:10:0:1::2", 64),
            dns: vec!["fd00:10::53".parse().expect("IPv6 littérale valide")],
            include_routes: vec![net6("fd00:10::", 48)],
            exclude_routes: vec![net6("2001:db8:dead::", 48)],
        });
        cfg.idle_timeout = Some(3600);
        cfg.auth_timeout = Some(28800);
        cfg
    }

    /// `true` si aucune route d'inclusion : tout le trafic passe dans le tunnel.
    pub fn is_full_tunnel(&self) -> bool {
        self.ipv4.include_routes.is_empty()
    }

    /// Document XML tel que servi (avec ou sans la section `<ipv6>`).
    pub fn to_xml(&self, dual_stack: bool) -> String {
        let mut x = String::with_capacity(1280);
        x.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        let _ = writeln!(
            x,
            "<sslvpn-tunnel ver=\"2\" dtls=\"{}\" patch=\"1\">",
            u8::from(self.dtls)
        );
        if let Some(d) = &self.dtls_config {
            let _ = writeln!(
                x,
                "  <dtls-config heartbeat-interval=\"{}\" heartbeat-fail-count=\"{}\" \
                 heartbeat-idle-timeout=\"{}\" client-hello-timeout=\"{}\"/>",
                d.heartbeat_interval,
                d.heartbeat_fail_count,
                d.heartbeat_idle_timeout,
                d.client_hello_timeout
            );
        }
        for m in &self.tunnel_methods {
            let _ = writeln!(x, "  <tunnel-method value=\"{}\"/>", esc(m));
        }
        if let Some(f) = &self.fos {
            let _ = writeln!(
                x,
                "  <fos platform=\"{}\" major=\"{}\" minor=\"{}\" patch=\"{}\" build=\"{}\" \
                 branch=\"{}\"/>",
                esc(&f.platform),
                esc(&f.major),
                esc(&f.minor),
                esc(&f.patch),
                esc(&f.build),
                esc(&f.branch)
            );
        }
        if let Some(a) = &self.auth_ses {
            let _ = writeln!(
                x,
                "  <auth-ses check-src-ip='{}' tun-connect-without-reauth='{}' \
                 tun-user-ses-timeout='{}' />",
                u8::from(a.check_src_ip),
                u8::from(a.tun_connect_without_reauth),
                a.tun_user_ses_timeout
            );
        }
        if let Some(c) = &self.client_config {
            let _ = writeln!(
                x,
                "  <client-config save-password=\"{}\" keep-alive=\"{}\" auto-connect=\"{}\"/>",
                on_off(c.save_password),
                on_off(c.keep_alive),
                on_off(c.auto_connect)
            );
        }
        self.write_ipv4(&mut x);
        if let (true, Some(v6)) = (dual_stack, &self.ipv6) {
            write_ipv6(&mut x, v6);
        }
        if let Some(v) = self.idle_timeout {
            let _ = writeln!(x, "  <idle-timeout val=\"{v}\"/>");
        }
        if let Some(v) = self.auth_timeout {
            let _ = writeln!(x, "  <auth-timeout val=\"{v}\"/>");
        }
        x.push_str("</sslvpn-tunnel>");
        x
    }

    fn write_ipv4(&self, x: &mut String) {
        let v4 = &self.ipv4;
        x.push_str("  <ipv4>\n");
        for d in &v4.dns {
            match &d.domain {
                Some(dom) => {
                    let _ = writeln!(x, "    <dns ip=\"{}\" domain=\"{}\"/>", d.ip, esc(dom));
                }
                None => {
                    let _ = writeln!(x, "    <dns ip=\"{}\"/>", d.ip);
                }
            }
        }
        for s in &v4.split_dns {
            let _ = write!(x, "    <split-dns domains='{}'", esc(&s.domains.join(",")));
            for (i, srv) in s.servers.iter().take(9).enumerate() {
                let _ = write!(x, " dnsserver{}='{srv}'", i + 1);
            }
            x.push_str(" />\n");
        }
        let _ = writeln!(x, "    <assigned-addr ipv4=\"{}\"/>", v4.assigned_addr);
        if !v4.include_routes.is_empty() {
            x.push_str("    <split-tunnel-info>\n");
            for r in &v4.include_routes {
                let _ = writeln!(
                    x,
                    "      <addr ip=\"{}\" mask=\"{}\"/>",
                    r.addr(),
                    r.netmask()
                );
            }
            x.push_str("    </split-tunnel-info>\n");
        }
        if !v4.exclude_routes.is_empty() {
            x.push_str("    <split-tunnel-info negate=\"1\">\n");
            for r in &v4.exclude_routes {
                let _ = writeln!(
                    x,
                    "      <addr ip=\"{}\" mask=\"{}\"/>",
                    r.addr(),
                    r.netmask()
                );
            }
            x.push_str("    </split-tunnel-info>\n");
        }
        x.push_str("  </ipv4>\n");
    }
}

fn write_ipv6(x: &mut String, v6: &Ipv6Config) {
    x.push_str("  <ipv6>\n");
    for d in &v6.dns {
        let _ = writeln!(x, "    <dns ipv6=\"{d}\"/>");
    }
    let _ = writeln!(
        x,
        "    <assigned-addr ipv6='{}' prefix-len='{}'/>",
        v6.assigned_addr.addr(),
        v6.assigned_addr.prefix_len()
    );
    for (routes, open) in [
        (&v6.include_routes, "    <split-tunnel-info>\n"),
        (&v6.exclude_routes, "    <split-tunnel-info negate=\"1\">\n"),
    ] {
        if routes.is_empty() {
            continue;
        }
        x.push_str(open);
        for r in routes {
            let _ = writeln!(
                x,
                "      <addr ipv6='{}' prefix-len='{}'/>",
                r.addr(),
                r.prefix_len()
            );
        }
        x.push_str("    </split-tunnel-info>\n");
    }
    x.push_str("  </ipv6>\n");
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// Échappement d'une valeur d'attribut XML (guillemets simples et doubles).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

fn net4(a: [u8; 4], len: u8) -> Ipv4Net {
    Ipv4Net::new(Ipv4Addr::from(a), len).expect("longueur de préfixe IPv4 valide")
}

fn net6(a: &str, len: u8) -> Ipv6Net {
    Ipv6Net::new(a.parse().expect("IPv6 littérale valide"), len)
        .expect("longueur de préfixe IPv6 valide")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_attribute_values() {
        assert_eq!(esc("a&b<'\">"), "a&amp;b&lt;&apos;&quot;&gt;");
    }

    #[test]
    fn full_tunnel_has_no_split_info() {
        let xml = TunnelConfig::vector_full_tunnel().to_xml(false);
        assert!(!xml.contains("split-tunnel-info"));
        assert!(TunnelConfig::vector_full_tunnel().is_full_tunnel());
    }

    #[test]
    fn ipv6_only_when_dual_stack_requested() {
        let cfg = TunnelConfig::vector_dual_stack();
        assert!(!cfg.to_xml(false).contains("<ipv6>"));
        assert!(cfg.to_xml(true).contains("<ipv6>"));
    }
}
