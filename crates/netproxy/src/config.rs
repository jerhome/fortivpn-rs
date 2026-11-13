//! Configuration du mode proxy : écoute SOCKS5, redirections de ports, limites.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

/// Adresse d'écoute SOCKS5 par défaut.
pub const DEFAULT_SOCKS: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
    DEFAULT_SOCKS_PORT,
);
/// Port SOCKS5 par défaut.
pub const DEFAULT_SOCKS_PORT: u16 = 1080;
/// Nombre maximal de redirections de ports.
pub const MAX_FORWARDS: usize = 64;
/// Longueur maximale d'un nom de domaine (RFC 1035).
pub const MAX_DOMAIN_LEN: usize = 253;

/// Erreur de configuration du proxy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyConfigError {
    /// Redirection mal formée.
    #[error("redirection « {spec} » invalide : {reason} (attendu : « 127.0.0.1:PORT=hôte:port »)")]
    InvalidForward {
        /// Texte fautif.
        spec: String,
        /// Cause.
        reason: &'static str,
    },
    /// Adresse d'écoute non loopback sans autorisation explicite.
    #[error(
        "adresse d'écoute {0} non loopback : le proxy serait accessible depuis le réseau \
         (autorisez-le explicitement si c'est voulu)"
    )]
    NonLoopback(SocketAddr),
    /// Deux écoutes sur la même adresse.
    #[error("adresse d'écoute {0} utilisée deux fois")]
    DuplicateListen(SocketAddr),
    /// Rien à écouter.
    #[error("ni proxy SOCKS ni redirection : rien à faire")]
    Empty,
    /// Trop de redirections.
    #[error("trop de redirections (maximum {MAX_FORWARDS})")]
    TooManyForwards,
}

/// Hôte de destination (dans le tunnel).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// Adresse IPv4.
    Ip(Ipv4Addr),
    /// Nom de domaine, résolu par les serveurs DNS du tunnel.
    Domain(String),
}

impl Host {
    /// Analyse un hôte : adresse IPv4 littérale ou nom de domaine valide.
    pub fn parse(s: &str) -> Option<Self> {
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            return Some(Self::Ip(ip));
        }
        valid_domain(s).then(|| Self::Domain(s.trim_end_matches('.').to_ascii_lowercase()))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Domain(d) => f.write_str(d),
        }
    }
}

/// Nom de domaine acceptable : 1 à 253 caractères, étiquettes de 1 à 63 caractères
/// `[A-Za-z0-9_-]`, ne commençant ni ne finissant par `-` (point final toléré).
pub fn valid_domain(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > MAX_DOMAIN_LEN {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    })
}

/// Destination TCP dans le tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// Hôte.
    pub host: Host,
    /// Port (non nul).
    pub port: u16,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Redirection statique `écoute locale → hôte:port` (TCP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    /// Adresse d'écoute locale.
    pub listen: SocketAddr,
    /// Destination dans le tunnel.
    pub target: Target,
}

impl FromStr for Forward {
    type Err = ProxyConfigError;

    /// Format `ADRESSE_LOCALE:PORT=hôte:port`, par ex. `127.0.0.1:13389=srv.corp:3389`.
    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let err = |reason| ProxyConfigError::InvalidForward {
            spec: spec.to_owned(),
            reason,
        };
        let (listen, target) = spec.split_once('=').ok_or_else(|| err("« = » manquant"))?;
        let listen: SocketAddr = listen
            .trim()
            .parse()
            .map_err(|_| err("adresse d'écoute invalide (IP:PORT attendu)"))?;
        if listen.port() == 0 {
            return Err(err("port d'écoute nul"));
        }
        let (host, port) = target
            .trim()
            .rsplit_once(':')
            .ok_or_else(|| err("port de destination manquant"))?;
        let port: u16 = port
            .parse()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| err("port de destination invalide"))?;
        let host = Host::parse(host)
            .ok_or_else(|| err("hôte de destination invalide (IPv4 ou nom de domaine)"))?;
        Ok(Self {
            listen,
            target: Target { host, port },
        })
    }
}

/// Limites de ressources du proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Connexions TCP simultanées dans le tunnel (au-delà : refus).
    pub max_connections: usize,
    /// Taille des tampons d'émission et de réception de chaque socket smoltcp.
    pub socket_buffer: usize,
    /// Délai maximal de la négociation SOCKS5 côté client.
    pub handshake_timeout: Duration,
    /// Délai maximal d'établissement d'une connexion (résolution DNS comprise).
    pub connect_timeout: Duration,
    /// Délai sans acquittement avant abandon d'une connexion établie.
    pub tcp_timeout: Duration,
    /// Intervalle des keep-alive TCP dans le tunnel.
    pub keep_alive: Duration,
    /// Clients simultanés sur l'écouteur SOCKS (M2).
    pub socks_connections: usize,
    /// Clients simultanés par redirection de port (M2).
    pub forward_connections: usize,
    /// Clients simultanément en cours de négociation/connexion, tous écouteurs (M2).
    pub max_handshakes: usize,
    /// Inactivité (aucun octet dans aucun sens) après laquelle une connexion
    /// établie est coupée (M2).
    pub idle_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 256,
            socket_buffer: 64 * 1024,
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(30),
            tcp_timeout: Duration::from_secs(120),
            keep_alive: Duration::from_secs(60),
            socks_connections: 64,
            forward_connections: 32,
            max_handshakes: 16,
            idle_timeout: Duration::from_secs(300),
        }
    }
}

/// Configuration complète du mode proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// Écoute SOCKS5 (`None` : pas de SOCKS, redirections seulement).
    pub socks: Option<SocketAddr>,
    /// Redirections de ports.
    pub forwards: Vec<Forward>,
    /// Autorise une écoute hors loopback (SOCKS alors sans authentification :
    /// à réserver à un réseau de confiance).
    pub allow_non_loopback: bool,
    /// Limites de ressources.
    pub limits: Limits,
    /// N'accepte que les clients dont le processus appartient à l'utilisateur qui a
    /// lancé le proxy (uid sous Linux, SID sous Windows ; défaut `true`, M1). Un pair
    /// non vérifiable (dont tout client distant) est refusé. À désactiver seulement
    /// si nécessaire (ex. clients d'un autre compte, conteneur/WSL en réseau miroir).
    pub owner_check: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            socks: Some(DEFAULT_SOCKS),
            forwards: Vec::new(),
            allow_non_loopback: false,
            limits: Limits::default(),
            owner_check: true,
        }
    }
}

impl ProxyConfig {
    /// Configuration avec SOCKS et redirections données.
    pub fn new(socks: Option<SocketAddr>, forwards: Vec<Forward>) -> Self {
        Self {
            socks,
            forwards,
            ..Self::default()
        }
    }

    /// Autorise (ou non) une écoute hors loopback.
    #[must_use]
    pub fn with_allow_non_loopback(mut self, allow: bool) -> Self {
        self.allow_non_loopback = allow;
        self
    }

    /// Active ou désactive le contrôle du propriétaire du processus client.
    #[must_use]
    pub fn with_owner_check(mut self, on: bool) -> Self {
        self.owner_check = on;
        self
    }

    /// Remplace les limites.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Vérifie la cohérence : au moins une écoute, loopback sauf autorisation,
    /// pas de doublon. Un port 0 n'est accepté que pour SOCKS (port éphémère, tests).
    pub fn validate(&self) -> Result<(), ProxyConfigError> {
        if self.socks.is_none() && self.forwards.is_empty() {
            return Err(ProxyConfigError::Empty);
        }
        if self.forwards.len() > MAX_FORWARDS {
            return Err(ProxyConfigError::TooManyForwards);
        }
        let mut seen: Vec<SocketAddr> = Vec::new();
        for addr in self.listen_addrs() {
            if !self.allow_non_loopback && !addr.ip().is_loopback() {
                return Err(ProxyConfigError::NonLoopback(addr));
            }
            if addr.port() != 0 && seen.contains(&addr) {
                return Err(ProxyConfigError::DuplicateListen(addr));
            }
            seen.push(addr);
        }
        Ok(())
    }

    fn listen_addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.socks
            .into_iter()
            .chain(self.forwards.iter().map(|f| f.listen))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(s: &str) -> Forward {
        s.parse().unwrap()
    }

    #[test]
    fn forward_parsing() {
        let f = fwd("127.0.0.1:13389=srv.corp:3389");
        assert_eq!(f.listen, "127.0.0.1:13389".parse().unwrap());
        assert_eq!(
            f.target,
            Target {
                host: Host::Domain("srv.corp".into()),
                port: 3389
            }
        );
        let f = fwd(" 127.0.0.1:8080 = 10.1.2.3:80 ");
        assert_eq!(f.target.host, Host::Ip(Ipv4Addr::new(10, 1, 2, 3)));
        let f = fwd("[::1]:2222=Git.Corp.:22");
        assert!(f.listen.ip().is_loopback());
        assert_eq!(f.target.host, Host::Domain("git.corp".into()));
    }

    #[test]
    fn forward_errors() {
        for bad in [
            "",
            "127.0.0.1:1",
            "127.0.0.1=srv:1",
            "localhost:80=srv:1",
            "127.0.0.1:0=srv:1",
            "127.0.0.1:80=srv",
            "127.0.0.1:80=srv:0",
            "127.0.0.1:80=srv:99999",
            "127.0.0.1:80=:22",
            "127.0.0.1:80=bad host:22",
            "127.0.0.1:80=-x.corp:22",
            "127.0.0.1:80=a..b:22",
            "127.0.0.1:80=[2001:db8::1]:22",
        ] {
            assert!(
                matches!(
                    bad.parse::<Forward>(),
                    Err(ProxyConfigError::InvalidForward { .. })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn domain_validation() {
        assert!(valid_domain("a"));
        assert!(valid_domain("srv-1.corp.example."));
        assert!(valid_domain("_ldap._tcp.corp"));
        assert!(!valid_domain("."));
        assert!(!valid_domain(&"a".repeat(64)));
        assert!(!valid_domain(&format!("{}.b", "a.".repeat(127))));
        assert!(!valid_domain("é.corp"));
        assert!(!valid_domain("a b"));
    }

    #[test]
    fn validation() {
        assert_eq!(ProxyConfig::default().validate(), Ok(()));
        assert_eq!(
            ProxyConfig::new(None, vec![]).validate(),
            Err(ProxyConfigError::Empty)
        );
        let remote: SocketAddr = "0.0.0.0:1080".parse().unwrap();
        let c = ProxyConfig::new(Some(remote), vec![]);
        assert_eq!(c.validate(), Err(ProxyConfigError::NonLoopback(remote)));
        assert_eq!(c.with_allow_non_loopback(true).validate(), Ok(()));
        let c = ProxyConfig::new(None, vec![fwd("192.168.1.2:80=srv:80")]);
        assert!(matches!(
            c.validate(),
            Err(ProxyConfigError::NonLoopback(_))
        ));
        let c = ProxyConfig::new(
            Some("127.0.0.1:1080".parse().unwrap()),
            vec![fwd("127.0.0.1:1080=srv:80")],
        );
        assert!(matches!(
            c.validate(),
            Err(ProxyConfigError::DuplicateListen(_))
        ));
        let many = (1..=65)
            .map(|p| fwd(&format!("127.0.0.1:{p}=srv:80")))
            .collect();
        assert_eq!(
            ProxyConfig::new(None, many).validate(),
            Err(ProxyConfigError::TooManyForwards)
        );
    }
}
