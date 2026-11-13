//! Mode proxy en espace utilisateur, **sans droits d'administration** (story 7.1).
//!
//! [`ProxyBackend`] implémente [`NetBackend`](fortivpn_core::NetBackend) sans toucher
//! au système : au lieu d'une interface TUN, le canal de paquets du tunnel alimente
//! une pile TCP/IP [`smoltcp`] en espace utilisateur (adresse et MTU du tunnel,
//! route par défaut dans le tunnel, DNS du tunnel). Les applications y accèdent par :
//!
//! - un **proxy SOCKS5** local (défaut `127.0.0.1:1080`) : `CONNECT` TCP vers une
//!   IPv4 ou un nom de domaine (résolu par les serveurs DNS du tunnel) ; `BIND`,
//!   `UDP ASSOCIATE` et IPv6 sont refusés ; méthode « sans authentification »
//!   uniquement, d'où l'écoute limitée à loopback sauf autorisation explicite ;
//! - des **redirections de ports** statiques `127.0.0.1:LPORT → hôte:port` (TCP).
//!
//! `Session`, le transport et la reconnexion sont réutilisés tels quels : à chaque
//! (re)connexion `create_tun` + `apply` créent une nouvelle pile, le `NetGuard`
//! l'arrête ; les écoutes locales, elles, restent ouvertes.
//!
//! Limites : TCP uniquement (pas d'UDP ni d'ICMP pour les applications), IPv4
//! uniquement, au plus 3 serveurs DNS (essayés dans l'ordre), tout le trafic des
//! clients passe par le tunnel même en split-tunnel (la passerelle filtre).

mod backend;
mod config;
mod listen;
mod socks;
mod stack;

pub use backend::{ProxyBackend, ProxyCleanup, ProxyError};
pub use config::{
    DEFAULT_SOCKS, DEFAULT_SOCKS_PORT, Forward, Host, Limits, MAX_DOMAIN_LEN, MAX_FORWARDS,
    ProxyConfig, ProxyConfigError, Target, valid_domain,
};
pub use socks::Reply as SocksReply;
