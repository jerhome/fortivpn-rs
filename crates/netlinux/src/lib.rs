//! Implémentation Linux de `NetBackend` (TUN, routes/adresses, DNS).
//!
//! Utilisée pour les tests e2e dans WSL (netns). Vide hors Linux.
//!
//! - TUN : `tokio-tun` (`/dev/net/tun`, sans en-tête `packet_info`) ; deux
//!   tâches relaient le descripteur et le [`PacketChannel`] du [`TunDevice`].
//! - Lien (MTU, `up`), adresse, routes : rtnetlink, sans commande externe.
//! - Route de la passerelle : la route d'origine est résolue par
//!   `RTM_GETROUTE` avant toute modification, puis une `/32` `via` la même
//!   passerelle et interface est installée (sauf passerelle locale à l'hôte).
//! - Full-tunnel : `0.0.0.0/1` + `128.0.0.0/1` via la TUN (la route par défaut
//!   d'origine n'est pas touchée) ; chaque exclusion est routée via sa route
//!   d'origine ; l'IPv6 de l'hôte est bloqué par deux routes `blackhole`
//!   `::/1` + `8000::/1` (ignorées avec avertissement si l'hôte n'a pas IPv6).
//! - Serveurs DNS IPv4 du tunnel non couverts (split : hors inclusions ;
//!   full : dans une exclusion) : `/32` via la TUN (sauf DNS == passerelle).
//! - DNS : voir [`DnsStrategy`] (jamais `/etc/resolv.conf` ; aucun lien
//!   suivi, restauration par descripteur).
//! - Adresse/passerelle IPv6 du tunnel : [`NetError::Unsupported`].
//!
//! Tout ce qui est installé est annulé par le [`NetGuard`] retourné par
//! `apply` (ordre inverse ; version bloquante sur un thread dédié pour `Drop`).
//!
//! [`PacketChannel`]: fortivpn_core::PacketChannel
//! [`TunDevice`]: fortivpn_core::TunDevice
//! [`NetError::Unsupported`]: fortivpn_core::NetError::Unsupported
//! [`NetGuard`]: fortivpn_core::NetGuard
#![cfg(target_os = "linux")]

mod backend;
mod dns;
mod netlink;
mod plan;
mod system;
mod tun;

pub use backend::{LinuxCleanup, LinuxNetBackend};
pub use dns::DnsStrategy;
