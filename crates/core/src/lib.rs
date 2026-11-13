//! Cœur du client : session, boucle tunnel tokio et reconnexion.
//!
//! Ce crate ne connaît ni le protocole précis (SSL-VPN ou IPsec), ni le réseau de
//! l'OS : il manipule deux abstractions.
//!
//! - [`Transport`] : établit la session avec la passerelle et fournit une
//!   [`TunnelConfig`] neutre + un canal de paquets IP ([`PacketChannel`]).
//! - [`NetBackend`] : crée l'interface TUN et y applique la [`TunnelConfig`]
//!   (adresse, MTU, routes, DNS). Le nettoyage est garanti par le [`NetGuard`]
//!   retourné par [`NetBackend::apply`].
//!
//! Les implémentations fictives en mémoire ([`fake`]) sont disponibles en test et
//! via la feature `test-util`.

pub mod config;
pub mod error;
pub mod net;
pub mod packet;
pub mod session;
pub mod sslvpn;
pub mod transport;
pub mod tunnel;

#[cfg(any(test, feature = "test-util"))]
pub mod fake;

pub use config::{DnsConfig, Ipv4Config, Ipv6Config, RoutingMode, TunnelConfig};
pub use error::{ChannelClosed, ConfigError, NetError, TransportError};
pub use net::{NetBackend, NetCleanup, NetGuard, TunDevice, TunInfo, TunOptions};
pub use packet::{PacketChannel, PacketPermit, PacketReceiver, PacketSender};
pub use session::{
    DisconnectReason, ReconnectPolicy, Session, SessionEvent, SessionEvents, SessionHandle,
    SessionOptions, SessionState,
};
pub use transport::{
    ConnectStep, Credentials, ProgressSink, SessionEnd, SessionEndNotifier, Transport,
    TransportSession, session_end,
};
pub use tunnel::{Tunnel, TunnelError, TunnelHandle, TunnelOptions, TunnelParams};
