//! Transport SSL-VPN, partie HTTPS (stories 1.1, 1.3, 2.1) : TLS + épinglage,
//! authentification `logincheck`, « allocation », configuration XML, logout.
//!
//! Séquence (`docs/protocol.md` §1) :
//!
//! 1. [`SslVpnClient::authenticate`] — connexion n°1 : `logincheck` (+ allocation),
//!    renvoie le [`SessionCookie`] ;
//! 2. [`SslVpnClient::fetch_config`] — connexion n°2 : `fortisslvpn_xml`, renvoie la
//!    configuration et la connexion à réutiliser pour `sslvpn-tunnel` (story 2.2) ;
//! 3. [`tunnel_config`] — après IPCP, construit la [`TunnelConfig`](crate::TunnelConfig) ;
//! 4. [`SslVpnClient::logout`] — connexion n°3.
//!
//! [`SslVpnTransport`] enchaîne ces étapes et le tunnel PPP derrière le trait
//! [`Transport`](crate::Transport).
//!
//! Aucun secret (mot de passe, cookie) n'est journalisé.

mod client;
mod config;
mod error;
mod tls;
mod transport;

pub use client::{GatewayConnection, SslVpnClient, SslVpnOptions, Timeouts};
pub use config::{NegotiatedIpv4, tunnel_config};
pub use error::SslVpnError;
pub use proto::auth::SessionCookie;
pub use proto::config::VpnConfig;
pub use proto::http::ConfigQuery;
pub use tls::{CertFingerprint, InvalidFingerprint, TlsOptions};
pub use transport::SslVpnTransport;
