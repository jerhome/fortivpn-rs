//! Protocole Fortinet SSL VPN, pur et sans I/O OS.
//!
//! Authentification HTTPS (`/remote/logincheck`), configuration XML
//! (`/remote/fortisslvpn_xml`), framing `0x5050` et machine à états PPP
//! (LCP/IPCP).
//!
//! - [`frame`] : enveloppe `0x5050` du flux TLS (`docs/protocol.md` §7).
//! - [`ppp`] : paquets PPP typés (§9) et automate LCP/IPCP sans I/O
//!   ([`ppp::PppSession`]).
//!
//! Rien dans ce crate ne fait d'I/O ni ne lit l'horloge : le temps est fourni par
//! l'appelant (`std::time::Instant`).

pub mod auth;
pub mod config;
pub mod frame;
pub mod http;
pub mod ppp;

pub use frame::{FrameDecoder, FrameError, decode_frame, encode_frame, encode_ppp_frame};
pub use ppp::{DownReason, PppConfig, PppEvent, PppSession, Protocol};
