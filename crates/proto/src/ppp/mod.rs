//! PPP sans HDLC (`docs/protocol.md` §9) : paquets typés et automate LCP/IPCP.
//!
//! - [`PppFrame`] / [`Packet`] : trame PPP (protocole + information).
//! - [`ControlPacket`] : paquet de contrôle LCP/IPCP (code, identifiant, données).
//! - [`ConfigOption`], [`LcpOption`], [`IpcpOption`] : options TLV.
//! - [`PppSession`] : automate « sans I/O ».
//!
//! Toutes les fonctions d'analyse acceptent des octets arbitraires sans paniquer.

mod options;
mod packet;
mod session;

pub use options::{ConfigOption, IpcpOption, LcpOption, encode_options, parse_options};
pub use packet::{Code, ControlPacket, MAX_CONTROL_DATA, Packet, PacketError, PppFrame, Protocol};
pub use session::{DEFAULT_MRU, DownReason, PppConfig, PppEvent, PppSession};
