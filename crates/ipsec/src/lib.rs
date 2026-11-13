//! Transport IPsec (IKE + ESP en espace utilisateur) — Epic 6.
//!
//! Tranche 6.1a : briques sans-io (aucune I/O, aucun aléa interne : l'appelant fournit
//! nonces, IV et clés privées DH).
//!
//! - [`wire`] : messages et payloads IKEv2 (RFC 7296).
//! - [`crypto`] : PRF, prf+, DH (groupes 14 et 19), dérivation SK_*, AUTH.
//! - [`sk`] : payload SK (AES-CBC+HMAC, AES-GCM-16).
//! - [`mschapv2`] : EAP-MSCHAPv2 et MSK.
//! - [`esp`] : ESP en espace utilisateur (RFC 4303, UDP 4500, anti-rejeu).
//! - [`ike`] : initiateur IKEv2 sans-io (IKE_SA_INIT, IKE_AUTH EAP-MSCHAPv2, KEYMAT).
//! - [`transport`] : [`IpsecTransport`], implémentation tokio/UDP du trait `Transport` de core (6.T).

#![allow(clippy::doc_markdown)]

pub mod crypto;
pub mod error;
pub mod esp;
pub mod ike;
pub mod mschapv2;
pub mod sk;
pub mod transport;
pub mod wire;

#[cfg(any(test, feature = "test-util"))]
pub mod testutil;

#[cfg(test)]
mod ike_tests;
#[cfg(test)]
mod tests;

pub use error::{Error, Result};
pub use transport::{IpsecOptions, IpsecTransport};
