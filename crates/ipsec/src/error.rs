//! Erreurs du crate `ipsec` (sans-io).

/// Erreur de codage/décodage IKE ou de cryptographie.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("message tronqué")]
    Truncated,
    #[error("message mal formé : {0}")]
    Malformed(&'static str),
    #[error("limite dépassée : {0}")]
    TooLarge(&'static str),
    #[error("payload critique inconnu (type {0})")]
    UnsupportedCritical(u8),
    #[error("paramètre non supporté : {0}")]
    Unsupported(&'static str),
    #[error("échec de vérification d'intégrité")]
    Integrity,
    #[error("erreur cryptographique : {0}")]
    Crypto(&'static str),
}

/// Alias de résultat.
pub type Result<T> = core::result::Result<T, Error>;
