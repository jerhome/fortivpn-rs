//! Types d'erreur du crate.

use std::net::IpAddr;

use ipnet::IpNet;

/// Configuration de tunnel incohérente.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// MTU inférieure au minimum IPv4.
    #[error("MTU invalide : {0} (minimum {min})", min = crate::config::MIN_MTU)]
    InvalidMtu(u16),
    /// Adresse non utilisable (non spécifiée, multicast, broadcast).
    #[error("adresse invalide : {0}")]
    InvalidAddress(IpAddr),
    /// Route IPv6 alors qu'aucun adressage IPv6 n'est configuré.
    #[error("route {0} d'une famille d'adresses non configurée")]
    RouteFamilyMismatch(IpNet),
    /// Trop de préfixes après soustraction des exclusions (config hostile).
    #[error("trop de routes après soustraction des exclusions (maximum {0})")]
    TooManyRoutes(usize),
}

/// Erreur d'un [`NetBackend`](crate::NetBackend).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// La configuration à appliquer est invalide.
    #[error("configuration tunnel invalide : {0}")]
    InvalidConfig(#[from] ConfigError),
    /// Fonctionnalité non prise en charge par ce backend (ex. IPv6).
    #[error("non pris en charge par ce backend : {0}")]
    Unsupported(&'static str),
    /// Erreur d'entrée/sortie lors d'une opération réseau.
    #[error("échec de l'opération réseau « {op} »")]
    Io {
        /// Opération en cours (ex. `"add_route"`).
        op: &'static str,
        /// Cause.
        #[source]
        source: std::io::Error,
    },
    /// Erreur rapportée par l'OS sous une forme non `io::Error`.
    #[error("échec de l'opération réseau « {op} » : {reason}")]
    Os {
        /// Opération en cours.
        op: &'static str,
        /// Message de l'OS.
        reason: String,
    },
    /// L'interface TUN a été fermée.
    #[error("interface TUN fermée")]
    TunClosed,
}

/// Erreur d'un [`Transport`](crate::Transport).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// Identifiants refusés par la passerelle.
    #[error("authentification refusée")]
    AuthFailed,
    /// Erreur d'entrée/sortie (réseau, TLS…).
    #[error("erreur d'entrée/sortie")]
    Io(#[from] std::io::Error),
    /// Violation du protocole par la passerelle.
    #[error("erreur de protocole : {0}")]
    Protocol(String),
    /// La passerelle a fourni une configuration incohérente.
    #[error("configuration reçue invalide : {0}")]
    InvalidConfig(#[from] ConfigError),
    /// `connect` appelé alors qu'une session est déjà active.
    #[error("session déjà établie")]
    AlreadyConnected,
    /// Le canal de paquets est fermé.
    #[error("canal de paquets fermé")]
    Closed,
    /// Échec ou fin du tunnel SSL-VPN (§12 : `TunnelRefused`, `BadFrame`,
    /// `PppNegotiationFailed`, `DeadPeer`, `ClosedByPeer`…).
    #[error(transparent)]
    Tunnel(#[from] crate::tunnel::TunnelError),
}

impl TransportError {
    /// Vrai si l'erreur est vraisemblablement passagère (réseau, coupure du tunnel) et
    /// justifie une reconnexion automatique. Faux pour un refus d'authentification, un
    /// second facteur exigé ou toute autre erreur de protocole, une configuration
    /// invalide ou une négociation PPP refusée.
    pub fn is_transient(&self) -> bool {
        use crate::tunnel::TunnelError as T;
        match self {
            Self::Io(_) | Self::Closed => true,
            Self::Tunnel(t) => !matches!(t, T::PppNegotiationFailed(_)),
            _ => false,
        }
    }
}

/// Le canal de paquets est fermé (l'autre extrémité a été libérée).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("canal de paquets fermé")]
pub struct ChannelClosed;

impl From<ChannelClosed> for TransportError {
    fn from(_: ChannelClosed) -> Self {
        Self::Closed
    }
}

impl From<ChannelClosed> for NetError {
    fn from(_: ChannelClosed) -> Self {
        Self::TunClosed
    }
}
