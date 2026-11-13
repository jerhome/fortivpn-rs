//! Codes de sortie du binaire `fortivpn`.

use std::process::ExitCode;

use fortivpn_core::{DisconnectReason, NetError, TransportError};

/// Code de sortie (valeur stable, documentée dans `--help`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    /// Arrêt demandé (Ctrl+C, fermeture de la console…) ou commande réussie.
    Ok = 0,
    /// Erreur interne ou inattendue (transport indisponible, saisie impossible…).
    Internal = 1,
    /// Ligne de commande invalide (code de `clap`).
    Usage = 2,
    /// Fichier de configuration absent ou invalide.
    Config = 3,
    /// Identifiants refusés par la passerelle.
    AuthRejected = 4,
    /// Erreur réseau côté passerelle : connexion/TLS impossible, tunnel refusé ou
    /// perdu, session fermée par la passerelle.
    Connection = 5,
    /// Erreur réseau locale : création ou configuration de l'interface TUN, des
    /// routes ou du DNS (souvent : droits insuffisants).
    LocalNetwork = 6,
    /// Une autre instance de fortivpn-rs est active (verrou d'instance Windows).
    AlreadyRunning = 7,
    /// Double authentification (OTP, challenge) exigée : non prise en charge.
    SecondFactor = 8,
    /// Connexion annulée par l'utilisateur (second facteur refusé de saisir).
    Cancelled = 9,
}

impl Exit {
    /// Valeur numérique.
    pub fn code(self) -> u8 {
        self as u8
    }
}

impl From<Exit> for ExitCode {
    fn from(e: Exit) -> Self {
        ExitCode::from(e.code())
    }
}

/// Code de sortie correspondant à la fin d'une session.
pub fn from_reason(reason: &DisconnectReason) -> Exit {
    match reason {
        DisconnectReason::Requested => Exit::Ok,
        DisconnectReason::ConnectFailed(e) => match **e {
            TransportError::AuthFailed => Exit::AuthRejected,
            TransportError::SecondFactorRequired => Exit::SecondFactor,
            TransportError::Cancelled => Exit::Cancelled,
            _ => Exit::Connection,
        },
        DisconnectReason::NetworkFailed(_) | DisconnectReason::TunClosed => Exit::LocalNetwork,
        DisconnectReason::TransportFailed(_) | DisconnectReason::TransportClosed => {
            Exit::Connection
        }
        _ => Exit::Internal,
    }
}

/// Message affiché quand le système refuse la création de l'interface (EPERM/EACCES).
pub const INSUFFICIENT_RIGHTS: &str = "droits insuffisants : lancez avec sudo (Linux) / via le service \
     (Windows), ou utilisez le mode proxy ([proxy] dans la config)";

/// L'erreur réseau est un refus de droits (EPERM, EACCES, accès refusé).
pub fn is_permission_denied(e: &NetError) -> bool {
    match e {
        NetError::Io { source, .. } => {
            source.kind() == std::io::ErrorKind::PermissionDenied
                || matches!(source.raw_os_error(), Some(1 | 13))
        }
        _ => false,
    }
}

/// Code de sortie d'un échec de création du backend réseau.
///
/// `netwin` signale une autre instance active par `NetError::AlreadyRunning`.
pub fn from_backend_error(e: &NetError) -> Exit {
    match e {
        NetError::AlreadyRunning => Exit::AlreadyRunning,
        _ => Exit::LocalNetwork,
    }
}

/// Aide affichée par `--help`.
pub const HELP: &str = "\
Codes de sortie :
  0  arrêt demandé (Ctrl+C, fermeture de la console) ou commande réussie
  1  erreur interne
  2  ligne de commande invalide
  3  configuration absente ou invalide
  4  authentification refusée
  5  erreur réseau côté passerelle (connexion, TLS, tunnel refusé ou perdu)
  6  erreur réseau locale (interface TUN, routes, DNS ; droits insuffisants ?)
  7  une autre instance de fortivpn-rs est déjà active
  8  double authentification (OTP, challenge) non prise en charge par cette configuration
  9  connexion annulée par l'utilisateur (saisie du second facteur abandonnée)";

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test]
    fn permission_denied_detection() {
        let io = |source| NetError::Io {
            op: "create_tun",
            source,
        };
        assert!(is_permission_denied(&io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        ))));
        assert!(is_permission_denied(&io(
            std::io::Error::from_raw_os_error(1)
        )));
        assert!(!is_permission_denied(&io(
            std::io::Error::from_raw_os_error(2)
        )));
        assert!(!is_permission_denied(&NetError::AlreadyRunning));
        assert!(INSUFFICIENT_RIGHTS.starts_with("droits insuffisants : lancez avec sudo"));
        assert!(INSUFFICIENT_RIGHTS.contains("[proxy]"));
    }

    use super::*;

    #[test]
    fn mapping() {
        let t = |e| Arc::new(e);
        let cases = [
            (DisconnectReason::Requested, Exit::Ok, 0),
            (
                DisconnectReason::ConnectFailed(t(TransportError::AuthFailed)),
                Exit::AuthRejected,
                4,
            ),
            (
                DisconnectReason::ConnectFailed(t(TransportError::Io(std::io::Error::from(
                    std::io::ErrorKind::ConnectionRefused,
                )))),
                Exit::Connection,
                5,
            ),
            (
                DisconnectReason::ConnectFailed(t(TransportError::Protocol("x".into()))),
                Exit::Connection,
                5,
            ),
            (
                DisconnectReason::TransportFailed(t(TransportError::Closed)),
                Exit::Connection,
                5,
            ),
            (
                DisconnectReason::ConnectFailed(t(TransportError::SecondFactorRequired)),
                Exit::SecondFactor,
                8,
            ),
            (
                DisconnectReason::ConnectFailed(t(TransportError::Cancelled)),
                Exit::Cancelled,
                9,
            ),
            (DisconnectReason::TransportClosed, Exit::Connection, 5),
            (
                DisconnectReason::NetworkFailed(Arc::new(NetError::Unsupported("ipv6"))),
                Exit::LocalNetwork,
                6,
            ),
            (DisconnectReason::TunClosed, Exit::LocalNetwork, 6),
        ];
        for (reason, exit, code) in cases {
            assert_eq!(from_reason(&reason), exit, "{reason:?}");
            assert_eq!(exit.code(), code);
        }
    }

    #[test]
    fn backend_errors() {
        assert_eq!(
            from_backend_error(&NetError::AlreadyRunning),
            Exit::AlreadyRunning
        );
        // Plus de détection par chaîne : un `Os` « instance_lock » n'est qu'une erreur locale.
        let lock = NetError::Os {
            op: "instance_lock",
            reason: "x".into(),
        };
        assert_eq!(from_backend_error(&lock), Exit::LocalNetwork);
        assert_eq!(Exit::AlreadyRunning.code(), 7);
        let other = NetError::Os {
            op: "wintun_load",
            reason: "x".into(),
        };
        assert_eq!(from_backend_error(&other), Exit::LocalNetwork);
        assert_eq!(
            from_backend_error(&NetError::Unsupported("x")),
            Exit::LocalNetwork
        );
    }

    #[test]
    fn codes_are_distinct() {
        let all = [
            Exit::Ok,
            Exit::Internal,
            Exit::Usage,
            Exit::Config,
            Exit::AuthRejected,
            Exit::Connection,
            Exit::LocalNetwork,
            Exit::AlreadyRunning,
            Exit::SecondFactor,
            Exit::Cancelled,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.code(), b.code());
            }
            assert!(HELP.contains(&format!("  {}  ", a.code())));
        }
    }
}
