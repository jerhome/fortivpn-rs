//! Codes de sortie du binaire `fortivpn`.

use std::process::ExitCode;

use fortivpn_core::{DisconnectReason, NetError, TransportError};

/// Code de sortie (valeur stable, documentée dans `--help`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Exit {
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
}

impl Exit {
    /// Valeur numérique.
    pub(crate) fn code(self) -> u8 {
        self as u8
    }
}

impl From<Exit> for ExitCode {
    fn from(e: Exit) -> Self {
        ExitCode::from(e.code())
    }
}

/// Code de sortie correspondant à la fin d'une session.
pub(crate) fn from_reason(reason: &DisconnectReason) -> Exit {
    match reason {
        DisconnectReason::Requested => Exit::Ok,
        DisconnectReason::ConnectFailed(e) => match **e {
            TransportError::AuthFailed => Exit::AuthRejected,
            _ => Exit::Connection,
        },
        DisconnectReason::NetworkFailed(_) | DisconnectReason::TunClosed => Exit::LocalNetwork,
        DisconnectReason::TransportFailed(_) | DisconnectReason::TransportClosed => {
            Exit::Connection
        }
        _ => Exit::Internal,
    }
}

/// Code de sortie d'un échec de création du backend réseau.
///
/// `netwin` signale le verrou d'instance par `NetError::Os { op: "instance_lock" }`
/// (autre instance active, ou mutex inaccessible faute de droits).
pub(crate) fn from_backend_error(e: &NetError) -> Exit {
    match e {
        NetError::Os { op, .. } if *op == INSTANCE_LOCK_OP => Exit::AlreadyRunning,
        _ => Exit::LocalNetwork,
    }
}

/// Opération `netwin` du verrou d'instance.
const INSTANCE_LOCK_OP: &str = "instance_lock";

/// Aide affichée par `--help`.
pub(crate) const HELP: &str = "\
Codes de sortie :
  0  arrêt demandé (Ctrl+C, fermeture de la console) ou commande réussie
  1  erreur interne
  2  ligne de commande invalide
  3  configuration absente ou invalide
  4  authentification refusée
  5  erreur réseau côté passerelle (connexion, TLS, tunnel refusé ou perdu)
  6  erreur réseau locale (interface TUN, routes, DNS ; droits insuffisants ?)
  7  une autre instance de fortivpn-rs est déjà active";

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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
        let lock = NetError::Os {
            op: "instance_lock",
            reason: "une autre instance de fortivpn-rs est déjà active".into(),
        };
        assert_eq!(from_backend_error(&lock), Exit::AlreadyRunning);
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
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.code(), b.code());
            }
            assert!(HELP.contains(&format!("  {}  ", a.code())));
        }
    }
}
