//! Erreurs du transport SSL-VPN (`docs/protocol.md` §12).

use proto::auth::CookieError;
use proto::config::XmlConfigError;
use proto::http::HttpError;

use crate::error::TransportError;

/// Erreur d'authentification / de récupération de configuration SSL-VPN.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SslVpnError {
    /// Options de connexion invalides.
    #[error("options invalides : {0}")]
    InvalidOptions(String),
    /// Résolution DNS de la passerelle impossible.
    #[error("résolution DNS de la passerelle impossible")]
    Resolve(#[source] std::io::Error),
    /// Connexion TCP impossible vers toutes les adresses de la passerelle.
    #[error("connexion TCP à la passerelle impossible")]
    Connect(#[source] std::io::Error),
    /// Délai dépassé pour l'étape indiquée.
    #[error("délai dépassé : {0}")]
    Timeout(&'static str),
    /// Certificat de la passerelle refusé (§2.3). L'empreinte peut être ajoutée aux
    /// certificats épinglés si l'utilisateur l'a vérifiée par un autre canal.
    #[error("certificat de la passerelle refusé ({reason}) ; empreinte SHA-256 : {sha256_hex}")]
    TlsUntrusted {
        /// Empreinte SHA-256 du certificat feuille (64 hex minuscules).
        sha256_hex: String,
        /// Motif du refus.
        reason: String,
    },
    /// Autre erreur TLS (poignée de main).
    #[error("erreur TLS")]
    Tls(#[source] std::io::Error),
    /// Erreur d'entrée/sortie sur la connexion établie.
    #[error("erreur d'entrée/sortie")]
    Io(#[from] std::io::Error),
    /// Réponse HTTP invalide.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// Identifiants refusés (`ret=0`, 405, `permission_denied`).
    #[error("identifiants refusés")]
    AuthFailed,
    /// Second facteur exigé (non supporté dans le MVP).
    #[error("authentification à deux facteurs requise (non supportée)")]
    SecondFactorRequired,
    /// Saisie du second facteur annulée par l'utilisateur.
    #[error("second facteur annulé")]
    SecondFactorCancelled,
    /// `ret=6`.
    #[error("challenge d'authentification non supporté")]
    UnsupportedChallenge,
    /// Statut 200 sans cookie.
    #[error(
        "la passerelle n'a pas fourni de cookie de session ; relancez avec -vv et vérifiez le mot de passe et le realm"
    )]
    NoCookie,
    /// Host-check exigé.
    #[error(
        "contrôle de conformité du poste (host-check) exigé par la passerelle, non pris en charge"
    )]
    HostCheckRequired,
    /// Realm/portail requis.
    #[error("realm/portail requis : ajoutez `realm = \"...\"` à la configuration")]
    RealmRequired,
    /// Cookie reçu invalide.
    #[error("cookie de session invalide : {0}")]
    InvalidCookie(#[from] CookieError),
    /// Statut HTTP inattendu.
    #[error("statut HTTP inattendu : {0}")]
    HttpStatus(u16),
    /// Redirection inattendue.
    #[error("redirection inattendue (HTTP {status})")]
    Redirect {
        /// Statut 3xx.
        status: u16,
        /// En-tête `Location`.
        location: Option<String>,
    },
    /// Cookie expiré ou refusé (redirection vers le login, 401/403 sur la config).
    #[error("session expirée ou cookie refusé")]
    SessionExpired,
    /// Configuration XML invalide.
    #[error(transparent)]
    Config(#[from] XmlConfigError),
}

impl From<SslVpnError> for TransportError {
    fn from(e: SslVpnError) -> Self {
        match e {
            SslVpnError::AuthFailed => Self::AuthFailed,
            SslVpnError::SecondFactorRequired | SslVpnError::UnsupportedChallenge => {
                Self::SecondFactorRequired
            }
            SslVpnError::SecondFactorCancelled => Self::Cancelled,
            SslVpnError::Io(io) | SslVpnError::Tls(io) | SslVpnError::Connect(io) => Self::Io(io),
            other => Self::Protocol(other.to_string()),
        }
    }
}
