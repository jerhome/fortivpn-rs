//! Trait `Transport` **provisoire**.
//!
//! Un transport (SSL-VPN : Epics 1–2, IPsec : Epic 6) authentifie l'utilisateur
//! auprès de la passerelle, obtient la configuration réseau et fournit un canal
//! de paquets IP. Ce trait est volontairement minimal : il sera ajusté une fois
//! `docs/protocol.md` et `docs/protocol-ipsec.md` finalisées (second facteur
//! OTP/FortiToken, SAML, rekey, keepalive…).

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use secrecy::SecretString;
use tokio::sync::oneshot;

use crate::config::TunnelConfig;
use crate::error::TransportError;
use crate::packet::PacketChannel;

/// Identifiants utilisateur. Le mot de passe est effacé de la mémoire à la
/// libération et masqué dans `Debug`.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// Nom d'utilisateur.
    pub username: String,
    /// Mot de passe (accès via [`secrecy::ExposeSecret`]).
    pub password: SecretString,
}

impl Credentials {
    /// Construit des identifiants.
    pub fn new(username: impl Into<String>, password: impl Into<SecretString>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// Nature du second facteur demandé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecondFactorKind {
    /// Code à saisir (OTP, FortiToken matériel/mobile).
    Code,
    /// Notification push FortiToken Mobile à approuver sur l'appareil.
    Push,
}

/// Demande de second facteur transmise à un [`SecondFactorProvider`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondFactorChallenge {
    /// Nature du facteur demandé.
    pub kind: SecondFactorKind,
    /// Message de la passerelle (`chal_msg`), à afficher tel quel à l'utilisateur.
    pub message: Option<String>,
}

/// Réponse d'un [`SecondFactorProvider`].
#[non_exhaustive]
pub enum SecondFactorAnswer {
    /// Code saisi. Consommé et effacé de la mémoire dès la requête construite.
    Code(SecretString),
    /// (Challenge `Push`) l'utilisateur a été prévenu : envoyer la validation push ; la
    /// passerelle répond une fois la notification approuvée ou expirée.
    Push,
    /// L'utilisateur renonce : la connexion échoue avec [`TransportError::Cancelled`].
    Cancelled,
}

impl fmt::Debug for SecondFactorAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(_) => f.write_str("Code([REDACTED])"),
            Self::Push => f.write_str("Push"),
            Self::Cancelled => f.write_str("Cancelled"),
        }
    }
}

/// Futur renvoyé par [`SecondFactorProvider::second_factor`].
pub type SecondFactorFuture<'a> = Pin<Box<dyn Future<Output = SecondFactorAnswer> + Send + 'a>>;

/// Fournisseur de second facteur (invite CLI, boîte de dialogue GUI…), injecté dans le
/// transport. Appelé au plus une fois par authentification ; le code n'est jamais
/// journalisé ni conservé par le transport.
pub trait SecondFactorProvider: Send + Sync {
    /// Obtient le second facteur pour `challenge`.
    fn second_factor<'a>(&'a self, challenge: &'a SecondFactorChallenge) -> SecondFactorFuture<'a>;
}

/// Session établie par un transport.
#[derive(Debug)]
pub struct TransportSession {
    /// Configuration réseau négociée (validée par le transport).
    pub config: TunnelConfig,
    /// Paquets IP : `recv` = paquets reçus de la passerelle,
    /// `send` = paquets à émettre vers la passerelle.
    /// Fermé par le transport quand la session se termine.
    pub packets: PacketChannel,
    /// Raison de la fin de session, signalée par le transport **avant** de fermer
    /// [`packets`](Self::packets).
    pub end: SessionEnd,
}

/// Côté transport de la notification de fin de session (cf. [`session_end`]).
#[derive(Debug)]
pub struct SessionEndNotifier(oneshot::Sender<Result<(), TransportError>>);

/// Côté consommateur de la notification de fin de session (cf. [`session_end`]).
#[derive(Debug)]
pub struct SessionEnd {
    rx: Option<oneshot::Receiver<Result<(), TransportError>>>,
}

/// Crée une paire notificateur / récepteur de fin de session.
///
/// Le transport appelle [`SessionEndNotifier::finish`] avec `Ok(())` (fermeture
/// normale ou demandée) ou l'erreur qui a mis fin à la session. Si le notificateur
/// est libéré sans `finish` (tâche annulée, panique), la fin est signalée comme
/// [`TransportError::Closed`].
pub fn session_end() -> (SessionEndNotifier, SessionEnd) {
    let (tx, rx) = oneshot::channel();
    (SessionEndNotifier(tx), SessionEnd { rx: Some(rx) })
}

impl SessionEndNotifier {
    /// Signale la fin de session.
    pub fn finish(self, result: Result<(), TransportError>) {
        // Le récepteur peut avoir été libéré : personne n'attend plus la raison.
        let _ = self.0.send(result);
    }
}

impl SessionEnd {
    /// Attend la fin de session. Ne se termine qu'une fois : les appels suivants
    /// restent en attente indéfiniment. Annulable (utilisable dans `select!`).
    pub async fn wait(&mut self) -> Result<(), TransportError> {
        let Some(rx) = self.rx.as_mut() else {
            return std::future::pending().await;
        };
        let result = rx.await.unwrap_or(Err(TransportError::Closed));
        self.rx = None;
        result
    }

    /// Raison de fin si elle est déjà connue, sans attendre.
    pub fn try_result(&mut self) -> Option<Result<(), TransportError>> {
        let rx = self.rx.as_mut()?;
        let result = match rx.try_recv() {
            Ok(r) => r,
            Err(oneshot::error::TryRecvError::Empty) => return None,
            Err(oneshot::error::TryRecvError::Closed) => Err(TransportError::Closed),
        };
        self.rx = None;
        Some(result)
    }
}

/// Étape intermédiaire de [`Transport::connect`], pour le suivi d'état et le
/// chronométrage (story 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectStep {
    /// Identifiants acceptés (cookie de session obtenu).
    Authenticated,
    /// Configuration réseau reçue de la passerelle.
    ConfigReceived,
}

/// Récepteur des étapes de connexion, fourni au transport par
/// [`Transport::set_progress`].
#[derive(Clone)]
pub struct ProgressSink(Arc<dyn Fn(ConnectStep) + Send + Sync>);

impl ProgressSink {
    /// Crée un récepteur appelant `f` à chaque étape (doit être rapide et non bloquant).
    pub fn new(f: impl Fn(ConnectStep) + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Signale une étape.
    pub fn report(&self, step: ConnectStep) {
        (self.0)(step);
    }
}

impl fmt::Debug for ProgressSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProgressSink")
    }
}

/// Transport vers la passerelle (provisoire, cf. doc du module).
pub trait Transport: Send {
    /// Se connecte, s'authentifie et ouvre le tunnel.
    fn connect(
        &mut self,
        credentials: &Credentials,
    ) -> impl Future<Output = Result<TransportSession, TransportError>> + Send;

    /// Ferme la session (déconnexion propre côté passerelle). Idempotent.
    fn disconnect(&mut self) -> impl Future<Output = Result<(), TransportError>> + Send;

    /// Ferme la session **en vue d'une reconnexion** (story 4.1) : le tunnel est fermé
    /// mais l'état réutilisable (ex. cookie SSL-VPN) est conservé pour que le prochain
    /// [`connect`](Self::connect) évite si possible une ré-authentification. Idempotent.
    ///
    /// Par défaut : [`disconnect`](Self::disconnect).
    fn suspend(&mut self) -> impl Future<Output = Result<(), TransportError>> + Send {
        self.disconnect()
    }

    /// Installe le récepteur des étapes intermédiaires de [`connect`](Self::connect).
    /// Optionnel : par défaut, aucune étape n'est signalée.
    fn set_progress(&mut self, sink: ProgressSink) {
        let _ = sink;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_masks_password() {
        let c = Credentials::new("alice", "hunter2-s3cr3t");
        let dbg = format!("{c:?}");
        assert!(dbg.contains("alice"));
        assert!(!dbg.contains("hunter2-s3cr3t"));
    }

    #[tokio::test]
    async fn session_end_reports_result_once() {
        let (tx, mut end) = session_end();
        assert!(end.try_result().is_none());
        tx.finish(Err(TransportError::AuthFailed));
        assert!(matches!(end.wait().await, Err(TransportError::AuthFailed)));
        assert!(end.try_result().is_none());
    }

    #[tokio::test]
    async fn dropped_notifier_means_closed() {
        let (tx, mut end) = session_end();
        drop(tx);
        assert!(matches!(
            end.try_result(),
            Some(Err(TransportError::Closed))
        ));

        let (tx, mut end) = session_end();
        tx.finish(Ok(()));
        assert!(end.wait().await.is_ok());
    }
}
