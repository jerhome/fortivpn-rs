//! Abstraction du réseau de l'OS : interface TUN, adresse, MTU, routes, DNS.
//!
//! Cycle de vie attendu :
//!
//! 1. [`NetBackend::create_tun`] crée l'interface et retourne un [`TunDevice`]
//!    (identité + canal de paquets IP). L'interface vit tant que son canal de
//!    paquets n'est pas libéré.
//! 2. [`NetBackend::apply`] installe adresse/MTU, route de préservation de la
//!    passerelle, routes et DNS, puis retourne un [`NetGuard`].
//! 3. [`NetGuard::teardown`] (async, explicite, idempotent) annule ce qui a été
//!    installé. À défaut, le `Drop` du guard le fait de manière bloquante
//!    (best-effort) : panique, `?` anticipé, tâche annulée…
//!
//!
//! Maintien de la protection pendant une reconnexion (opt-in) : par défaut, la
//! session appelle [`NetGuard::teardown`] dès la fin du relais, donc routes, DNS et
//! éventuels filtres de fuite disparaissent pendant le backoff et la reconnexion.
//! Un backend dont [`NetBackend::keep_guard_during_reconnect`] retourne `true`
//! change le contrat : la session n'appelle alors PAS `teardown` à la fin d'un
//! relais mais [`NetBackend::suspend`], garde le guard armé pendant l'état
//! `Reconnecting`, puis (make-before-break) ne le démonte qu'après le succès du
//! `apply` suivant, ou à la fin définitive de la session (`teardown`, avant la
//! déconnexion du transport). Le backend doit donc : (1) dans `suspend`, retirer ce
//! qui est propre au tunnel mort (routes, DNS) mais garder la protection
//! (ex. filtres WFP bloquant tout sauf tunnel/passerelle) ; (2) tolérer qu'un
//! nouvel `apply` ait lieu pendant que l'ancien guard est encore armé, puis que
//! l'ancien guard soit démonté ensuite sans retirer ce que le nouveau a adopté ;
//! (3) retirer toute la protection quand le dernier guard est démonté ou lâché.
//!
//! Les implémentations réelles sont dans `netlinux` et `netwin`.

use std::future::Future;

use crate::config::TunnelConfig;
use crate::error::NetError;
use crate::packet::PacketChannel;

/// Paramètres de création de l'interface TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TunOptions {
    /// Nom souhaité de l'interface (le backend peut l'ajuster).
    pub name: String,
    /// Nombre maximal de paquets en attente par direction.
    pub queue_capacity: usize,
}

impl TunOptions {
    /// Options par défaut avec le nom donné.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            queue_capacity: 256,
        }
    }
}

/// Identité d'une interface TUN créée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunInfo {
    /// Nom effectif de l'interface.
    pub name: String,
    /// Index OS de l'interface, si le backend en dispose.
    pub index: Option<u32>,
}

/// Interface TUN créée par un backend.
#[derive(Debug)]
pub struct TunDevice {
    /// Identité de l'interface (à passer à [`NetBackend::apply`]).
    pub info: TunInfo,
    /// Paquets IP : `recv` = paquets émis par l'OS vers le tunnel,
    /// `send` = paquets reçus du tunnel à injecter dans l'OS.
    pub packets: PacketChannel,
}

/// Backend réseau de l'OS (choisi à la compilation).
///
/// Les méthodes retournent des futures `Send` pour pouvoir être lancées dans
/// `tokio::spawn`. Le trait n'est pas « dyn-compatible » : `core` est générique
/// sur le backend.
pub trait NetBackend: Send + Sync {
    /// Annulation des modifications installées par [`NetBackend::apply`].
    type Cleanup: NetCleanup;

    /// Crée l'interface TUN.
    fn create_tun(
        &self,
        options: &TunOptions,
    ) -> impl Future<Output = Result<TunDevice, NetError>> + Send;

    /// Applique `config` sur l'interface `tun` : adresse et MTU, route de la
    /// passerelle hors tunnel, routes (split ou full), DNS.
    ///
    /// Contrat : en cas d'erreur, l'implémentation doit avoir annulé ce
    /// qu'elle a déjà installé avant de retourner (pas d'état partiel).
    fn apply(
        &self,
        tun: &TunInfo,
        config: &TunnelConfig,
    ) -> impl Future<Output = Result<NetGuard<Self::Cleanup>, NetError>> + Send;

    /// Vrai si la protection doit être maintenue pendant `Reconnecting` (cf. la
    /// documentation du module). Défaut : `false` (démontage complet à chaque
    /// fin de relais, comportement historique).
    fn keep_guard_during_reconnect(&self) -> bool {
        false
    }

    /// Appelée à la place de [`NetGuard::teardown`] à la fin d'un relais, seulement si
    /// [`keep_guard_during_reconnect`](Self::keep_guard_during_reconnect) est vrai.
    /// Le guard reste armé après l'appel. Une erreur est journalisée et ne change
    /// pas le flux (le guard est conservé). Défaut : ne fait rien.
    fn suspend(
        &self,
        guard: &mut NetGuard<Self::Cleanup>,
    ) -> impl Future<Output = Result<(), NetError>> + Send {
        let _ = guard;
        std::future::ready(Ok(()))
    }
}

/// Annulation, fournie par un backend, de ce qu'il a installé.
///
/// N'est pas appelée directement : elle est pilotée par [`NetGuard`], qui
/// garantit qu'après un succès elle n'est plus jamais rappelée.
pub trait NetCleanup: Send + 'static {
    /// Annulation asynchrone (chemin normal, via [`NetGuard::teardown`]).
    ///
    /// Doit tolérer d'être rappelée après un échec partiel ou une annulation de
    /// la future (ne retirer que ce qui reste installé).
    fn cleanup(&mut self) -> impl Future<Output = Result<(), NetError>> + Send;

    /// Annulation bloquante best-effort, appelée depuis `Drop`. Doit être
    /// rapide et ne jamais paniquer.
    fn cleanup_blocking(&mut self) -> Result<(), NetError>;
}

/// Guard RAII de la configuration réseau appliquée.
///
/// - [`NetGuard::teardown`] : annulation explicite, idempotente.
/// - `Drop` : si `teardown` n'a pas abouti (oubli, erreur, panique, future
///   annulée), annulation bloquante via [`NetCleanup::cleanup_blocking`].
#[derive(Debug)]
#[must_use = "lâcher le guard annule immédiatement la configuration réseau"]
pub struct NetGuard<C: NetCleanup> {
    cleanup: Option<C>,
}

impl<C: NetCleanup> NetGuard<C> {
    /// Arme un guard autour de l'annulation fournie par le backend.
    pub fn new(cleanup: C) -> Self {
        Self {
            cleanup: Some(cleanup),
        }
    }

    /// Vrai tant que la configuration n'a pas été annulée avec succès.
    pub fn is_active(&self) -> bool {
        self.cleanup.is_some()
    }

    /// Transforme l'annulation portée par le guard (ex. pour l'envelopper dans un
    /// type commun à plusieurs backends) sans la déclencher.
    pub fn map<D: NetCleanup>(mut self, f: impl FnOnce(C) -> D) -> NetGuard<D> {
        NetGuard {
            cleanup: self.cleanup.take().map(f),
        }
    }

    /// Annule la configuration. Idempotent : sans effet après un succès.
    /// En cas d'erreur le guard reste armé (nouvel essai possible, sinon au `Drop`).
    pub async fn teardown(&mut self) -> Result<(), NetError> {
        if let Some(cleanup) = self.cleanup.as_mut() {
            cleanup.cleanup().await?;
            self.cleanup = None;
        }
        Ok(())
    }
}

impl<C: NetCleanup> Drop for NetGuard<C> {
    fn drop(&mut self) {
        if let Some(mut cleanup) = self.cleanup.take() {
            tracing::debug!("NetGuard lâché sans teardown : annulation bloquante");
            if let Err(e) = cleanup.cleanup_blocking() {
                tracing::error!(error = %e, "échec du nettoyage réseau au Drop");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct Count(Arc<AtomicUsize>);

    impl NetCleanup for Count {
        fn cleanup(&mut self) -> impl Future<Output = Result<(), NetError>> + Send {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }

        fn cleanup_blocking(&mut self) -> Result<(), NetError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Wrapped(Count);

    impl NetCleanup for Wrapped {
        async fn cleanup(&mut self) -> Result<(), NetError> {
            self.0.cleanup().await
        }

        fn cleanup_blocking(&mut self) -> Result<(), NetError> {
            self.0.cleanup_blocking()
        }
    }

    #[test]
    fn map_moves_cleanup_without_running_it() {
        let n = Arc::new(AtomicUsize::new(0));
        let guard = NetGuard::new(Count(Arc::clone(&n)));
        let mapped = guard.map(Wrapped);
        assert_eq!(n.load(Ordering::SeqCst), 0);
        assert!(mapped.is_active());
        drop(mapped);
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }
}
