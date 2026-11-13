//! Exécution du plan avec annulation garantie.
//!
//! [`System`] abstrait les appels à l'OS (netlink + fichier resolv) pour que
//! l'enchaînement, le rollback et l'annulation bloquante soient testables sans
//! privilèges. [`Rollback`] conserve la liste des annulations des opérations
//! effectivement réalisées et les rejoue dans l'ordre inverse.

use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::time::Duration;

use fortivpn_core::{NetCleanup, NetError};

use crate::plan::{Op, OriginRoute, Undo};

/// Délai maximal de l'annulation bloquante (appelée depuis `Drop`).
pub(crate) const BLOCKING_TIMEOUT: Duration = Duration::from_secs(5);

/// Résultat d'une opération.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Réalisée : à annuler avec cette opération.
    Installed(Undo),
    /// Rien à annuler (MTU/up, ou élément déjà présent qui ne nous appartient pas).
    Unchanged,
}

/// Accès à l'OS. Chaque future est autonome (pas d'état de connexion partagé),
/// ce qui permet de rejouer les annulations depuis un autre runtime/thread.
pub(crate) trait System: Clone + Send + Sync + 'static {
    /// Index de l'interface nommée.
    fn link_index(&self, name: &str) -> impl Future<Output = Result<u32, NetError>> + Send;

    /// Route d'origine vers `dst` (`None` : injoignable).
    fn lookup_route(
        &self,
        dst: Ipv4Addr,
    ) -> impl Future<Output = Result<Option<OriginRoute>, NetError>> + Send;

    /// Exécute une opération.
    fn execute(&self, op: &Op) -> impl Future<Output = Result<Outcome, NetError>> + Send;

    /// Annule une opération. Un élément déjà absent est un succès.
    fn revert(&self, undo: &Undo) -> impl Future<Output = Result<(), NetError>> + Send;
}

/// Annulations en attente, rejouées dans l'ordre inverse.
///
/// Filet de sécurité : si elle est lâchée non vide (future d'`apply` annulée,
/// panique…), le `Drop` tente une annulation bloquante.
#[derive(Debug)]
pub(crate) struct Rollback<S: System> {
    sys: S,
    undos: Vec<Undo>,
}

impl<S: System> Rollback<S> {
    pub(crate) fn new(sys: S) -> Self {
        Self {
            sys,
            undos: Vec::new(),
        }
    }

    /// Annulations restantes, dans l'ordre d'installation.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> &[Undo] {
        &self.undos
    }

    /// Annule tout ce qui reste, du plus récent au plus ancien. Continue après
    /// un échec ; les annulations échouées restent en attente (nouvel essai
    /// possible) et la première erreur est retournée.
    ///
    /// Annulable sans perte : une annulation n'est retirée de la liste qu'après
    /// son succès (et un élément déjà absent est un succès au rejeu).
    pub(crate) async fn revert_all(&mut self) -> Result<(), NetError> {
        let mut first_err = None;
        let mut i = self.undos.len();
        while i > 0 {
            i -= 1;
            match self.sys.revert(&self.undos[i]).await {
                Ok(()) => {
                    self.undos.remove(i);
                }
                Err(e) => {
                    tracing::warn!(error = %e, undo = ?self.undos[i], "échec d'annulation");
                    first_err.get_or_insert(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Annulation bloquante, utilisable depuis `Drop` y compris à l'intérieur
    /// d'un runtime tokio : exécutée sur un thread dédié avec son propre runtime
    /// `current_thread` (jamais de runtime imbriqué), bornée par
    /// [`BLOCKING_TIMEOUT`]. Définitive : ce qui n'a pas pu être retiré est
    /// journalisé puis oublié.
    pub(crate) fn revert_blocking(&mut self) -> Result<(), NetError> {
        if self.undos.is_empty() {
            return Ok(());
        }
        let mut job = Self {
            sys: self.sys.clone(),
            undos: std::mem::take(&mut self.undos),
        };
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("netlinux-cleanup".into())
            .spawn(move || {
                let result = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt.block_on(job.revert_all()),
                    Err(source) => Err(NetError::Io {
                        op: "cleanup_runtime",
                        source,
                    }),
                };
                // Vide `job` pour que son `Drop` ne relance rien.
                let remaining = std::mem::take(&mut job.undos);
                let _ = tx.send((result, remaining));
            })
            .map_err(|source| NetError::Io {
                op: "cleanup_thread",
                source,
            })?;
        match rx.recv_timeout(BLOCKING_TIMEOUT) {
            Ok((result, remaining)) => {
                if !remaining.is_empty() {
                    tracing::error!(?remaining, "configuration réseau restée en place");
                }
                result
            }
            Err(_) => Err(NetError::Os {
                op: "cleanup_blocking",
                reason: format!("délai de {BLOCKING_TIMEOUT:?} dépassé"),
            }),
        }
    }
}

impl<S: System> Drop for Rollback<S> {
    fn drop(&mut self) {
        if !self.undos.is_empty() {
            tracing::warn!(
                pending = self.undos.len(),
                "annulations en attente au Drop : nettoyage bloquant"
            );
            if let Err(e) = self.revert_blocking() {
                tracing::error!(error = %e, "échec du nettoyage bloquant");
            }
        }
    }
}

impl<S: System> NetCleanup for Rollback<S> {
    fn cleanup(&mut self) -> impl Future<Output = Result<(), NetError>> + Send {
        self.revert_all()
    }

    fn cleanup_blocking(&mut self) -> Result<(), NetError> {
        self.revert_blocking()
    }
}

/// Exécute le plan dans l'ordre. En cas d'erreur, annule ce qui a déjà été
/// fait avant de retourner l'erreur (contrat « pas d'état partiel » de
/// `NetBackend::apply`). Si la future est abandonnée en cours de route, le
/// `Drop` du [`Rollback`] partiel annule de manière bloquante.
pub(crate) async fn install<S: System>(sys: &S, ops: &[Op]) -> Result<Rollback<S>, NetError> {
    let mut rollback = Rollback::new(sys.clone());
    for op in ops {
        match sys.execute(op).await {
            Ok(Outcome::Installed(undo)) => rollback.undos.push(undo),
            Ok(Outcome::Unchanged) => {}
            Err(e) => {
                tracing::warn!(error = %e, ?op, "échec d'application : rollback");
                if let Err(re) = rollback.revert_all().await {
                    // Le Drop de `rollback` retentera de manière bloquante.
                    tracing::error!(error = %re, "rollback incomplet");
                }
                return Err(e);
            }
        }
    }
    Ok(rollback)
}

#[cfg(test)]
pub(crate) mod mock {
    //! [`System`] en mémoire pour les tests sans privilèges.

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    use ipnet::Ipv6Net;

    use super::*;
    use crate::dns::DnsUndo;
    use crate::plan::{AddrSpec, RouteSpec};

    /// Événement observé.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Event {
        Exec(Op),
        Revert(Undo),
    }

    #[derive(Debug, Default)]
    pub(crate) struct State {
        pub(crate) events: Vec<Event>,
        pub(crate) addresses: Vec<AddrSpec>,
        pub(crate) routes: Vec<RouteSpec>,
        pub(crate) blackholes: Vec<Ipv6Net>,
        pub(crate) dns: bool,
        /// Routes préexistantes (EEXIST à l'ajout).
        pub(crate) foreign_routes: Vec<RouteSpec>,
        /// Échec de la n-ième (0-based) exécution.
        pub(crate) fail_exec_at: Option<usize>,
        /// La n-ième exécution ne se termine jamais.
        pub(crate) hang_exec_at: Option<usize>,
        /// Les annulations échouent.
        pub(crate) fail_revert: bool,
        pub(crate) exec_count: usize,
        pub(crate) origins: HashMap<Ipv4Addr, OriginRoute>,
        pub(crate) default_origin: Option<OriginRoute>,
        pub(crate) links: HashMap<String, u32>,
        pub(crate) lookups: Vec<Ipv4Addr>,
    }

    #[derive(Debug, Clone, Default)]
    pub(crate) struct MockSystem(pub(crate) Arc<Mutex<State>>);

    impl MockSystem {
        pub(crate) fn state(&self) -> MutexGuard<'_, State> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        pub(crate) fn is_clean(&self) -> bool {
            let s = self.state();
            s.addresses.is_empty() && s.routes.is_empty() && s.blackholes.is_empty() && !s.dns
        }

        fn exec_now(&self, op: &Op) -> Option<Result<Outcome, NetError>> {
            let mut s = self.state();
            let n = s.exec_count;
            s.exec_count += 1;
            if s.hang_exec_at == Some(n) {
                return None;
            }
            if s.fail_exec_at == Some(n) {
                return Some(Err(NetError::Os {
                    op: "mock",
                    reason: format!("échec injecté à l'opération {n}"),
                }));
            }
            s.events.push(Event::Exec(op.clone()));
            Some(Ok(match op {
                Op::Link { .. } => Outcome::Unchanged,
                Op::Address(a) => {
                    s.addresses.push(*a);
                    Outcome::Installed(Undo::Address(*a))
                }
                Op::Route(r) if s.foreign_routes.contains(r) => Outcome::Unchanged,
                Op::Route(r) => {
                    s.routes.push(*r);
                    Outcome::Installed(Undo::Route(*r))
                }
                Op::Blackhole6(n) => {
                    s.blackholes.push(*n);
                    Outcome::Installed(Undo::Blackhole6(*n))
                }
                Op::Dns(w) => {
                    s.dns = true;
                    Outcome::Installed(Undo::Dns(DnsUndo::placeholder(&w.path)))
                }
            }))
        }

        fn revert_now(&self, undo: &Undo) -> Result<(), NetError> {
            let mut s = self.state();
            if s.fail_revert {
                return Err(NetError::Os {
                    op: "mock",
                    reason: "échec d'annulation injecté".into(),
                });
            }
            s.events.push(Event::Revert(undo.clone()));
            match undo {
                Undo::Address(a) => s.addresses.retain(|x| x != a),
                Undo::Route(r) => s.routes.retain(|x| x != r),
                Undo::Blackhole6(n) => s.blackholes.retain(|x| x != n),
                Undo::Dns(_) => s.dns = false,
            }
            Ok(())
        }
    }

    impl System for MockSystem {
        fn link_index(&self, name: &str) -> impl Future<Output = Result<u32, NetError>> + Send {
            let r = self.state().links.get(name).copied().ok_or(NetError::Os {
                op: "link_index",
                reason: "interface inconnue".into(),
            });
            std::future::ready(r)
        }

        fn lookup_route(
            &self,
            dst: Ipv4Addr,
        ) -> impl Future<Output = Result<Option<OriginRoute>, NetError>> + Send {
            let mut s = self.state();
            s.lookups.push(dst);
            let r = s.origins.get(&dst).copied().or(s.default_origin);
            std::future::ready(Ok(r))
        }

        fn execute(&self, op: &Op) -> impl Future<Output = Result<Outcome, NetError>> + Send {
            let r = self.exec_now(op);
            async move {
                match r {
                    Some(r) => r,
                    None => std::future::pending().await,
                }
            }
        }

        fn revert(&self, undo: &Undo) -> impl Future<Output = Result<(), NetError>> + Send {
            std::future::ready(self.revert_now(undo))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{Event, MockSystem};
    use super::*;
    use crate::plan::{AddrSpec, DnsWrite, RouteSpec};

    fn route(dest: &str, oif: u32) -> RouteSpec {
        RouteSpec {
            dest: dest.parse().unwrap(),
            oif,
            gateway: None,
        }
    }

    fn ops() -> Vec<Op> {
        vec![
            Op::Link {
                index: 7,
                mtu: 1400,
            },
            Op::Address(AddrSpec {
                index: 7,
                address: "10.0.0.2/32".parse().unwrap(),
                peer: None,
            }),
            Op::Route(route("203.0.113.10/32", 2)),
            Op::Route(route("10.0.0.0/8", 7)),
            Op::Dns(DnsWrite {
                path: "/nonexistent/resolv".into(),
                content: String::new(),
            }),
        ]
    }

    fn reverts(sys: &MockSystem) -> Vec<Undo> {
        sys.state()
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Revert(u) => Some(u.clone()),
                Event::Exec(_) => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn install_then_revert_in_reverse_order() {
        let sys = MockSystem::default();
        let mut rb = install(&sys, &ops()).await.unwrap();
        assert_eq!(rb.pending().len(), 4, "Link n'a pas d'annulation");
        rb.revert_all().await.unwrap();
        assert!(sys.is_clean());
        let r = reverts(&sys);
        assert!(matches!(r[0], Undo::Dns(_)));
        assert_eq!(r[1], Undo::Route(route("10.0.0.0/8", 7)));
        assert_eq!(r[2], Undo::Route(route("203.0.113.10/32", 2)));
        assert!(matches!(r[3], Undo::Address(_)));
        // Idempotent.
        rb.revert_all().await.unwrap();
        assert_eq!(reverts(&sys).len(), 4);
    }

    #[tokio::test]
    async fn failure_at_any_step_leaves_no_partial_state() {
        for step in 0..ops().len() {
            let sys = MockSystem::default();
            sys.state().fail_exec_at = Some(step);
            assert!(install(&sys, &ops()).await.is_err(), "étape {step}");
            assert!(sys.is_clean(), "étape {step}");
            // Tout ce qui a été fait a été défait.
            let execs = sys
                .state()
                .events
                .iter()
                .filter(|e| matches!(e, Event::Exec(Op::Address(_) | Op::Route(_) | Op::Dns(_))))
                .count();
            assert_eq!(reverts(&sys).len(), execs, "étape {step}");
        }
    }

    #[tokio::test]
    async fn preexisting_route_is_not_removed() {
        let sys = MockSystem::default();
        let foreign = route("203.0.113.10/32", 2);
        sys.state().foreign_routes.push(foreign);
        let mut rb = install(&sys, &ops()).await.unwrap();
        rb.revert_all().await.unwrap();
        assert!(!reverts(&sys).contains(&Undo::Route(foreign)));
    }

    #[tokio::test]
    async fn failed_revert_is_kept_for_retry() {
        let sys = MockSystem::default();
        let mut rb = install(&sys, &ops()).await.unwrap();
        sys.state().fail_revert = true;
        assert!(rb.revert_all().await.is_err());
        assert_eq!(rb.pending().len(), 4);
        sys.state().fail_revert = false;
        rb.revert_all().await.unwrap();
        assert!(rb.pending().is_empty());
        assert!(sys.is_clean());
    }

    #[tokio::test]
    async fn cancelled_install_is_rolled_back_by_drop() {
        let sys = MockSystem::default();
        sys.state().hang_exec_at = Some(3);
        let r = tokio::time::timeout(Duration::from_millis(50), install(&sys, &ops())).await;
        assert!(r.is_err(), "doit être bloqué à l'étape 3");
        assert!(sys.is_clean(), "le Drop du rollback partiel doit nettoyer");
    }

    #[test]
    fn blocking_revert_outside_runtime() {
        let sys = MockSystem::default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut rb = rt.block_on(install(&sys, &ops())).unwrap();
        drop(rt);
        rb.revert_blocking().unwrap();
        assert!(sys.is_clean());
        assert!(rb.pending().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_revert_inside_current_thread_runtime_does_not_panic() {
        let sys = MockSystem::default();
        let rb = install(&sys, &ops()).await.unwrap();
        drop(rb); // Drop -> revert_blocking depuis un runtime actif.
        assert!(sys.is_clean());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guard_drop_inside_multi_thread_runtime() {
        let sys = MockSystem::default();
        let guard = fortivpn_core::NetGuard::new(install(&sys, &ops()).await.unwrap());
        drop(guard);
        assert!(sys.is_clean());
        assert_eq!(reverts(&sys).len(), 4);
    }

    #[tokio::test]
    async fn guard_teardown_then_drop_does_nothing_more() {
        let sys = MockSystem::default();
        let mut guard = fortivpn_core::NetGuard::new(install(&sys, &ops()).await.unwrap());
        sys.state().fail_revert = true;
        assert!(guard.teardown().await.is_err());
        assert!(guard.is_active());
        sys.state().fail_revert = false;
        guard.teardown().await.unwrap();
        assert!(!guard.is_active());
        drop(guard);
        assert_eq!(reverts(&sys).len(), 4);
        assert!(sys.is_clean());
    }

    #[tokio::test]
    async fn blocking_revert_failure_is_reported_and_final() {
        let sys = MockSystem::default();
        let mut rb = install(&sys, &ops()).await.unwrap();
        sys.state().fail_revert = true;
        assert!(rb.revert_blocking().is_err());
        assert!(rb.pending().is_empty(), "le chemin bloquant est définitif");
    }
}
