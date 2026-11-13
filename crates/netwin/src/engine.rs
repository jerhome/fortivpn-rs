//! Moteur d'installation / annulation, indépendant de l'OS.
//!
//! Les appels système sont abstraits par [`SystemOps`] (implémenté par
//! `win::ffi::WinOps` sous Windows, par un simulateur en test). Ce module porte
//! toute la logique de cohérence :
//!
//! - ordre d'installation (interface, adresse, routes underlay résolues avant
//!   toute route tunnel, routes tunnel, blocage IPv6, DNS d'interface, NRPT
//!   locale ; détection d'une NRPT de stratégie de groupe qui la masquerait) ;
//! - journal write-ahead persistant ([`JournalStore`]) ;
//! - rollback interne en cas d'erreur (aucun état partiel) ;
//! - annulation en ordre inverse, tolérante (continue après une erreur, garde
//!   ce qui n'a pas pu être retiré pour un nouvel essai) ;
//! - récupération des résidus d'une exécution précédente, **après
//!   vérification** de chaque entrée du journal contre l'état du système
//!   (revue 5.3, E1 : le journal n'est jamais cru sur parole).

use std::net::Ipv4Addr;

use fortivpn_core::{NetError, RoutingMode, TunnelConfig};
use ipnet::{Ipv4Net, Ipv6Net};

use crate::plan::{self, DnsPlan, NrptRule, PlannedRoute, Via};
use crate::state::{Installed, JournalStore};

/// Route d'origine (hors tunnel) vers une destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Underlay {
    /// `NET_LUID` de l'interface physique.
    pub(crate) luid: u64,
    /// Prochain saut (`0.0.0.0` : on-link).
    pub(crate) next_hop: Ipv4Addr,
}

/// Opération d'installation (porte les données nécessaires à la création).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Address {
        luid: u64,
        address: Ipv4Net,
    },
    Route {
        luid: u64,
        dest: Ipv4Net,
        next_hop: Ipv4Addr,
        metric: u32,
    },
    /// Route IPv6 on-link (blocage IPv6 du full-tunnel).
    Route6 {
        luid: u64,
        dest: Ipv6Net,
        metric: u32,
    },
    InterfaceDns {
        luid: u64,
        servers: Vec<Ipv4Addr>,
        search: Vec<String>,
    },
    Nrpt(NrptRule),
}

impl Action {
    /// Entrée de journal permettant d'annuler l'action.
    pub(crate) fn record(&self) -> Installed {
        match self {
            Self::Address { luid, address } => Installed::Address {
                luid: *luid,
                address: *address,
            },
            Self::Route {
                luid,
                dest,
                next_hop,
                ..
            } => Installed::Route {
                luid: *luid,
                dest: *dest,
                next_hop: *next_hop,
            },
            Self::Route6 { luid, dest, .. } => Installed::Route6 {
                luid: *luid,
                dest: *dest,
            },
            Self::InterfaceDns { luid, .. } => Installed::InterfaceDns { luid: *luid },
            Self::Nrpt(rule) => Installed::NrptRule {
                name: rule.name.clone(),
            },
        }
    }
}

/// Résultat d'une création.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Applied {
    /// Créé par nous : sera retiré à l'annulation.
    Created,
    /// Existait déjà (`ERROR_OBJECT_ALREADY_EXISTS`) : pas à nous, on n'y
    /// touchera pas.
    AlreadyPresent,
}

/// Appels système nécessaires au backend.
pub(crate) trait SystemOps {
    /// MTU IPv4 et métrique (fixe, non automatique) de l'interface du tunnel.
    /// Non annulé : l'interface appartient au tunnel et disparaît avec lui.
    fn set_interface(&mut self, luid: u64, mtu: u16, metric: u32) -> Result<(), NetError>;
    /// Active IPv6 sur l'interface du tunnel (métrique fixe ; MTU si ≥ 1280).
    /// `Ok(false)` si la pile IPv6 n'est pas liée à l'interface.
    fn set_interface_v6(&mut self, luid: u64, mtu: u16, metric: u32) -> Result<bool, NetError>;
    /// Vrai si le système dispose d'une route IPv6 vers l'Internet.
    fn has_ipv6_route(&mut self) -> Result<bool, NetError>;
    /// Route actuellement choisie par l'OS vers `dest` (`GetBestRoute2`).
    fn best_route(&mut self, dest: Ipv4Addr) -> Result<Underlay, NetError>;
    /// Crée un objet.
    fn add(&mut self, action: &Action) -> Result<Applied, NetError>;
    /// Retire un objet ; un objet déjà absent n'est pas une erreur.
    fn remove(&mut self, item: &Installed) -> Result<(), NetError>;
    /// Vrai si la route journalisée `item` (`Route` / `Route6`) existe et
    /// porte nos marques (protocole `MIB_IPPROTO_NETMGMT`, métrique
    /// [`plan::ROUTE_METRIC`]). Faux pour tout autre type d'entrée.
    fn route_is_ours(&mut self, item: &Installed) -> Result<bool, NetError>;
    /// Noms des règles NRPT locales existantes (toutes, pas seulement les nôtres).
    fn list_nrpt_rules(&mut self) -> Result<Vec<String>, NetError>;
    /// Vrai si des règles NRPT de stratégie de groupe existent : Windows
    /// ignore alors les règles NRPT locales (revue 5.3, M3). Lecture seule.
    fn nrpt_policy_active(&mut self) -> Result<bool, NetError>;
    /// Vide le cache du résolveur DNS.
    fn flush_dns(&mut self) -> Result<(), NetError>;
}

impl<O: SystemOps + ?Sized> SystemOps for &mut O {
    fn set_interface(&mut self, luid: u64, mtu: u16, metric: u32) -> Result<(), NetError> {
        (**self).set_interface(luid, mtu, metric)
    }
    fn set_interface_v6(&mut self, luid: u64, mtu: u16, metric: u32) -> Result<bool, NetError> {
        (**self).set_interface_v6(luid, mtu, metric)
    }
    fn has_ipv6_route(&mut self) -> Result<bool, NetError> {
        (**self).has_ipv6_route()
    }
    fn best_route(&mut self, dest: Ipv4Addr) -> Result<Underlay, NetError> {
        (**self).best_route(dest)
    }
    fn add(&mut self, action: &Action) -> Result<Applied, NetError> {
        (**self).add(action)
    }
    fn remove(&mut self, item: &Installed) -> Result<(), NetError> {
        (**self).remove(item)
    }
    fn route_is_ours(&mut self, item: &Installed) -> Result<bool, NetError> {
        (**self).route_is_ours(item)
    }
    fn list_nrpt_rules(&mut self) -> Result<Vec<String>, NetError> {
        (**self).list_nrpt_rules()
    }
    fn nrpt_policy_active(&mut self) -> Result<bool, NetError> {
        (**self).nrpt_policy_active()
    }
    fn flush_dns(&mut self) -> Result<(), NetError> {
        (**self).flush_dns()
    }
}

impl<J: JournalStore + ?Sized> JournalStore for &mut J {
    fn load(&mut self) -> Result<Vec<Installed>, NetError> {
        (**self).load()
    }
    fn save(&mut self, items: &[Installed]) -> Result<(), NetError> {
        (**self).save(items)
    }
}

/// Bilan d'une récupération des résidus d'une exécution précédente.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryReport {
    /// Entrées trouvées dans le journal.
    pub stale_entries: usize,
    /// Entrées ignorées sans rien retirer : objet absent, ou non attribuable
    /// à fortivpn-rs (route sans nos marques, interface autre que notre
    /// adaptateur, nom de règle NRPT étranger).
    pub rejected_entries: usize,
    /// Entrées vérifiées puis retirées (ou disparues entre-temps).
    pub removed_entries: usize,
    /// Règles NRPT fortivpn-rs orphelines (absentes du journal) supprimées.
    pub orphan_nrpt_rules: usize,
    /// Journal illisible ou hors bornes (ignoré puis remplacé).
    pub corrupt_state: bool,
}

impl RecoveryReport {
    /// Vrai si rien n'a été trouvé à nettoyer.
    pub fn was_clean(&self) -> bool {
        self.stale_entries == 0 && self.orphan_nrpt_rules == 0 && !self.corrupt_state
    }
}

/// Ne garde, parmi les entrées d'un journal relu, que celles qui désignent
/// de façon vérifiable un objet créé par fortivpn-rs (revue 5.3, E1) :
///
/// - `Address` / `InterfaceDns` : seulement sur notre adaptateur
///   (`owned_luid`, LUID dérivé de son GUID) ; `None` : aucune (un adaptateur
///   Wintun disparaît avec son processus, ses adresses et DNS avec lui) ;
/// - `Route` / `Route6` : seulement si la route existe avec nos marques ;
/// - `NrptRule` : seulement un nom de la forme fortivpn-rs.
///
/// Retourne les entrées gardées (ordre conservé) et le nombre d'écartées.
fn vet_stale<O: SystemOps>(
    ops: &mut O,
    items: Vec<Installed>,
    owned_luid: Option<u64>,
) -> (Vec<Installed>, usize) {
    let mut kept = Vec::with_capacity(items.len());
    let mut rejected = 0;
    for item in items {
        let ours = match &item {
            Installed::Address { luid, .. } | Installed::InterfaceDns { luid } => {
                owned_luid == Some(*luid)
            }
            Installed::Route { .. } | Installed::Route6 { .. } => {
                ops.route_is_ours(&item).unwrap_or_else(|e| {
                    tracing::warn!(?item, error = %e, "vérification de route impossible");
                    false
                })
            }
            Installed::NrptRule { name, .. } => plan::is_our_nrpt_rule(name),
        };
        if ours {
            kept.push(item);
        } else {
            tracing::warn!(
                ?item,
                "entrée du journal absente ou non attribuable : ignorée"
            );
            rejected += 1;
        }
    }
    (kept, rejected)
}

/// Objets installés + journal persistant.
#[derive(Debug)]
pub(crate) struct Tracker<O, J> {
    ops: O,
    store: J,
    /// Ordre d'installation ; annulation en ordre inverse.
    items: Vec<Installed>,
    /// Diagnostic : NRPT de stratégie de groupe détectée à l'installation
    /// (nos règles NRPT locales sont alors ignorées par Windows).
    gpo_nrpt_detected: bool,
}

impl<O: SystemOps, J: JournalStore> Tracker<O, J> {
    /// Reprend le journal existant : vérifie chaque entrée ([`vet_stale`]),
    /// retire les résidus confirmés et les règles NRPT orphelines. Ce qui n'a
    /// pas pu être retiré reste dans le journal (nouvel essai à la prochaine
    /// annulation).
    pub(crate) fn resume(
        mut ops: O,
        mut store: J,
        owned_luid: Option<u64>,
    ) -> (Self, RecoveryReport, Option<NetError>) {
        let mut report = RecoveryReport::default();
        let loaded = store.load().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "journal d'état illisible : ignoré");
            report.corrupt_state = true;
            Vec::new()
        });
        report.stale_entries = loaded.len();
        if report.stale_entries > 0 {
            tracing::warn!(
                count = report.stale_entries,
                "résidus d'une exécution précédente : vérification et nettoyage"
            );
        }
        let (items, rejected) = vet_stale(&mut ops, loaded, owned_luid);
        report.rejected_entries = rejected;
        let vetted = items.len();
        let mut t = Self {
            ops,
            store,
            items,
            gpo_nrpt_detected: false,
        };
        let mut first_err = None;
        if rejected > 0 || report.corrupt_state {
            // Persiste le journal filtré (le retrait ci-dessous ne réécrit
            // rien s'il ne reste aucune entrée).
            if let Err(e) = t.store.save(&t.items) {
                first_err.get_or_insert(e);
            }
        }
        if let Err(e) = t.uninstall() {
            first_err.get_or_insert(e);
        }
        report.removed_entries = vetted - t.items.len();

        match t.remove_orphan_rules() {
            Ok(n) => report.orphan_nrpt_rules = n,
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
        if report.orphan_nrpt_rules > 0 {
            t.flush_dns_best_effort();
        }
        (t, report, first_err)
    }

    /// Supprime nos règles NRPT locales présentes mais absentes du journal.
    fn remove_orphan_rules(&mut self) -> Result<usize, NetError> {
        let names = self.ops.list_nrpt_rules()?;
        let orphans: Vec<String> = names
            .into_iter()
            .filter(|n| {
                plan::is_our_nrpt_rule(n)
                    && !self
                        .items
                        .iter()
                        .any(|i| matches!(i, Installed::NrptRule { name } if name == n))
            })
            .collect();
        let mut removed = 0;
        let mut first_err = None;
        for name in orphans {
            tracing::warn!(rule = %name, "règle NRPT orpheline supprimée");
            match self.ops.remove(&Installed::NrptRule { name }) {
                Ok(()) => removed += 1,
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        first_err.map_or(Ok(removed), Err)
    }

    /// Objets actuellement journalisés (ordre d'installation).
    pub(crate) fn installed(&self) -> &[Installed] {
        &self.items
    }

    fn flush_dns_best_effort(&mut self) {
        if let Err(e) = self.ops.flush_dns() {
            tracing::warn!(error = %e, "échec du vidage du cache DNS");
        }
    }

    /// Vrai si une NRPT de stratégie de groupe a été détectée à
    /// l'installation : nos règles NRPT locales sont ignorées par Windows
    /// (fuite DNS possible, en particulier en full-tunnel).
    pub(crate) fn gpo_nrpt_detected(&self) -> bool {
        self.gpo_nrpt_detected
    }

    /// Journalise puis exécute `action`.
    fn install(&mut self, action: &Action) -> Result<(), NetError> {
        self.items.push(action.record());
        if let Err(e) = self.store.save(&self.items) {
            self.items.pop();
            return Err(e);
        }
        match self.ops.add(action) {
            Ok(Applied::Created) => Ok(()),
            Ok(Applied::AlreadyPresent) => {
                tracing::warn!(
                    ?action,
                    "déjà présent : conservé tel quel, ne sera pas retiré"
                );
                self.items.pop();
                self.save_best_effort();
                Ok(())
            }
            Err(e) => {
                self.items.pop();
                self.save_best_effort();
                Err(e)
            }
        }
    }

    fn save_best_effort(&mut self) {
        if let Err(e) = self.store.save(&self.items) {
            tracing::warn!(error = %e, "échec d'écriture du journal d'état");
        }
    }

    /// Retire tout ce qui est journalisé, en ordre inverse. Continue après une
    /// erreur ; ce qui n'a pas pu être retiré reste journalisé et la première
    /// erreur est retournée. Idempotent.
    pub(crate) fn uninstall(&mut self) -> Result<(), NetError> {
        if self.items.is_empty() {
            return Ok(());
        }
        let mut first_err = None;
        let mut kept: Vec<Installed> = Vec::new();
        let mut dns_removed = false;
        while let Some(item) = self.items.pop() {
            match self.ops.remove(&item) {
                Ok(()) => dns_removed |= item.is_dns(),
                Err(e) => {
                    tracing::warn!(?item, error = %e, "échec du retrait");
                    kept.push(item);
                    first_err.get_or_insert(e);
                }
            }
            let mut remaining = self.items.clone();
            remaining.extend(kept.iter().rev().cloned());
            if let Err(e) = self.store.save(&remaining) {
                tracing::warn!(error = %e, "échec d'écriture du journal d'état");
            }
        }
        kept.reverse();
        self.items = kept;
        if let Err(e) = self.store.save(&self.items) {
            first_err.get_or_insert(e);
        }
        if dns_removed {
            self.flush_dns_best_effort();
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Prépare IPv6 sur le tunnel pour le blocage du full-tunnel. Vrai si les
    /// routes de blocage peuvent être installées. Erreur si IPv6 est routé
    /// par ailleurs mais indisponible sur l'adaptateur (fuite certaine).
    fn prepare_ipv6_block(&mut self, tun_luid: u64, mtu: u16) -> Result<bool, NetError> {
        if self
            .ops
            .set_interface_v6(tun_luid, mtu, plan::TUNNEL_INTERFACE_METRIC)?
        {
            return Ok(true);
        }
        if self.ops.has_ipv6_route()? {
            return Err(NetError::Os {
                op: "ipv6_block",
                reason: "IPv6 routé sur ce poste mais non lié à l'adaptateur du tunnel : \
                         le trafic IPv6 sortirait en clair, full-tunnel refusé"
                    .into(),
            });
        }
        tracing::info!("IPv6 sans route sur ce poste : pas de routes de blocage IPv6");
        Ok(false)
    }

    /// Détecte une NRPT de stratégie de groupe (lecture seule). Par décision
    /// produit, on n'écrit rien sous la clé GPO : avertissement et diagnostic
    /// seulement, la connexion continue (split comme full).
    fn detect_gpo_nrpt(&mut self, full_tunnel: bool) {
        match self.ops.nrpt_policy_active() {
            Ok(false) => {}
            Ok(true) => {
                self.gpo_nrpt_detected = true;
                if full_tunnel {
                    tracing::warn!(
                        "règles NRPT de stratégie de groupe présentes : Windows ignore les règles \
                         NRPT locales de fortivpn-rs ; en full-tunnel, des requêtes DNS peuvent \
                         partir hors tunnel (fuite DNS)"
                    );
                } else {
                    tracing::warn!(
                        "règles NRPT de stratégie de groupe présentes : Windows ignore les règles \
                         NRPT locales de fortivpn-rs ; les noms internes peuvent être résolus \
                         par le DNS de la carte physique"
                    );
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "détection de la NRPT de stratégie de groupe impossible"
            ),
        }
    }

    fn install_all(
        &mut self,
        tun_luid: u64,
        config: &TunnelConfig,
        routes: &[PlannedRoute],
        block_v6: &[Ipv6Net],
        dns: &DnsPlan,
    ) -> Result<(), NetError> {
        self.ops
            .set_interface(tun_luid, config.mtu, plan::TUNNEL_INTERFACE_METRIC)?;
        let block_v6 = if block_v6.is_empty() || !self.prepare_ipv6_block(tun_luid, config.mtu)? {
            &[]
        } else {
            block_v6
        };
        self.install(&Action::Address {
            luid: tun_luid,
            address: config.ipv4.address,
        })?;

        // Toutes les routes d'origine sont résolues avant d'installer la
        // moindre route tunnel (sinon GetBestRoute2 verrait le tunnel).
        let mut actions = Vec::with_capacity(routes.len() + block_v6.len());
        for r in routes {
            let (luid, next_hop) = match r.via {
                Via::Tunnel => (tun_luid, Ipv4Addr::UNSPECIFIED),
                Via::Underlay => {
                    let u = self.ops.best_route(r.dest.network())?;
                    if u.luid == tun_luid {
                        return Err(NetError::Os {
                            op: "best_route",
                            reason: format!(
                                "la route d'origine vers {} passe déjà par le tunnel",
                                r.dest
                            ),
                        });
                    }
                    (u.luid, u.next_hop)
                }
            };
            actions.push(Action::Route {
                luid,
                dest: r.dest,
                next_hop,
                metric: plan::ROUTE_METRIC,
            });
        }
        actions.extend(block_v6.iter().map(|dest| Action::Route6 {
            luid: tun_luid,
            dest: *dest,
            metric: plan::ROUTE_METRIC,
        }));
        for a in &actions {
            self.install(a)?;
        }

        if dns.has_interface_settings() {
            self.install(&Action::InterfaceDns {
                luid: tun_luid,
                servers: dns.servers.clone(),
                search: dns.search.clone(),
            })?;
        }
        for rule in &dns.nrpt {
            self.install(&Action::Nrpt(rule.clone()))?;
        }
        if !dns.nrpt.is_empty() {
            self.detect_gpo_nrpt(matches!(config.routing, RoutingMode::Full { .. }));
        }
        if dns.has_interface_settings() || !dns.nrpt.is_empty() {
            self.flush_dns_best_effort();
        }
        Ok(())
    }
}

/// Applique `config` sur l'interface `tun_luid` (LUID de notre adaptateur,
/// vérifié par l'appelant).
///
/// Les résidus d'une exécution précédente trouvés dans le journal sont d'abord
/// vérifiés et retirés. En cas d'erreur, tout ce qui a été installé par cet
/// appel est retiré avant de retourner (contrat `NetBackend::apply`).
pub(crate) fn apply_config<O: SystemOps, J: JournalStore>(
    ops: O,
    store: J,
    tun_luid: u64,
    config: &TunnelConfig,
) -> Result<Tracker<O, J>, NetError> {
    plan::check_supported(config)?;
    let routes = plan::plan_routes(config)?;
    let block_v6 = plan::plan_ipv6_block(config);
    let dns = plan::plan_dns(config);

    let (mut t, report, err) = Tracker::resume(ops, store, Some(tun_luid));
    if let Some(e) = err {
        tracing::warn!(
            error = %e,
            ?report,
            "résidus non entièrement retirés : conservés dans le journal"
        );
    }
    let leftovers = t.items.len();
    match t.install_all(tun_luid, config, &routes, &block_v6, &dns) {
        Ok(()) => Ok(t),
        Err(e) => {
            // Retire ce que cet appel a installé, plus les résidus éventuels.
            if let Err(re) = t.uninstall() {
                tracing::error!(error = %re, leftovers, "rollback incomplet");
            }
            Err(e)
        }
    }
}

/// Purge les résidus d'une exécution précédente (journal vérifié + règles NRPT
/// orphelines). `owned_luid` : LUID de notre adaptateur s'il existe.
/// Erreur si quelque chose n'a pas pu être retiré.
pub(crate) fn recover<O: SystemOps, J: JournalStore>(
    ops: O,
    store: J,
    owned_luid: Option<u64>,
) -> Result<RecoveryReport, NetError> {
    let (_t, report, err) = Tracker::resume(ops, store, owned_luid);
    match err {
        Some(e) => Err(e),
        None => Ok(report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::tests::sample;
    use crate::state::MemStore;

    const TUN: u64 = 0xAAAA;
    const PHYS: u64 = 0x0007;
    const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    /// Simulateur du système : objets présents + journal des appels.
    #[derive(Debug, Default)]
    #[allow(clippy::struct_excessive_bools)]
    struct Sim {
        present: Vec<Installed>,
        /// Règles NRPT locales tierces.
        foreign_nrpt: Vec<String>,
        /// Règles NRPT de stratégie de groupe présentes.
        gpo_nrpt: bool,
        /// Routes présentes mais sans nos marques (protocole / métrique).
        foreign_marks: Vec<Installed>,
        log: Vec<String>,
        adds: usize,
        fail_add_at: Option<usize>,
        fail_set_interface: bool,
        fail_remove: Vec<Installed>,
        already_present: Vec<Installed>,
        underlay_luid: u64,
        flushes: usize,
        /// IPv6 non lié à l'adaptateur.
        no_v6_on_tun: bool,
        /// Route IPv6 Internet présente.
        v6_route: bool,
    }

    impl Sim {
        fn new() -> Self {
            Self {
                underlay_luid: PHYS,
                ..Self::default()
            }
        }
    }

    impl SystemOps for Sim {
        fn set_interface(&mut self, luid: u64, mtu: u16, metric: u32) -> Result<(), NetError> {
            self.log
                .push(format!("iface {luid:x} mtu={mtu} metric={metric}"));
            if self.fail_set_interface {
                return Err(NetError::Os {
                    op: "sim",
                    reason: "set_interface".into(),
                });
            }
            Ok(())
        }
        fn set_interface_v6(&mut self, luid: u64, mtu: u16, metric: u32) -> Result<bool, NetError> {
            self.log
                .push(format!("iface6 {luid:x} mtu={mtu} metric={metric}"));
            Ok(!self.no_v6_on_tun)
        }
        fn has_ipv6_route(&mut self) -> Result<bool, NetError> {
            Ok(self.v6_route)
        }
        fn best_route(&mut self, dest: Ipv4Addr) -> Result<Underlay, NetError> {
            self.log.push(format!("best {dest}"));
            Ok(Underlay {
                luid: self.underlay_luid,
                next_hop: ROUTER,
            })
        }
        fn add(&mut self, action: &Action) -> Result<Applied, NetError> {
            self.adds += 1;
            let rec = action.record();
            self.log.push(format!("add {rec:?}"));
            if self.fail_add_at == Some(self.adds) {
                return Err(NetError::Os {
                    op: "sim",
                    reason: format!("add #{}", self.adds),
                });
            }
            if self.already_present.contains(&rec) || self.present.contains(&rec) {
                return Ok(Applied::AlreadyPresent);
            }
            self.present.push(rec);
            Ok(Applied::Created)
        }
        fn remove(&mut self, item: &Installed) -> Result<(), NetError> {
            self.log.push(format!("remove {item:?}"));
            if self.fail_remove.contains(item) {
                return Err(NetError::Os {
                    op: "sim",
                    reason: "remove".into(),
                });
            }
            self.present.retain(|p| p != item);
            if let Installed::NrptRule { name } = item {
                self.foreign_nrpt.retain(|n| n != name);
            }
            Ok(())
        }
        fn route_is_ours(&mut self, item: &Installed) -> Result<bool, NetError> {
            Ok(
                matches!(item, Installed::Route { .. } | Installed::Route6 { .. })
                    && self.present.contains(item)
                    && !self.foreign_marks.contains(item),
            )
        }
        fn list_nrpt_rules(&mut self) -> Result<Vec<String>, NetError> {
            let mut names: Vec<String> = self
                .present
                .iter()
                .filter_map(|p| match p {
                    Installed::NrptRule { name } => Some(name.clone()),
                    _ => None,
                })
                .collect();
            names.extend(self.foreign_nrpt.iter().cloned());
            Ok(names)
        }
        fn nrpt_policy_active(&mut self) -> Result<bool, NetError> {
            self.log.push("gpo?".into());
            Ok(self.gpo_nrpt)
        }
        fn flush_dns(&mut self) -> Result<(), NetError> {
            self.flushes += 1;
            Ok(())
        }
    }

    fn route(luid: u64, dest: &str, next_hop: Ipv4Addr) -> Installed {
        Installed::Route {
            luid,
            dest: dest.parse().unwrap(),
            next_hop,
        }
    }

    fn route6(dest: &str) -> Installed {
        Installed::Route6 {
            luid: TUN,
            dest: dest.parse().unwrap(),
        }
    }

    fn nrpt(i: usize) -> Installed {
        Installed::NrptRule {
            name: plan::nrpt_rule_name(i),
        }
    }

    const FOREIGN_RULE: &str = "{12345678-1234-1234-1234-123456789abc}";

    fn full() -> TunnelConfig {
        let mut c = sample();
        c.routing = RoutingMode::Full {
            exclude: vec!["192.168.1.0/24".parse().unwrap()],
        };
        c
    }

    fn expected_split() -> Vec<Installed> {
        vec![
            Installed::Address {
                luid: TUN,
                address: sample().ipv4.address,
            },
            route(PHYS, "203.0.113.10/32", ROUTER),
            route(TUN, "10.0.0.0/8", Ipv4Addr::UNSPECIFIED),
            route(TUN, "10.0.0.53/32", Ipv4Addr::UNSPECIFIED),
            Installed::InterfaceDns { luid: TUN },
            nrpt(0),
        ]
    }

    #[test]
    fn apply_split_installs_everything_and_journals_it() {
        let mut sim = Sim::new();
        let mut store = MemStore::default();
        let t = apply_config(&mut sim, &mut store, TUN, &sample()).unwrap();
        assert_eq!(t.installed(), expected_split().as_slice());
        drop(t);
        assert_eq!(sim.present, expected_split());
        assert_eq!(store.items, expected_split());
        assert_eq!(sim.log[0], format!("iface {TUN:x} mtu=1354 metric=1"));
        assert!(
            !sim.log.iter().any(|l| l.starts_with("iface6")),
            "pas d'IPv6 en split"
        );
        assert_eq!(sim.flushes, 1);
    }

    #[test]
    fn apply_full_resolves_underlay_before_any_tunnel_route() {
        let mut sim = Sim::new();
        let mut store = MemStore::default();
        let t = apply_config(&mut sim, &mut store, TUN, &full()).unwrap();
        drop(t);
        let last_best = sim
            .log
            .iter()
            .rposition(|l| l.starts_with("best "))
            .unwrap();
        let first_tunnel_route = sim
            .log
            .iter()
            .position(|l| l.starts_with("add Route") && l.contains(&format!("luid: {TUN}")))
            .unwrap();
        assert!(last_best < first_tunnel_route, "{:#?}", sim.log);
        assert!(sim.log.contains(&"best 192.168.1.0".to_owned()));
        assert!(sim.present.contains(&route(PHYS, "192.168.1.0/24", ROUTER)));
        for dest in ["0.0.0.0/1", "128.0.0.0/1", "10.0.0.53/32"] {
            assert!(
                sim.present
                    .contains(&route(TUN, dest, Ipv4Addr::UNSPECIFIED)),
                "{dest}"
            );
        }
        assert!(sim.present.contains(&nrpt(0)));
    }

    #[test]
    fn full_tunnel_blocks_ipv6_on_the_adapter() {
        let mut sim = Sim::new();
        let mut store = MemStore::default();
        let mut t = apply_config(&mut sim, &mut store, TUN, &full()).unwrap();
        assert!(t.installed().contains(&route6("::/1")));
        assert!(t.installed().contains(&route6("8000::/1")));
        t.uninstall().unwrap();
        drop(t);
        assert!(
            sim.log
                .contains(&format!("iface6 {TUN:x} mtu=1354 metric=1"))
        );
        assert!(sim.present.is_empty(), "routes IPv6 retirées");
    }

    #[test]
    fn full_tunnel_without_ipv6_anywhere_skips_the_block() {
        let mut sim = Sim::new();
        sim.no_v6_on_tun = true;
        let mut store = MemStore::default();
        let t = apply_config(&mut sim, &mut store, TUN, &full()).unwrap();
        assert!(
            !t.installed()
                .iter()
                .any(|i| matches!(i, Installed::Route6 { .. }))
        );
    }

    #[test]
    fn full_tunnel_refused_if_ipv6_routed_but_not_on_adapter() {
        let mut sim = Sim::new();
        sim.no_v6_on_tun = true;
        sim.v6_route = true;
        let mut store = MemStore::default();
        let err = apply_config(&mut sim, &mut store, TUN, &full()).unwrap_err();
        assert!(
            matches!(
                err,
                NetError::Os {
                    op: "ipv6_block",
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(sim.adds, 0, "refus avant toute installation");
    }

    #[test]
    fn failure_at_any_step_rolls_back_everything_in_reverse() {
        for n in 1..=expected_split().len() {
            let mut sim = Sim::new();
            sim.fail_add_at = Some(n);
            let mut store = MemStore::default();
            assert!(apply_config(&mut sim, &mut store, TUN, &sample()).is_err());
            assert!(sim.present.is_empty(), "étape {n}: {:#?}", sim.present);
            assert!(store.items.is_empty(), "étape {n}");
            let removes: Vec<&String> =
                sim.log.iter().filter(|l| l.starts_with("remove")).collect();
            let expected: Vec<String> = expected_split()[..n - 1]
                .iter()
                .rev()
                .map(|i| format!("remove {i:?}"))
                .collect();
            assert_eq!(
                removes,
                expected.iter().collect::<Vec<_>>(),
                "ordre inverse, étape {n}"
            );
        }
    }

    #[test]
    fn set_interface_failure_installs_nothing() {
        let mut sim = Sim::new();
        sim.fail_set_interface = true;
        let mut store = MemStore::default();
        assert!(apply_config(&mut sim, &mut store, TUN, &sample()).is_err());
        assert_eq!(sim.adds, 0);
        assert!(store.items.is_empty());
    }

    #[test]
    fn journal_write_failure_rolls_back_without_untracked_objects() {
        // Écritures : 1 = adresse, 2 = route passerelle, 3 = route tunnel…
        for n in 1..=expected_split().len() {
            let mut sim = Sim::new();
            let mut store = MemStore {
                fail_on_save: Some(n),
                ..MemStore::default()
            };
            assert!(apply_config(&mut sim, &mut store, TUN, &sample()).is_err());
            assert!(sim.present.is_empty(), "écriture {n}");
            assert_eq!(sim.adds, n - 1, "jamais d'appel système sans journal");
        }
    }

    #[test]
    fn already_present_objects_are_not_owned() {
        let gw = route(PHYS, "203.0.113.10/32", ROUTER);
        let mut sim = Sim::new();
        sim.present.push(gw.clone());
        let mut store = MemStore::default();
        let mut t = apply_config(&mut sim, &mut store, TUN, &sample()).unwrap();
        assert!(!t.installed().contains(&gw));
        t.uninstall().unwrap();
        drop(t);
        assert_eq!(sim.present, vec![gw], "route préexistante conservée");
    }

    #[test]
    fn uninstall_is_reverse_idempotent_and_flushes_once() {
        let mut sim = Sim::new();
        let mut store = MemStore::default();
        let mut t = apply_config(&mut sim, &mut store, TUN, &sample()).unwrap();
        t.uninstall().unwrap();
        t.uninstall().unwrap();
        drop(t);
        assert!(sim.present.is_empty());
        assert!(store.items.is_empty());
        let removes: Vec<String> = sim
            .log
            .iter()
            .filter(|l| l.starts_with("remove"))
            .cloned()
            .collect();
        let expected: Vec<String> = expected_split()
            .iter()
            .rev()
            .map(|i| format!("remove {i:?}"))
            .collect();
        assert_eq!(removes, expected);
        assert_eq!(sim.flushes, 2, "1 à l'installation, 1 au retrait");
    }

    #[test]
    fn failed_removal_is_kept_and_retried() {
        let gw = route(PHYS, "203.0.113.10/32", ROUTER);
        let mut sim = Sim::new();
        let mut store = MemStore::default();
        let mut t = apply_config(&mut sim, &mut store, TUN, &sample()).unwrap();
        t.ops.fail_remove.push(gw.clone());
        assert!(t.uninstall().is_err());
        assert_eq!(t.installed(), std::slice::from_ref(&gw));
        assert_eq!(t.store.items, vec![gw.clone()], "journal à jour");
        t.ops.fail_remove.clear();
        t.uninstall().unwrap();
        assert!(t.installed().is_empty());
        drop(t);
        assert!(sim.present.is_empty());
    }

    #[test]
    fn underlay_through_tunnel_is_rejected() {
        let mut sim = Sim::new();
        sim.underlay_luid = TUN;
        let mut store = MemStore::default();
        assert!(apply_config(&mut sim, &mut store, TUN, &sample()).is_err());
        assert!(sim.present.is_empty());
    }

    #[test]
    fn ipv6_is_rejected_before_any_system_call() {
        let mut sim = Sim::new();
        let mut store = MemStore::default();
        let mut c = sample();
        c.ipv6 = Some(fortivpn_core::Ipv6Config {
            address: "fd00::2/64".parse().unwrap(),
            peer: None,
        });
        assert!(matches!(
            apply_config(&mut sim, &mut store, TUN, &c),
            Err(NetError::Unsupported(_))
        ));
        assert!(sim.log.is_empty());
        assert_eq!(store.saves, 0);
    }

    #[test]
    fn recover_purges_vetted_journal_and_orphan_rules_only() {
        let orphan = plan::nrpt_rule_name(7);
        let mut sim = Sim::new();
        // Résidus d'un crash : objets présents + journal.
        sim.present = expected_split();
        sim.present.push(Installed::NrptRule { name: orphan });
        sim.foreign_nrpt.push(FOREIGN_RULE.to_owned());
        let mut store = MemStore {
            items: expected_split(),
            ..MemStore::default()
        };
        // Adaptateur toujours présent : LUID connu.
        let report = recover(&mut sim, &mut store, Some(TUN)).unwrap();
        assert_eq!(report.stale_entries, 6);
        assert_eq!(report.rejected_entries, 0);
        assert_eq!(report.removed_entries, 6);
        assert_eq!(report.orphan_nrpt_rules, 1);
        assert!(!report.was_clean());
        assert!(sim.present.is_empty());
        assert_eq!(
            sim.foreign_nrpt,
            vec![FOREIGN_RULE.to_owned()],
            "règle tierce intacte"
        );
        assert!(store.items.is_empty());

        let report = recover(&mut sim, &mut store, Some(TUN)).unwrap();
        assert!(report.was_clean());
    }

    #[test]
    fn recover_never_touches_unverifiable_entries() {
        // Journal forgé : adresse / DNS / route de la carte physique.
        let static_ip = Installed::Address {
            luid: PHYS,
            address: "192.168.1.10/24".parse().unwrap(),
        };
        let phys_dns = Installed::InterfaceDns { luid: PHYS };
        let default_route = route(PHYS, "0.0.0.0/0", ROUTER);
        let foreign_rule = Installed::NrptRule {
            name: FOREIGN_RULE.to_owned(),
        };
        let gone = route(PHYS, "198.51.100.1/32", ROUTER);
        // Notre route, encore présente avec nos marques : retirée.
        let ours = route(PHYS, "203.0.113.10/32", ROUTER);
        let tun_addr = Installed::Address {
            luid: TUN,
            address: "10.212.134.200/32".parse().unwrap(),
        };

        let mut sim = Sim::new();
        sim.present = vec![
            static_ip.clone(),
            phys_dns.clone(),
            default_route.clone(),
            ours.clone(),
            tun_addr.clone(),
        ];
        sim.foreign_marks.push(default_route.clone());
        sim.foreign_nrpt.push(FOREIGN_RULE.to_owned());
        let journal = vec![
            static_ip.clone(),
            phys_dns.clone(),
            default_route.clone(),
            foreign_rule,
            gone,
            ours.clone(),
            tun_addr.clone(),
        ];
        let mut store = MemStore {
            items: journal,
            ..MemStore::default()
        };
        // Au démarrage : pas d'adaptateur, aucun LUID ne nous appartient.
        let report = recover(&mut sim, &mut store, None).unwrap();
        assert_eq!(report.stale_entries, 7);
        assert_eq!(report.rejected_entries, 6);
        assert_eq!(report.removed_entries, 1);
        let removes: Vec<&String> = sim.log.iter().filter(|l| l.starts_with("remove")).collect();
        assert_eq!(removes, vec![&format!("remove {ours:?}")]);
        assert_eq!(
            sim.present,
            vec![static_ip, phys_dns, default_route, tun_addr],
            "rien d'autre n'est retiré"
        );
        assert_eq!(sim.foreign_nrpt.len(), 1);
        assert!(store.items.is_empty(), "journal filtré puis vidé");
    }

    #[test]
    fn apply_retries_unremovable_leftovers_at_teardown() {
        let stale = route(PHYS, "198.51.100.1/32", ROUTER);
        let mut sim = Sim::new();
        sim.present.push(stale.clone());
        sim.fail_remove.push(stale.clone());
        let mut store = MemStore {
            items: vec![stale.clone()],
            ..MemStore::default()
        };
        let mut t = apply_config(&mut sim, &mut store, TUN, &sample()).unwrap();
        assert_eq!(
            t.installed()[0],
            stale,
            "résidu conservé en tête du journal"
        );
        t.ops.fail_remove.clear();
        t.uninstall().unwrap();
        drop(t);
        assert!(sim.present.is_empty());
    }

    #[test]
    fn corrupt_state_is_reported_and_replaced() {
        #[derive(Default)]
        struct Corrupt(Option<usize>);
        impl JournalStore for Corrupt {
            fn load(&mut self) -> Result<Vec<Installed>, NetError> {
                Err(NetError::Os {
                    op: "state_parse",
                    reason: "corrompu".into(),
                })
            }
            fn save(&mut self, items: &[Installed]) -> Result<(), NetError> {
                self.0 = Some(items.len());
                Ok(())
            }
        }
        let mut store = Corrupt::default();
        let report = recover(Sim::new(), &mut store, None).unwrap();
        assert!(report.corrupt_state);
        assert_eq!(store.0, Some(0), "journal remplacé (vidé)");
    }

    #[test]
    fn gpo_nrpt_is_detected_reported_and_not_touched() {
        for c in [sample(), full()] {
            let mut sim = Sim::new();
            sim.gpo_nrpt = true;
            let mut store = MemStore::default();
            let t = apply_config(&mut sim, &mut store, TUN, &c).unwrap();
            assert!(t.gpo_nrpt_detected(), "diagnostic remonté");
            assert!(
                t.installed().contains(&nrpt(0)),
                "règle locale posée quand même"
            );
            drop(t);
            assert!(sim.log.contains(&"gpo?".to_owned()));
        }
        let mut sim = Sim::new();
        let mut store = MemStore::default();
        let t = apply_config(&mut sim, &mut store, TUN, &sample()).unwrap();
        assert!(!t.gpo_nrpt_detected());
    }
}
