//! Politique de reconnexion automatique (story 4.1) : backoff exponentiel borné avec
//! jitter, et détection de saut d'horloge (mise en veille / reprise).
//!
//! Fonctions pures, testées sans I/O ; la boucle est dans [`Session`](super::Session).

use std::num::NonZeroU32;
use std::time::Duration;

/// Politique de reconnexion d'une [`Session`](super::Session).
///
/// Après une coupure du tunnel **établi** (`DeadPeer`, `ClosedByPeer`, erreur d'E/S,
/// fin du transport, saut d'horloge), la session annule la configuration réseau,
/// suspend le transport ([`Transport::suspend`](crate::Transport::suspend) : le cookie
/// est conservé), attend le délai puis se reconnecte. Jamais de reconnexion sur un
/// refus d'authentification, un second facteur exigé, une erreur de protocole ou
/// locale, ni après un arrêt demandé. Le premier `connect` n'est pas réessayé.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ReconnectPolicy {
    /// Reconnexion activée (défaut : oui).
    pub enabled: bool,
    /// Délai avant le 1er essai (défaut 1 s) ; doublé à chaque échec.
    pub initial_delay: Duration,
    /// Délai maximal entre deux essais (défaut 60 s).
    pub max_delay: Duration,
    /// Part aléatoire retranchée du délai, dans `[0, 1]` (défaut 0,2 : délai tiré dans
    /// `[0,8 × d, d]`) : évite que tous les clients reviennent en même temps.
    pub jitter: f64,
    /// Nombre maximal d'essais consécutifs sans retour du tunnel (`None` : illimité,
    /// défaut). Le compteur est remis à zéro dès que le tunnel est rétabli.
    pub max_attempts: Option<NonZeroU32>,
    /// Détection de saut d'horloge (veille) : seuil au-delà duquel un écart entre
    /// horloge monotone et horloge murale, ou un tick en retard, force une reconnexion
    /// immédiate. `None` : désactivée. Défaut 20 s.
    pub clock_jump_threshold: Option<Duration>,
    /// Période de vérification de l'horloge pendant que le tunnel est actif (défaut 5 s).
    pub clock_check_interval: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            jitter: 0.2,
            max_attempts: None,
            clock_jump_threshold: Some(Duration::from_secs(20)),
            clock_check_interval: Duration::from_secs(5),
        }
    }
}

impl ReconnectPolicy {
    /// Politique sans reconnexion : la session se termine à la première coupure.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// Délai avant l'essai n° `attempt` (à partir de 1), `rand01` dans `[0, 1)` :
    /// `min(initial × 2^(attempt-1), max)` diminué d'au plus `jitter` × ce délai.
    pub fn delay(&self, attempt: u32, rand01: f64) -> Duration {
        let exp = attempt.saturating_sub(1).min(31);
        let base = self
            .initial_delay
            .saturating_mul(1u32 << exp)
            .min(self.max_delay);
        let cut = self.jitter.clamp(0.0, 1.0) * rand01.clamp(0.0, 1.0);
        base.mul_f64(1.0 - cut)
    }

    /// Vrai si un essai supplémentaire n° `attempt` est autorisé.
    pub(crate) fn allows(&self, attempt: u32) -> bool {
        self.enabled && self.max_attempts.is_none_or(|max| attempt <= max.get())
    }
}

/// Saut d'horloge détecté entre deux vérifications espacées de `expected` :
/// `mono` = temps écoulé selon l'horloge monotone, `wall` = selon l'horloge murale
/// (`None` si elle a reculé).
///
/// - tick en retard : `mono − expected > threshold` (processus gelé ; sous Windows,
///   l'horloge monotone avance pendant la veille) ;
/// - horloge murale en avance : `wall − mono > threshold` (sous Linux, l'horloge
///   monotone de tokio s'arrête pendant la veille, pas l'horloge murale).
///
/// Un recul de l'horloge murale (correction NTP) est ignoré. Retourne l'écart estimé.
pub(crate) fn clock_jump(
    mono: Duration,
    wall: Option<Duration>,
    expected: Duration,
    threshold: Duration,
) -> Option<Duration> {
    let late = mono.saturating_sub(expected);
    let ahead = wall.map_or(Duration::ZERO, |w| w.saturating_sub(mono));
    let jump = late.max(ahead);
    (jump > threshold).then_some(jump)
}

/// Aléa non cryptographique dans `[0, 1)` (jitter uniquement).
pub(crate) fn rand01() -> f64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        h.write_u128(d.as_nanos());
    }
    let x = u32::try_from(h.finish() >> 32).unwrap_or(0);
    f64::from(x) / (f64::from(u32::MAX) + 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn exponential_backoff_is_bounded() {
        let p = ReconnectPolicy {
            jitter: 0.0,
            ..ReconnectPolicy::default()
        };
        let delays: Vec<_> = (1..=9).map(|n| p.delay(n, 0.5)).collect();
        assert_eq!(
            delays,
            [S(1), S(2), S(4), S(8), S(16), S(32), S(60), S(60), S(60)]
        );
        assert_eq!(p.delay(0, 0.0), S(1));
        assert_eq!(p.delay(u32::MAX, 0.0), S(60));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let p = ReconnectPolicy::default();
        assert_eq!(p.delay(3, 0.0), S(4));
        assert_eq!(p.delay(3, 1.0), Duration::from_millis(3200));
        for _ in 0..100 {
            let d = p.delay(10, rand01());
            assert!(d <= S(60) && d >= S(48), "{d:?}");
        }
    }

    #[test]
    fn rand01_in_unit_interval() {
        for _ in 0..1000 {
            let r = rand01();
            assert!((0.0..1.0).contains(&r));
        }
    }

    #[test]
    fn attempts_limit() {
        let mut p = ReconnectPolicy::default();
        assert!(p.allows(1_000_000));
        p.max_attempts = NonZeroU32::new(2);
        assert!(p.allows(2));
        assert!(!p.allows(3));
        assert!(!ReconnectPolicy::disabled().allows(1));
    }

    #[test]
    fn clock_jump_detection() {
        let tick = S(5);
        let th = S(20);
        // Normal.
        assert_eq!(clock_jump(S(5), Some(S(5)), tick, th), None);
        // Léger retard / dérive : ignoré.
        assert_eq!(clock_jump(S(24), Some(S(30)), tick, th), None);
        // Veille Linux : monotone arrêtée, murale +10 min.
        assert_eq!(clock_jump(S(5), Some(S(605)), tick, th), Some(S(600)));
        // Veille Windows / processus gelé : tick très en retard.
        assert_eq!(clock_jump(S(65), Some(S(65)), tick, th), Some(S(60)));
        // Horloge murale reculée (NTP) : ignoré.
        assert_eq!(clock_jump(S(5), None, tick, th), None);
    }
}
