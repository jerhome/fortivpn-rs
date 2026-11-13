//! Identité de l'appelant du pipe et limitation des échecs d'authentification
//! (revue 5.3 passe 2, M3) — logique pure, testée sous Linux.
//!
//! La session VPN appartient au SID de l'utilisateur qui a fait `connect` : seul ce
//! SID (ou un administrateur) peut la couper ou en voir le détail. Les échecs
//! d'authentification sont comptés par SID : 3 échecs -> 30 s d'attente, 4 -> 60 s,
//! 5 -> blocage de 15 min. Aucun mot de passe n'intervient ici ni dans les journaux.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// `NT AUTHORITY\SYSTEM`.
const SID_SYSTEM: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// `SE_GROUP_ENABLED` : un groupe « deny-only » (jeton filtré) ne compte pas.
pub const SE_GROUP_ENABLED: u32 = 0x4;

/// Échecs tolérés avant la première attente.
const FREE_FAILURES: u32 = 3;
/// Attente après le 3e échec ; doublée au 4e.
const FIRST_DELAY: Duration = Duration::from_secs(30);
/// Échecs entraînant le blocage long.
const BLOCK_FAILURES: u32 = 5;
/// Durée du blocage long.
const BLOCK_DURATION: Duration = Duration::from_secs(15 * 60);
/// Sans nouvel échec pendant ce délai, le compteur repart de zéro.
const FORGET_AFTER: Duration = Duration::from_secs(60 * 60);
/// SID suivis au plus (borne mémoire).
const MAX_TRACKED: usize = 64;

/// Appelant identifié du pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    sid: String,
    admin: bool,
}

impl Caller {
    /// Appelant de SID `sid` ; `admin` : administrateur (jeton élevé) ou SYSTEM.
    pub fn new(sid: impl Into<String>, admin: bool) -> Self {
        Self {
            sid: sid.into(),
            admin,
        }
    }

    /// Construit l'appelant depuis le SID de l'utilisateur et les groupes du jeton
    /// (SID, attributs).
    pub fn from_token(user_sid: &str, groups: &[(String, u32)]) -> Self {
        let admin = user_sid == SID_SYSTEM
            || groups
                .iter()
                .any(|(sid, attrs)| sid == SID_ADMINISTRATORS && attrs & SE_GROUP_ENABLED != 0);
        Self::new(user_sid, admin)
    }

    /// SID de l'utilisateur.
    pub fn sid(&self) -> &str {
        &self.sid
    }

    /// Administrateur ?
    pub fn is_admin(&self) -> bool {
        self.admin
    }
}

/// Une session a-t-elle `owner` pour propriétaire : `caller` peut-il la piloter ou
/// en voir le détail ? Oui s'il est administrateur, si la session n'a pas de
/// propriétaire, ou s'il en est le propriétaire.
pub(crate) fn may_control(owner: Option<&str>, caller: &Caller) -> bool {
    caller.admin || owner.is_none_or(|o| o == caller.sid)
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    last: Instant,
    blocked_until: Option<Instant>,
}

/// Compteur d'échecs d'authentification par SID.
#[derive(Debug, Default)]
pub struct AuthThrottle {
    entries: HashMap<String, Entry>,
}

impl AuthThrottle {
    /// Compteur vide.
    pub fn new() -> Self {
        Self::default()
    }

    /// `Ok` si `sid` peut tenter une connexion à l'instant `now` ; sinon l'attente
    /// restante.
    pub fn check(&mut self, sid: &str, now: Instant) -> Result<(), Duration> {
        let Some(entry) = self.entries.get(sid).copied() else {
            return Ok(());
        };
        if let Some(until) = entry.blocked_until
            && until > now
        {
            return Err(until - now);
        }
        if entry.failures >= BLOCK_FAILURES
            || now.saturating_duration_since(entry.last) > FORGET_AFTER
        {
            // Blocage long écoulé, ou ancien : on repart de zéro.
            self.entries.remove(sid);
        }
        Ok(())
    }

    /// Enregistre un échec d'authentification de `sid`.
    pub fn record_failure(&mut self, sid: &str, now: Instant) {
        if !self.entries.contains_key(sid) && self.entries.len() >= MAX_TRACKED {
            self.evict(now);
        }
        let entry = self.entries.entry(sid.to_owned()).or_insert(Entry {
            failures: 0,
            last: now,
            blocked_until: None,
        });
        entry.failures = entry.failures.saturating_add(1);
        entry.last = now;
        entry.blocked_until = match entry.failures {
            n if n >= BLOCK_FAILURES => Some(now + BLOCK_DURATION),
            n if n >= FREE_FAILURES => {
                Some(now + FIRST_DELAY * 2u32.pow(n - FREE_FAILURES))
            }
            _ => None,
        };
    }

    /// Authentification réussie : le compteur de `sid` est remis à zéro.
    pub fn record_success(&mut self, sid: &str) {
        self.entries.remove(sid);
    }

    /// Libère une place : entrées expirées, sinon la plus ancienne.
    fn evict(&mut self, now: Instant) {
        self.entries
            .retain(|_, e| e.blocked_until.is_some_and(|u| u > now));
        if self.entries.len() >= MAX_TRACKED
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last)
                .map(|(k, _)| k.clone())
        {
            self.entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const BOB: &str = "S-1-5-21-1-2-3-1002";

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn admin_detection() {
        let g = |attrs| vec![("S-1-5-32-544".to_owned(), attrs)];
        assert!(Caller::from_token(ALICE, &g(0x7)).is_admin());
        // Groupe « deny-only » (jeton non élevé) : pas administrateur.
        assert!(!Caller::from_token(ALICE, &g(0x10)).is_admin());
        assert!(!Caller::from_token(ALICE, &[("S-1-5-32-545".into(), 0x7)]).is_admin());
        assert!(Caller::from_token("S-1-5-18", &[]).is_admin());
    }

    #[test]
    fn ownership_rules() {
        let alice = Caller::new(ALICE, false);
        let bob = Caller::new(BOB, false);
        let admin = Caller::new("S-1-5-21-1-2-3-500", true);
        assert!(may_control(None, &bob));
        assert!(may_control(Some(ALICE), &alice));
        assert!(!may_control(Some(ALICE), &bob));
        assert!(may_control(Some(ALICE), &admin));
    }

    #[test]
    fn throttle_escalates_then_blocks_then_releases() {
        let mut th = AuthThrottle::new();
        let now = t0();
        for _ in 0..2 {
            th.record_failure(ALICE, now);
            assert!(th.check(ALICE, now).is_ok());
        }
        th.record_failure(ALICE, now);
        assert_eq!(th.check(ALICE, now), Err(Duration::from_secs(30)));
        assert!(th.check(ALICE, now + Duration::from_secs(31)).is_ok());
        let later = now + Duration::from_secs(31);
        th.record_failure(ALICE, later);
        assert_eq!(th.check(ALICE, later), Err(Duration::from_secs(60)));
        let later = later + Duration::from_secs(61);
        th.record_failure(ALICE, later);
        assert_eq!(th.check(ALICE, later), Err(BLOCK_DURATION));
        // Les autres SID ne sont pas touchés.
        assert!(th.check(BOB, later).is_ok());
        // Fin du blocage : compteur remis à zéro.
        let free = later + BLOCK_DURATION + Duration::from_secs(1);
        assert!(th.check(ALICE, free).is_ok());
        th.record_failure(ALICE, free);
        assert!(th.check(ALICE, free).is_ok());
    }

    #[test]
    fn success_and_age_reset_the_counter() {
        let mut th = AuthThrottle::new();
        let now = t0();
        th.record_failure(ALICE, now);
        th.record_failure(ALICE, now);
        th.record_success(ALICE);
        th.record_failure(ALICE, now);
        assert!(th.check(ALICE, now).is_ok());
        th.record_failure(ALICE, now);
        th.record_failure(ALICE, now);
        assert!(th.check(ALICE, now + FORGET_AFTER + FIRST_DELAY).is_ok());
        th.record_failure(ALICE, now + FORGET_AFTER + FIRST_DELAY);
        assert!(
            th.check(ALICE, now + FORGET_AFTER + FIRST_DELAY).is_ok(),
            "compteur remis à zéro par l'âge"
        );
    }

    #[test]
    fn tracked_sids_are_bounded() {
        let mut th = AuthThrottle::new();
        let now = t0();
        for i in 0..(MAX_TRACKED * 2) {
            th.record_failure(&format!("S-1-5-21-{i}"), now + Duration::from_millis(i as u64));
        }
        assert!(th.entries.len() <= MAX_TRACKED);
    }
}
