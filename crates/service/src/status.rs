//! Machine d'états du service (logique pure) : où en est la connexion, depuis quand,
//! avec quelle issue. Alimentée par le runner de session via [`Stage`].

use std::time::{Duration, Instant};

use crate::protocol::{Outcome, State, StatusReport, StepTimings};

/// Étape signalée par la session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// Connexion à la passerelle.
    Connecting,
    /// Identifiants acceptés.
    Authenticated,
    /// Configuration reçue.
    ConfigReceived,
    /// Tunnel actif ; description (interface, adresse) sans secret.
    TunnelUp(String),
    /// Session terminée (nettoyage fait).
    Disconnected(Outcome),
}

/// Refus de démarrer : une session est déjà en cours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy;

/// Suivi de l'état et des durées.
#[derive(Debug)]
pub struct StatusTracker {
    state: State,
    steps: StepTimings,
    tunnel: Option<String>,
    tunnel_since: Option<Instant>,
    last_outcome: Option<Outcome>,
}

impl Default for StatusTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusTracker {
    /// État initial : inactif.
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            steps: StepTimings::default(),
            tunnel: None,
            tunnel_since: None,
            last_outcome: None,
        }
    }

    /// État courant.
    pub fn state(&self) -> State {
        self.state
    }

    /// Issue de la dernière session terminée.
    pub fn last_outcome(&self) -> Option<&Outcome> {
        self.last_outcome.as_ref()
    }

    /// Réserve la machine pour une nouvelle session ; refusé si elle n'est pas
    /// inactive (une seule connexion à la fois, aussi pour `Disconnecting`).
    pub fn begin_connect(&mut self) -> Result<(), Busy> {
        if self.state != State::Idle {
            return Err(Busy);
        }
        *self = Self {
            state: State::Connecting,
            last_outcome: None,
            ..Self::new()
        };
        Ok(())
    }

    /// Demande d'arrêt : vrai si une session est active (il faut alors lui signaler
    /// l'arrêt), faux si inactive ou déjà en cours d'arrêt.
    pub fn request_stop(&mut self) -> bool {
        match self.state {
            State::Idle | State::Disconnecting => false,
            _ => {
                self.state = State::Disconnecting;
                true
            }
        }
    }

    /// Enregistre une étape à `elapsed` (temps depuis le début de la session) ;
    /// `now` date l'établissement du tunnel. Les événements arrivant hors session
    /// (état `Idle`) sont ignorés, sauf `Disconnected` (idempotent).
    pub fn observe(&mut self, stage: Stage, elapsed: Duration, now: Instant) {
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        // Pendant l'arrêt, l'état reste `Disconnecting` jusqu'à `Disconnected`.
        let stopping = self.state == State::Disconnecting;
        if self.state == State::Idle && !matches!(stage, Stage::Disconnected(_)) {
            return;
        }
        match stage {
            Stage::Connecting => {
                self.steps.connecting_ms = Some(ms);
                self.set(State::Connecting, stopping);
            }
            Stage::Authenticated => {
                self.steps.authenticated_ms = Some(ms);
                self.set(State::Authenticated, stopping);
            }
            Stage::ConfigReceived => {
                self.steps.config_received_ms = Some(ms);
                self.set(State::ConfigReceived, stopping);
            }
            Stage::TunnelUp(desc) => {
                self.steps.tunnel_up_ms = Some(ms);
                self.tunnel = Some(desc);
                self.tunnel_since = Some(now);
                self.set(State::TunnelUp, stopping);
            }
            Stage::Disconnected(outcome) => {
                self.state = State::Idle;
                self.tunnel = None;
                self.tunnel_since = None;
                self.last_outcome = Some(outcome);
            }
        }
    }

    fn set(&mut self, state: State, stopping: bool) {
        if !stopping {
            self.state = state;
        }
    }

    /// Rapport d'état à l'instant `now`.
    pub fn report(&self, now: Instant) -> StatusReport {
        StatusReport {
            state: self.state,
            steps: self.steps.clone(),
            connected_for_ms: self.tunnel_since.map(|t| {
                u64::try_from(now.saturating_duration_since(t).as_millis()).unwrap_or(u64::MAX)
            }),
            tunnel: self.tunnel.clone(),
            last_outcome: self.last_outcome.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ErrorCode;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn happy_path_with_timings() {
        let t0 = Instant::now();
        let mut t = StatusTracker::new();
        assert_eq!(t.state(), State::Idle);
        t.begin_connect().unwrap();
        assert_eq!(t.state(), State::Connecting);
        assert_eq!(t.begin_connect(), Err(Busy));
        t.observe(Stage::Connecting, ms(0), t0);
        t.observe(Stage::Authenticated, ms(120), t0);
        assert_eq!(t.state(), State::Authenticated);
        t.observe(Stage::ConfigReceived, ms(180), t0);
        t.observe(Stage::TunnelUp("fortivpn 10.0.0.2".into()), ms(900), t0);
        let r = t.report(t0 + ms(5000));
        assert_eq!(r.state, State::TunnelUp);
        assert_eq!(r.steps.authenticated_ms, Some(120));
        assert_eq!(r.steps.config_received_ms, Some(180));
        assert_eq!(r.steps.tunnel_up_ms, Some(900));
        assert_eq!(r.connected_for_ms, Some(5000));
        assert_eq!(r.tunnel.as_deref(), Some("fortivpn 10.0.0.2"));
        assert_eq!(t.begin_connect(), Err(Busy));
    }

    #[test]
    fn stop_flow() {
        let t0 = Instant::now();
        let mut t = StatusTracker::new();
        assert!(!t.request_stop(), "inactif : rien à arrêter");
        t.begin_connect().unwrap();
        assert!(t.request_stop());
        assert!(!t.request_stop(), "déjà en arrêt");
        // Un événement tardif ne ressuscite pas l'état.
        t.observe(Stage::Authenticated, ms(10), t0);
        assert_eq!(t.state(), State::Disconnecting);
        assert_eq!(t.begin_connect(), Err(Busy));
        t.observe(Stage::Disconnected(Outcome::requested()), ms(20), t0);
        assert_eq!(t.state(), State::Idle);
        assert_eq!(t.last_outcome(), Some(&Outcome::requested()));
        assert_eq!(t.report(t0).connected_for_ms, None);
        t.begin_connect().unwrap();
    }

    #[test]
    fn failure_is_remembered_until_next_connect() {
        let t0 = Instant::now();
        let mut t = StatusTracker::new();
        t.begin_connect().unwrap();
        let out = Outcome::failed(ErrorCode::AuthRejected, "refusé");
        t.observe(Stage::Disconnected(out.clone()), ms(50), t0);
        assert_eq!(t.state(), State::Idle);
        assert_eq!(t.report(t0).last_outcome, Some(out));
        t.begin_connect().unwrap();
        assert_eq!(t.report(t0).last_outcome, None);
        assert_eq!(t.report(t0).steps, StepTimings::default());
    }

    #[test]
    fn stray_events_when_idle_are_ignored() {
        let t0 = Instant::now();
        let mut t = StatusTracker::new();
        t.observe(Stage::TunnelUp("x".into()), ms(1), t0);
        assert_eq!(t.state(), State::Idle);
        assert!(t.report(t0).tunnel.is_none());
    }
}
