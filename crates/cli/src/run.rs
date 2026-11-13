//! Exécution d'une session, indépendante de l'OS et du transport (testable avec les
//! fakes de `core`) : arrêt sur signal, suivi des événements, chronométrage.

use std::fmt::Write as _;
use std::future::Future;
use std::time::Duration;

use fortivpn_core::{
    Credentials, DisconnectReason, NetBackend, Session, SessionEvent, SessionOptions, SessionState,
    Transport,
};

/// Exécute une session jusqu'à sa fin.
///
/// Quand `stop` se termine (il fournit le plafond de déconnexion si l'OS impose un
/// arrêt rapide, `None` sinon), l'arrêt est demandé via
/// [`SessionHandle::shutdown`](fortivpn_core::SessionHandle::shutdown) puis la fin propre
/// de la session (nettoyage réseau puis déconnexion du transport) est **attendue**.
/// `on_event` reçoit chaque événement, y compris le `Disconnected` final.
pub async fn run_session<T, B, S, F>(
    transport: T,
    backend: B,
    credentials: Credentials,
    options: SessionOptions,
    stop: S,
    mut on_event: F,
) -> DisconnectReason
where
    T: Transport,
    B: NetBackend,
    S: Future<Output = Option<Duration>>,
    F: FnMut(&SessionEvent),
{
    let (mut session, handle, mut events) = Session::new(transport, backend, credentials, options);
    let run = session.run();
    tokio::pin!(run);
    tokio::pin!(stop);
    let mut stop_requested = false;
    let reason = loop {
        tokio::select! {
            reason = &mut run => break reason,
            limit = &mut stop, if !stop_requested => {
                stop_requested = true;
                tracing::info!("arrêt demandé : nettoyage réseau et déconnexion…");
                match limit {
                    Some(limit) => handle.shutdown_within(limit),
                    None => handle.shutdown(),
                }
            }
            Some(event) = events.recv() => on_event(&event),
        }
    };
    while let Some(event) = events.try_recv() {
        on_event(&event);
    }
    reason
}

/// Suivi des événements : lignes lisibles et chronométrage des étapes (story 4.4).
#[derive(Debug, Default)]
pub struct Reporter {
    connecting: Option<Duration>,
    authenticated: Option<Duration>,
    config_received: Option<Duration>,
    tunnel_up: Option<Duration>,
}

impl Reporter {
    /// Enregistre l'événement et retourne la ligne à afficher.
    pub fn observe(&mut self, event: &SessionEvent) -> String {
        let at = event.elapsed;
        let what = match &event.state {
            SessionState::Connecting => {
                *self = Self {
                    connecting: Some(at),
                    ..Self::default()
                };
                "connexion à la passerelle…".to_owned()
            }
            SessionState::Authenticated => {
                self.authenticated = Some(at);
                "authentification acceptée".to_owned()
            }
            SessionState::ConfigReceived => {
                self.config_received = Some(at);
                "configuration reçue".to_owned()
            }
            SessionState::TunnelUp { config, interface } => {
                self.tunnel_up = Some(at);
                format!(
                    "tunnel actif sur {} (adresse {}, MTU {})",
                    interface.name, config.ipv4.address, config.mtu
                )
            }
            SessionState::Disconnected { reason } => {
                format!("déconnecté : {}", describe_reason(reason))
            }
            SessionState::Reconnecting {
                attempt,
                delay,
                cause,
            } => format!(
                "{} ; reconnexion (essai {attempt}) dans {} ms",
                describe_reason(cause),
                delay.as_millis()
            ),
            other => format!("{other:?}"),
        };
        format!("[{:>6} ms] {what}", at.as_millis())
    }

    /// « connecté en X ms (étape : Y ms, …) », une fois le tunnel actif.
    pub fn summary(&self) -> Option<String> {
        let up = self.tunnel_up?;
        let start = self.connecting.unwrap_or_default();
        let mut out = format!("connecté en {} ms", up.saturating_sub(start).as_millis());
        let steps = [
            ("authentification", self.authenticated),
            ("configuration", self.config_received),
            ("tunnel", Some(up)),
        ];
        let mut prev = start;
        let mut parts = Vec::new();
        for (name, at) in steps {
            if let Some(at) = at {
                parts.push(format!(
                    "{name} : {} ms",
                    at.saturating_sub(prev).as_millis()
                ));
                prev = at;
            }
        }
        let _ = write!(out, " ({})", parts.join(", "));
        Some(out)
    }
}

/// Raison de fin lisible (sans secret : les erreurs de `core` n'en contiennent pas).
pub fn describe_reason(reason: &DisconnectReason) -> String {
    match reason {
        DisconnectReason::Requested => "arrêt demandé".to_owned(),
        DisconnectReason::ConnectFailed(e) => format!("échec de la connexion : {e}"),
        DisconnectReason::NetworkFailed(e) if crate::exit::is_permission_denied(e) => {
            format!(
                "échec de la configuration réseau : {}",
                crate::exit::INSUFFICIENT_RIGHTS
            )
        }
        DisconnectReason::NetworkFailed(e) => format!("échec de la configuration réseau : {e}"),
        DisconnectReason::TransportFailed(e) => format!("tunnel interrompu : {e}"),
        DisconnectReason::TransportClosed => "session fermée par la passerelle".to_owned(),
        DisconnectReason::TunClosed => "interface TUN fermée".to_owned(),
        DisconnectReason::ClockJump(d) => format!(
            "sortie de veille détectée (saut d'horloge de {} s), reconnexion",
            d.as_secs()
        ),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use fortivpn_core::fake::{FakeNetBackend, FakeTransport, NetOp, TransportEvent};
    use fortivpn_core::{DnsConfig, Ipv4Config, NetError, RoutingMode, TunnelConfig};
    use tokio::sync::oneshot;

    use super::*;
    use crate::exit::{Exit, from_reason};

    fn sample() -> TunnelConfig {
        TunnelConfig {
            ipv4: Ipv4Config {
                address: "10.212.134.200/32".parse().unwrap(),
                peer: Some(Ipv4Addr::new(169, 254, 2, 1)),
            },
            ipv6: None,
            mtu: 1354,
            dns: DnsConfig {
                servers: vec!["10.0.0.53".parse().unwrap()],
                search_domains: vec!["corp.example".into()],
            },
            routing: RoutingMode::Split {
                include: vec!["10.0.0.0/8".parse().unwrap()],
            },
            gateway: "203.0.113.10".parse().unwrap(),
        }
    }

    fn creds(password: &str) -> Credentials {
        Credentials::new("alice", password)
    }

    #[tokio::test]
    async fn stop_signal_shuts_down_and_cleans_up() {
        let transport = FakeTransport::new(creds("s3cr3t"), sample());
        let backend = FakeNetBackend::new();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let mut stop_tx = Some(stop_tx);
        let mut reporter = Reporter::default();
        let mut lines = Vec::new();
        let mut summary = None;

        let reason = run_session(
            transport.clone(),
            backend.clone(),
            creds("s3cr3t"),
            SessionOptions::new("fvpn0"),
            async {
                let _ = stop_rx.await;
                None
            },
            |ev| {
                lines.push(reporter.observe(ev));
                if matches!(ev.state, SessionState::TunnelUp { .. }) {
                    // Le tunnel est actif : simule Ctrl+C.
                    assert!(!backend.is_clean());
                    summary = reporter.summary();
                    if let Some(tx) = stop_tx.take() {
                        let _ = tx.send(());
                    }
                }
            },
        )
        .await;

        assert!(matches!(reason, DisconnectReason::Requested), "{reason:?}");
        assert_eq!(from_reason(&reason), Exit::Ok);
        // Teardown réseau fait, transport déconnecté.
        assert!(backend.is_clean());
        assert!(backend.ops().contains(&NetOp::CreateTun("fvpn0".into())));
        assert!(!transport.is_connected());
        assert_eq!(
            transport.events().last(),
            Some(&TransportEvent::Disconnected)
        );
        // Tous les événements ont été vus, dans l'ordre, y compris le dernier.
        assert_eq!(lines.len(), 5, "{lines:?}");
        assert!(lines[0].contains("connexion"));
        assert!(lines[1].contains("authentification acceptée"));
        assert!(lines[2].contains("configuration reçue"));
        assert!(lines[3].contains("tunnel actif sur fvpn0"));
        assert!(lines[4].contains("arrêt demandé"));
        assert!(
            lines
                .iter()
                .all(|l| l.starts_with('[') && l.contains(" ms]"))
        );
        assert!(lines.iter().all(|l| !l.contains("s3cr3t")));
        let summary = summary.unwrap();
        assert!(summary.starts_with("connecté en "), "{summary}");
        assert!(summary.contains("authentification : "), "{summary}");
        assert!(summary.contains("tunnel : "), "{summary}");
    }

    #[tokio::test]
    async fn auth_failure_maps_to_auth_exit_code() {
        let transport = FakeTransport::new(creds("right"), sample());
        let backend = FakeNetBackend::new();
        let mut reporter = Reporter::default();
        let reason = run_session(
            transport.clone(),
            backend.clone(),
            creds("wrong"),
            SessionOptions::new("fvpn0"),
            std::future::pending::<Option<Duration>>(),
            |ev| {
                reporter.observe(ev);
            },
        )
        .await;
        assert_eq!(from_reason(&reason), Exit::AuthRejected, "{reason:?}");
        assert!(backend.ops().is_empty());
        assert!(reporter.summary().is_none());
    }

    #[tokio::test]
    async fn gateway_end_maps_to_connection_exit_code() {
        let transport = FakeTransport::new(creds("pw"), sample());
        let backend = FakeNetBackend::new();
        let observer = transport.clone();
        let reason = run_session(
            transport,
            backend.clone(),
            creds("pw"),
            SessionOptions::new("fvpn0").with_reconnect(fortivpn_core::ReconnectPolicy::disabled()),
            std::future::pending::<Option<Duration>>(),
            |ev| {
                if matches!(ev.state, SessionState::TunnelUp { .. }) {
                    observer.end_session(Err(fortivpn_core::TransportError::Closed));
                }
            },
        )
        .await;
        assert_eq!(from_reason(&reason), Exit::Connection, "{reason:?}");
        assert!(backend.is_clean());
    }

    #[test]
    fn clock_jump_is_readable() {
        let msg = describe_reason(&DisconnectReason::ClockJump(Duration::from_millis(312_900)));
        assert_eq!(
            msg,
            "sortie de veille détectée (saut d'horloge de 312 s), reconnexion"
        );
    }

    #[test]
    fn second_factor_message_and_exit() {
        let reason = DisconnectReason::ConnectFailed(std::sync::Arc::new(
            fortivpn_core::TransportError::SecondFactorRequired,
        ));
        assert!(describe_reason(&reason).contains("double authentification non prise en charge"));
        assert_eq!(from_reason(&reason), Exit::SecondFactor);
    }

    #[test]
    fn permission_denied_gets_a_clear_message() {
        let e = NetError::Io {
            op: "create_tun",
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        let reason = DisconnectReason::NetworkFailed(std::sync::Arc::new(e));
        let msg = describe_reason(&reason);
        assert!(
            msg.contains("droits insuffisants : lancez avec sudo"),
            "{msg}"
        );
        assert_eq!(from_reason(&reason), Exit::LocalNetwork);
    }

    #[test]
    fn summary_without_intermediate_steps() {
        let mut r = Reporter {
            connecting: Some(Duration::from_millis(1)),
            tunnel_up: Some(Duration::from_millis(251)),
            ..Reporter::default()
        };
        assert_eq!(
            r.summary().as_deref(),
            Some("connecté en 250 ms (tunnel : 250 ms)")
        );
        r.authenticated = Some(Duration::from_millis(101));
        r.config_received = Some(Duration::from_millis(201));
        assert_eq!(
            r.summary().as_deref(),
            Some(
                "connecté en 250 ms (authentification : 100 ms, configuration : 100 ms, \
                 tunnel : 50 ms)"
            )
        );
    }
}
