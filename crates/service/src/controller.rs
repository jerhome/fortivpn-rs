//! Contrôleur du service : applique les requêtes validées à la machine d'états et
//! pilote la session (via [`SessionRunner`]). Indépendant de l'OS : le transport
//! (named pipe) est abstrait par `AsyncRead + AsyncWrite` ([`serve_connection`]).

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{oneshot, watch};

use crate::access::{AuthThrottle, Caller, may_control};
use crate::protocol::{
    self, ErrorCode, Outcome, ProtocolError, Request, Response, State, StatusReport, StepTimings,
};
use crate::status::{Stage, StatusTracker};

/// Attente maximale de l'établissement du tunnel avant de répondre `timeout`.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(90);
/// Attente maximale de la fin d'une session lors d'un arrêt.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Récepteur des étapes d'une session (cloneable, utilisable depuis un thread).
#[derive(Debug, Clone)]
pub struct EventSink(Arc<watch::Sender<StatusTracker>>);

impl EventSink {
    /// Signale une étape atteinte `elapsed` après le début de la session.
    pub fn stage(&self, stage: Stage, elapsed: Duration) {
        let now = Instant::now();
        self.0.send_modify(|t| t.observe(stage, elapsed, now));
    }
}

/// Exécute une session complète. L'implémentation (dans le binaire) lit la
/// configuration **côté service**, construit transport et backend réseau, et ne
/// reçoit du client que le mot de passe.
pub trait SessionRunner: Send + Sync + 'static {
    /// Bloquant, exécuté sur un thread dédié (aucune contrainte `Send` sur la
    /// session elle-même). Doit signaler ses étapes via `events` et rendre l'issue
    /// quand la session est terminée **et** le réseau nettoyé. `stop` se déclenche
    /// (ou est abandonné) quand l'arrêt est demandé.
    fn run(
        &self,
        password: SecretString,
        stop: oneshot::Receiver<()>,
        events: &EventSink,
    ) -> Outcome;
}

/// Contrôleur partagé entre les connexions au pipe.
#[derive(Debug)]
pub struct Controller<R> {
    runner: Arc<R>,
    tracker: Arc<watch::Sender<StatusTracker>>,
    /// Signal d'arrêt de la session courante. Verrou pris **avant** de modifier la
    /// machine d'états : un `disconnect` ne peut pas se glisser entre la
    /// réservation et l'enregistrement du signal.
    stop: Mutex<Option<oneshot::Sender<()>>>,
    /// SID de l'utilisateur ayant fait le dernier `connect` accepté (M3).
    owner: Mutex<Option<String>>,
    /// Limitation des échecs d'authentification, par SID (M3).
    throttle: Arc<Mutex<AuthThrottle>>,
    connect_timeout: Duration,
    stop_timeout: Duration,
}

impl<R: SessionRunner> Controller<R> {
    /// Contrôleur avec les délais par défaut.
    pub fn new(runner: R) -> Self {
        Self::with_timeouts(runner, CONNECT_TIMEOUT, STOP_TIMEOUT)
    }

    /// Contrôleur avec délais explicites (tests).
    pub fn with_timeouts(runner: R, connect_timeout: Duration, stop_timeout: Duration) -> Self {
        let (tx, _rx) = watch::channel(StatusTracker::new());
        Self {
            runner: Arc::new(runner),
            tracker: Arc::new(tx),
            stop: Mutex::new(None),
            owner: Mutex::new(None),
            throttle: Arc::new(Mutex::new(AuthThrottle::new())),
            connect_timeout,
            stop_timeout,
        }
    }

    fn report(&self) -> StatusReport {
        self.tracker.borrow().report(Instant::now())
    }

    fn owner(&self) -> Option<String> {
        self.owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Rapport d'état ; sans le détail (tunnel, étapes, issue) pour un utilisateur
    /// qui n'est ni propriétaire de la session ni administrateur.
    fn report_for(&self, caller: &Caller) -> StatusReport {
        let full = self.report();
        if may_control(self.owner().as_deref(), caller) {
            full
        } else {
            StatusReport {
                state: full.state,
                steps: StepTimings::default(),
                connected_for_ms: None,
                tunnel: None,
                last_outcome: None,
            }
        }
    }

    async fn wait_for(&self, timeout: Duration, pred: impl Fn(&StatusTracker) -> bool) -> bool {
        let mut rx = self.tracker.subscribe();
        let waited = tokio::time::timeout(timeout, rx.wait_for(|t| pred(t))).await;
        let ok = matches!(waited, Ok(Ok(_)));
        drop(waited);
        ok
    }

    /// Traite une requête déjà validée, émise par `caller`.
    pub async fn handle(&self, request: Request, caller: &Caller) -> Response {
        match request {
            Request::Status {} => Response::Ok {
                status: self.report_for(caller),
            },
            Request::Disconnect {} => self.disconnect(caller).await,
            Request::Connect { password } => {
                // Copie à la taille exacte ; `password` est effacé à la sortie.
                let secret = SecretString::from(password.as_str());
                drop(password);
                self.connect(secret, caller).await
            }
        }
    }

    async fn connect(&self, password: SecretString, caller: &Caller) -> Response {
        if let Err(wait) = self
            .throttle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .check(caller.sid(), Instant::now())
        {
            tracing::warn!(sid = caller.sid(), "connexion refusée : trop d'échecs d'authentification");
            return Response::error(
                ErrorCode::RateLimited,
                format!(
                    "trop d'échecs d'authentification : réessayez dans {} s",
                    wait.as_secs() + 1
                ),
            );
        }
        let stop_rx = {
            let mut stop = self.stop.lock().unwrap_or_else(PoisonError::into_inner);
            if !self.tracker.send_if_modified(|t| t.begin_connect().is_ok()) {
                return Response::error(
                    ErrorCode::Busy,
                    "une connexion est déjà en cours ou établie (disconnect d'abord)",
                );
            }
            *self.owner.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(caller.sid().to_owned());
            let (tx, rx) = oneshot::channel();
            *stop = Some(tx);
            rx
        };
        let sink = EventSink(Arc::clone(&self.tracker));
        let runner = Arc::clone(&self.runner);
        let thread_sink = sink.clone();
        let throttle = Arc::clone(&self.throttle);
        let sid = caller.sid().to_owned();
        let spawned = std::thread::Builder::new()
            .name("fortivpn-session".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    runner.run(password, stop_rx, &thread_sink)
                }))
                .unwrap_or_else(|_| {
                    Outcome::failed(
                        ErrorCode::Internal,
                        "session interrompue de façon inattendue",
                    )
                });
                record_auth_result(&throttle, &sid, &outcome, &thread_sink);
                thread_sink.stage(Stage::Disconnected(outcome), Duration::ZERO);
            });
        if let Err(e) = spawned {
            tracing::error!(error = %e, "démarrage du thread de session impossible");
            sink.stage(
                Stage::Disconnected(Outcome::failed(ErrorCode::Internal, "thread de session")),
                Duration::ZERO,
            );
            return Response::error(ErrorCode::Internal, "démarrage de la session impossible");
        }

        let done = self
            .wait_for(self.connect_timeout, |t| {
                matches!(t.state(), State::TunnelUp | State::Idle)
            })
            .await;
        if !done {
            return Response::error(
                ErrorCode::Timeout,
                "délai dépassé : la connexion se poursuit, voir `status`",
            );
        }
        let tracker = self.tracker.borrow();
        if tracker.state() == State::TunnelUp {
            return Response::Ok {
                status: tracker.report(Instant::now()),
            };
        }
        match tracker.last_outcome() {
            Some(Outcome {
                error: Some(code),
                message,
            }) => Response::error(*code, message.clone()),
            _ => Response::error(ErrorCode::Internal, "connexion annulée"),
        }
    }

    /// Demande l'arrêt de la session courante (sans attendre).
    fn signal_stop(&self) {
        let mut stop = self.stop.lock().unwrap_or_else(PoisonError::into_inner);
        if self.tracker.send_if_modified(StatusTracker::request_stop) {
            if let Some(tx) = stop.take() {
                let _ = tx.send(());
            }
        }
    }

    async fn disconnect(&self, caller: &Caller) -> Response {
        if !may_control(self.owner().as_deref(), caller) {
            tracing::warn!(sid = caller.sid(), "disconnect refusé : session d'un autre utilisateur");
            return Response::error(
                ErrorCode::Forbidden,
                "la connexion appartient à un autre utilisateur",
            );
        }
        self.signal_stop();
        if self
            .wait_for(self.stop_timeout, |t| t.state() == State::Idle)
            .await
        {
            Response::Ok {
                status: self.report(),
            }
        } else {
            Response::error(ErrorCode::Timeout, "l'arrêt prend plus de temps que prévu")
        }
    }

    /// Arrêt du service : coupe la session éventuelle et attend le nettoyage réseau.
    pub async fn shutdown(&self) {
        self.signal_stop();
        if !self
            .wait_for(self.stop_timeout, |t| t.state() == State::Idle)
            .await
        {
            tracing::error!("arrêt du service : la session ne s'est pas terminée à temps");
        }
    }
}

/// Compte l'issue d'une session dans le limiteur : échec d'authentification, ou
/// réinitialisation si l'authentification avait abouti.
fn record_auth_result(
    throttle: &Mutex<AuthThrottle>,
    sid: &str,
    outcome: &Outcome,
    sink: &EventSink,
) {
    let mut throttle = throttle.lock().unwrap_or_else(PoisonError::into_inner);
    if outcome.error == Some(ErrorCode::AuthRejected) {
        throttle.record_failure(sid, Instant::now());
        tracing::warn!(sid, "échec d'authentification enregistré");
    } else if sink.0.borrow().report(Instant::now()).steps.authenticated_ms.is_some() {
        throttle.record_success(sid);
    }
}

/// Sert **une** requête sur `stream` (lecture bornée, validation, réponse, fermeture).
/// Les erreurs de protocole reçoivent une réponse générique `bad_request`, sans écho
/// de l'entrée.
pub async fn serve_connection<S, R>(mut stream: S, controller: &Controller<R>, caller: &Caller)
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: SessionRunner,
{
    let read = tokio::time::timeout(protocol::READ_TIMEOUT, async {
        let line = protocol::read_message(&mut stream).await?;
        protocol::decode_request(&line)
    })
    .await;
    let response = match read {
        Ok(Ok(request)) => {
            tracing::debug!(?request, "requête");
            controller.handle(request, caller).await
        }
        Ok(Err(ProtocolError::Io(e))) => {
            tracing::debug!(error = %e, "lecture de la requête impossible");
            return;
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "requête refusée");
            Response::error(ErrorCode::BadRequest, e.to_string())
        }
        Err(_) => {
            tracing::warn!("requête incomplète : délai dépassé");
            return;
        }
    };
    match protocol::encode_response(&response) {
        Ok(line) => {
            if let Err(e) = stream.write_all(&line).await {
                tracing::debug!(error = %e, "écriture de la réponse impossible");
            }
            let _ = stream.flush().await;
        }
        Err(e) => tracing::error!(error = %e, "encodage de la réponse impossible"),
    }
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use secrecy::ExposeSecret;

    use super::*;
    use crate::client;

    /// Runner de test : `Connecting` → `Authenticated` → `TunnelUp`, puis attend l'arrêt.
    #[derive(Debug, Default)]
    struct Fake {
        /// Mot de passe attendu ; autre → `AuthRejected`.
        expect: &'static str,
        runs: AtomicUsize,
        /// Panique au lieu de se connecter.
        panic: bool,
    }

    impl SessionRunner for Fake {
        fn run(
            &self,
            password: SecretString,
            stop: oneshot::Receiver<()>,
            events: &EventSink,
        ) -> Outcome {
            self.runs.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panic, "panique de test");
            events.stage(Stage::Connecting, Duration::ZERO);
            if password.expose_secret() != self.expect {
                return Outcome::failed(ErrorCode::AuthRejected, "identifiants refusés");
            }
            events.stage(Stage::Authenticated, Duration::from_millis(10));
            events.stage(Stage::TunnelUp("fvpn0".into()), Duration::from_millis(30));
            let _ = stop.blocking_recv();
            Outcome::requested()
        }
    }

    fn controller(panic: bool) -> Controller<Fake> {
        Controller::with_timeouts(
            Fake {
                expect: "good",
                panic,
                ..Fake::default()
            },
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
    }

    fn me() -> Caller {
        Caller::new("S-1-5-21-1-2-3-1001", false)
    }

    fn connect(pw: &str) -> Request {
        Request::Connect {
            password: zeroize::Zeroizing::new(pw.to_owned()),
        }
    }

    #[tokio::test]
    async fn connect_status_disconnect() {
        let c = controller(false);
        let Response::Ok { status } = c.handle(connect("good"), &me()).await else {
            panic!("connect");
        };
        assert_eq!(status.state, State::TunnelUp);
        assert_eq!(status.steps.authenticated_ms, Some(10));
        assert_eq!(status.steps.tunnel_up_ms, Some(30));
        assert_eq!(status.tunnel.as_deref(), Some("fvpn0"));

        // 2e connexion refusée, la session en cours n'est pas touchée.
        let Response::Error { code, .. } = c.handle(connect("good"), &me()).await else {
            panic!("busy");
        };
        assert_eq!(code, ErrorCode::Busy);
        assert_eq!(c.runner.runs.load(Ordering::SeqCst), 1);

        let Response::Ok { status } = c.handle(Request::Status {}, &me()).await else {
            panic!("status");
        };
        assert_eq!(status.state, State::TunnelUp);

        let Response::Ok { status } = c.handle(Request::Disconnect {}, &me()).await else {
            panic!("disconnect");
        };
        assert_eq!(status.state, State::Idle);
        assert_eq!(status.last_outcome, Some(Outcome::requested()));
        // Idempotent.
        let Response::Ok { status } = c.handle(Request::Disconnect {}, &me()).await else {
            panic!("disconnect 2");
        };
        assert_eq!(status.state, State::Idle);
        // Reconnexion possible.
        assert!(matches!(
            c.handle(connect("good"), &me()).await,
            Response::Ok { .. }
        ));
        c.shutdown().await;
        assert_eq!(c.report().state, State::Idle);
    }

    #[tokio::test]
    async fn failures_are_reported_with_their_code() {
        let c = controller(false);
        let Response::Error { code, message } = c.handle(connect("bad"), &me()).await else {
            panic!("auth");
        };
        assert_eq!(code, ErrorCode::AuthRejected);
        assert!(!message.contains("bad"));
        assert_eq!(c.report().state, State::Idle);

        let c = controller(true);
        let Response::Error { code, .. } = c.handle(connect("good"), &me()).await else {
            panic!("panic");
        };
        assert_eq!(code, ErrorCode::Internal);
        // La machine est revenue à `Idle` : on peut réessayer.
        assert_eq!(c.report().state, State::Idle);
    }

    #[tokio::test]
    async fn connect_timeout_keeps_session_running() {
        struct Slow;
        impl SessionRunner for Slow {
            fn run(&self, _: SecretString, stop: oneshot::Receiver<()>, e: &EventSink) -> Outcome {
                e.stage(Stage::Connecting, Duration::ZERO);
                let _ = stop.blocking_recv();
                Outcome::requested()
            }
        }
        let c = Controller::with_timeouts(Slow, Duration::from_millis(50), Duration::from_secs(5));
        let Response::Error { code, .. } = c.handle(connect("x"), &me()).await else {
            panic!();
        };
        assert_eq!(code, ErrorCode::Timeout);
        assert_eq!(c.report().state, State::Connecting);
        // `disconnect` pendant `Connecting` annule.
        assert!(matches!(
            c.handle(Request::Disconnect {}, &me()).await,
            Response::Ok { .. }
        ));
        assert_eq!(c.report().state, State::Idle);
    }

    async fn roundtrip(c: &Controller<Fake>, raw: &[u8]) -> Response {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let raw = raw.to_vec();
        let caller = me();
        let ((), response) = tokio::join!(serve_connection(server, c, &caller), async move {
            client.write_all(&raw).await.unwrap();
            let line = protocol::read_message(&mut client).await.unwrap();
            protocol::decode_response(&line).unwrap()
        });
        response
    }

    #[tokio::test]
    async fn serve_connection_over_a_stream() {
        let c = controller(false);
        let r = roundtrip(&c, b"{\"cmd\":\"status\"}\n").await;
        assert!(matches!(r, Response::Ok { status } if status.state == State::Idle));

        let r = roundtrip(&c, b"{\"cmd\":\"connect\",\"password\":\"good\"}\n").await;
        assert!(matches!(r, Response::Ok { status } if status.state == State::TunnelUp));

        // Requêtes malformées : `bad_request` générique, rien n'est lancé.
        for raw in [
            &b"{\"cmd\":\"connect\",\"password\":\"SECRETX\",\"host\":\"evil\"}\n"[..],
            b"garbage\n",
            b"{\"cmd\":\"connect\",\"password\":\"\"}\n",
        ] {
            let Response::Error { code, message } = roundtrip(&c, raw).await else {
                panic!();
            };
            assert_eq!(code, ErrorCode::BadRequest);
            assert!(!message.contains("SECRETX") && !message.contains("evil"));
        }
        assert_eq!(c.runner.runs.load(Ordering::SeqCst), 1);

        let r = roundtrip(&c, b"{\"cmd\":\"disconnect\"}\n").await;
        assert!(matches!(r, Response::Ok { status } if status.state == State::Idle));
    }

    #[tokio::test]
    async fn oversized_request_is_refused() {
        let c = controller(false);
        let mut raw = vec![b'a'; protocol::MAX_MESSAGE_BYTES + 10];
        raw.push(b'\n');
        let Response::Error { code, .. } = roundtrip(&c, &raw).await else {
            panic!();
        };
        assert_eq!(code, ErrorCode::BadRequest);
    }

    #[tokio::test]
    async fn client_helper_talks_to_server() {
        let c = controller(false);
        let (mut cl, server) = tokio::io::duplex(64 * 1024);
        let caller = me();
        let ((), r) = tokio::join!(serve_connection(server, &c, &caller), async move {
            client::call(&mut cl, &Request::Status {}).await.unwrap()
        });
        assert!(matches!(r, Response::Ok { .. }));
    }

    fn other() -> Caller {
        Caller::new("S-1-5-21-1-2-3-1002", false)
    }

    #[tokio::test]
    async fn session_belongs_to_the_connecting_sid() {
        let c = controller(false);
        assert!(matches!(
            c.handle(connect("good"), &me()).await,
            Response::Ok { .. }
        ));
        // Un autre utilisateur : ni disconnect, ni détail.
        let Response::Error { code, .. } = c.handle(Request::Disconnect {}, &other()).await else {
            panic!("forbidden");
        };
        assert_eq!(code, ErrorCode::Forbidden);
        assert_eq!(c.report().state, State::TunnelUp);
        let Response::Ok { status } = c.handle(Request::Status {}, &other()).await else {
            panic!("status");
        };
        assert_eq!(status.state, State::TunnelUp);
        assert_eq!(status.tunnel, None);
        assert_eq!(status.steps, StepTimings::default());
        let Response::Ok { status } = c.handle(Request::Status {}, &me()).await else {
            panic!("status");
        };
        assert_eq!(status.tunnel.as_deref(), Some("fvpn0"));
        // Un administrateur peut couper.
        let admin = Caller::new("S-1-5-21-1-2-3-500", true);
        assert!(matches!(
            c.handle(Request::Disconnect {}, &admin).await,
            Response::Ok { .. }
        ));
        assert_eq!(c.report().state, State::Idle);
    }

    #[tokio::test]
    async fn repeated_auth_failures_are_throttled_per_sid() {
        let c = controller(false);
        for _ in 0..3 {
            let Response::Error { code, .. } = c.handle(connect("bad"), &me()).await else {
                panic!("auth");
            };
            assert_eq!(code, ErrorCode::AuthRejected);
        }
        // 4e tentative, même avec le bon mot de passe : refusée sans lancer de session.
        let runs = c.runner.runs.load(Ordering::SeqCst);
        let Response::Error { code, message } = c.handle(connect("good"), &me()).await else {
            panic!("limited");
        };
        assert_eq!(code, ErrorCode::RateLimited);
        assert!(!message.contains("good"));
        assert_eq!(c.runner.runs.load(Ordering::SeqCst), runs);
        // Un autre SID n'est pas affecté.
        assert!(matches!(
            c.handle(connect("good"), &other()).await,
            Response::Ok { .. }
        ));
        c.shutdown().await;
    }
}
