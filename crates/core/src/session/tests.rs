//! Session de bout en bout avec `FakeTransport` + `FakeNetBackend`, et sur le vrai
//! tunnel PPP face à une passerelle simulée.

use std::future::Future;

use bytes::Bytes;
use proto::ppp::{Code, ControlPacket, Protocol};
use tokio::io::{DuplexStream, duplex};
use tokio::task::JoinHandle;

use super::*;
use crate::config::tests::sample;
use crate::error::TransportError;
use crate::fake::{FailPoint, FakeNetBackend, FakeTransport, NetOp, TransportEvent};
use crate::transport::TransportSession;
use crate::tunnel::{self, TunnelError, TunnelHandle};

const STEP: Duration = Duration::from_secs(5);

fn creds(password: &str) -> Credentials {
    Credentials::new("alice", password.to_owned())
}

type Running<T, B> = JoinHandle<(DisconnectReason, Session<T, B>)>;

/// Session sans reconnexion automatique (cf. `start_with`).
fn start<T, B>(
    transport: T,
    backend: B,
    password: &str,
) -> (Running<T, B>, SessionHandle, SessionEvents)
where
    T: Transport + Send + 'static,
    B: NetBackend + 'static,
    B::Cleanup: Send,
{
    start_with(
        transport,
        backend,
        password,
        SessionOptions::new("fvpn0").with_reconnect(ReconnectPolicy::disabled()),
    )
}

fn start_with<T, B>(
    transport: T,
    backend: B,
    password: &str,
    options: SessionOptions,
) -> (Running<T, B>, SessionHandle, SessionEvents)
where
    T: Transport + Send + 'static,
    B: NetBackend + 'static,
    B::Cleanup: Send,
{
    let (mut session, handle, events) = Session::new(transport, backend, creds(password), options);
    let task = tokio::spawn(async move {
        let reason = session.run().await;
        (reason, session)
    });
    (task, handle, events)
}

async fn next_state(events: &mut SessionEvents) -> SessionState {
    tokio::time::timeout(STEP, events.recv())
        .await
        .expect("événement attendu")
        .expect("flux d'événements fermé")
        .state
}

/// Attend `TunnelUp` en vérifiant les étapes précédentes.
async fn wait_up(events: &mut SessionEvents) -> TunnelConfig {
    assert!(matches!(next_state(events).await, SessionState::Connecting));
    assert!(matches!(
        next_state(events).await,
        SessionState::Authenticated
    ));
    assert!(matches!(
        next_state(events).await,
        SessionState::ConfigReceived
    ));
    match next_state(events).await {
        SessionState::TunnelUp { config, interface } => {
            assert_eq!(interface.name, "fvpn0");
            config
        }
        other => panic!("TunnelUp attendu : {other:?}"),
    }
}

async fn finish<T: Transport, B: NetBackend>(task: Running<T, B>) -> DisconnectReason {
    tokio::time::timeout(STEP, task).await.unwrap().unwrap().0
}

fn assert_disconnected(transport: &FakeTransport) {
    assert!(!transport.is_connected());
    assert_eq!(
        transport.events().last(),
        Some(&TransportEvent::Disconnected)
    );
}

#[tokio::test]
async fn relays_packets_then_shutdown_cleans_up() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, handle, mut events) = start(transport.clone(), backend.clone(), "good");

    assert_eq!(wait_up(&mut events).await, sample());
    assert!(!backend.is_clean());

    let mut os = backend.take_tun_peer().unwrap();
    let mut gw = transport.take_gateway_peer().unwrap();
    os.send(Bytes::from_static(b"echo-request")).await.unwrap();
    assert_eq!(
        gw.recv().await.unwrap(),
        Bytes::from_static(b"echo-request")
    );
    gw.send(Bytes::from_static(b"echo-reply")).await.unwrap();
    assert_eq!(os.recv().await.unwrap(), Bytes::from_static(b"echo-reply"));

    handle.shutdown();
    assert!(matches!(finish(task).await, DisconnectReason::Requested));
    assert!(backend.is_clean());
    assert!(
        backend
            .ops()
            .contains(&NetOp::TeardownStart { blocking: false })
    );
    assert_disconnected(&transport);
    let last = events.recv().await.unwrap();
    assert!(matches!(
        last.state,
        SessionState::Disconnected {
            reason: DisconnectReason::Requested
        }
    ));
}

#[tokio::test]
async fn events_are_timestamped_in_order() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, handle, mut events) = start(transport, backend, "good");
    handle.shutdown();
    finish(task).await;
    let mut last = Duration::ZERO;
    while let Some(ev) = events.try_recv() {
        assert!(ev.elapsed >= last);
        last = ev.elapsed;
    }
}

#[tokio::test]
async fn auth_failure_creates_no_interface() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, _handle, mut events) = start(transport.clone(), backend.clone(), "bad");
    let reason = finish(task).await;
    assert!(
        matches!(&reason, DisconnectReason::ConnectFailed(e) if matches!(**e, TransportError::AuthFailed))
    );
    assert!(backend.ops().is_empty());
    assert_disconnected(&transport);
    assert!(matches!(
        next_state(&mut events).await,
        SessionState::Connecting
    ));
    assert!(matches!(
        next_state(&mut events).await,
        SessionState::Disconnected {
            reason: DisconnectReason::ConnectFailed(_)
        }
    ));
}

#[tokio::test]
async fn network_failures_disconnect_transport() {
    for point in [FailPoint::CreateTun, FailPoint::Routes, FailPoint::Dns] {
        let backend = FakeNetBackend::new();
        backend.fail_at(Some(point));
        let transport = FakeTransport::new(creds("good"), sample());
        let (task, _handle, _events) = start(transport.clone(), backend.clone(), "good");
        assert!(
            matches!(finish(task).await, DisconnectReason::NetworkFailed(_)),
            "{point:?}"
        );
        assert!(backend.is_clean(), "{point:?}");
        assert_disconnected(&transport);
    }
}

#[tokio::test]
async fn transport_error_tears_down() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, _handle, mut events) = start(transport.clone(), backend.clone(), "good");
    wait_up(&mut events).await;

    let gw = transport.take_gateway_peer().unwrap();
    transport.end_session(Err(TunnelError::DeadPeer.into()));
    drop(gw);
    let reason = finish(task).await;
    assert!(matches!(
        &reason,
        DisconnectReason::TransportFailed(e)
            if matches!(**e, TransportError::Tunnel(TunnelError::DeadPeer))
    ));
    assert!(backend.is_clean());
    assert_disconnected(&transport);
}

#[tokio::test]
async fn transport_channel_closed() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, _handle, mut events) = start(transport.clone(), backend.clone(), "good");
    wait_up(&mut events).await;
    drop(transport.take_gateway_peer());
    assert!(matches!(
        finish(task).await,
        DisconnectReason::TransportClosed
    ));
    assert!(backend.is_clean());
    assert_disconnected(&transport);
}

#[tokio::test]
async fn tun_closed() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, _handle, mut events) = start(transport.clone(), backend.clone(), "good");
    wait_up(&mut events).await;
    drop(backend.take_tun_peer());
    assert!(matches!(finish(task).await, DisconnectReason::TunClosed));
    assert!(backend.is_clean());
    assert_disconnected(&transport);
}

#[tokio::test]
async fn failed_teardown_falls_back_to_drop() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, handle, mut events) = start(transport.clone(), backend.clone(), "good");
    wait_up(&mut events).await;
    backend.fail_at(Some(FailPoint::Teardown));
    handle.shutdown();
    finish(task).await;
    assert!(backend.is_clean());
    assert!(
        backend
            .ops()
            .contains(&NetOp::TeardownStart { blocking: true })
    );
    assert_disconnected(&transport);
}

#[tokio::test]
async fn shutdown_before_run_does_nothing() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (mut session, handle, mut events) = Session::new(
        transport.clone(),
        backend.clone(),
        creds("good"),
        SessionOptions::new("fvpn0"),
    );
    handle.shutdown();
    assert!(matches!(session.run().await, DisconnectReason::Requested));
    assert!(transport.events().is_empty());
    assert!(backend.ops().is_empty());
    assert!(matches!(
        next_state(&mut events).await,
        SessionState::Disconnected { .. }
    ));
}

#[tokio::test]
async fn session_can_run_again_after_transport_end() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, handle, mut events) = start(transport.clone(), backend.clone(), "good");
    wait_up(&mut events).await;
    transport.end_session(Ok(()));
    let (reason, mut session) = tokio::time::timeout(STEP, task).await.unwrap().unwrap();
    assert!(matches!(reason, DisconnectReason::TransportClosed));
    next_state(&mut events).await; // Disconnected

    let again = tokio::spawn(async move { session.run().await });
    wait_up(&mut events).await;
    handle.shutdown();
    assert!(matches!(
        tokio::time::timeout(STEP, again).await.unwrap().unwrap(),
        DisconnectReason::Requested
    ));
    assert!(backend.is_clean());
}

/// Transport dont la connexion ne se termine jamais.
#[derive(Debug, Default)]
struct HangingTransport {
    disconnected: bool,
}

impl Transport for HangingTransport {
    fn connect(
        &mut self,
        _: &Credentials,
    ) -> impl Future<Output = Result<TransportSession, TransportError>> + Send {
        std::future::pending()
    }

    fn disconnect(&mut self) -> impl Future<Output = Result<(), TransportError>> + Send {
        self.disconnected = true;
        std::future::ready(Ok(()))
    }
}

#[tokio::test]
async fn shutdown_during_connect() {
    let backend = FakeNetBackend::new();
    let (task, handle, mut events) = start(HangingTransport::default(), backend.clone(), "x");
    assert!(matches!(
        next_state(&mut events).await,
        SessionState::Connecting
    ));
    handle.shutdown();
    let (reason, session) = tokio::time::timeout(STEP, task).await.unwrap().unwrap();
    assert!(matches!(reason, DisconnectReason::Requested));
    assert!(session.transport().disconnected);
    assert!(backend.ops().is_empty());
}

// ------------------------------------------------- sur le vrai tunnel PPP

/// Transport minimal : tunnel PPP sur un duplex (pas d'auth ni de TLS).
#[derive(Debug)]
struct PppTransport {
    stream: Option<DuplexStream>,
    tunnel: Option<TunnelHandle>,
}

impl Transport for PppTransport {
    async fn connect(&mut self, _: &Credentials) -> Result<TransportSession, TransportError> {
        let stream = self.stream.take().ok_or(TransportError::AlreadyConnected)?;
        let t = tunnel::open(stream, tunnel::tests::options()).await?;
        let mut config = sample();
        config.ipv4.address = t.params.local_ip.into();
        config.mtu = t.params.mtu;
        config.validate()?;
        self.tunnel = Some(t.handle);
        Ok(TransportSession {
            config,
            packets: t.packets,
            end: t.end,
        })
    }

    async fn disconnect(&mut self) -> Result<(), TransportError> {
        if let Some(handle) = self.tunnel.take() {
            handle.close().await;
        }
        Ok(())
    }
}

#[tokio::test]
async fn end_to_end_over_ppp_tunnel() {
    let (client, server) = duplex(64 * 1024);
    let gateway = tokio::spawn(async move {
        let mut gw = tunnel::tests::Gateway::new(server);
        tunnel::tests::negotiate(&mut gw).await;
        gw.expect("ipv4_icmp_echo_request").await;
        gw.send("ipv4_icmp_echo_reply").await;
        let req = gw.recv_lcp().await;
        assert_eq!(req.code(), Code::TerminateRequest);
        let ack = ControlPacket::new(Code::TerminateAck, req.id(), Bytes::new()).unwrap();
        gw.send_raw(&proto::frame::frame_to_bytes(&ack.to_frame(Protocol::LCP)).unwrap())
            .await;
        gw.expect_eof().await;
    });

    let backend = FakeNetBackend::new();
    let transport = PppTransport {
        stream: Some(client),
        tunnel: None,
    };
    let (task, handle, mut events) = start(transport, backend.clone(), "unused");
    assert!(matches!(
        next_state(&mut events).await,
        SessionState::Connecting
    ));
    let config = match next_state(&mut events).await {
        SessionState::TunnelUp { config, .. } => config,
        other => panic!("TunnelUp attendu : {other:?}"),
    };
    assert_eq!(config.ipv4.address, "10.10.0.2/32".parse().unwrap());
    assert!(backend.ops().contains(&NetOp::SetMtu(1354)));

    let mut os = backend.take_tun_peer().unwrap();
    let request = tunnel::tests::wire("ipv4_icmp_echo_request_raw_ip");
    os.send(Bytes::from(request)).await.unwrap();
    let reply = tokio::time::timeout(STEP, os.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &reply[..],
        &tunnel::tests::wire("ipv4_icmp_echo_reply")[8..]
    );

    handle.shutdown();
    assert!(matches!(finish(task).await, DisconnectReason::Requested));
    tokio::time::timeout(STEP, gateway).await.unwrap().unwrap();
    assert!(backend.is_clean());
}

#[tokio::test]
async fn ppp_tunnel_terminated_by_gateway() {
    let (client, server) = duplex(64 * 1024);
    let gateway = tokio::spawn(async move {
        let mut gw = tunnel::tests::Gateway::new(server);
        tunnel::tests::negotiate(&mut gw).await;
        gw.send("lcp_terminate_request_gateway").await;
        gw.expect("lcp_terminate_ack_client").await;
        gw.expect_eof().await;
    });
    let backend = FakeNetBackend::new();
    let transport = PppTransport {
        stream: Some(client),
        tunnel: None,
    };
    let (task, _handle, _events) = start(transport, backend.clone(), "unused");
    let reason = finish(task).await;
    assert!(matches!(
        &reason,
        DisconnectReason::TransportFailed(e)
            if matches!(**e, TransportError::Tunnel(TunnelError::ClosedByPeer))
    ));
    tokio::time::timeout(STEP, gateway).await.unwrap().unwrap();
    assert!(backend.is_clean());
}

// ------------------------------------------------- reconnexion automatique

/// Politique déterministe : 1 s → 60 s, sans jitter.
fn policy() -> ReconnectPolicy {
    ReconnectPolicy {
        jitter: 0.0,
        ..ReconnectPolicy::default()
    }
}

fn reconnecting(
    transport: FakeTransport,
    backend: FakeNetBackend,
    p: ReconnectPolicy,
) -> (
    Running<FakeTransport, FakeNetBackend>,
    SessionHandle,
    SessionEvents,
) {
    start_with(
        transport,
        backend,
        "good",
        SessionOptions::new("fvpn0").with_reconnect(p),
    )
}

/// Attend le prochain `Reconnecting` (en sautant les autres événements).
async fn next_reconnecting(
    events: &mut SessionEvents,
) -> (SessionEvent, u32, Duration, DisconnectReason) {
    loop {
        let ev = tokio::time::timeout(STEP, events.recv())
            .await
            .expect("Reconnecting attendu")
            .expect("flux fermé");
        match &ev.state {
            SessionState::Reconnecting {
                attempt,
                delay,
                cause,
            } => {
                let (a, d, c) = (*attempt, *delay, cause.clone());
                return (ev, a, d, c);
            }
            SessionState::Disconnected { reason } => panic!("fin inattendue : {reason:?}"),
            _ => {}
        }
    }
}

fn io_error() -> TransportError {
    TransportError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
}

#[tokio::test(start_paused = true)]
async fn dead_peer_reconnects_after_backoff() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, handle, mut events) = reconnecting(transport.clone(), backend.clone(), policy());
    wait_up(&mut events).await;

    transport.end_session(Err(TunnelError::DeadPeer.into()));
    let (ev, attempt, delay, cause) = next_reconnecting(&mut events).await;
    assert_eq!((attempt, delay), (1, Duration::from_secs(1)));
    assert!(matches!(
        &cause,
        DisconnectReason::TransportFailed(e) if matches!(**e, TransportError::Tunnel(TunnelError::DeadPeer))
    ));
    // Réseau annulé et transport suspendu (pas déconnecté) avant l'attente.
    assert!(backend.is_clean());
    assert_eq!(transport.events().last(), Some(&TransportEvent::Suspended));
    assert!(!transport.events().contains(&TransportEvent::Disconnected));

    wait_up(&mut events).await;
    let up_at = Instant::now();
    assert!(up_at.duration_since(ev.at) >= Duration::from_secs(1));
    assert_eq!(transport.connect_count(), 2);
    assert!(!backend.is_clean());

    // Nouvelle coupure : le compteur d'essais repart de 1.
    transport.end_session(Ok(()));
    let (_, attempt, delay, cause) = next_reconnecting(&mut events).await;
    assert_eq!((attempt, delay), (1, Duration::from_secs(1)));
    assert!(matches!(cause, DisconnectReason::TransportClosed));
    wait_up(&mut events).await;

    handle.shutdown();
    assert!(matches!(finish(task).await, DisconnectReason::Requested));
    assert!(backend.is_clean());
    assert_disconnected(&transport);
}

#[tokio::test(start_paused = true)]
async fn guard_is_kept_during_reconnect_when_backend_asks() {
    let backend = FakeNetBackend::new();
    backend.set_keep_guard_during_reconnect(true);
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, handle, mut events) = reconnecting(transport.clone(), backend.clone(), policy());
    wait_up(&mut events).await;

    transport.end_session(Err(TunnelError::DeadPeer.into()));
    next_reconnecting(&mut events).await;
    // Pas de teardown complet : suspend appelé, protection maintenue.
    assert!(backend.ops().contains(&NetOp::Suspend));
    assert!(backend.is_protected());
    assert!(!backend.is_clean());

    wait_up(&mut events).await;
    // Ancien guard démonté après le nouvel apply ; la nouvelle config reste installée.
    assert!(!backend.is_protected());
    assert!(!backend.installed_routes().is_empty());

    handle.shutdown();
    assert!(matches!(finish(task).await, DisconnectReason::Requested));
    assert!(backend.is_clean());
}

#[tokio::test(start_paused = true)]
async fn held_guard_released_on_final_disconnect() {
    let backend = FakeNetBackend::new();
    backend.set_keep_guard_during_reconnect(true);
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, handle, mut events) = reconnecting(transport.clone(), backend.clone(), policy());
    wait_up(&mut events).await;
    transport.end_session(Err(TunnelError::DeadPeer.into()));
    next_reconnecting(&mut events).await;
    assert!(backend.is_protected());
    handle.shutdown();
    assert!(matches!(finish(task).await, DisconnectReason::Requested));
    assert!(backend.is_clean());
    assert_disconnected(&transport);
}

#[tokio::test(start_paused = true)]
async fn backoff_doubles_until_max_attempts() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let p = ReconnectPolicy {
        max_attempts: std::num::NonZeroU32::new(4),
        max_delay: Duration::from_secs(5),
        ..policy()
    };
    let (task, _handle, mut events) = reconnecting(transport.clone(), backend.clone(), p);
    wait_up(&mut events).await;
    for _ in 0..10 {
        transport.fail_next_connect(io_error());
    }
    let gone = Instant::now();
    transport.end_session(Err(io_error()));

    let mut delays = Vec::new();
    for n in 1..=4 {
        let (_, attempt, delay, cause) = next_reconnecting(&mut events).await;
        assert_eq!(attempt, n);
        if n > 1 {
            assert!(
                matches!(&cause, DisconnectReason::ConnectFailed(e) if e.is_transient()),
                "{cause:?}"
            );
        }
        delays.push(delay.as_secs());
    }
    assert_eq!(delays, [1, 2, 4, 5]);
    let reason = tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(
        matches!(&reason, DisconnectReason::ConnectFailed(e) if matches!(**e, TransportError::Io(_))),
        "{reason:?}"
    );
    assert!(Instant::now().duration_since(gone) >= Duration::from_secs(12));
    assert_eq!(transport.connect_count(), 1);
    assert!(backend.is_clean());
    assert_disconnected(&transport);
}

#[tokio::test(start_paused = true)]
async fn shutdown_during_backoff() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let p = ReconnectPolicy {
        initial_delay: Duration::from_secs(3600),
        max_delay: Duration::from_secs(3600),
        ..policy()
    };
    let (task, handle, mut events) = reconnecting(transport.clone(), backend.clone(), p);
    wait_up(&mut events).await;
    transport.end_session(Err(TunnelError::ClosedByPeer.into()));
    let (_, _, delay, _) = next_reconnecting(&mut events).await;
    assert_eq!(delay, Duration::from_secs(3600));
    let before = Instant::now();
    handle.shutdown();
    assert!(matches!(finish(task).await, DisconnectReason::Requested));
    assert!(Instant::now().duration_since(before) < Duration::from_secs(1));
    assert_eq!(transport.connect_count(), 1);
    assert!(backend.is_clean());
    assert_disconnected(&transport);
}

#[tokio::test(start_paused = true)]
async fn no_reconnect_on_auth_failure_or_protocol_error() {
    for err in [
        TransportError::AuthFailed,
        TransportError::SecondFactorRequired,
        TransportError::Protocol("erreur de protocole".into()),
    ] {
        let backend = FakeNetBackend::new();
        let transport = FakeTransport::new(creds("good"), sample());
        let (task, _handle, mut events) =
            reconnecting(transport.clone(), backend.clone(), policy());
        wait_up(&mut events).await;
        transport.fail_next_connect(err);
        transport.end_session(Err(TunnelError::DeadPeer.into()));
        let (_, attempt, _, _) = next_reconnecting(&mut events).await;
        assert_eq!(attempt, 1);
        let reason = finish(task).await;
        assert!(
            matches!(&reason, DisconnectReason::ConnectFailed(e) if !e.is_transient()),
            "{reason:?}"
        );
        assert!(backend.is_clean());
        assert_disconnected(&transport);
        let n = std::iter::from_fn(|| events.try_recv())
            .filter(|e| matches!(e.state, SessionState::Reconnecting { .. }))
            .count();
        assert_eq!(n, 0, "un seul essai");
    }
}

#[tokio::test(start_paused = true)]
async fn initial_connect_failure_is_not_retried() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    transport.fail_next_connect(io_error());
    let (task, _handle, mut events) = reconnecting(transport.clone(), backend.clone(), policy());
    assert!(matches!(
        finish(task).await,
        DisconnectReason::ConnectFailed(_)
    ));
    assert!(
        std::iter::from_fn(|| events.try_recv())
            .all(|e| !matches!(e.state, SessionState::Reconnecting { .. }))
    );
}

#[tokio::test(start_paused = true)]
async fn tun_closed_and_requested_are_final() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, _handle, mut events) = reconnecting(transport.clone(), backend.clone(), policy());
    wait_up(&mut events).await;
    drop(backend.take_tun_peer());
    assert!(matches!(finish(task).await, DisconnectReason::TunClosed));
    assert_disconnected(&transport);
}

#[tokio::test(start_paused = true)]
async fn clock_jump_forces_immediate_reconnect() {
    let backend = FakeNetBackend::new();
    let transport = FakeTransport::new(creds("good"), sample());
    let (task, handle, mut events) = reconnecting(transport.clone(), backend.clone(), policy());
    wait_up(&mut events).await;
    // Ticks réguliers : aucune détection.
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(events.try_recv().is_none());
    // Processus gelé 5 min (veille) : tick très en retard.
    tokio::time::advance(Duration::from_secs(300)).await;
    let (_, attempt, delay, cause) = next_reconnecting(&mut events).await;
    assert_eq!((attempt, delay), (1, Duration::ZERO));
    assert!(matches!(cause, DisconnectReason::ClockJump(gap) if gap >= Duration::from_secs(250)));
    wait_up(&mut events).await;
    assert_eq!(transport.connect_count(), 2);
    handle.shutdown();
    assert!(matches!(finish(task).await, DisconnectReason::Requested));
    assert!(backend.is_clean());
}

#[test]
fn shutdown_within_caps_disconnect_timeout() {
    let transport = FakeTransport::new(creds("pw"), sample());
    let (session, handle, _events) = Session::new(
        transport,
        FakeNetBackend::new(),
        creds("pw"),
        SessionOptions::new("fvpn0"),
    );
    assert_eq!(session.effective_disconnect_timeout(), DISCONNECT_TIMEOUT);
    handle.shutdown_within(Duration::from_secs(4));
    assert_eq!(
        session.effective_disconnect_timeout(),
        Duration::from_secs(4)
    );
    // Jamais au-delà du délai configuré.
    handle.shutdown_within(Duration::from_secs(3600));
    assert_eq!(session.effective_disconnect_timeout(), DISCONNECT_TIMEOUT);
}

#[test]
fn second_factor_is_never_transient() {
    assert!(!TransportError::SecondFactorRequired.is_transient());
    let from_ssl: TransportError = crate::sslvpn::SslVpnError::SecondFactorRequired.into();
    assert!(matches!(from_ssl, TransportError::SecondFactorRequired));
    let from_ssl: TransportError = crate::sslvpn::SslVpnError::UnsupportedChallenge.into();
    assert!(matches!(from_ssl, TransportError::SecondFactorRequired));
}
