//! Scénarios d'erreur : cookie refusé, coupures TLS après auth, arrêt, délais.

mod common;

use std::io;
use std::time::Duration;

use common::{connect, exchange, login, read_response, read_to_end, request, tunnel_request};
use mock_gw::{
    CookieCheck, DropPoint, ExpiredSession, LoggedResponse, MockGateway, Scenario, TunnelContext,
    TunnelStream,
};
use tokio::io::AsyncWriteExt;

/// Coupure sans `close_notify` : rustls signale `UnexpectedEof`.
fn assert_abrupt<T: std::fmt::Debug>(r: io::Result<T>) {
    let err = r.expect_err("la connexion aurait dû être coupée");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
}

#[tokio::test]
async fn cookie_rejected_after_login() {
    let gw = MockGateway::builder()
        .scenario(Scenario::CookieRejected)
        .expired_session(ExpiredSession::Forbidden)
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let cookie = login(&mut s).await;
    let r = exchange(
        &mut s,
        &request("GET", "/remote/fortisslvpn_xml", Some(&cookie), ""),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 403);
    s.write_all(&tunnel_request(&cookie)).await.unwrap();
    assert_eq!(read_response(&mut s).await.unwrap().status, 403);
    let e = gw.log().entries();
    assert_eq!(e[1].cookie, CookieCheck::Rejected);
    assert_eq!(e[2].cookie, CookieCheck::Rejected);
    gw.shutdown().await;
}

#[tokio::test]
async fn drop_after_login_response() {
    let gw = MockGateway::builder()
        .scenario(Scenario::DropAfterAuth(DropPoint::AfterLoginResponse))
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    // La réponse complète arrive, puis la connexion est coupée sans close_notify.
    let cookie = login(&mut s).await;
    assert_abrupt(read_to_end(&mut s).await);
    assert_eq!(
        gw.log().entries()[0].response,
        LoggedResponse::StatusThenDropped(200)
    );
    // La session reste valide : une nouvelle connexion peut continuer.
    let mut s = connect(&gw).await;
    let r = exchange(
        &mut s,
        &request("GET", "/remote/fortisslvpn_xml", Some(&cookie), ""),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    gw.shutdown().await;
}

#[tokio::test]
async fn drop_before_config() {
    let gw = MockGateway::builder()
        .scenario(Scenario::DropAfterAuth(DropPoint::BeforeConfig))
        .start()
        .await
        .unwrap();
    for path in [
        "/remote/index",
        "/remote/fortisslvpn",
        "/remote/fortisslvpn_xml",
    ] {
        let mut s = connect(&gw).await;
        let cookie = login(&mut s).await;
        assert_abrupt(exchange(&mut s, &request("GET", path, Some(&cookie), "")).await);
        let last = gw.log().entries().pop().unwrap();
        assert_eq!(last.path, path);
        assert_eq!(last.response, LoggedResponse::Dropped);
    }
    // Sans cookie valide, pas de coupure : comportement normal.
    let mut s = connect(&gw).await;
    let r = exchange(&mut s, &request("GET", "/remote/fortisslvpn_xml", None, ""))
        .await
        .unwrap();
    assert_eq!(r.status, 302);
    gw.shutdown().await;
}

#[tokio::test]
async fn drop_before_tunnel() {
    let gw = MockGateway::builder()
        .scenario(Scenario::DropAfterAuth(DropPoint::BeforeTunnel))
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let cookie = login(&mut s).await;
    let r = exchange(
        &mut s,
        &request("GET", "/remote/fortisslvpn_xml", Some(&cookie), ""),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    s.write_all(&tunnel_request(&cookie)).await.unwrap();
    assert_abrupt(read_to_end(&mut s).await);
    assert_eq!(
        gw.log().entries().pop().unwrap().response,
        LoggedResponse::Dropped
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn handler_can_abort_tunnel_without_close_notify() {
    let gw = MockGateway::builder()
        .tunnel_handler(|stream: TunnelStream, _ctx: TunnelContext| async move {
            stream.abort();
        })
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let cookie = login(&mut s).await;
    s.write_all(&tunnel_request(&cookie)).await.unwrap();
    assert_abrupt(read_to_end(&mut s).await);
    gw.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_listener_and_live_tunnels() {
    let gw = MockGateway::builder()
        .tunnel_handler(|_stream: TunnelStream, _ctx: TunnelContext| async move {
            // Garde la connexion ouverte indéfiniment.
            std::future::pending::<()>().await;
        })
        .start()
        .await
        .unwrap();
    let addr = gw.addr();
    let mut s = connect(&gw).await;
    let cookie = login(&mut s).await;
    s.write_all(&tunnel_request(&cookie)).await.unwrap();
    // Attendre que la bascule soit enregistrée avant l'arrêt.
    for _ in 0..100 {
        if gw.log().for_path("/remote/sslvpn-tunnel").len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::timeout(Duration::from_secs(5), gw.shutdown())
        .await
        .expect("arrêt borné");
    assert_abrupt(read_to_end(&mut s).await);
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn idle_connection_is_closed_after_io_timeout() {
    let gw = MockGateway::builder()
        .io_timeout(Duration::from_millis(200))
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    // Rien envoyé : fermeture propre par la passerelle à l'expiration.
    assert_eq!(read_to_end(&mut s).await.unwrap(), b"");
    gw.shutdown().await;
}

#[tokio::test]
async fn sessions_are_independent() {
    let gw = MockGateway::builder().start().await.unwrap();
    let mut s = connect(&gw).await;
    let a = login(&mut s).await;
    let b = login(&mut s).await;
    let r = exchange(&mut s, &request("GET", "/remote/logout", Some(&a), ""))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    let r = exchange(
        &mut s,
        &request("GET", "/remote/fortisslvpn_xml", Some(&b), ""),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "la session b survit au logout de a");
    let r = exchange(
        &mut s,
        &request("GET", "/remote/fortisslvpn_xml", Some(&a), ""),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 302);
    gw.shutdown().await;
}
