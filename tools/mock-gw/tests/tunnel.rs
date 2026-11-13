//! `GET /remote/sslvpn-tunnel` (docs/protocol.md §6) : refus 403, bascule en flux brut,
//! séquence complète openfortivpn et logout (§10.1).

mod common;

use std::sync::{Arc, Mutex};

use common::{
    VECTOR_COOKIE, connect, exchange, hex_frame, http_vector, login, parse_response, read_response,
    read_to_end, request, tunnel_request,
};
use mock_gw::{
    CookieCheck, LoggedResponse, MockGateway, TunnelConfig, TunnelContext, TunnelStream,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn forbidden_vector() -> common::HttpResponse {
    parse_response(&http_vector("sslvpn_tunnel_403.http"))
        .unwrap()
        .0
}

#[tokio::test]
async fn refused_without_valid_cookie() {
    let gw = MockGateway::builder().start().await.unwrap();
    let mut s = connect(&gw).await;
    let requests: [&[u8]; 3] = [
        b"GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\n\r\n",
        b"GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: SVPNCOOKIE=\r\n\r\n",
        &http_vector("sslvpn_tunnel_request.http"), // cookie du vecteur, jamais émis ici
    ];
    for raw in requests {
        s.write_all(raw).await.unwrap();
        // Le client détecte le refus par les 6 premiers octets (« HTTP/1 »).
        let mut head = [0u8; 6];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1");
        let mut rest = head.to_vec();
        loop {
            if let Some((resp, _)) = parse_response(&rest) {
                assert_eq!(resp, forbidden_vector());
                break;
            }
            let mut b = [0u8; 256];
            let n = s.read(&mut b).await.unwrap();
            assert!(n > 0);
            rest.extend_from_slice(&b[..n]);
        }
    }
    let checks: Vec<_> = gw.log().entries().iter().map(|e| e.cookie).collect();
    assert_eq!(
        checks,
        [
            CookieCheck::Absent,
            CookieCheck::Empty,
            CookieCheck::Rejected
        ]
    );
    assert!(
        gw.log()
            .entries()
            .iter()
            .all(|e| e.response == LoggedResponse::Status(403))
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn default_handler_switches_then_closes_without_http() {
    let gw = MockGateway::builder().start().await.unwrap();
    let mut s = connect(&gw).await;
    let cookie = login(&mut s).await;
    s.write_all(&tunnel_request(&cookie)).await.unwrap();
    // Aucune réponse HTTP, fermeture propre (close_notify) par CloseTunnel.
    assert_eq!(read_to_end(&mut s).await.unwrap(), b"");
    let e = gw.log().for_path("/remote/sslvpn-tunnel").remove(0);
    assert_eq!(e.response, LoggedResponse::TunnelOpened);
    assert_eq!(e.cookie, CookieCheck::Valid);
    gw.shutdown().await;
}

/// Ce que le handler de test a observé.
#[derive(Debug, Default)]
struct Seen {
    ctx: Option<TunnelContext>,
    pending: Vec<u8>,
}

#[tokio::test]
async fn raw_stream_is_handed_over_with_pipelined_bytes() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen2 = Arc::clone(&seen);
    let handler = move |mut stream: TunnelStream, ctx: TunnelContext| {
        let seen = Arc::clone(&seen2);
        async move {
            {
                let mut s = seen.lock().unwrap();
                s.pending = stream.pending().to_vec();
                s.ctx = Some(ctx);
            }
            // Écho : préfixe « G> » sur chaque lecture, jusqu'à EOF.
            let mut buf = [0u8; 2048];
            loop {
                let n = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut out = b"G>".to_vec();
                out.extend_from_slice(&buf[..n]);
                if stream.write_all(&out).await.is_err() {
                    break;
                }
            }
            let _ = stream.close().await;
        }
    };
    let gw = MockGateway::builder()
        .session_cookie(VECTOR_COOKIE)
        .tunnel_config(TunnelConfig::vector_full_tunnel())
        .tunnel_handler(handler)
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    exchange(&mut s, &http_vector("logincheck_request.http"))
        .await
        .unwrap();

    let mut s = connect(&gw).await;
    exchange(&mut s, &http_vector("fortisslvpn_xml_request.http"))
        .await
        .unwrap();
    // Requête tunnel + première trame LCP dans la même écriture (comme pppd peut le faire).
    let lcp = hex_frame("lcp.hex", "lcp_confreq_client");
    let mut first = http_vector("sslvpn_tunnel_request.http");
    first.extend_from_slice(&lcp);
    s.write_all(&first).await.unwrap();

    let mut got = vec![0u8; 2 + lcp.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got[..2], b"G>", "pas de réponse HTTP avant le flux");
    assert_eq!(&got[2..], &lcp[..]);

    // Le flux reste bidirectionnel.
    s.write_all(b"\x00\x01\x02").await.unwrap();
    let mut got = [0u8; 5];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"G>\x00\x01\x02");
    s.shutdown().await.unwrap();
    assert_eq!(read_to_end(&mut s).await.unwrap(), b"");

    let seen = std::mem::take(&mut *seen.lock().unwrap());
    assert_eq!(seen.pending, lcp, "octets pipelinés restitués au handler");
    let ctx = seen.ctx.as_ref().unwrap();
    assert_eq!(ctx.username, "jdoe");
    assert_eq!(ctx.conn_id, 2);
    assert_eq!(*ctx.config, TunnelConfig::vector_full_tunnel());
    gw.shutdown().await;
}

#[tokio::test]
async fn full_openfortivpn_sequence_then_logout() {
    let gw = MockGateway::builder().start().await.unwrap();
    // conn #1 : auth + allocation.
    let mut c1 = connect(&gw).await;
    let cookie = login(&mut c1).await;
    for path in ["/remote/index", "/remote/fortisslvpn"] {
        let r = exchange(&mut c1, &request("GET", path, Some(&cookie), ""))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
    }
    drop(c1);
    // conn #2 : config + tunnel.
    let mut c2 = connect(&gw).await;
    let r = exchange(
        &mut c2,
        &request("GET", "/remote/fortisslvpn_xml", Some(&cookie), ""),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    c2.write_all(&tunnel_request(&cookie)).await.unwrap();
    assert_eq!(read_to_end(&mut c2).await.unwrap(), b"");
    // conn #3 : logout.
    let mut c3 = connect(&gw).await;
    let r = exchange(
        &mut c3,
        &request("GET", "/remote/logout", Some(&cookie), ""),
    )
    .await
    .unwrap();
    let expected = parse_response(&http_vector("logout_response.http"))
        .unwrap()
        .0;
    assert_eq!(r, expected);
    // Session fermée : config et tunnel refusés.
    let r = exchange(
        &mut c3,
        &request("GET", "/remote/fortisslvpn_xml", Some(&cookie), ""),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 302);
    c3.write_all(&tunnel_request(&cookie)).await.unwrap();
    assert_eq!(read_response(&mut c3).await.unwrap().status, 403);

    let entries = gw.log().entries();
    let seq: Vec<(u64, &str)> = entries
        .iter()
        .map(|e| (e.conn_id, e.path.as_str()))
        .collect();
    assert_eq!(
        seq,
        [
            (1, "/remote/logincheck"),
            (1, "/remote/index"),
            (1, "/remote/fortisslvpn"),
            (2, "/remote/fortisslvpn_xml"),
            (2, "/remote/sslvpn-tunnel"),
            (3, "/remote/logout"),
            (3, "/remote/fortisslvpn_xml"),
            (3, "/remote/sslvpn-tunnel"),
        ]
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn logout_vector_request() {
    let gw = MockGateway::builder()
        .session_cookie(VECTOR_COOKIE)
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    exchange(&mut s, &http_vector("logincheck_request.http"))
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let r = exchange(&mut s, &http_vector("logout_request.http"))
        .await
        .unwrap();
    assert_eq!(
        r,
        parse_response(&http_vector("logout_response.http"))
            .unwrap()
            .0
    );
    let e = gw.log().for_path("/remote/logout").remove(0);
    assert_eq!(e.cookie, CookieCheck::Valid);
    // Logout sans session : toujours 200.
    let r = exchange(&mut s, &http_vector("logout_request.http"))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(
        gw.log().for_path("/remote/logout")[1].cookie,
        CookieCheck::Rejected
    );
    gw.shutdown().await;
}
