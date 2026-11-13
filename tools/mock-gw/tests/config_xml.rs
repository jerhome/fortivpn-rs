//! `GET /remote/fortisslvpn_xml` (docs/protocol.md §5) : conformité aux vecteurs XML,
//! session expirée, étape d'« allocation ».

mod common;

use std::net::Ipv4Addr;

use common::{
    VECTOR_COOKIE, connect, exchange, http_vector, login, parse_response, read_vector, request,
};
use mock_gw::{DnsServer, ExpiredSession, MockGateway, SplitDns, TunnelConfig};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};

/// Représentation structurelle d'un document : une ligne par ouverture/fermeture
/// d'élément, attributs (dans l'ordre, valeurs déséchappées) ; commentaires, déclaration
/// XML, blancs et style de guillemets ignorés.
fn structure(xml: &str) -> Vec<String> {
    fn open(e: &BytesStart<'_>) -> String {
        let name = e.name().as_ref().to_owned();
        let attrs: Vec<String> = e
            .attributes()
            .map(|a| {
                let a = a.expect("attribut valide");
                format!(
                    "{}={}",
                    a.key.as_ref().to_owned(),
                    a.normalized_value(XmlVersion::Implicit1_0)
                        .expect("valeur valide")
                )
            })
            .collect();
        format!("<{name} {}>", attrs.join(" "))
    }
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut out = Vec::new();
    loop {
        match reader.read_event().expect("XML bien formé") {
            Event::Start(e) => out.push(open(&e)),
            Event::Empty(e) => {
                out.push(open(&e));
                out.push(format!("</{}>", e.name().as_ref().to_owned()));
            }
            Event::End(e) => out.push(format!("</{}>", e.name().as_ref().to_owned())),
            Event::Text(t) => assert!(t.as_ref().trim().is_empty(), "texte inattendu"),
            Event::Eof => break,
            _ => {}
        }
    }
    out
}

async fn fetch_xml(gw: &mock_gw::RunningGateway, target: &str) -> String {
    let mut s = connect(gw).await;
    let cookie = login(&mut s).await;
    drop(s);
    // Nouvelle connexion, comme openfortivpn (§1).
    let mut s = connect(gw).await;
    let resp = exchange(&mut s, &request("GET", target, Some(&cookie), ""))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("Content-Type"), Some("text/xml"));
    resp.body_str().to_owned()
}

#[tokio::test]
async fn vector_request_gets_vector_response_byte_for_byte() {
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
    let resp = exchange(&mut s, &http_vector("fortisslvpn_xml_request.http"))
        .await
        .unwrap();
    let raw = http_vector("fortisslvpn_xml_response.http");
    let (expected, _) = parse_response(&raw).unwrap();
    assert_eq!(resp, expected);
    gw.shutdown().await;
}

#[tokio::test]
async fn split_config_matches_vector_structure() {
    let gw = MockGateway::builder()
        .tunnel_config(TunnelConfig::vector_split())
        .start()
        .await
        .unwrap();
    let xml = fetch_xml(&gw, "/remote/fortisslvpn_xml").await;
    assert_eq!(structure(&xml), structure(&read_vector("config_split.xml")));
    gw.shutdown().await;
}

#[tokio::test]
async fn full_tunnel_config_matches_vector_structure() {
    let gw = MockGateway::builder()
        .tunnel_config(TunnelConfig::vector_full_tunnel())
        .start()
        .await
        .unwrap();
    let xml = fetch_xml(&gw, "/remote/fortisslvpn_xml").await;
    assert_eq!(
        structure(&xml),
        structure(&read_vector("config_full_tunnel.xml"))
    );
    assert!(!xml.contains("split-tunnel-info"));
    gw.shutdown().await;
}

#[tokio::test]
async fn dual_stack_section_only_on_request() {
    let gw = MockGateway::builder()
        .tunnel_config(TunnelConfig::vector_dual_stack())
        .start()
        .await
        .unwrap();
    let xml = fetch_xml(&gw, "/remote/fortisslvpn_xml?dual_stack=1").await;
    assert_eq!(
        structure(&xml),
        structure(&read_vector("config_dual_stack.xml"))
    );
    let xml = fetch_xml(&gw, "/remote/fortisslvpn_xml").await;
    assert!(!xml.contains("<ipv6>"));
    assert!(xml.contains("<ipv4>"));
    gw.shutdown().await;
}

#[tokio::test]
async fn custom_config_is_escaped_and_well_formed() {
    let mut cfg = TunnelConfig::split(
        Ipv4Addr::new(192, 168, 77, 9),
        vec![
            DnsServer::new(Ipv4Addr::new(192, 168, 77, 1)).with_domain("a&b\"c'.example"),
            DnsServer::new(Ipv4Addr::new(192, 168, 77, 2)),
        ],
        vec!["192.168.0.0/16".parse().unwrap()],
    );
    cfg.ipv4.split_dns.push(SplitDns {
        domains: vec!["x.example".into(), "y.example".into()],
        servers: (1..=12).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect(),
    });
    let gw = MockGateway::builder()
        .tunnel_config(cfg)
        .start()
        .await
        .unwrap();
    let st = structure(&fetch_xml(&gw, "/remote/fortisslvpn_xml").await);
    assert!(st.contains(&"<dns ip=192.168.77.1 domain=a&b\"c'.example>".to_owned()));
    assert!(st.contains(&"<assigned-addr ipv4=192.168.77.9>".to_owned()));
    assert!(st.contains(&"<addr ip=192.168.0.0 mask=255.255.0.0>".to_owned()));
    let split_dns = st.iter().find(|l| l.starts_with("<split-dns ")).unwrap();
    assert!(split_dns.contains("domains=x.example,y.example"));
    assert!(split_dns.contains("dnsserver9=10.0.0.9"));
    assert!(!split_dns.contains("dnsserver10"), "au plus 9 serveurs");
    gw.shutdown().await;
}

#[tokio::test]
async fn invalid_or_missing_cookie_per_mode() {
    for (mode, status) in [
        (ExpiredSession::RedirectToLogin, 302),
        (ExpiredSession::Forbidden, 403),
        (ExpiredSession::Unauthorized, 401),
    ] {
        let gw = MockGateway::builder()
            .expired_session(mode)
            .start()
            .await
            .unwrap();
        let mut s = connect(&gw).await;
        for cookie in [None, Some(""), Some("inconnu")] {
            let resp = exchange(
                &mut s,
                &request("GET", "/remote/fortisslvpn_xml", cookie, ""),
            )
            .await
            .unwrap();
            assert_eq!(resp.status, status, "{mode:?} {cookie:?}");
            assert!(resp.body.is_empty());
            if status == 302 {
                assert_eq!(resp.header("Location"), Some("/remote/login"));
            }
        }
        gw.shutdown().await;
    }
}

#[tokio::test]
async fn allocation_steps_require_cookie() {
    let gw = MockGateway::builder().start().await.unwrap();
    let mut s = connect(&gw).await;
    for path in ["/remote/index", "/remote/fortisslvpn"] {
        let resp = exchange(&mut s, &request("GET", path, None, ""))
            .await
            .unwrap();
        assert_eq!(resp.status, 302, "{path}");
    }
    let cookie = login(&mut s).await;
    for path in ["/remote/index", "/remote/fortisslvpn"] {
        let resp = exchange(&mut s, &request("GET", path, Some(&cookie), ""))
            .await
            .unwrap();
        assert_eq!(resp.status, 200, "{path}");
    }
    gw.shutdown().await;
}
