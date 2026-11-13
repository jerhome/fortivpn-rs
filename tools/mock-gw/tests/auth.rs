//! `POST /remote/logincheck` (docs/protocol.md §4) : succès, échecs (ret=0, 405), 2FA,
//! journal sans secret.

mod common;

use common::{
    HttpResponse, VECTOR_COOKIE, connect, exchange, http_vector, login, login_body, parse_response,
    request,
};
use mock_gw::{
    AuthOutcome, CookieCheck, DEFAULT_PASSWORD, DEFAULT_USERNAME, LoggedResponse, LoginFailure,
    MockGateway, REDACTED, Scenario,
};

fn vector_response(name: &str) -> HttpResponse {
    let raw = http_vector(name);
    let (resp, used) = parse_response(&raw).expect("vecteur complet");
    assert_eq!(used, raw.len(), "{name}: Content-Length incohérent");
    resp
}

fn without_header(mut r: HttpResponse, name: &str) -> HttpResponse {
    r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    r
}

#[tokio::test]
async fn vector_request_succeeds_with_vector_response() {
    let gw = MockGateway::builder()
        .realm(Some("staff".into()))
        .session_cookie(VECTOR_COOKIE)
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let resp = exchange(&mut s, &http_vector("logincheck_request.http"))
        .await
        .unwrap();
    // Le vecteur contient un en-tête `Date` (fixe) que mock-gw n'émet pas.
    assert_eq!(
        resp,
        without_header(vector_response("logincheck_success.http"), "Date")
    );

    let log = gw.log().for_path("/remote/logincheck");
    assert_eq!(log.len(), 1);
    let e = &log[0];
    assert_eq!(e.method, "POST");
    assert_eq!(e.auth, Some(AuthOutcome::Accepted));
    assert_eq!(e.response, LoggedResponse::Status(200));
    assert_eq!(e.cookie, CookieCheck::Absent, "`Cookie: ` vide = absent");
    assert_eq!(e.form_field("username"), Some("jdoe"));
    assert_eq!(e.form_field("credential"), Some(REDACTED));
    assert_eq!(e.form_field("realm"), Some("staff"));
    assert_eq!(e.form_field("ajax"), Some("1"));
    assert_eq!(e.header("User-Agent"), Some("Mozilla/5.0 SV1"));
    gw.shutdown().await;
}

#[tokio::test]
async fn random_cookies_are_distinct() {
    let gw = MockGateway::builder().start().await.unwrap();
    let mut s = connect(&gw).await;
    let a = login(&mut s).await;
    let b = login(&mut s).await;
    assert_ne!(a, b);
    assert_eq!(a.len(), 64);
    gw.shutdown().await;
}

#[tokio::test]
async fn wrong_password_ret0_matches_vector() {
    let gw = MockGateway::builder().start().await.unwrap();
    let mut s = connect(&gw).await;
    let body = login_body(DEFAULT_USERNAME, "mauvais", "");
    let resp = exchange(&mut s, &request("POST", "/remote/logincheck", None, &body))
        .await
        .unwrap();
    assert_eq!(resp, vector_response("logincheck_failure.http"));
    assert_eq!(resp.svpn_cookie(), Some(""));
    let e = &gw.log().entries()[0];
    assert_eq!(e.auth, Some(AuthOutcome::Rejected));
    assert_eq!(e.form_field("credential"), Some(REDACTED));
    gw.shutdown().await;
}

#[tokio::test]
async fn wrong_password_405_matches_vector() {
    let gw = MockGateway::builder()
        .login_failure(LoginFailure::Status405)
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let body = login_body(DEFAULT_USERNAME, "mauvais", "");
    let resp = exchange(&mut s, &request("POST", "/remote/logincheck", None, &body))
        .await
        .unwrap();
    assert_eq!(resp, vector_response("logincheck_failure_405.http"));
    assert_eq!(gw.log().entries()[0].response, LoggedResponse::Status(405));
    gw.shutdown().await;
}

#[tokio::test]
async fn wrong_username_realm_or_missing_fields_are_rejected() {
    let gw = MockGateway::builder()
        .realm(Some("staff".into()))
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let bodies = [
        login_body("autre", DEFAULT_PASSWORD, "staff"),
        login_body(DEFAULT_USERNAME, DEFAULT_PASSWORD, ""),
        login_body(DEFAULT_USERNAME, DEFAULT_PASSWORD, "admins"),
        format!("username={DEFAULT_USERNAME}&realm=staff&ajax=1"),
        String::new(),
    ];
    for body in &bodies {
        let resp = exchange(&mut s, &request("POST", "/remote/logincheck", None, body))
            .await
            .unwrap();
        assert_eq!(resp.status, 200, "{body}");
        assert!(resp.body_str().starts_with("ret=0,"), "{body}");
    }
    assert!(
        gw.log()
            .entries()
            .iter()
            .all(|e| e.auth == Some(AuthOutcome::Rejected))
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn second_factor_matches_vector() {
    let gw = MockGateway::builder()
        .scenario(Scenario::SecondFactorRequired)
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let body = login_body(DEFAULT_USERNAME, DEFAULT_PASSWORD, "");
    let resp = exchange(&mut s, &request("POST", "/remote/logincheck", None, &body))
        .await
        .unwrap();
    assert_eq!(resp, vector_response("logincheck_2fa_tokeninfo.http"));
    assert_eq!(resp.svpn_cookie(), None);
    assert_eq!(
        gw.log().entries()[0].auth,
        Some(AuthOutcome::SecondFactorRequested)
    );

    // Mauvais mot de passe : refusé avant toute demande de 2FA.
    let body = login_body(DEFAULT_USERNAME, "mauvais", "");
    let resp = exchange(&mut s, &request("POST", "/remote/logincheck", None, &body))
        .await
        .unwrap();
    assert!(resp.body_str().starts_with("ret=0,"));
    gw.shutdown().await;
}

#[tokio::test]
async fn custom_credentials_with_special_characters() {
    let password = "p@ss w0rd/+%;é€";
    let gw = MockGateway::builder()
        .credentials("Prénom.Nom@corp", password)
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    let body = login_body("Prénom.Nom@corp", password, "");
    let resp = exchange(&mut s, &request("POST", "/remote/logincheck", None, &body))
        .await
        .unwrap();
    assert!(resp.svpn_cookie().is_some_and(|c| !c.is_empty()));
    assert_eq!(
        gw.log().entries()[0].form_field("username"),
        Some("Prénom.Nom@corp")
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn log_never_contains_secrets() {
    let gw = MockGateway::builder()
        .session_cookie(VECTOR_COOKIE)
        .start()
        .await
        .unwrap();
    let mut s = connect(&gw).await;
    exchange(&mut s, &http_vector("logincheck_request.http"))
        .await
        .unwrap();
    exchange(&mut s, &http_vector("fortisslvpn_xml_request.http"))
        .await
        .unwrap();
    exchange(&mut s, &http_vector("logout_request.http"))
        .await
        .unwrap();
    let dump = format!("{:?}", gw.log().entries());
    for secret in [DEFAULT_PASSWORD, "S3cr3t", "S3cr3t%21", VECTOR_COOKIE] {
        assert!(
            !dump.contains(secret),
            "secret « {secret} » dans le journal"
        );
    }
    let xml = &gw.log().for_path("/remote/fortisslvpn_xml")[0];
    assert_eq!(xml.cookie, CookieCheck::Valid);
    assert_eq!(xml.header("Cookie"), Some("SVPNCOOKIE=<redacted>"));
    // Le Debug du builder masque aussi le mot de passe.
    let builder = format!("{:?}", MockGateway::builder());
    assert!(!builder.contains("S3cr3t"), "{builder}");
    gw.shutdown().await;
}

#[tokio::test]
async fn login_page_and_method_checks() {
    let gw = MockGateway::builder().start().await.unwrap();
    let mut s = connect(&gw).await;
    let resp = exchange(&mut s, &http_vector("login_request.http"))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body_str().contains("/remote/logincheck"));
    let entry = &gw.log().entries()[0];
    assert_eq!(entry.target, "/remote/login?realm=staff");
    assert_eq!(entry.path, "/remote/login");

    let resp = exchange(&mut s, &request("GET", "/remote/logincheck", None, ""))
        .await
        .unwrap();
    assert_eq!(resp.status, 405);
    let resp = exchange(&mut s, &request("GET", "/nope", None, ""))
        .await
        .unwrap();
    assert_eq!(resp.status, 404);
    gw.shutdown().await;
}

#[tokio::test]
async fn connection_close_is_honoured() {
    let gw = MockGateway::builder().start().await.unwrap();
    let mut s = connect(&gw).await;
    let resp = exchange(
        &mut s,
        b"GET /remote/login HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(resp.header("Connection"), Some("close"));
    assert_eq!(common::read_to_end(&mut s).await.unwrap(), b"");
    gw.shutdown().await;
}

#[tokio::test]
async fn malformed_request_gets_400() {
    let gw = MockGateway::builder().start().await.unwrap();
    let mut s = connect(&gw).await;
    let resp = exchange(&mut s, b"\x00\x16\x50\x50 garbage\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(resp.status, 400);
    gw.shutdown().await;
}
