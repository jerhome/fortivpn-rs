//! Tests d'intégration de `fortivpn_core::sslvpn` contre un petit serveur rustls local
//! (certificats rcgen générés à la volée). Aucune connexion extérieure.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fortivpn_core::Credentials;
use fortivpn_core::sslvpn::{
    CertFingerprint, SessionCookie, SslVpnClient, SslVpnError, SslVpnOptions, TlsOptions,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const COOKIE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MTkyMDYzODg0MjAxNw==";

/// Octets « sur le fil » d'un vecteur `.http` (cf. docs/vectors/README.md).
fn vector(name: &str) -> Vec<u8> {
    let path = format!("{}/../../docs/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path).unwrap();
    let mut lines = text
        .split_inclusive('\n')
        .skip_while(|l| l.starts_with('#'));
    let mut out = Vec::new();
    for line in lines.by_ref() {
        let content = line.strip_suffix('\n').unwrap_or(line);
        out.extend_from_slice(content.as_bytes());
        out.extend_from_slice(b"\r\n");
        if content.is_empty() {
            break;
        }
    }
    let body: String = lines.collect();
    out.extend_from_slice(body.strip_suffix('\n').unwrap_or(&body).as_bytes());
    out
}

struct Pki {
    /// Racine à faire confiance côté client (absente pour un auto-signé).
    ca: Option<CertificateDer<'static>>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Pki {
    fn leaf_der(&self) -> &CertificateDer<'static> {
        &self.chain[0]
    }
}

/// Feuille pour `san` signée par une CA de test.
fn ca_signed(san: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![san.to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    Pki {
        ca: Some(ca_cert.der().clone()),
        chain: vec![leaf.der().clone()],
        key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
    }
}

/// Feuille auto-signée (cas typique d'un FortiGate avec certificat d'usine).
fn self_signed(san: &str) -> Pki {
    let ck = rcgen::generate_simple_self_signed(vec![san.to_owned()]).unwrap();
    Pki {
        ca: None,
        chain: vec![ck.cert.der().clone()],
        key: PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()).into(),
    }
}

type Log = Arc<Mutex<Vec<Vec<u8>>>>;

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Réponse de la fausse passerelle à une requête complète.
fn respond(req: &[u8]) -> Option<Vec<u8>> {
    let line_end = find(req, b"\r\n")?;
    let line = String::from_utf8_lossy(&req[..line_end]).into_owned();
    let good_cookie = find(
        req,
        format!("\r\nCookie: SVPNCOOKIE={COOKIE}\r\n").as_bytes(),
    )
    .is_some();
    let empty = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
    Some(match line.as_str() {
        "POST /remote/logincheck HTTP/1.1" => {
            if find(req, b"credential=S3cr3t%21%26%3D%20%C3%A9&").is_some() {
                vector("logincheck_success.http")
            } else if find(req, b"username=otp").is_some() {
                vector("logincheck_2fa_tokeninfo.http")
            } else {
                vector("logincheck_failure.http")
            }
        }
        "GET /remote/index HTTP/1.1" | "GET /remote/fortisslvpn HTTP/1.1" => empty,
        "GET /remote/fortisslvpn_xml HTTP/1.1" if good_cookie => {
            vector("fortisslvpn_xml_response.http")
        }
        "GET /remote/fortisslvpn_xml HTTP/1.1" => vector("sslvpn_tunnel_403.http"),
        "GET /remote/logout HTTP/1.1" => vector("logout_response.http"),
        "GET /hang HTTP/1.1" => return None,
        _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    })
}

/// Lance la fausse passerelle sur 127.0.0.1 ; renvoie son adresse et le journal des
/// requêtes reçues (une entrée par requête).
async fn spawn_gateway(pki: &Pki) -> (SocketAddr, Log) {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(pki.chain.clone(), pki.key.clone_key())
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log: Log = Arc::default();
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let log = log2.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    // Une requête complète : en-têtes + Content-Length éventuel.
                    let req = loop {
                        if let Some(end) = find(&buf, b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                            let len = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length: "))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if buf.len() >= end + 4 + len {
                                break buf.drain(..end + 4 + len).collect::<Vec<u8>>();
                            }
                        }
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    log.lock().unwrap().push(req.clone());
                    let Some(resp) = respond(&req) else {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        return;
                    };
                    if tls.write_all(&resp).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, log)
}

fn options(addr: SocketAddr, tls: TlsOptions) -> SslVpnOptions {
    let mut o = SslVpnOptions::new("localhost", addr.port());
    o.tls = tls;
    o
}

fn trust_ca(pki: &Pki) -> TlsOptions {
    TlsOptions {
        use_system_roots: false,
        extra_roots: pki.ca.iter().cloned().collect(),
        ..TlsOptions::default()
    }
}

fn pin(fp: CertFingerprint) -> TlsOptions {
    TlsOptions {
        use_system_roots: false,
        pinned: vec![fp],
        ..TlsOptions::default()
    }
}

/// Empreinte calculée indépendamment de `CertFingerprint::of_der`.
fn sha256_hex(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn good_creds() -> Credentials {
    Credentials::new("jdoe", "S3cr3t!&= é")
}

#[tokio::test]
async fn full_sequence_with_pki() {
    let pki = ca_signed("localhost");
    let (addr, log) = spawn_gateway(&pki).await;
    let mut opts = options(addr, trust_ca(&pki));
    opts.realm = "staff".into();
    let client = SslVpnClient::new(&opts).unwrap();

    let cookie = client.authenticate(&good_creds()).await.unwrap();
    assert_eq!(cookie.expose_value(), COOKIE);
    assert!(!format!("{cookie:?}").contains(COOKIE));

    let (config, conn) = client.fetch_config(&cookie).await.unwrap();
    assert!(config.is_split_tunnel());
    assert_eq!(config.ipv4.include_routes.len(), 4);
    assert_eq!(config.ipv4.exclude_routes.len(), 1);
    assert_eq!(conn.peer_addr().ip(), IpAddr::from([127, 0, 0, 1]));
    conn.shutdown().await;

    client.logout(&cookie).await.unwrap();

    let log = log.lock().unwrap();
    let lines: Vec<String> = log
        .iter()
        .map(|r| String::from_utf8_lossy(&r[..find(r, b"\r\n").unwrap()]).into_owned())
        .collect();
    assert_eq!(
        lines,
        [
            "POST /remote/logincheck HTTP/1.1",
            "GET /remote/index HTTP/1.1",
            "GET /remote/fortisslvpn HTTP/1.1",
            "GET /remote/fortisslvpn_xml HTTP/1.1",
            "GET /remote/logout HTTP/1.1",
        ]
    );
    // Requête logincheck identique au vecteur, au port près.
    let expected = String::from_utf8(vector("logincheck_request.http"))
        .unwrap()
        .replace("vpn.example.com:443", &format!("localhost:{}", addr.port()));
    assert_eq!(String::from_utf8_lossy(&log[0]), expected);
}

#[tokio::test]
async fn bad_credentials() {
    let pki = ca_signed("localhost");
    let (addr, log) = spawn_gateway(&pki).await;
    let client = SslVpnClient::new(&options(addr, trust_ca(&pki))).unwrap();
    let err = client
        .authenticate(&Credentials::new("jdoe", "wrong"))
        .await
        .unwrap_err();
    assert!(matches!(err, SslVpnError::AuthFailed), "{err:?}");
    // Pas d'allocation après un échec.
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn second_factor_is_reported() {
    let pki = ca_signed("localhost");
    let (addr, _log) = spawn_gateway(&pki).await;
    let client = SslVpnClient::new(&options(addr, trust_ca(&pki))).unwrap();
    let err = client
        .authenticate(&Credentials::new("otp", "x"))
        .await
        .unwrap_err();
    assert!(matches!(err, SslVpnError::SecondFactorRequired), "{err:?}");
}

#[tokio::test]
async fn expired_cookie_on_config() {
    let pki = ca_signed("localhost");
    let (addr, _log) = spawn_gateway(&pki).await;
    let client = SslVpnClient::new(&options(addr, trust_ca(&pki))).unwrap();
    let stale = SessionCookie::new("stale").unwrap();
    let err = client.fetch_config(&stale).await.unwrap_err();
    assert!(matches!(err, SslVpnError::SessionExpired), "{err:?}");
}

#[tokio::test]
async fn pinning_accepts_self_signed() {
    let pki = self_signed("fortigate.invalid");
    let (addr, _log) = spawn_gateway(&pki).await;
    let fp: CertFingerprint = sha256_hex(pki.leaf_der()).parse().unwrap();
    assert_eq!(fp, CertFingerprint::of_der(pki.leaf_der()));
    // Nom d'hôte différent du SAN : l'épinglage seul fait foi.
    let client = SslVpnClient::new(&options(addr, pin(fp))).unwrap();
    let cookie = client.authenticate(&good_creds()).await.unwrap();
    assert_eq!(cookie.expose_value(), COOKIE);
}

#[tokio::test]
async fn pinning_rejects_other_certificate() {
    let pki = self_signed("localhost");
    let (addr, log) = spawn_gateway(&pki).await;
    let wrong = CertFingerprint::of_der(b"not the certificate");
    let client = SslVpnClient::new(&options(addr, pin(wrong))).unwrap();
    match client.authenticate(&good_creds()).await.unwrap_err() {
        SslVpnError::TlsUntrusted { sha256_hex, .. } => {
            assert_eq!(sha256_hex, sha256_hex_of(&pki));
        }
        e => panic!("{e:?}"),
    }
    // Aucune requête HTTP (donc aucun mot de passe) n'a atteint le serveur.
    assert!(log.lock().unwrap().is_empty());
}

fn sha256_hex_of(pki: &Pki) -> String {
    sha256_hex(pki.leaf_der())
}

#[tokio::test]
async fn pinning_is_strict_even_if_pki_valid() {
    let pki = ca_signed("localhost");
    let (addr, _log) = spawn_gateway(&pki).await;
    let mut tls = trust_ca(&pki);
    tls.pinned = vec![CertFingerprint::of_der(b"another cert")];
    let client = SslVpnClient::new(&options(addr, tls)).unwrap();
    let err = client.authenticate(&good_creds()).await.unwrap_err();
    assert!(matches!(err, SslVpnError::TlsUntrusted { .. }), "{err:?}");
}

#[tokio::test]
async fn pki_rejects_hostname_mismatch_and_unknown_ca() {
    // Mauvais nom.
    let pki = ca_signed("other.example");
    let (addr, log) = spawn_gateway(&pki).await;
    let client = SslVpnClient::new(&options(addr, trust_ca(&pki))).unwrap();
    match client.authenticate(&good_creds()).await.unwrap_err() {
        SslVpnError::TlsUntrusted { sha256_hex, reason } => {
            assert_eq!(sha256_hex, sha256_hex_of(&pki));
            assert!(!reason.is_empty());
        }
        e => panic!("{e:?}"),
    }
    assert!(log.lock().unwrap().is_empty());

    // CA inconnue.
    let pki = self_signed("localhost");
    let other_ca = ca_signed("localhost");
    let (addr, _log) = spawn_gateway(&pki).await;
    let client = SslVpnClient::new(&options(addr, trust_ca(&other_ca))).unwrap();
    let err = client.authenticate(&good_creds()).await.unwrap_err();
    assert!(matches!(err, SslVpnError::TlsUntrusted { .. }), "{err:?}");
}

#[tokio::test]
async fn http_timeout() {
    let pki = ca_signed("localhost");
    let (addr, _log) = spawn_gateway(&pki).await;
    let mut opts = options(addr, trust_ca(&pki));
    opts.timeouts.http = Duration::from_millis(200);
    let client = SslVpnClient::new(&opts).unwrap();
    let mut conn = client.connect().await.unwrap();
    let err = conn
        .request(b"GET /hang HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap_err();
    assert!(matches!(err, SslVpnError::Timeout(_)), "{err:?}");
}

#[tokio::test]
async fn connect_refused() {
    let pki = ca_signed("localhost");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut opts = SslVpnOptions::new("127.0.0.1", port);
    opts.tls = trust_ca(&pki);
    let client = SslVpnClient::new(&opts).unwrap();
    let err = client.authenticate(&good_creds()).await.unwrap_err();
    assert!(matches!(err, SslVpnError::Connect(_)), "{err:?}");
}
