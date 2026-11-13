//! Petit client HTTP/TLS de test (tokio-rustls à la main) + lecture des vecteurs.
#![allow(dead_code)]

pub(crate) mod ppp;

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mock_gw::RunningGateway;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Cookie fictif présent dans les vecteurs `*_request.http`.
pub(crate) const VECTOR_COOKIE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MTkyMDYzODg0MjAxNw==";
pub(crate) const SNI: &str = "vpn.example.com";
pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) type Client = TlsStream<TcpStream>;

// ---------------------------------------------------------------- vecteurs

pub(crate) fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectors")
}

pub(crate) fn read_vector(name: &str) -> String {
    let path = vectors_dir().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Octets « sur le fil » d'un vecteur `.http` (cf. docs/vectors/README.md) : commentaires
/// `#` de tête retirés, ligne de départ et en-têtes en CRLF, corps sans le LF final.
pub(crate) fn http_vector(name: &str) -> Vec<u8> {
    let text = read_vector(name);
    let mut lines = text
        .split_inclusive('\n')
        .skip_while(|l| l.starts_with('#'));
    let mut out = Vec::new();
    for line in lines.by_ref() {
        let l = line.trim_end_matches('\n');
        out.extend_from_slice(l.as_bytes());
        out.extend_from_slice(b"\r\n");
        if l.is_empty() {
            break;
        }
    }
    let body: String = lines.collect();
    let body = body.strip_suffix('\n').unwrap_or(&body);
    out.extend_from_slice(body.as_bytes());
    out
}

// ---------------------------------------------------------------- messages HTTP

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl HttpResponse {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).expect("corps UTF-8")
    }

    /// Valeur du `SVPNCOOKIE` de `Set-Cookie` (parcourt tous les `Set-Cookie`).
    pub(crate) fn svpn_cookie(&self) -> Option<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .find_map(|(_, v)| v.strip_prefix("SVPNCOOKIE="))
            .map(|v| v.split(';').next().unwrap_or(""))
    }
}

/// Analyse une réponse complète (`Content-Length` obligatoire, sinon corps vide).
/// Renvoie aussi le nombre d'octets consommés ; `None` si incomplète.
pub(crate) fn parse_response(raw: &[u8]) -> Option<(HttpResponse, usize)> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let head = match resp.parse(raw).expect("réponse HTTP valide") {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return None,
    };
    let headers: Vec<(String, String)> = resp
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_owned(),
                String::from_utf8(h.value.to_vec()).unwrap(),
            )
        })
        .collect();
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, v)| v.trim().parse::<usize>().unwrap());
    if raw.len() < head + len {
        return None;
    }
    Some((
        HttpResponse {
            status: resp.code.unwrap(),
            reason: resp.reason.unwrap_or_default().to_owned(),
            headers,
            body: raw[head..head + len].to_vec(),
        },
        head + len,
    ))
}

/// Requête au gabarit openfortivpn (docs/protocol.md §3.1).
pub(crate) fn request(method: &str, target: &str, cookie: Option<&str>, body: &str) -> Vec<u8> {
    format!(
        "{method} {target} HTTP/1.1\r\n\
         Host: {SNI}:443\r\n\
         User-Agent: Mozilla/5.0 SV1\r\n\
         Accept: */*\r\n\
         Accept-Encoding: identity\r\n\
         Pragma: no-cache\r\n\
         Cache-Control: no-store, no-cache, must-revalidate\r\n\
         If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Cookie: {}\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        cookie
            .map(|c| format!("SVPNCOOKIE={c}"))
            .unwrap_or_default(),
        body.len()
    )
    .into_bytes()
}

/// `GET /remote/sslvpn-tunnel` exactement comme openfortivpn (§6).
pub(crate) fn tunnel_request(cookie: &str) -> Vec<u8> {
    format!(
        "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: SVPNCOOKIE={cookie}\r\n\r\n"
    )
    .into_bytes()
}

/// Encodage formulaire façon openfortivpn (§3.3).
pub(crate) fn url_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

pub(crate) fn login_body(user: &str, password: &str, realm: &str) -> String {
    format!(
        "username={}&credential={}&realm={}&ajax=1",
        url_encode(user),
        url_encode(password),
        url_encode(realm)
    )
}

// ---------------------------------------------------------------- TLS

/// Vérificateur par épinglage SHA-256 du DER feuille (sémantique `trusted-cert`).
#[derive(Debug)]
pub(crate) struct PinnedVerifier {
    sha256_hex: String,
    provider: Arc<CryptoProvider>,
}

pub(crate) fn sha256_hex(der: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(der)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if sha256_hex(end_entity.as_ref()) == self.sha256_hex {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("empreinte non épinglée".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(crate) fn pinned_config(sha256_hex: &str) -> ClientConfig {
    let provider = provider();
    ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
            sha256_hex: sha256_hex.to_owned(),
            provider,
        }))
        .with_no_client_auth()
}

pub(crate) async fn connect_with(
    addr: SocketAddr,
    config: ClientConfig,
    sni: &str,
) -> io::Result<Client> {
    let tcp = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr)).await??;
    let name = ServerName::try_from(sni.to_owned()).map_err(io::Error::other)?;
    tokio::time::timeout(
        TIMEOUT,
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await?
}

/// Nouvelle connexion TLS, certificat épinglé, SNI `vpn.example.com`.
pub(crate) async fn connect(gw: &RunningGateway) -> Client {
    connect_with(gw.addr(), pinned_config(gw.cert().sha256_hex()), SNI)
        .await
        .expect("connexion TLS à mock-gw")
}

// ---------------------------------------------------------------- échanges

/// Lit une réponse HTTP complète ; `Err` si la connexion se ferme avant.
pub(crate) async fn read_response(s: &mut Client) -> io::Result<HttpResponse> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((resp, used)) = parse_response(&buf) {
            assert_eq!(used, buf.len(), "octets en trop après la réponse");
            return Ok(resp);
        }
        let n = tokio::time::timeout(TIMEOUT, s.read(&mut chunk)).await??;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Envoie `raw` puis lit la réponse.
pub(crate) async fn exchange(s: &mut Client, raw: &[u8]) -> io::Result<HttpResponse> {
    s.write_all(raw).await?;
    s.flush().await?;
    read_response(s).await
}

/// Lit jusqu'à la fin du flux : `Ok(octets)` si fermeture propre (`close_notify`),
/// `Err(UnexpectedEof)` si coupure TCP sans `close_notify`.
pub(crate) async fn read_to_end(s: &mut Client) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    tokio::time::timeout(TIMEOUT, s.read_to_end(&mut out)).await??;
    Ok(out)
}

/// Login nominal (identifiants par défaut) ; renvoie la valeur du cookie.
pub(crate) async fn login(s: &mut Client) -> String {
    let body = login_body(mock_gw::DEFAULT_USERNAME, mock_gw::DEFAULT_PASSWORD, "");
    let resp = exchange(s, &request("POST", "/remote/logincheck", None, &body))
        .await
        .expect("réponse logincheck");
    assert_eq!(resp.status, 200);
    resp.svpn_cookie()
        .filter(|c| !c.is_empty())
        .expect("SVPNCOOKIE non vide")
        .to_owned()
}

/// Octets de la trame `name` d'un vecteur `.hex` (contrôle `len=`).
pub(crate) fn hex_frame(file: &str, name: &str) -> Vec<u8> {
    let text = read_vector(file);
    let mut out = Vec::new();
    let mut expected_len = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("@frame ") {
            if expected_len.is_some() {
                break;
            }
            let mut parts = rest.split_whitespace();
            if parts.next() == Some(name) {
                expected_len = parts
                    .find_map(|p| p.strip_prefix("len="))
                    .map(|l| l.parse::<usize>().unwrap());
            }
        } else if expected_len.is_some() && !line.is_empty() && !line.starts_with('#') {
            out.extend(
                line.split_whitespace()
                    .map(|h| u8::from_str_radix(h, 16).unwrap()),
            );
        }
    }
    let len = expected_len.unwrap_or_else(|| panic!("trame {name} absente de {file}"));
    assert_eq!(out.len(), len, "{file}:{name} len=");
    out
}
