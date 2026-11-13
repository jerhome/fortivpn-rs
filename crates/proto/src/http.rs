//! Couche HTTP/1.1 minimale du SSL-VPN (`docs/protocol.md` §3, §4, §5.1, §6, §10.1).
//!
//! - Construction **octet pour octet** des requêtes émises par le client (gabarit
//!   openfortivpn `do_http_request`, §3.1), y compris `logincheck` (§4.2), la récupération
//!   de la configuration (§5.1), l'« allocation » (§4.4), l'ouverture du tunnel (§6) et le
//!   logout (§10.1).
//! - Encodage `application/x-www-form-urlencoded` exact de la spec (§3.3).
//! - Parseur de réponse incrémental ([`ResponseParser`]) : statut, en-têtes (dont
//!   `Set-Cookie` multiples), corps `Content-Length`, `chunked` ou délimité par la
//!   fermeture de la connexion (§3.2).
//!
//! Les requêtes qui contiennent un secret (mot de passe, cookie) sont rendues dans un
//! [`Zeroizing`] et ne sont jamais affichées par `Debug`.

use std::fmt;
use std::net::Ipv6Addr;

use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{ChallengeState, SessionCookie};

/// `User-Agent` par défaut (openfortivpn et openconnect, §3.1).
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 SV1";

/// Taille maximale acceptée pour l'en-tête d'une réponse.
pub const MAX_HEAD_SIZE: usize = 64 * 1024;

/// Taille maximale acceptée pour une réponse complète (en-tête + corps brut).
pub const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Nombre maximal d'en-têtes dans une réponse.
const MAX_HEADERS: usize = 128;

/// URI de l'authentification (§4.2).
pub const URI_LOGINCHECK: &str = "/remote/logincheck";
/// URI de la configuration XML (§5.1).
pub const URI_CONFIG_XML: &str = "/remote/fortisslvpn_xml";
/// URI de la configuration XML avec la section IPv6 (openconnect, hors MVP).
pub const URI_CONFIG_XML_DUAL_STACK: &str = "/remote/fortisslvpn_xml?dual_stack=1";
/// Première requête de l'« allocation » (§4.4).
pub const URI_ALLOC_INDEX: &str = "/remote/index";
/// Seconde requête de l'« allocation » (§4.4).
pub const URI_ALLOC_FORTISSLVPN: &str = "/remote/fortisslvpn";
/// URI d'ouverture du tunnel (§6).
pub const URI_TUNNEL: &str = "/remote/sslvpn-tunnel";
/// URI de déconnexion (§10.1).
pub const URI_LOGOUT: &str = "/remote/logout";

/// Erreurs de la couche HTTP.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HttpError {
    /// Nom d'hôte de passerelle invalide (caractères interdits, vide…).
    #[error("nom d'hôte de passerelle invalide")]
    InvalidHost,
    /// `User-Agent` invalide (caractères de contrôle…).
    #[error("User-Agent invalide")]
    InvalidUserAgent,
    /// Réponse HTTP syntaxiquement invalide.
    #[error("réponse HTTP invalide : {0}")]
    Malformed(&'static str),
    /// Réponse trop volumineuse (protection mémoire).
    #[error("réponse HTTP trop volumineuse")]
    TooLarge,
    /// Connexion fermée avant la fin de la réponse.
    #[error("réponse HTTP tronquée (connexion fermée)")]
    Truncated,
}

// ---------------------------------------------------------------------------
// Passerelle et requêtes
// ---------------------------------------------------------------------------

/// Cible HTTP : hôte, port et `User-Agent` de la passerelle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    host: String,
    port: u16,
    user_agent: String,
}

impl Gateway {
    /// Construit une cible. `host` est un nom DNS, une IPv4 ou une IPv6 (avec ou sans
    /// crochets). Les caractères pouvant injecter des en-têtes sont refusés.
    pub fn new(host: &str, port: u16) -> Result<Self, HttpError> {
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let valid_name = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
        if !valid_name && host.parse::<Ipv6Addr>().is_err() {
            return Err(HttpError::InvalidHost);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
        })
    }

    /// Remplace le `User-Agent` (certaines passerelles filtrent l'UA, §3.1).
    pub fn with_user_agent(mut self, user_agent: &str) -> Result<Self, HttpError> {
        if user_agent.is_empty() || !user_agent.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(HttpError::InvalidUserAgent);
        }
        user_agent.clone_into(&mut self.user_agent);
        Ok(self)
    }

    /// Hôte (sans crochets pour une IPv6).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Port TCP.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `User-Agent` envoyé.
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Valeur de l'en-tête `Host` : toujours `hôte:port`, même pour 443 (§3.1).
    pub fn host_header(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Encode `input` en `application/x-www-form-urlencoded` selon §3.3 : seuls
/// `A-Z a-z 0-9 - _ . ~` sont conservés, tout autre octet devient `%XX` (hexadécimal
/// majuscule), l'espace devient `%20` (jamais `+`).
pub fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    url_encode_into(&mut out, input.as_bytes());
    out
}

/// Variante de [`url_encode`] qui écrit dans un tampon existant (utile pour garder
/// un secret dans un tampon [`Zeroizing`] dimensionné à l'avance).
pub fn url_encode_into(out: &mut String, input: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in input {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
    }
}

/// Construit une requête selon le gabarit §3.1. Sans cookie, l'en-tête `Cookie:` est
/// émis **vide** comme le fait openfortivpn (vecteur `logincheck_request.http`).
pub fn build_request(
    gateway: &Gateway,
    method: &str,
    uri: &str,
    cookie: Option<&SessionCookie>,
    body: &[u8],
) -> Zeroizing<Vec<u8>> {
    let cookie_len = cookie.map_or(0, |c| c.expose_value().len() + 16);
    let capacity = 400
        + method.len()
        + uri.len()
        + gateway.host.len()
        + gateway.user_agent.len()
        + cookie_len
        + body.len();
    // Capacité calculée à l'avance : pas de réallocation, donc pas de copie du secret
    // laissée non effacée dans un ancien tampon.
    let mut out = Zeroizing::new(Vec::with_capacity(capacity));
    let push = |out: &mut Vec<u8>, parts: &[&[u8]]| {
        for p in parts {
            out.extend_from_slice(p);
        }
        out.extend_from_slice(b"\r\n");
    };
    push(
        &mut out,
        &[method.as_bytes(), b" ", uri.as_bytes(), b" HTTP/1.1"],
    );
    push(&mut out, &[b"Host: ", gateway.host_header().as_bytes()]);
    push(&mut out, &[b"User-Agent: ", gateway.user_agent.as_bytes()]);
    push(&mut out, &[b"Accept: */*"]);
    push(&mut out, &[b"Accept-Encoding: identity"]);
    push(&mut out, &[b"Pragma: no-cache"]);
    push(
        &mut out,
        &[b"Cache-Control: no-store, no-cache, must-revalidate"],
    );
    push(
        &mut out,
        &[b"If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT"],
    );
    push(
        &mut out,
        &[b"Content-Type: application/x-www-form-urlencoded"],
    );
    match cookie {
        Some(c) => push(
            &mut out,
            &[b"Cookie: SVPNCOOKIE=", c.expose_value().as_bytes()],
        ),
        None => push(&mut out, &[b"Cookie: "]),
    }
    push(
        &mut out,
        &[b"Content-Length: ", body.len().to_string().as_bytes()],
    );
    push(&mut out, &[]);
    out.extend_from_slice(body);
    out
}

/// `GET /remote/login?realm=<realm>` (§4.1, optionnel ; vecteur `login_request.http`).
/// Gabarit réduit : `Host`, `User-Agent`, `Accept`.
pub fn login_page_request(gateway: &Gateway, realm: &str) -> Vec<u8> {
    format!(
        "GET /remote/login?realm={} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\n\r\n",
        url_encode(realm),
        gateway.host_header(),
        gateway.user_agent
    )
    .into_bytes()
}

/// `POST /remote/logincheck` (§4.2) : corps
/// `username=<u>&credential=<p>&realm=<r>&ajax=1`, `realm=` toujours présent.
pub fn logincheck_request(
    gateway: &Gateway,
    username: &str,
    password: &SecretString,
    realm: &str,
) -> Zeroizing<Vec<u8>> {
    let password = password.expose_secret();
    let capacity = 64 + 3 * (username.len() + password.len() + realm.len());
    let mut body = Zeroizing::new(String::with_capacity(capacity));
    body.push_str("username=");
    url_encode_into(&mut body, username.as_bytes());
    body.push_str("&credential=");
    url_encode_into(&mut body, password.as_bytes());
    body.push_str("&realm=");
    url_encode_into(&mut body, realm.as_bytes());
    body.push_str("&ajax=1");
    build_request(gateway, "POST", URI_LOGINCHECK, None, body.as_bytes())
}

/// Réponse au challenge de second facteur (§13).
#[derive(Debug, Clone, Copy)]
pub enum SecondFactorReply<'a> {
    /// Code OTP saisi par l'utilisateur.
    Code(&'a SecretString),
    /// Notification push FortiToken Mobile acceptée sur l'appareil (`ftmpush=1`).
    Push,
}

/// 2e `POST /remote/logincheck` après un challenge `ret=2` (§13) : corps
/// `username=..&realm=..&reqid=..&polid=..&grp=..&portal=..&peer=..&code=<otp>&code2=&magic=..`
/// ou, pour le push, `...&peer=..&ftmpush=1`. Toutes les valeurs sont encodées (§3.3).
pub fn logincheck_second_factor_request(
    gateway: &Gateway,
    username: &str,
    realm: &str,
    state: &ChallengeState,
    reply: SecondFactorReply<'_>,
) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(String::with_capacity(256));
    for (i, (k, v)) in [
        ("username", username),
        ("realm", realm),
        ("reqid", state.reqid.as_str()),
        ("polid", state.polid.as_str()),
        ("grp", state.grp.as_str()),
        ("portal", state.portal.as_str()),
        ("peer", state.peer.as_str()),
    ]
    .into_iter()
    .enumerate()
    {
        if i > 0 {
            body.push('&');
        }
        body.push_str(k);
        body.push('=');
        url_encode_into(&mut body, v.as_bytes());
    }
    match reply {
        SecondFactorReply::Code(code) => {
            body.push_str("&code=");
            url_encode_into(&mut body, code.expose_secret().as_bytes());
            body.push_str("&code2=&magic=");
            url_encode_into(&mut body, state.magic.as_bytes());
        }
        SecondFactorReply::Push => body.push_str("&ftmpush=1"),
    }
    build_request(gateway, "POST", URI_LOGINCHECK, None, body.as_bytes())
}

/// Variante de la requête de configuration (§5.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConfigQuery {
    /// `/remote/fortisslvpn_xml` (openfortivpn, MVP).
    #[default]
    Ipv4,
    /// `/remote/fortisslvpn_xml?dual_stack=1` (openconnect, ajoute `<ipv6>`).
    DualStack,
}

/// `GET /remote/fortisslvpn_xml` (§5.1 ; vecteur `fortisslvpn_xml_request.http`).
pub fn config_request(
    gateway: &Gateway,
    cookie: &SessionCookie,
    query: ConfigQuery,
) -> Zeroizing<Vec<u8>> {
    let uri = match query {
        ConfigQuery::Ipv4 => URI_CONFIG_XML,
        ConfigQuery::DualStack => URI_CONFIG_XML_DUAL_STACK,
    };
    build_request(gateway, "GET", uri, Some(cookie), b"")
}

/// Les deux requêtes d'« allocation » d'openfortivpn (§4.4), dans l'ordre :
/// `GET /remote/index` puis `GET /remote/fortisslvpn`.
pub fn allocation_requests(gateway: &Gateway, cookie: &SessionCookie) -> [Zeroizing<Vec<u8>>; 2] {
    [
        build_request(gateway, "GET", URI_ALLOC_INDEX, Some(cookie), b""),
        build_request(gateway, "GET", URI_ALLOC_FORTISSLVPN, Some(cookie), b""),
    ]
}

/// `GET /remote/sslvpn-tunnel` exactement comme openfortivpn (§6 ; vecteur
/// `sslvpn_tunnel_request.http`) : `Host: sslvpn` littéral, pas d'autre en-tête.
pub fn tunnel_request(cookie: &SessionCookie) -> Zeroizing<Vec<u8>> {
    const PREFIX: &[u8] =
        b"GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: SVPNCOOKIE=";
    let value = cookie.expose_value().as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(PREFIX.len() + value.len() + 4));
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n\r\n");
    out
}

/// `GET /remote/logout` (§10.1 ; vecteur `logout_request.http`).
pub fn logout_request(gateway: &Gateway, cookie: &SessionCookie) -> Zeroizing<Vec<u8>> {
    build_request(gateway, "GET", URI_LOGOUT, Some(cookie), b"")
}

// ---------------------------------------------------------------------------
// Réponses
// ---------------------------------------------------------------------------

/// En-tête de réponse (nom tel que reçu, valeur brute).
#[derive(Clone)]
pub struct Header {
    name: String,
    value: Vec<u8>,
}

impl Header {
    /// Nom de l'en-tête (casse d'origine).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Valeur brute.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    fn is_sensitive(&self) -> bool {
        self.name.eq_ignore_ascii_case("set-cookie") || self.name.eq_ignore_ascii_case("cookie")
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_sensitive() {
            write!(f, "{}: [REDACTED]", self.name)
        } else {
            write!(
                f,
                "{}: {:?}",
                self.name,
                String::from_utf8_lossy(&self.value)
            )
        }
    }
}

/// Réponse HTTP complète. Les tampons (en-têtes bruts, valeurs, corps) sont effacés à
/// la libération ; `Debug` masque `Set-Cookie`/`Cookie` et n'affiche pas le corps.
pub struct HttpResponse {
    status: u16,
    reason: String,
    headers: Vec<Header>,
    raw_head: Vec<u8>,
    body: Vec<u8>,
}

impl HttpResponse {
    /// Code de statut.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Texte de la ligne de statut.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Tous les en-têtes, dans l'ordre de réception.
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Valeurs de tous les en-têtes `name` (insensible à la casse), dans l'ordre.
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_slice())
    }

    /// Premier en-tête `name` (insensible à la casse).
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_slice())
    }

    /// En-tête `Location` (redirection), si présent et en UTF-8.
    pub fn location(&self) -> Option<&str> {
        self.header("location")
            .and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Ligne de statut + en-têtes bruts (CRLF compris, sans la ligne vide finale).
    pub fn raw_head(&self) -> &[u8] {
        &self.raw_head
    }

    /// Corps décodé (chunked retiré).
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Détection « permission refusée » globale (§3.2) : marqueur
    /// `<!--sslvpnerrmsgkey=sslvpn_login_permission_denied-->` dans le corps, ou
    /// `permission_denied denied` / `Permission denied` dans les en-têtes.
    pub fn is_permission_denied(&self) -> bool {
        contains(
            &self.body,
            b"<!--sslvpnerrmsgkey=sslvpn_login_permission_denied-->",
        ) || contains(&self.raw_head, b"permission_denied denied")
            || contains(&self.raw_head, b"Permission denied")
    }

    /// Construit une réponse (tests et outils).
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let mut p = ResponseParser::new();
        p.push(bytes).expect("parse").expect("complete")
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("reason", &self.reason)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl Drop for HttpResponse {
    fn drop(&mut self) {
        self.raw_head.zeroize();
        self.body.zeroize();
        for h in &mut self.headers {
            h.value.zeroize();
        }
    }
}

/// Recherche naïve d'une sous-séquence.
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Délimitation du corps (RFC 9112 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    None,
    Length(usize),
    Chunked,
    UntilClose,
}

#[derive(Debug)]
struct ParsedHead {
    status: u16,
    reason: String,
    headers: Vec<Header>,
    head_len: usize,
    body: BodyKind,
}

/// Parseur incrémental d'**une** réponse HTTP/1.1.
///
/// Usage : [`push`](Self::push) les octets reçus jusqu'à obtenir `Some(réponse)` ; si
/// la connexion se ferme avant, appeler [`finish`](Self::finish) (corps délimité par la
/// fermeture). Les octets reçus au-delà de la réponse sont disponibles via
/// [`take_remaining`](Self::take_remaining). Les réponses intermédiaires 1xx sont
/// ignorées. Le tampon interne est effacé à la libération.
#[derive(Default)]
pub struct ResponseParser {
    buf: Zeroizing<Vec<u8>>,
    head: Option<ParsedHead>,
    remaining: Zeroizing<Vec<u8>>,
    /// Début de la zone du tampon pas encore examinée pour la fin d'en-tête.
    head_scan: usize,
    /// État du décodage `chunked` en cours (incrémental).
    chunks: ChunkDecoder,
}

impl fmt::Debug for ResponseParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseParser")
            .field("buffered", &self.buf.len())
            .field("head_parsed", &self.head.is_some())
            .finish_non_exhaustive()
    }
}

impl ResponseParser {
    /// Nouveau parseur (tampon initial de 16 Kio pour limiter les réallocations).
    pub fn new() -> Self {
        Self {
            buf: Zeroizing::new(Vec::with_capacity(16 * 1024)),
            head: None,
            remaining: Zeroizing::new(Vec::new()),
            head_scan: 0,
            chunks: ChunkDecoder::default(),
        }
    }

    /// Ajoute des octets reçus ; renvoie la réponse dès qu'elle est complète.
    pub fn push(&mut self, data: &[u8]) -> Result<Option<HttpResponse>, HttpError> {
        if self.buf.len() + data.len() > MAX_RESPONSE_SIZE {
            return Err(HttpError::TooLarge);
        }
        self.buf.extend_from_slice(data);
        self.advance(false)
    }

    /// La connexion est fermée : termine la réponse si son corps est délimité par la
    /// fermeture, sinon [`HttpError::Truncated`].
    pub fn finish(&mut self) -> Result<HttpResponse, HttpError> {
        self.advance(true)?.ok_or(HttpError::Truncated)
    }

    /// Octets reçus après la fin de la réponse (pipelining / début du flux suivant).
    pub fn take_remaining(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::take(&mut self.remaining)
    }

    fn advance(&mut self, eof: bool) -> Result<Option<HttpResponse>, HttpError> {
        loop {
            if self.head.is_none() {
                // Ne reparse l'en-tête que si une fin d'en-tête (ligne vide) est apparue.
                let from = self.head_scan.saturating_sub(3);
                self.head_scan = self.buf.len();
                let terminated = self.buf[from..].windows(2).enumerate().any(|(i, w)| {
                    w[0] == b'\n'
                        && (w[1] == b'\n'
                            || (w[1] == b'\r' && self.buf.get(from + i + 2) == Some(&b'\n')))
                });
                if !terminated {
                    if eof {
                        return Err(HttpError::Truncated);
                    }
                    if self.buf.len() > MAX_HEAD_SIZE {
                        return Err(HttpError::TooLarge);
                    }
                    return Ok(None);
                }
                match parse_head(&self.buf)? {
                    Some(h) => self.head = Some(h),
                    None if eof => return Err(HttpError::Truncated),
                    None => return Ok(None),
                }
            }
            let Some(head) = self.head.as_ref() else {
                return Ok(None);
            };
            let body_bytes = &self.buf[head.head_len..];
            let decoded = match head.body {
                BodyKind::None => Some((Vec::new(), 0)),
                BodyKind::Length(n) => {
                    (body_bytes.len() >= n).then(|| (body_bytes[..n].to_vec(), n))
                }
                BodyKind::Chunked => self.chunks.decode(body_bytes)?,
                BodyKind::UntilClose => eof.then(|| (body_bytes.to_vec(), body_bytes.len())),
            };
            let Some((body, used)) = decoded else {
                return if eof {
                    Err(HttpError::Truncated)
                } else {
                    Ok(None)
                };
            };
            let Some(head) = self.head.take() else {
                return Ok(None);
            };
            let end = head.head_len + used;
            if (100..200).contains(&head.status) {
                // Réponse intermédiaire : on la jette et on continue.
                self.buf.drain(..end);
                self.head_scan = 0;
                self.chunks = ChunkDecoder::default();
                continue;
            }
            let raw_head = self.buf[..head.head_len.saturating_sub(2)].to_vec();
            self.remaining = Zeroizing::new(self.buf[end..].to_vec());
            self.buf.zeroize();
            self.buf.clear();
            return Ok(Some(HttpResponse {
                status: head.status,
                reason: head.reason,
                headers: head.headers,
                raw_head,
                body,
            }));
        }
    }
}

fn parse_head(buf: &[u8]) -> Result<Option<ParsedHead>, HttpError> {
    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut storage);
    let head_len = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return if buf.len() > MAX_HEAD_SIZE {
                Err(HttpError::TooLarge)
            } else {
                Ok(None)
            };
        }
        Err(httparse::Error::TooManyHeaders) => {
            return Err(HttpError::Malformed("trop d'en-têtes"));
        }
        Err(_) => return Err(HttpError::Malformed("ligne de statut ou en-tête")),
    };
    if head_len > MAX_HEAD_SIZE {
        return Err(HttpError::TooLarge);
    }
    if resp.version != Some(1) {
        return Err(HttpError::Malformed("version HTTP non 1.1"));
    }
    let status = resp.code.ok_or(HttpError::Malformed("statut absent"))?;
    let reason = resp.reason.unwrap_or_default().to_owned();
    let headers: Vec<Header> = resp
        .headers
        .iter()
        .map(|h| Header {
            name: h.name.to_owned(),
            value: h.value.to_vec(),
        })
        .collect();

    let mut chunked = false;
    let mut length: Option<usize> = None;
    for h in &headers {
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            let v = String::from_utf8_lossy(&h.value).to_ascii_lowercase();
            if v.split(',').any(|t| t.trim() == "chunked") {
                chunked = true;
            }
        } else if h.name.eq_ignore_ascii_case("content-length") {
            let n = std::str::from_utf8(&h.value)
                .ok()
                .map(str::trim)
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or(HttpError::Malformed("Content-Length"))?;
            if length.is_some_and(|l| l != n) {
                return Err(HttpError::Malformed("Content-Length multiples"));
            }
            length = Some(n);
        }
    }
    let body = if (100..200).contains(&status) || status == 204 || status == 304 {
        BodyKind::None
    } else if chunked {
        BodyKind::Chunked
    } else if let Some(n) = length {
        if n > MAX_RESPONSE_SIZE {
            return Err(HttpError::TooLarge);
        }
        BodyKind::Length(n)
    } else {
        BodyKind::UntilClose
    };
    Ok(Some(ParsedHead {
        status,
        reason,
        headers,
        head_len,
        body,
    }))
}

/// Longueur maximale d'une ligne de chunk / trailer sans CRLF.
const MAX_CHUNK_LINE: usize = 1024;

/// Décodeur `chunked` incrémental : mémorise l'offset consommé et le corps déjà décodé,
/// donc chaque octet n'est examiné qu'un nombre borné de fois (F2).
#[derive(Debug, Default)]
struct ChunkDecoder {
    /// Octets du corps brut déjà consommés (chunks complets).
    pos: usize,
    body: Vec<u8>,
    /// Taille 0 vue : on lit les trailers.
    trailers: bool,
}

impl ChunkDecoder {
    /// `input` = tout le corps brut reçu depuis le début ; `Ok(None)` s'il manque des
    /// octets. Renvoie le corps et le nombre d'octets consommés.
    fn decode(&mut self, input: &[u8]) -> Result<Option<(Vec<u8>, usize)>, HttpError> {
        loop {
            let rest = &input[self.pos.min(input.len())..];
            let Some(line_end) = find_crlf(rest) else {
                if rest.len() > MAX_CHUNK_LINE {
                    return Err(HttpError::Malformed("taille de chunk"));
                }
                return Ok(None);
            };
            if self.trailers {
                self.pos += line_end + 2;
                if line_end == 0 {
                    return Ok(Some((std::mem::take(&mut self.body), self.pos)));
                }
                continue;
            }
            let line = &rest[..line_end];
            let size_part = line.split(|&b| b == b';').next().unwrap_or_default();
            let size_str = std::str::from_utf8(size_part)
                .map_err(|_| HttpError::Malformed("taille de chunk"))?
                .trim();
            if size_str.is_empty() || size_str.len() > 8 {
                return Err(HttpError::Malformed("taille de chunk"));
            }
            let size = usize::from_str_radix(size_str, 16)
                .map_err(|_| HttpError::Malformed("taille de chunk"))?;
            let data = &rest[line_end + 2..];
            if size == 0 {
                self.pos += line_end + 2;
                self.trailers = true;
                continue;
            }
            if self.body.len() + size > MAX_RESPONSE_SIZE {
                return Err(HttpError::TooLarge);
            }
            if data.len() < size + 2 {
                return Ok(None);
            }
            if &data[size..size + 2] != b"\r\n" {
                return Err(HttpError::Malformed("fin de chunk"));
            }
            self.body.extend_from_slice(&data[..size]);
            self.pos += line_end + 2 + size + 2;
        }
    }
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

// ---------------------------------------------------------------------------
// Vecteurs (tests)
// ---------------------------------------------------------------------------

/// Lecture des vecteurs `.http` de `docs/vectors` (format décrit dans leur README).
#[cfg(test)]
pub(crate) mod vectors {
    /// Chemin d'un vecteur.
    pub(crate) fn path(name: &str) -> String {
        format!("{}/../../docs/vectors/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Octets « sur le fil » d'un vecteur `.http` : commentaires `#` retirés, lignes
    /// d'en-tête en CRLF, corps sans le LF final unique.
    pub(crate) fn http(name: &str) -> Vec<u8> {
        let text = std::fs::read_to_string(path(name)).expect("vecteur lisible");
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
        let body = body.strip_suffix('\n').unwrap_or(&body);
        out.extend_from_slice(body.as_bytes());
        out
    }

    /// Contenu brut d'un vecteur (XML).
    pub(crate) fn raw(name: &str) -> String {
        std::fs::read_to_string(path(name)).expect("vecteur lisible")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COOKIE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MTkyMDYzODg0MjAxNw==";

    fn gw() -> Gateway {
        Gateway::new("vpn.example.com", 443).unwrap()
    }

    fn cookie() -> SessionCookie {
        SessionCookie::new(COOKIE).unwrap()
    }

    #[test]
    fn url_encode_spec_vector() {
        assert_eq!(url_encode("S3cr3t!&= é"), "S3cr3t%21%26%3D%20%C3%A9");
        assert_eq!(url_encode("aZ09-_.~"), "aZ09-_.~");
        assert_eq!(url_encode("a+b/c"), "a%2Bb%2Fc");
        assert_eq!(url_encode("\r\n"), "%0D%0A");
    }

    #[test]
    fn logincheck_request_matches_vector() {
        let pw = SecretString::from("S3cr3t!&= é");
        let req = logincheck_request(&gw(), "jdoe", &pw, "staff");
        assert_eq!(*req, vectors::http("logincheck_request.http"));
    }

    #[test]
    fn logincheck_request_empty_realm() {
        let pw = SecretString::from("x");
        let req = logincheck_request(&gw(), "jdoe", &pw, "");
        assert!(req.ends_with(b"\r\n\r\nusername=jdoe&credential=x&realm=&ajax=1"));
    }

    fn challenge() -> ChallengeState {
        ChallengeState {
            reqid: "12345678".into(),
            polid: "1-1-87654321".into(),
            grp: "staff-grp".into(),
            portal: "full-access".into(),
            peer: String::new(),
            magic: "1-23456789".into(),
        }
    }

    #[test]
    fn second_factor_request_code() {
        let code = SecretString::from("12 34&6");
        let req = logincheck_second_factor_request(
            &gw(),
            "jdoe",
            "staff",
            &challenge(),
            SecondFactorReply::Code(&code),
        );
        let text = String::from_utf8(req.to_vec()).unwrap();
        assert!(text.starts_with("POST /remote/logincheck HTTP/1.1\r\n"));
        assert!(text.ends_with(
            "\r\n\r\nusername=jdoe&realm=staff&reqid=12345678&polid=1-1-87654321&grp=staff-grp\
             &portal=full-access&peer=&code=12%2034%266&code2=&magic=1-23456789"
        ));
    }

    #[test]
    fn second_factor_request_push() {
        let req = logincheck_second_factor_request(
            &gw(),
            "jdoe",
            "",
            &challenge(),
            SecondFactorReply::Push,
        );
        let text = String::from_utf8(req.to_vec()).unwrap();
        assert!(text.ends_with("&portal=full-access&peer=&ftmpush=1"));
        assert!(!text.contains("code="));
    }

    #[test]
    fn config_request_matches_vector() {
        let req = config_request(&gw(), &cookie(), ConfigQuery::Ipv4);
        assert_eq!(*req, vectors::http("fortisslvpn_xml_request.http"));
        let dual = config_request(&gw(), &cookie(), ConfigQuery::DualStack);
        assert!(dual.starts_with(b"GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1\r\n"));
    }

    #[test]
    fn logout_request_matches_vector() {
        assert_eq!(
            *logout_request(&gw(), &cookie()),
            vectors::http("logout_request.http")
        );
    }

    #[test]
    fn tunnel_request_matches_vector() {
        assert_eq!(
            *tunnel_request(&cookie()),
            vectors::http("sslvpn_tunnel_request.http")
        );
    }

    #[test]
    fn login_page_request_matches_vector() {
        assert_eq!(
            login_page_request(&gw(), "staff"),
            vectors::http("login_request.http")
        );
    }

    #[test]
    fn allocation_requests_uris() {
        let [a, b] = allocation_requests(&gw(), &cookie());
        assert!(a.starts_with(b"GET /remote/index HTTP/1.1\r\nHost: vpn.example.com:443\r\n"));
        assert!(b.starts_with(b"GET /remote/fortisslvpn HTTP/1.1\r\n"));
        assert!(contains(&b, b"\r\nCookie: SVPNCOOKIE="));
        assert!(b.ends_with(b"Content-Length: 0\r\n\r\n"));
    }

    #[test]
    fn host_header_always_has_port() {
        assert_eq!(gw().host_header(), "vpn.example.com:443");
        let g = Gateway::new("192.0.2.1", 10443).unwrap();
        assert_eq!(g.host_header(), "192.0.2.1:10443");
        let g = Gateway::new("[2001:db8::1]", 443).unwrap();
        assert_eq!(g.host(), "2001:db8::1");
        assert_eq!(g.host_header(), "[2001:db8::1]:443");
    }

    #[test]
    fn gateway_rejects_injection() {
        assert_eq!(Gateway::new("", 443), Err(HttpError::InvalidHost));
        assert_eq!(
            Gateway::new("vpn.example.com\r\nX: y", 443),
            Err(HttpError::InvalidHost)
        );
        assert_eq!(Gateway::new("a b", 443), Err(HttpError::InvalidHost));
        assert_eq!(
            gw().with_user_agent("UA\r\nX: y"),
            Err(HttpError::InvalidUserAgent)
        );
        let g = gw().with_user_agent("FortiClient/7").unwrap();
        assert!(contains(
            &build_request(&g, "GET", "/", None, b""),
            b"\r\nUser-Agent: FortiClient/7\r\n"
        ));
    }

    #[test]
    fn parses_all_response_vectors() {
        for (name, status, body_len) in [
            ("logincheck_success.http", 200, 35),
            ("logincheck_failure.http", 200, 69),
            ("logincheck_failure_405.http", 405, 44),
            ("logincheck_2fa_tokeninfo.http", 200, 138),
            ("fortisslvpn_xml_response.http", 200, 1191),
            ("logout_response.http", 200, 43),
            ("sslvpn_tunnel_403.http", 403, 0),
        ] {
            let bytes = vectors::http(name);
            let mut p = ResponseParser::new();
            let r = p.push(&bytes).unwrap().unwrap_or_else(|| panic!("{name}"));
            assert_eq!(r.status(), status, "{name}");
            assert_eq!(r.body().len(), body_len, "{name}");
            assert!(p.take_remaining().is_empty());
        }
    }

    #[test]
    fn parses_byte_by_byte() {
        let bytes = vectors::http("logincheck_success.http");
        let mut p = ResponseParser::new();
        let mut got = None;
        for (i, b) in bytes.iter().enumerate() {
            let r = p.push(std::slice::from_ref(b)).unwrap();
            if let Some(r) = r {
                assert_eq!(i, bytes.len() - 1, "complète trop tôt");
                got = Some(r);
            }
        }
        let r = got.unwrap();
        assert_eq!(r.body(), b"ret=1,redir=/remote/fortisslvpn_xml");
        assert_eq!(r.header("content-type"), Some(&b"text/plain"[..]));
    }

    #[test]
    fn multiple_set_cookie_and_remaining() {
        let raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: A=1\r\nset-cookie: SVPNCOOKIE=x; path=/\r\nContent-Length: 2\r\n\r\nokEXTRA";
        let mut p = ResponseParser::new();
        let r = p.push(raw).unwrap().unwrap();
        let cookies: Vec<_> = r.header_values("Set-Cookie").collect();
        assert_eq!(cookies, [&b"A=1"[..], b"SVPNCOOKIE=x; path=/"]);
        assert_eq!(r.body(), b"ok");
        assert_eq!(&*p.take_remaining(), b"EXTRA");
    }

    #[test]
    fn chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\nNEXT";
        let mut p = ResponseParser::new();
        // Coupé en deux.
        assert!(p.push(&raw[..60]).unwrap().is_none());
        let r = p.push(&raw[60..]).unwrap().unwrap();
        assert_eq!(r.body(), b"hello world");
        assert_eq!(&*p.take_remaining(), b"NEXT");
    }

    #[test]
    fn chunked_errors() {
        let mut p = ResponseParser::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
        assert!(matches!(p.push(raw), Err(HttpError::Malformed(_))));
        let mut p = ResponseParser::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabcd";
        assert!(matches!(p.push(raw), Err(HttpError::Malformed(_))));
    }

    #[test]
    fn body_until_close() {
        let mut p = ResponseParser::new();
        assert!(
            p.push(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n<x/>")
                .unwrap()
                .is_none()
        );
        let r = p.finish().unwrap();
        assert_eq!(r.body(), b"<x/>");
    }

    #[test]
    fn truncated_and_limits() {
        let mut p = ResponseParser::new();
        assert!(
            p.push(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
                .unwrap()
                .is_none()
        );
        assert_eq!(p.finish().unwrap_err(), HttpError::Truncated);

        let mut p = ResponseParser::new();
        assert!(p.push(b"HTTP/1.1 200").unwrap().is_none());
        assert_eq!(p.finish().unwrap_err(), HttpError::Truncated);

        let mut p = ResponseParser::new();
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n";
        assert_eq!(p.push(raw).unwrap_err(), HttpError::TooLarge);

        let mut p = ResponseParser::new();
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
        assert!(matches!(p.push(raw), Err(HttpError::Malformed(_))));

        let mut p = ResponseParser::new();
        assert!(matches!(
            p.push(b"garbage\r\n\r\n"),
            Err(HttpError::Malformed(_))
        ));
    }

    #[test]
    fn skips_interim_responses() {
        let mut p = ResponseParser::new();
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(p.push(raw).unwrap().unwrap().status(), 204);
    }

    #[test]
    fn permission_denied_markers() {
        let r = HttpResponse::from_bytes(
            b"HTTP/1.1 200 OK\r\nContent-Length: 53\r\n\r\n<!--sslvpnerrmsgkey=sslvpn_login_permission_denied-->",
        );
        assert!(r.is_permission_denied());
        let r = HttpResponse::from_bytes(
            b"HTTP/1.1 200 OK\r\nX-Err: Permission denied\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(r.is_permission_denied());
        let r = HttpResponse::from_bytes(&vectors::http("logincheck_success.http"));
        assert!(!r.is_permission_denied());
    }

    #[test]
    fn debug_hides_secrets() {
        let r = HttpResponse::from_bytes(&vectors::http("logincheck_success.http"));
        let dbg = format!("{r:?}");
        assert!(!dbg.contains(COOKIE), "{dbg}");
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn chunked_byte_by_byte_is_incremental() {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let mut expected = Vec::new();
        for i in 0..2000u32 {
            raw.extend_from_slice(b"1\r\n");
            raw.push(b'a' + (i % 26) as u8);
            expected.push(b'a' + (i % 26) as u8);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"0\r\nX-T: 1\r\n\r\nNEXT");
        let mut p = ResponseParser::new();
        let mut got = None;
        let start = std::time::Instant::now();
        for (i, b) in raw.iter().enumerate() {
            if let Some(r) = p.push(std::slice::from_ref(b)).unwrap() {
                assert_eq!(i, raw.len() - 5, "complète trop tôt");
                got = Some(r);
                break;
            }
        }
        // Les 4 octets restants "NEXT" arrivent après la fin.
        let r = got.unwrap_or_else(|| panic!("réponse incomplète"));
        assert_eq!(r.body(), &expected[..]);
        assert!(start.elapsed().as_secs() < 5);
    }

    #[test]
    fn head_not_reparsed_until_terminator() {
        let mut p = ResponseParser::new();
        for b in b"HTTP/1.1 200 OK\r\nX-A: 1\r\nContent-Length: 1\r\n" {
            assert!(p.push(std::slice::from_ref(b)).unwrap().is_none());
            assert!(p.head.is_none());
        }
        assert!(p.push(b"\r").unwrap().is_none());
        assert!(p.push(b"\n").unwrap().is_none());
        assert_eq!(p.push(b"z").unwrap().unwrap().body(), b"z");
    }
}
