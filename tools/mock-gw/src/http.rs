//! HTTP/1.1 minimal côté serveur : lecture d'une requête (httparse) en conservant les
//! octets qui suivent (début du flux tunnel), écriture d'une réponse avec
//! `Content-Length`, décodage `application/x-www-form-urlencoded`.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::{Zeroize, Zeroizing};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 48;

/// Requête reçue. Le corps peut contenir le mot de passe : il est effacé à la libération.
pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) path: String,
    pub(crate) query: Option<String>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl Request {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `true` si le paramètre de requête `key=value` est présent.
    pub(crate) fn has_query_param(&self, key: &str, value: &str) -> bool {
        self.query.as_deref().is_some_and(|q| {
            q.split('&').any(|kv| {
                kv.split_once('=')
                    .is_some_and(|(k, v)| k == key && v == value)
            })
        })
    }

    pub(crate) fn wants_close(&self) -> bool {
        self.header("connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("close"))
    }

    /// Valeur de `SVPNCOOKIE` dans l'en-tête `Cookie` : `None` si absent.
    pub(crate) fn svpn_cookie(&self) -> Option<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .flat_map(|(_, v)| v.split(';'))
            .find_map(|c| c.trim().strip_prefix("SVPNCOOKIE="))
    }
}

/// Retire les `n` premiers octets de `buf` en effaçant la zone libérée.
fn consume(buf: &mut Vec<u8>, n: usize) {
    let len = buf.len();
    buf.copy_within(n.., 0);
    buf[len - n..].zeroize();
    buf.truncate(len - n);
}

/// Lit une requête complète. `buf` contient les octets déjà reçus et, au retour, ceux qui
/// suivent la requête (à remettre au tunnel). `Ok(None)` = EOF propre entre deux requêtes.
pub(crate) async fn read_request<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> io::Result<Option<Request>>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        if let Some((req, used)) = try_parse(buf)? {
            consume(buf, used);
            return Ok(Some(req));
        }
        let n = stream.read(&mut chunk[..]).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Analyse `buf` ; `Ok(None)` s'il manque des octets.
fn try_parse(buf: &[u8]) -> io::Result<Option<(Request, usize)>> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let head_len = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return if buf.len() > MAX_HEADER_BYTES {
                Err(bad("en-têtes HTTP trop longs"))
            } else {
                Ok(None)
            };
        }
        Err(_) => return Err(bad("requête HTTP invalide")),
    };
    let headers: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_owned(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    if headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(bad("Transfer-Encoding non supporté par mock-gw"));
    }
    let body_len = match headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        Some((_, v)) => v
            .trim()
            .parse::<usize>()
            .map_err(|_| bad("Content-Length invalide"))?,
        None => 0,
    };
    if body_len > MAX_BODY_BYTES {
        return Err(bad("corps HTTP trop long"));
    }
    if buf.len() < head_len + body_len {
        return Ok(None);
    }
    let method = req.method.unwrap_or_default().to_owned();
    let target = req.path.unwrap_or_default().to_owned();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
        None => (target.clone(), None),
    };
    let body = Zeroizing::new(buf[head_len..head_len + body_len].to_vec());
    Ok(Some((
        Request {
            method,
            target,
            path,
            query,
            headers,
            body,
        },
        head_len + body_len,
    )))
}

/// Réponse HTTP ; `Content-Length` est ajouté en dernier en-tête.
#[derive(Debug, Clone)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) reason: &'static str,
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) body: Vec<u8>,
}

impl Response {
    pub(crate) fn new(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    #[must_use]
    pub(crate) fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} {}\r\n", self.status, self.reason).into_bytes();
        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Décode un corps `application/x-www-form-urlencoded`. Les valeurs sont effacées à la
/// libération (elles peuvent contenir le mot de passe). `+` est décodé en espace.
pub(crate) fn parse_form(body: &[u8]) -> Vec<(String, Zeroizing<Vec<u8>>)> {
    body.split(|&b| b == b'&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = match kv.iter().position(|&b| b == b'=') {
                Some(i) => (&kv[..i], &kv[i + 1..]),
                None => (kv, &[][..]),
            };
            let key = String::from_utf8_lossy(&percent_decode(k)).into_owned();
            (key, Zeroizing::new(percent_decode(v)))
        })
        .collect()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Décodage `%XX` tolérant (une séquence invalide est conservée telle quelle).
pub(crate) fn percent_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' if i + 2 < s.len() => match (hex_val(s[i + 1]), hex_val(s[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

/// Comparaison en temps indépendant du contenu (longueurs exceptées).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_vector_password() {
        let form =
            parse_form(b"username=jdoe&credential=S3cr3t%21%26%3D%20%C3%A9&realm=staff&ajax=1");
        let get = |k: &str| {
            form.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.to_vec())
                .unwrap()
        };
        assert_eq!(get("username"), b"jdoe");
        assert_eq!(get("credential"), "S3cr3t!&= é".as_bytes());
        assert_eq!(get("realm"), b"staff");
        assert_eq!(get("ajax"), b"1");
    }

    #[test]
    fn percent_decode_edge_cases() {
        assert_eq!(percent_decode(b"%"), b"%");
        assert_eq!(percent_decode(b"%4"), b"%4");
        assert_eq!(percent_decode(b"%41"), b"A");
        assert_eq!(percent_decode(b"%zz"), b"%zz");
        assert_eq!(percent_decode(b"a+b"), b"a b");
        assert_eq!(percent_decode(b"x%41"), b"xA");
    }

    #[test]
    fn consume_keeps_tail() {
        let mut v = b"abcdef".to_vec();
        consume(&mut v, 4);
        assert_eq!(v, b"ef");
    }

    #[test]
    fn partial_then_complete() {
        assert!(
            try_parse(b"GET / HTTP/1.1\r\nHost: x\r\n")
                .unwrap()
                .is_none()
        );
        let raw = b"POST /a?b=1 HTTP/1.1\r\nContent-Length: 3\r\n\r\nxyzTAIL";
        let (req, used) = try_parse(raw).unwrap().unwrap();
        assert_eq!(req.path, "/a");
        assert_eq!(req.query.as_deref(), Some("b=1"));
        assert_eq!(&req.body[..], b"xyz");
        assert_eq!(&raw[used..], b"TAIL");
    }
}
