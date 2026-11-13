//! Interprétation de la réponse à `POST /remote/logincheck` (`docs/protocol.md` §4.3)
//! et cookie de session `SVPNCOOKIE`.

use std::fmt::{self, Write as _};

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::http::HttpResponse;

/// Nom du cookie de session.
pub const COOKIE_NAME: &str = "SVPNCOOKIE";

/// Longueur maximale de `SVPNCOOKIE=<valeur>` (openfortivpn, §4.3 étape 4).
pub const MAX_COOKIE_LEN: usize = 4096;

/// Cookie invalide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CookieError {
    /// Valeur vide (la passerelle efface le cookie : échec).
    #[error("cookie de session vide")]
    Empty,
    /// Valeur trop longue.
    #[error("cookie de session trop long")]
    TooLong,
    /// Caractère interdit (contrôle, espace, `;`, non-ASCII).
    #[error("cookie de session : caractère invalide")]
    InvalidChar,
}

/// Valeur du cookie `SVPNCOOKIE` (sans le préfixe `SVPNCOOKIE=`).
///
/// Effacée de la mémoire à la libération, jamais affichée par `Debug`. La valeur est
/// validée (ASCII visible sans `;`) : elle peut être recopiée telle quelle dans un
/// en-tête `Cookie:` sans risque d'injection.
#[derive(Clone)]
pub struct SessionCookie(SecretString);

impl SessionCookie {
    /// Valide et enveloppe une valeur de cookie.
    pub fn new(value: &str) -> Result<Self, CookieError> {
        if value.is_empty() {
            return Err(CookieError::Empty);
        }
        if value.len() + COOKIE_NAME.len() + 1 > MAX_COOKIE_LEN {
            return Err(CookieError::TooLong);
        }
        if !value
            .bytes()
            .all(|b| (0x21..0x7f).contains(&b) && b != b';')
        {
            return Err(CookieError::InvalidChar);
        }
        Ok(Self(SecretString::from(value)))
    }

    /// Valeur brute (à ne jamais journaliser).
    pub fn expose_value(&self) -> &str {
        self.0.expose_secret()
    }

    /// Chaîne complète `SVPNCOOKIE=<valeur>` (à ne jamais journaliser).
    pub fn header_value(&self) -> Zeroizing<String> {
        let v = self.expose_value();
        let mut s = Zeroizing::new(String::with_capacity(COOKIE_NAME.len() + 1 + v.len()));
        s.push_str(COOKIE_NAME);
        s.push('=');
        s.push_str(v);
        s
    }
}

impl fmt::Debug for SessionCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionCookie([REDACTED])")
    }
}

/// Valeur de `tokeninfo` désignant une notification push FortiToken Mobile.
pub const TOKENINFO_FTM_PUSH: &str = "ftm_push";

/// Champs de la réponse `ret=2` à renvoyer tels quels dans la 2e requête `logincheck`
/// (§13). Valeurs fournies par la passerelle (non secrètes), vides si absentes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChallengeState {
    /// `reqid`.
    pub reqid: String,
    /// `polid`.
    pub polid: String,
    /// `grp`.
    pub grp: String,
    /// `portal`.
    pub portal: String,
    /// `peer`.
    pub peer: String,
    /// `magic`.
    pub magic: String,
}

impl ChallengeState {
    fn from_body(body: &[u8]) -> Self {
        let get = |k: &[u8]| {
            token_value(body, k)
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_default()
        };
        Self {
            reqid: get(b"reqid="),
            polid: get(b"polid="),
            grp: get(b"grp="),
            portal: get(b"portal="),
            peer: get(b"peer="),
            magic: get(b"magic="),
        }
    }
}

/// Type de second facteur demandé par la passerelle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecondFactor {
    /// Réponse `ret=2,...,tokeninfo=<t>,chal_msg=<m>` sans cookie (§4.3 étape 5).
    TokenInfo {
        /// Valeur de `tokeninfo` (vide = OTP, `ftm_push` = push FortiToken Mobile).
        tokeninfo: String,
        /// Message de challenge (`chal_msg`), s'il est présent.
        challenge: Option<String>,
        /// Champs à renvoyer dans la 2e requête.
        state: ChallengeState,
    },
    /// Statut 401 avec formulaire HTML d'OTP (§4.3 étape 2).
    HtmlForm,
}

/// Résultat de l'authentification, selon la table de décision §4.3 (dans cet ordre).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthOutcome {
    /// Cookie `SVPNCOOKIE` non vide obtenu.
    Success {
        /// Cookie de session.
        cookie: SessionCookie,
    },
    /// Identifiants refusés : marqueur `permission_denied`, `ret=0` ou statut 405.
    BadCredentials,
    /// `ret=6` : challenge non supporté.
    UnsupportedChallenge,
    /// Second facteur exigé (401, ou `tokeninfo=` sans cookie).
    TwoFactorRequired(SecondFactor),
    /// Statut 3xx (pas de suivi automatique, §3.2).
    Redirect {
        /// Code de statut.
        status: u16,
        /// En-tête `Location` éventuel.
        location: Option<String>,
    },
    /// Autre statut ≠ 200.
    HttpStatus(u16),
    /// Statut 200 sans cookie ni `tokeninfo`.
    NoCookie,
    /// `redir=` vers un contrôle de conformité du poste (host-check), non pris en charge.
    HostCheckRequired,
    /// `redir=` vers un autre realm/portail : le realm doit être configuré.
    RealmRequired,
    /// `SVPNCOOKIE` non vide mais invalide (caractères interdits, trop long).
    InvalidCookie(CookieError),
}

/// Découpe sur `&`, `,`, CR, LF (openfortivpn, §4.3 étape 1).
fn tokens(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|&b| matches!(b, b'&' | b',' | b'\r' | b'\n'))
}

/// Valeur du premier jeton `key=` de `data`.
fn token_value<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    tokens(data).find_map(|t| t.strip_prefix(key))
}

/// Valeur de `ret=` : premier jeton commençant par `ret=` dans la réponse **entière**
/// (en-têtes puis corps), comme openfortivpn.
pub fn ret_code(response: &HttpResponse) -> Option<&[u8]> {
    token_value(response.raw_head(), b"ret=").or_else(|| token_value(response.body(), b"ret="))
}

/// Cherche `SVPNCOOKIE` dans **tous** les `Set-Cookie` (§4.3 étape 4, RECOMMANDÉ) et
/// renvoie la première valeur non vide. Le nom du cookie doit être exactement
/// `SVPNCOOKIE` (pas de recherche de sous-chaîne). `Ok(None)` si aucune valeur non vide.
pub fn extract_cookie(response: &HttpResponse) -> Result<Option<SessionCookie>, CookieError> {
    for value in response.header_values("set-cookie") {
        let pair = value.split(|&b| b == b';').next().unwrap_or_default();
        let Some(eq) = pair.iter().position(|&b| b == b'=') else {
            continue;
        };
        if pair[..eq].trim_ascii() != COOKIE_NAME.as_bytes() {
            continue;
        }
        let v = pair[eq + 1..].trim_ascii();
        if v.is_empty() {
            continue;
        }
        let v = std::str::from_utf8(v).map_err(|_| CookieError::InvalidChar)?;
        return SessionCookie::new(v).map(Some);
    }
    Ok(None)
}

/// Applique la table de décision §4.3 à la réponse de `logincheck`.
pub fn interpret_logincheck(response: &HttpResponse) -> AuthOutcome {
    if response.is_permission_denied() {
        return AuthOutcome::BadCredentials;
    }
    match ret_code(response) {
        Some(b"0") => return AuthOutcome::BadCredentials,
        Some(b"6") => return AuthOutcome::UnsupportedChallenge,
        _ => {}
    }
    match response.status() {
        200 => {}
        401 => return AuthOutcome::TwoFactorRequired(SecondFactor::HtmlForm),
        405 => return AuthOutcome::BadCredentials,
        s @ 300..=399 => {
            return AuthOutcome::Redirect {
                status: s,
                location: response.location().map(str::to_owned),
            };
        }
        s => return AuthOutcome::HttpStatus(s),
    }
    match extract_cookie(response) {
        Ok(Some(cookie)) => return AuthOutcome::Success { cookie },
        Ok(None) => {}
        Err(e) => return AuthOutcome::InvalidCookie(e),
    }
    if let Some(t) = token_value(response.body(), b"tokeninfo=") {
        let challenge = token_value(response.body(), b"chal_msg=")
            .map(|m| String::from_utf8_lossy(m).into_owned());
        return AuthOutcome::TwoFactorRequired(SecondFactor::TokenInfo {
            tokeninfo: String::from_utf8_lossy(t).into_owned(),
            challenge,
            state: ChallengeState::from_body(response.body()),
        });
    }
    if let Some(redir) = token_value(response.body(), b"redir=") {
        let path = path_only(redir).to_ascii_lowercase();
        let lower = String::from_utf8_lossy(redir).to_ascii_lowercase();
        if path.contains("hostcheck") || path.contains("host_check") || path.contains("host-check")
        {
            return AuthOutcome::HostCheckRequired;
        }
        if path.starts_with("/remote/login") && lower.contains("realm=") {
            return AuthOutcome::RealmRequired;
        }
    }
    if looks_like_login_page(response.body()) {
        return AuthOutcome::BadCredentials;
    }
    AuthOutcome::NoCookie
}

/// Chemin seul (sans `?query` ni `#fragment`), borné, sans caractère de contrôle.
fn path_only(v: &[u8]) -> String {
    let end = v
        .iter()
        .position(|&b| b == b'?' || b == b'#')
        .unwrap_or(v.len());
    String::from_utf8_lossy(&v[..end])
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect()
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

fn looks_like_html(body: &[u8]) -> bool {
    find_ci(body, b"<html").is_some() || find_ci(body, b"<form").is_some()
}

/// Noms des champs `<input name="...">` (borné à 16 noms de 40 caractères).
fn form_field_names(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while out.len() < 16 {
        let Some(i) = find_ci(rest, b"<input") else {
            break;
        };
        rest = &rest[i + 6..];
        let tag_end = rest.iter().position(|&b| b == b'>').unwrap_or(rest.len());
        let tag = &rest[..tag_end];
        if let Some(n) = find_ci(tag, b"name=") {
            let v = &tag[n + 5..];
            let (q, v) = match v.first() {
                Some(&q @ (b'"' | b'\'')) => (Some(q), &v[1..]),
                _ => (None, v),
            };
            let end = v
                .iter()
                .position(|&b| match q {
                    Some(q) => b == q,
                    None => b.is_ascii_whitespace(),
                })
                .unwrap_or(v.len());
            let name: String = String::from_utf8_lossy(&v[..end])
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .take(40)
                .collect();
            if !name.is_empty() {
                out.push(name);
            }
        }
        rest = &rest[tag_end..];
    }
    out
}

fn looks_like_login_page(body: &[u8]) -> bool {
    looks_like_html(body)
        && form_field_names(body).iter().any(|n| {
            let n = n.to_ascii_lowercase();
            n == "credential" || n == "password" || n == "username"
        })
}

fn html_title(body: &[u8]) -> Option<String> {
    let i = find_ci(body, b"<title")?;
    let after = &body[i..];
    let gt = after.iter().position(|&b| b == b'>')?;
    let after = &after[gt + 1..];
    let end = find_ci(after, b"</title").unwrap_or(after.len());
    let t: String = String::from_utf8_lossy(&after[..end])
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    Some(t.trim().to_owned())
}

/// Résumé **assaini** d'une réponse `logincheck`, pour les journaux de débogage :
/// statut, noms des `Set-Cookie`, chemin de `Location`, clés `clé=` du corps, `ret`,
/// chemin de `redir`, présence de `tokeninfo`/`chal_msg`, titre et champs d'un corps HTML.
/// Aucune valeur (cookie, magic, reqid, code…) n'est incluse. Longueur bornée.
pub fn sanitized_summary(response: &HttpResponse) -> String {
    let body = response.body();
    let mut set_cookies = Vec::new();
    for v in response.header_values("set-cookie").take(8) {
        let pair = v.split(|&b| b == b';').next().unwrap_or_default();
        let name = pair.split(|&b| b == b'=').next().unwrap_or_default();
        set_cookies.push(
            String::from_utf8_lossy(name)
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .take(40)
                .collect::<String>(),
        );
    }
    let location = response.location().map(|l| path_only(l.as_bytes()));
    let mut keys: Vec<String> = Vec::new();
    for t in tokens(body) {
        if let Some(eq) = t.iter().position(|&b| b == b'=') {
            let k: String = String::from_utf8_lossy(&t[..eq])
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .take(24)
                .collect();
            if !k.is_empty() && k.len() == eq && !keys.contains(&k) && keys.len() < 24 {
                keys.push(k);
            }
        }
    }
    let ret = token_value(body, b"ret=").map(|v| {
        String::from_utf8_lossy(v)
            .chars()
            .filter(char::is_ascii_digit)
            .take(3)
            .collect::<String>()
    });
    let redir = token_value(body, b"redir=").map(path_only);
    let html = looks_like_html(body);
    let mut s = format!(
        "status={} set_cookie={:?} location={:?} body_len={} keys={:?} ret={:?} redir={:?} tokeninfo={} chal_msg={}",
        response.status(),
        set_cookies,
        location,
        body.len(),
        keys,
        ret,
        redir,
        token_value(body, b"tokeninfo=").is_some(),
        token_value(body, b"chal_msg=").is_some(),
    );
    if html {
        let _ = write!(
            s,
            " html_title={:?} form_fields={:?}",
            html_title(body),
            form_field_names(body)
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::vectors;

    const COOKIE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MTkyMDYzODg0MjAxNw==";

    fn resp(name: &str) -> HttpResponse {
        HttpResponse::from_bytes(&vectors::http(name))
    }

    fn raw(s: &str) -> HttpResponse {
        HttpResponse::from_bytes(s.as_bytes())
    }

    #[test]
    fn success_vector() {
        let r = resp("logincheck_success.http");
        assert_eq!(ret_code(&r), Some(&b"1"[..]));
        match interpret_logincheck(&r) {
            AuthOutcome::Success { cookie } => {
                assert_eq!(cookie.expose_value(), COOKIE);
                assert_eq!(*cookie.header_value(), format!("SVPNCOOKIE={COOKIE}"));
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn failure_vector_ret0() {
        let r = resp("logincheck_failure.http");
        assert_eq!(ret_code(&r), Some(&b"0"[..]));
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::BadCredentials
        ));
        assert!(extract_cookie(&r).unwrap().is_none());
    }

    #[test]
    fn failure_vector_405() {
        let r = resp("logincheck_failure_405.http");
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::BadCredentials
        ));
    }

    #[test]
    fn tokeninfo_vector() {
        let r = resp("logincheck_2fa_tokeninfo.http");
        match interpret_logincheck(&r) {
            AuthOutcome::TwoFactorRequired(SecondFactor::TokenInfo {
                tokeninfo,
                challenge,
                state,
            }) => {
                assert_eq!(state.reqid, "12345678");
                assert_eq!(state.polid, "1-1-87654321");
                assert_eq!(state.grp, "staff-grp");
                assert_eq!(state.portal, "full-access");
                assert_eq!(state.magic, "1-23456789");
                assert_eq!(state.peer, "");
                assert_eq!(tokeninfo, "");
                assert_eq!(challenge.as_deref(), Some("Please enter your token code"));
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn decision_order() {
        // marqueur permission_denied prioritaire même avec cookie.
        let r = raw(
            "HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=abc\r\nContent-Length: 53\r\n\r\n<!--sslvpnerrmsgkey=sslvpn_login_permission_denied-->",
        );
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::BadCredentials
        ));
        // ret=6
        let r =
            raw("HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=abc\r\nContent-Length: 5\r\n\r\nret=6");
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::UnsupportedChallenge
        ));
        // ret=0 prioritaire sur le statut
        let r = raw("HTTP/1.1 500 Err\r\nContent-Length: 5\r\n\r\nret=0");
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::BadCredentials
        ));
        // 401
        let r = raw("HTTP/1.1 401 Authorization Required\r\nContent-Length: 0\r\n\r\n");
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::TwoFactorRequired(SecondFactor::HtmlForm)
        ));
        // 3xx
        let r = raw("HTTP/1.1 302 Found\r\nLocation: /remote/login\r\nContent-Length: 0\r\n\r\n");
        match interpret_logincheck(&r) {
            AuthOutcome::Redirect { status, location } => {
                assert_eq!(status, 302);
                assert_eq!(location.as_deref(), Some("/remote/login"));
            }
            o => panic!("{o:?}"),
        }
        // autre statut
        let r = raw("HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n");
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::HttpStatus(503)
        ));
        // 200 sans rien
        let r = raw("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nret=1");
        assert!(matches!(interpret_logincheck(&r), AuthOutcome::NoCookie));
        // ret absent mais cookie -> succès ; ret=2 sans tokeninfo -> continue
        let r =
            raw("HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=abc\r\nContent-Length: 5\r\n\r\nret=2");
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::Success { .. }
        ));
    }

    #[test]
    fn ret_token_found_in_headers_first() {
        let r = raw(
            "HTTP/1.1 200 OK\r\nX-Info: a,ret=0\r\nSet-Cookie: SVPNCOOKIE=abc\r\nContent-Length: 5\r\n\r\nret=1",
        );
        assert_eq!(ret_code(&r), Some(&b"0"[..]));
    }

    #[test]
    fn scans_all_set_cookie_headers() {
        let r = raw(
            "HTTP/1.1 200 OK\r\nSet-Cookie: OTHER=1; path=/\r\nSet-Cookie: SVPNCOOKIE=; path=/\r\nSet-Cookie: XSVPNCOOKIE=bad\r\nSet-Cookie: SVPNCOOKIE=good==; secure\r\nContent-Length: 0\r\n\r\n",
        );
        let c = extract_cookie(&r).unwrap().unwrap();
        assert_eq!(c.expose_value(), "good==");
    }

    #[test]
    fn invalid_cookie_rejected() {
        assert_eq!(
            SessionCookie::new("a b").unwrap_err(),
            CookieError::InvalidChar
        );
        assert_eq!(
            SessionCookie::new("é").unwrap_err(),
            CookieError::InvalidChar
        );
        assert_eq!(SessionCookie::new("").unwrap_err(), CookieError::Empty);
        assert_eq!(
            SessionCookie::new(&"a".repeat(MAX_COOKIE_LEN)).unwrap_err(),
            CookieError::TooLong
        );
        let r = raw("HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=a\tb\r\nContent-Length: 0\r\n\r\n");
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::InvalidCookie(CookieError::InvalidChar)
        ));
    }

    #[test]
    fn cookie_debug_is_redacted() {
        let c = SessionCookie::new(COOKIE).unwrap();
        let o = AuthOutcome::Success { cookie: c };
        let dbg = format!("{o:?}");
        assert!(!dbg.contains(COOKIE));
        assert!(dbg.contains("REDACTED"));
    }

    fn raw_resp(head: &str, body: &str) -> HttpResponse {
        raw(&format!(
            "HTTP/1.1 200 OK\r\n{head}Content-Length: {}\r\n\r\n{body}",
            body.len()
        ))
    }

    #[test]
    fn hostcheck_redir() {
        let r = raw_resp(
            "",
            "ret=1,redir=/remote/hostcheck_install?auth_type=1&magic=SECRETMAGIC",
        );
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::HostCheckRequired
        ));
    }

    #[test]
    fn realm_redir() {
        let r = raw_resp("", "ret=1,redir=/remote/login?realm=corp&lang=fr");
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::RealmRequired
        ));
    }

    #[test]
    fn html_login_page_is_bad_credentials() {
        let r = raw_resp(
            "",
            "<html><head><title>Login</title></head><form><input name=\"username\"><input type=password name='credential'></form></html>",
        );
        assert!(matches!(
            interpret_logincheck(&r),
            AuthOutcome::BadCredentials
        ));
    }

    #[test]
    fn residual_no_cookie() {
        let r = raw_resp("", "ret=1,redir=/remote/index");
        assert!(matches!(interpret_logincheck(&r), AuthOutcome::NoCookie));
    }

    #[test]
    fn summary_has_no_secret() {
        let r = raw_resp(
            "Set-Cookie: SVPNCOOKIE=TOPSECRETCOOKIE; path=/\r\nSet-Cookie: other=ZZZ\r\nLocation: /remote/login?code=SECRETCODE\r\n",
            "ret=2,reqid=SECRETREQID,magic=SECRETMAGIC,redir=/remote/x?magic=SECRETMAGIC,tokeninfo=,chal_msg=Enter SECRETCHAL\n<html><title>Portal</title><input name=\"credential\" value=\"SECRETPW\"></html>",
        );
        let s = sanitized_summary(&r);
        for bad in [
            "TOPSECRET",
            "SECRETCODE",
            "SECRETREQID",
            "SECRETMAGIC",
            "SECRETCHAL",
            "SECRETPW",
            "ZZZ",
        ] {
            assert!(!s.contains(bad), "{bad} dans {s}");
        }
        for ok in [
            "SVPNCOOKIE",
            "reqid",
            "/remote/login",
            "/remote/x",
            "Portal",
            "credential",
            "tokeninfo=true",
        ] {
            assert!(s.contains(ok), "{ok} absent de {s}");
        }
    }
}
