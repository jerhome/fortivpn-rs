//! Interprétation de la réponse à `POST /remote/logincheck` (`docs/protocol.md` §4.3)
//! et cookie de session `SVPNCOOKIE`.

use std::fmt;

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

/// Type de second facteur demandé par la passerelle (non supporté dans le MVP).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecondFactor {
    /// Réponse `ret=2,...,tokeninfo=<t>,chal_msg=<m>` sans cookie (§4.3 étape 5).
    TokenInfo {
        /// Valeur de `tokeninfo` (vide = OTP, `ftm_push` = push FortiToken Mobile).
        tokeninfo: String,
        /// Message de challenge (`chal_msg`), s'il est présent.
        challenge: Option<String>,
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
        });
    }
    AuthOutcome::NoCookie
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
            }) => {
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
}
