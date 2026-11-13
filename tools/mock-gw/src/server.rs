//! Boucle d'acceptation et traitement HTTP de chaque connexion TLS.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use zeroize::Zeroizing;

use crate::config::TunnelConfig;
use crate::http::{Request, Response, ct_eq, parse_form, read_request};
use crate::log::{AuthOutcome, CookieCheck, LoggedRequest, LoggedResponse, REDACTED, RequestLog};
use crate::tunnel::{TunnelContext, TunnelHandler, TunnelStream};
use crate::{DropPoint, ExpiredSession, LoginFailure, Options, Scenario};

const EXPIRED_COOKIE: &str =
    "SVPNCOOKIE=; path=/; expires=Sun, 11 Mar 1984 12:00:00 GMT; secure; httponly";

/// État partagé par toutes les connexions.
pub(crate) struct Shared {
    opts: Options,
    config: Arc<TunnelConfig>,
    handler: Arc<dyn TunnelHandler>,
    log: RequestLog,
    /// Sessions ouvertes : cookie -> utilisateur.
    sessions: Mutex<Vec<(Zeroizing<String>, String)>>,
    next_conn: AtomicU64,
}

impl Shared {
    pub(crate) fn new(
        opts: Options,
        config: Arc<TunnelConfig>,
        handler: Arc<dyn TunnelHandler>,
        log: RequestLog,
    ) -> Self {
        Self {
            opts,
            config,
            handler,
            log,
            sessions: Mutex::new(Vec::new()),
            next_conn: AtomicU64::new(1),
        }
    }

    fn sessions(&self) -> MutexGuard<'_, Vec<(Zeroizing<String>, String)>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Vérifie le cookie ; renvoie l'utilisateur de la session si valide.
    fn check_cookie(&self, req: &Request) -> (CookieCheck, Option<String>) {
        match req.svpn_cookie() {
            None => (CookieCheck::Absent, None),
            Some("") => (CookieCheck::Empty, None),
            Some(c) => match self
                .sessions()
                .iter()
                .find(|(k, _)| ct_eq(k.as_bytes(), c.as_bytes()))
            {
                Some((_, user)) => (CookieCheck::Valid, Some(user.clone())),
                None => (CookieCheck::Rejected, None),
            },
        }
    }

    fn new_cookie(&self) -> Zeroizing<String> {
        if let Some(c) = &self.opts.fixed_cookie {
            return c.clone();
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut raw[..])
            .expect("générateur aléatoire système indisponible");
        Zeroizing::new(crate::tls::hex_lower(&raw[..]))
    }
}

pub(crate) async fn accept_loop(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let acceptor = TlsAcceptor::from(tls);
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((tcp, peer)) => {
                    let conn_id = shared.next_conn.fetch_add(1, Ordering::Relaxed);
                    conns.spawn(handle_conn(
                        Arc::clone(&shared),
                        acceptor.clone(),
                        tcp,
                        peer,
                        conn_id,
                    ));
                }
                Err(e) => tracing::warn!(error = %e, "mock-gw: accept a échoué"),
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    drop(listener);
    conns.shutdown().await;
}

/// Action décidée pour une requête.
enum Action {
    Respond(Response),
    RespondThenDrop(Response),
    Drop,
    Tunnel(TunnelContext),
}

async fn handle_conn(
    shared: Arc<Shared>,
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    peer: SocketAddr,
    conn_id: u64,
) {
    let _ = tcp.set_nodelay(true);
    let io_timeout = shared.opts.io_timeout;
    let mut tls: TlsStream<TcpStream> = match timeout(io_timeout, acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!(conn_id, error = %e, "mock-gw: handshake TLS échoué");
            return;
        }
        Err(_) => {
            tracing::debug!(conn_id, "mock-gw: handshake TLS expiré");
            return;
        }
    };
    let mut buf = Vec::new();
    loop {
        let req = match timeout(io_timeout, read_request(&mut tls, &mut buf)).await {
            Ok(Ok(Some(r))) => r,
            // EOF entre deux requêtes ou délai dépassé.
            Ok(Ok(None)) | Err(_) => break,
            Ok(Err(e)) => {
                tracing::debug!(conn_id, error = %e, "mock-gw: requête illisible");
                if e.kind() == std::io::ErrorKind::InvalidData {
                    let resp = Response::new(400, "Bad Request").header("Connection", "close");
                    let _ = tls.write_all(&resp.to_bytes()).await;
                    break;
                }
                return;
            }
        };
        let close = req.wants_close();
        match route(&shared, conn_id, peer, &req) {
            Action::Respond(resp) => {
                let resp = if close {
                    resp.header("Connection", "close")
                } else {
                    resp
                };
                if tls.write_all(&resp.to_bytes()).await.is_err() || tls.flush().await.is_err() {
                    return;
                }
                if close {
                    break;
                }
            }
            Action::RespondThenDrop(resp) => {
                let _ = tls.write_all(&resp.to_bytes()).await;
                let _ = tls.flush().await;
                return;
            }
            Action::Drop => return,
            Action::Tunnel(ctx) => {
                drop(req);
                let pending = std::mem::take(&mut buf);
                let stream = TunnelStream::new(tls, pending);
                shared.handler.handle(stream, ctx).await;
                return;
            }
        }
    }
    let _ = tls.shutdown().await;
}

/// Construit l'entrée de journal (secrets masqués).
fn log_entry(conn_id: u64, req: &Request, cookie: CookieCheck) -> LoggedRequest {
    let headers = req
        .headers
        .iter()
        .map(|(k, v)| {
            if k.eq_ignore_ascii_case("cookie") && !v.trim().is_empty() {
                (k.clone(), redact_cookie_header(v))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    let is_form = req.method == "POST";
    let form = if is_form {
        parse_form(&req.body)
            .into_iter()
            .map(|(k, v)| {
                let shown = if is_secret_field(&k) {
                    REDACTED.to_owned()
                } else {
                    String::from_utf8_lossy(&v).into_owned()
                };
                (k, shown)
            })
            .collect()
    } else {
        Vec::new()
    };
    LoggedRequest {
        conn_id,
        method: req.method.clone(),
        target: req.target.clone(),
        path: req.path.clone(),
        headers,
        cookie,
        form,
        auth: None,
        response: LoggedResponse::Status(0),
    }
}

fn is_secret_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "credential" | "password" | "passwd" | "code" | "code2" | "magic"
    )
}

/// `a=1; SVPNCOOKIE=secret` -> `a=1; SVPNCOOKIE=<redacted>`.
fn redact_cookie_header(v: &str) -> String {
    v.split(';')
        .map(|c| {
            let c = c.trim();
            match c.split_once('=') {
                Some((name, val)) if !val.is_empty() => format!("{name}={REDACTED}"),
                _ => c.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn record(shared: &Shared, mut entry: LoggedRequest, action: &Action) {
    entry.response = match action {
        Action::Respond(r) => LoggedResponse::Status(r.status),
        Action::RespondThenDrop(r) => LoggedResponse::StatusThenDropped(r.status),
        Action::Drop => LoggedResponse::Dropped,
        Action::Tunnel(_) => LoggedResponse::TunnelOpened,
    };
    tracing::debug!(
        conn_id = entry.conn_id,
        method = %entry.method,
        path = %entry.path,
        response = ?entry.response,
        "mock-gw: requête"
    );
    shared.log.push(entry);
}

fn route(shared: &Shared, conn_id: u64, peer: SocketAddr, req: &Request) -> Action {
    let (cookie, user) = shared.check_cookie(req);
    let mut entry = log_entry(conn_id, req, cookie);
    let action = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/remote/login") => Action::Respond(login_page()),
        ("POST", "/remote/logincheck") => {
            let (outcome, action) = logincheck(shared, req);
            entry.auth = Some(outcome);
            action
        }
        (_, "/remote/logincheck") => Action::Respond(method_not_allowed()),
        ("GET", "/remote/index" | "/remote/fortisslvpn") => match user {
            Some(_) if drop_at(shared, DropPoint::BeforeConfig) => Action::Drop,
            Some(_) => Action::Respond(allocation_page()),
            None => Action::Respond(redirect_to_login()),
        },
        ("GET", "/remote/fortisslvpn_xml") => match user {
            Some(_) if drop_at(shared, DropPoint::BeforeConfig) => Action::Drop,
            Some(_) => Action::Respond(config_xml(shared, req)),
            None => Action::Respond(expired(shared.opts.expired_session)),
        },
        ("GET", "/remote/sslvpn-tunnel") => match user {
            Some(_) if drop_at(shared, DropPoint::BeforeTunnel) => Action::Drop,
            Some(username) => Action::Tunnel(TunnelContext {
                conn_id,
                peer,
                username,
                config: Arc::clone(&shared.config),
            }),
            None => Action::Respond(tunnel_forbidden()),
        },
        ("GET", "/remote/logout") => {
            if let Some(c) = req.svpn_cookie() {
                shared
                    .sessions()
                    .retain(|(k, _)| !ct_eq(k.as_bytes(), c.as_bytes()));
            }
            Action::Respond(logout())
        }
        _ => Action::Respond(
            Response::new(404, "Not Found")
                .header("Content-Type", "text/html")
                .body("<html><body>Not Found</body></html>"),
        ),
    };
    record(shared, entry, &action);
    action
}

fn drop_at(shared: &Shared, point: DropPoint) -> bool {
    shared.opts.scenario == Scenario::DropAfterAuth(point)
}

fn logincheck(shared: &Shared, req: &Request) -> (AuthOutcome, Action) {
    let form = parse_form(&req.body);
    let field = |name: &str| form.iter().find(|(k, _)| k == name).map(|(_, v)| &v[..]);
    let opts = &shared.opts;
    // 2e requête d'un challenge 2FA (§13) : pas de `credential`, mais `code`/`ftmpush`.
    let is_second = opts.scenario == Scenario::SecondFactorRequired
        && (field("code").is_some() || field("ftmpush").is_some());
    if is_second {
        let user_ok = field("username").is_some_and(|u| ct_eq(u, opts.username.as_bytes()));
        let state_ok = field("reqid") == Some(&b"12345678"[..])
            && (field("ftmpush").is_some() || field("magic") == Some(&b"1-23456789"[..]));
        let code_ok = match (&opts.otp, field("code")) {
            (Some(otp), Some(c)) => ct_eq(c, otp.as_bytes()),
            (Some(_), None) => field("ftmpush").is_some(),
            (None, _) => false,
        };
        if user_ok && state_ok && code_ok {
            return accepted(shared);
        }
        let resp = Response::new(200, "OK")
            .header("Content-Type", "text/plain")
            .body("ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied&lang=en");
        return (AuthOutcome::Rejected, Action::Respond(resp));
    }
    let user_ok = field("username").is_some_and(|u| ct_eq(u, opts.username.as_bytes()));
    let pass_ok = field("credential").is_some_and(|p| ct_eq(p, opts.password.as_bytes()));
    let realm_ok = match &opts.realm {
        None => true,
        Some(r) => field("realm").is_some_and(|v| v == r.as_bytes()),
    };
    // `form` (mot de passe décodé) est effacé à la sortie de la fonction (Zeroizing).
    if !(user_ok && pass_ok && realm_ok) {
        let resp = match opts.login_failure {
            LoginFailure::Ret0 => Response::new(200, "OK")
                .header("Set-Cookie", EXPIRED_COOKIE)
                .header("Content-Type", "text/plain")
                .body("ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied&lang=en"),
            LoginFailure::Status405 => method_not_allowed(),
        };
        return (AuthOutcome::Rejected, Action::Respond(resp));
    }
    if opts.scenario == Scenario::SecondFactorRequired {
        let resp = Response::new(200, "OK")
            .header("Content-Type", "text/plain")
            .body(
                "ret=2,reqid=12345678,polid=1-1-87654321,grp=staff-grp,portal=full-access,\
                 magic=1-23456789,tokeninfo=,chal_msg=Please enter your token code",
            );
        return (AuthOutcome::SecondFactorRequested, Action::Respond(resp));
    }
    accepted(shared)
}

fn accepted(shared: &Shared) -> (AuthOutcome, Action) {
    let opts = &shared.opts;
    let cookie = shared.new_cookie();
    let resp = Response::new(200, "OK")
        .header(
            "Set-Cookie",
            format!("SVPNCOOKIE={}; path=/; secure; httponly", cookie.as_str()),
        )
        .header("Content-Type", "text/plain")
        .header("X-Frame-Options", "SAMEORIGIN")
        .body("ret=1,redir=/remote/fortisslvpn_xml");
    if opts.scenario != Scenario::CookieRejected {
        shared.sessions().push((cookie, opts.username.clone()));
    }
    let action = if drop_at(shared, DropPoint::AfterLoginResponse) {
        Action::RespondThenDrop(resp)
    } else {
        Action::Respond(resp)
    };
    (AuthOutcome::Accepted, action)
}

fn config_xml(shared: &Shared, req: &Request) -> Response {
    let dual = req.has_query_param("dual_stack", "1");
    let mut resp = Response::new(200, "OK").header("Content-Type", "text/xml");
    if let Some(c) = req.svpn_cookie() {
        resp = resp.header(
            "Set-Cookie",
            format!("SVPNCOOKIE={c}; path=/; secure; httponly"),
        );
    }
    resp.body(shared.config.to_xml(dual))
}

fn login_page() -> Response {
    Response::new(200, "OK")
        .header("Content-Type", "text/html")
        .body(
            "<html><body><form action=\"/remote/logincheck\" method=\"post\">\
             <input name=\"username\"/><input name=\"credential\" type=\"password\"/>\
             </form></body></html>",
        )
}

fn allocation_page() -> Response {
    Response::new(200, "OK")
        .header("Content-Type", "text/html")
        .body("<html><body>SSL-VPN portal</body></html>")
}

fn redirect_to_login() -> Response {
    Response::new(302, "Found")
        .header("Location", "/remote/login")
        .header("Content-Type", "text/html")
}

fn method_not_allowed() -> Response {
    Response::new(405, "Method Not Allowed")
        .header("Content-Type", "text/html")
        .body("<html><body>Method Not Allowed</body></html>")
}

fn expired(mode: ExpiredSession) -> Response {
    match mode {
        ExpiredSession::RedirectToLogin => redirect_to_login(),
        ExpiredSession::Forbidden => {
            Response::new(403, "Forbidden").header("Content-Type", "text/html")
        }
        ExpiredSession::Unauthorized => {
            Response::new(401, "Unauthorized").header("Content-Type", "text/html")
        }
    }
}

fn tunnel_forbidden() -> Response {
    Response::new(403, "Forbidden").header("Content-Type", "text/html")
}

fn logout() -> Response {
    Response::new(200, "OK")
        .header("Set-Cookie", EXPIRED_COOKIE)
        .header("Content-Type", "text/html")
        .body("<html><body>Logout successful</body></html>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_header_is_redacted() {
        assert_eq!(
            redact_cookie_header("SVPNCOOKIE=abc; other=1;empty="),
            "SVPNCOOKIE=<redacted>; other=<redacted>; empty="
        );
    }
}
