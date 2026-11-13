//! Point d'entrée de la fausse passerelle FortiGate (`mock-gw`).
//!
//! Usage : `mock-gw [--listen ADDR] [--user NOM] [--realm REALM] [--scenario S]
//! [--login-failure ret0|405] [--config split|full|dual-stack] [--cookie VALEUR]
//! [--ppp] [--icmp-target ADDR] [--ipcp-empty] [--ppp-fault F] [--fault-delay SECS]`
//!
//! Le mot de passe attendu est lu dans `MOCK_GW_PASSWORD` (défaut : mot de passe fictif des
//! vecteurs) pour ne pas apparaître dans la ligne de commande.
//! Scénarios : `nominal`, `2fa`, `cookie-rejected`, `drop-after-login`,
//! `drop-before-config`, `drop-before-tunnel`.
//!
//! `--ppp` sert le tunnel avec le pair PPP ([`mock_gw::PppPeer`]) au lieu de le fermer ;
//! `--icmp-target`, `--ipcp-empty`, `--ppp-fault` l'impliquent. Les ouvertures IPCP et
//! fins de session sont affichées sur la sortie standard (`ppp: ...`).
//! Pannes : `ignore-echo`, `terminate`, `abort`, `bad-magic`, `bad-length`, `too-small`,
//! `http-403`, `ipcp-loop` ; celles qui ont un instant de déclenchement surviennent à
//! l'ouverture d'IPCP, ou `--fault-delay` secondes après.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use mock_gw::{
    DEFAULT_PASSWORD, DEFAULT_USERNAME, DropPoint, FaultTrigger, GatewayIpcpRequest, LoginFailure,
    MalformedFrame, MockGateway, MockGatewayBuilder, PppFault, PppObserver, PppPeer, PppPeerConfig,
    Scenario, TunnelConfig,
};

fn usage() -> &'static str {
    "usage : mock-gw [--listen ADDR] [--user NOM] [--realm REALM] [--scenario S] \
     [--login-failure ret0|405] [--config split|full|dual-stack] [--cookie VALEUR] \
     [--ppp] [--icmp-target ADDR] [--ipcp-empty] [--ppp-fault F] [--fault-delay SECS]\n\
     scénarios : nominal, 2fa, cookie-rejected, drop-after-login, drop-before-config, \
     drop-before-tunnel\n\
     pannes PPP : ignore-echo, terminate, abort, bad-magic, bad-length, too-small, \
     http-403, ipcp-loop\n\
     mot de passe attendu : variable MOCK_GW_PASSWORD"
}

fn parse_scenario(s: &str) -> Option<Scenario> {
    Some(match s {
        "nominal" => Scenario::Nominal,
        "2fa" => Scenario::SecondFactorRequired,
        "cookie-rejected" => Scenario::CookieRejected,
        "drop-after-login" => Scenario::DropAfterAuth(DropPoint::AfterLoginResponse),
        "drop-before-config" => Scenario::DropAfterAuth(DropPoint::BeforeConfig),
        "drop-before-tunnel" => Scenario::DropAfterAuth(DropPoint::BeforeTunnel),
        _ => return None,
    })
}

/// Options PPP de la ligne de commande.
#[derive(Debug, Default)]
struct PppArgs {
    enabled: bool,
    icmp_target: Option<Ipv4Addr>,
    ipcp_empty: bool,
    fault: Option<String>,
    fault_delay: Option<Duration>,
}

impl PppArgs {
    fn peer(&self) -> Option<PppPeer> {
        let when = match self.fault_delay {
            Some(d) if !d.is_zero() => FaultTrigger::AfterIpcpUp(d),
            _ => FaultTrigger::IpcpUp,
        };
        let malformed = |kind| PppFault::MalformedFrame { kind, when };
        let fault = match self.fault.as_deref() {
            None => PppFault::None,
            Some("ignore-echo") => PppFault::IgnoreEchoRequests,
            Some("terminate") => PppFault::GatewayTerminate { when },
            Some("abort") => PppFault::AbortTls { when },
            Some("bad-magic") => malformed(MalformedFrame::BadMagic),
            Some("bad-length") => malformed(MalformedFrame::InconsistentLengths),
            Some("too-small") => malformed(MalformedFrame::TotalTooSmall),
            Some("http-403") => PppFault::HttpInsteadOfPpp { status: 403 },
            Some("ipcp-loop") => PppFault::IpcpNeverConverges,
            Some(_) => return None,
        };
        Some(PppPeer::new(PppPeerConfig {
            icmp_target: self.icmp_target,
            ipcp_request: if self.ipcp_empty {
                GatewayIpcpRequest::Empty
            } else {
                GatewayIpcpRequest::default()
            },
            fault,
            ..PppPeerConfig::default()
        }))
    }
}

/// Applique une option `--nom valeur` au builder ; `None` si invalide.
fn apply(
    builder: MockGatewayBuilder,
    opt: &str,
    value: String,
    listen: &mut SocketAddr,
    user: &mut String,
    ppp: &mut PppArgs,
) -> Option<MockGatewayBuilder> {
    Some(match opt {
        "--listen" => {
            *listen = value.parse().ok()?;
            builder
        }
        "--user" => {
            *user = value;
            builder
        }
        "--realm" => builder.realm(Some(value)),
        "--scenario" => builder.scenario(parse_scenario(&value)?),
        "--login-failure" => builder.login_failure(match value.as_str() {
            "ret0" => LoginFailure::Ret0,
            "405" => LoginFailure::Status405,
            _ => return None,
        }),
        "--config" => builder.tunnel_config(match value.as_str() {
            "split" => TunnelConfig::vector_split(),
            "full" => TunnelConfig::vector_full_tunnel(),
            "dual-stack" => TunnelConfig::vector_dual_stack(),
            _ => return None,
        }),
        "--cookie" => builder.session_cookie(value),
        "--icmp-target" => {
            ppp.enabled = true;
            ppp.icmp_target = Some(value.parse().ok()?);
            builder
        }
        "--ppp-fault" => {
            ppp.enabled = true;
            ppp.fault = Some(value);
            builder
        }
        "--fault-delay" => {
            ppp.fault_delay = Some(Duration::from_secs_f64(
                value
                    .parse::<f64>()
                    .ok()
                    .filter(|s| (0.0..1e6).contains(s))?,
            ));
            builder
        }
        _ => return None,
    })
}

/// Affiche les ouvertures IPCP et fins de session (aucun secret dans l'état PPP).
async fn report(mut obs: PppObserver) {
    let mut shown_up = None;
    let mut shown_end = None;
    while let Some(st) = obs.changed().await {
        if let Some(up) = &st.ipcp {
            if shown_up != Some(up.conn_id) {
                shown_up = Some(up.conn_id);
                println!(
                    "ppp: conn {} IPCP up client={} dns={:?} passerelle={:?}",
                    up.conn_id, up.client_ip, up.dns, up.gateway_ip
                );
            }
        }
        if let (Some(end), Some(conn)) = (&st.end, st.conn_id) {
            if shown_end != Some(conn) {
                shown_end = Some(conn);
                println!("ppp: conn {conn} fin : {end:?}");
            }
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut listen: SocketAddr = ([127, 0, 0, 1], 10443).into();
    let mut user = DEFAULT_USERNAME.to_owned();
    let mut ppp = PppArgs::default();
    let mut builder = MockGateway::builder();
    let mut args = std::env::args().skip(1);
    while let Some(opt) = args.next() {
        match opt.as_str() {
            "-h" | "--help" => {
                println!("{}", usage());
                return ExitCode::SUCCESS;
            }
            "--ppp" => {
                ppp.enabled = true;
                continue;
            }
            "--ipcp-empty" => {
                ppp.enabled = true;
                ppp.ipcp_empty = true;
                continue;
            }
            _ => {}
        }
        let Some(value) = args.next() else {
            eprintln!("valeur manquante pour {opt}\n{}", usage());
            return ExitCode::from(2);
        };
        let Some(next) = apply(builder, &opt, value, &mut listen, &mut user, &mut ppp) else {
            eprintln!("argument invalide : {opt}\n{}", usage());
            return ExitCode::from(2);
        };
        builder = next;
    }
    if ppp.enabled {
        let Some(peer) = ppp.peer() else {
            eprintln!("argument invalide : --ppp-fault\n{}", usage());
            return ExitCode::from(2);
        };
        tokio::spawn(report(peer.observer()));
        builder = builder.tunnel_handler(peer);
    }
    let password =
        std::env::var("MOCK_GW_PASSWORD").unwrap_or_else(|_| DEFAULT_PASSWORD.to_owned());
    let gw = match builder
        .credentials(user, password)
        .listen(listen)
        .start()
        .await
    {
        Ok(gw) => gw,
        Err(e) => {
            eprintln!("mock-gw : démarrage impossible : {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "mock-gw {} écoute sur {}",
        env!("CARGO_PKG_VERSION"),
        gw.addr()
    );
    println!("trusted-cert (sha256) : {}", gw.cert().sha256_hex());
    if ppp.enabled {
        println!("ppp : pair PPP actif");
    }
    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("mock-gw : attente de Ctrl-C impossible");
    }
    gw.shutdown().await;
    ExitCode::SUCCESS
}
