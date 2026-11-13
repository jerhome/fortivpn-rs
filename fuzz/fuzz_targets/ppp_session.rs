//! Séquence arbitraire d'événements appliquée à `PppSession` (horloge monotone).
//!
//! Entrée : `cfg(4) | op…` ; chaque op = `tag` + arguments (voir `Op`). Des ops
//! « assistées » (Ack de notre dernière requête, Configure-Request du pair, grande trame)
//! permettent d'atteindre rapidement les états ouverts.
//!
//! Invariants :
//! - jamais de panic ni de boucle infinie ;
//! - sorties bornées par op (≤ 4 trames, ≤ 2 événements) : pas d'explosion mémoire ;
//! - chaque trame émise est un paquet LCP/IPCP valide, encapsulable (`encode_frame` OK,
//!   ≤ MAX_PPP_LEN) ;
//! - `Down` au plus une fois, puis automate inerte ; `IpcpUp` au plus une fois ;
//!   `Ipv4` seulement entre `IpcpUp` et `Down` ; `is_ip_up()` cohérent (faux dès `close`) ;
//! - après `handle_timeout(now)`, `poll_timeout()` est `None` ou strictement > `now`
//!   (pas de boucle de minuterie active).
#![no_main]

use std::num::NonZeroU32;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use fuzz_common::Cursor;
use libfuzzer_sys::fuzz_target;
use proto::frame::{MAX_PPP_LEN, encode_frame};
use proto::ppp::{Code, ControlPacket, Packet, PppConfig, PppEvent, PppSession, Protocol};

const MAX_OPS: usize = 512;

static DEBUG: OnceLock<bool> = OnceLock::new();
static IGNORE_KNOWN: OnceLock<bool> = OnceLock::new();

/// `FUZZ_DEBUG=1` : trace l'état après chaque op (reproduction d'un crash).
/// `FUZZ_IGNORE_KNOWN=1` : tolère le bug connu des Code-/Protocol-Reject dépassant
/// MAX_PPP_LEN (voir crates/proto/tests/fuzz_regressions.rs) pour explorer au-delà.
fn env_flag(cell: &OnceLock<bool>, name: &str) -> bool {
    *cell.get_or_init(|| std::env::var_os(name).is_some_and(|v| v != "0"))
}

fn config(c: &mut Cursor<'_>) -> PppConfig {
    let flags = c.u8();
    let magic = NonZeroU32::new(0x1a2b_3c4d).unwrap();
    let mut cfg = PppConfig::new(magic);
    if flags & 1 != 0 {
        cfg.mru = c.u16();
    }
    cfg.request_dns = flags & 2 == 0;
    if flags & 4 != 0 {
        cfg.echo_interval = None;
    }
    if flags & 8 != 0 {
        cfg.max_configure = u32::from(c.u8() % 16);
    }
    if flags & 16 != 0 {
        cfg.echo_max_failures = u32::from(c.u8() % 8);
    }
    if flags & 32 != 0 {
        // Intervalles courts mais non nuls.
        cfg.restart_interval = Duration::from_millis(1 + u64::from(c.u8()));
        cfg.terminate_timeout = Duration::from_millis(1 + u64::from(c.u8()));
        if cfg.echo_interval.is_some() {
            cfg.echo_interval = Some(Duration::from_millis(1 + u64::from(c.u8())));
        }
    }
    cfg
}

#[derive(Default)]
struct Model {
    down: bool,
    ipcp_up: bool,
    close_called: bool,
    last_req: [Option<(u8, Bytes)>; 2],
}

fn control_frame(proto: Protocol, code: Code, id: u8, data: &[u8]) -> Bytes {
    ControlPacket::new(code, id, Bytes::copy_from_slice(data))
        .expect("données bornées")
        .to_frame(proto)
}

/// Vide les sorties produites par une op et vérifie les invariants.
fn drain(s: &mut PppSession, m: &mut Model) {
    let mut n = 0;
    while let Some(f) = s.poll_transmit() {
        n += 1;
        assert!(n <= 4, "trop de trames émises pour une seule entrée");
        // `m.down` reflète les ops précédentes : une trame émise dans la même op que le
        // Down (Terminate-Ack) est légitime.
        assert!(!m.down, "trame émise après Down");
        let p = Packet::parse(f.clone()).expect("trame émise illisible");
        let known_bug = matches!(&p, Packet::Lcp(c) | Packet::Ipcp(c)
            if matches!(c.code(), Code::CodeReject | Code::ProtocolReject));
        if !(known_bug && env_flag(&IGNORE_KNOWN, "FUZZ_IGNORE_KNOWN")) {
            assert!(
                f.len() <= MAX_PPP_LEN,
                "trame émise trop longue pour 0x5050 : {} > {MAX_PPP_LEN}",
                f.len()
            );
            let mut w = BytesMut::new();
            encode_frame(&f, &mut w).expect("trame émise non encapsulable");
        }
        match p {
            Packet::Lcp(p) => {
                if p.code() == Code::ConfigureRequest {
                    m.last_req[0] = Some((p.id(), p.data().clone()));
                }
            }
            Packet::Ipcp(p) => {
                if p.code() == Code::ConfigureRequest {
                    m.last_req[1] = Some((p.id(), p.data().clone()));
                }
            }
            other => panic!("protocole inattendu en émission : {other:?}"),
        }
    }
    let mut e = 0;
    while let Some(ev) = s.poll_event() {
        e += 1;
        assert!(e <= 2, "trop d'événements pour une seule entrée");
        assert!(!m.down, "événement après Down");
        match ev {
            PppEvent::Down(_) => m.down = true,
            PppEvent::IpcpUp { .. } => {
                assert!(!m.ipcp_up, "IpcpUp émis deux fois");
                m.ipcp_up = true;
            }
            PppEvent::Ipv4(_) => assert!(m.ipcp_up, "Ipv4 avant IpcpUp"),
        }
    }
    assert_eq!(s.is_closed(), m.down);
    if s.is_ip_up() {
        assert!(m.ipcp_up && !m.down, "is_ip_up sans IpcpUp");
    } else if !m.close_called {
        assert!(!m.ipcp_up || m.down, "IpcpUp sans is_ip_up");
    }
    if m.down {
        assert_eq!(s.poll_timeout(), None);
    }
    let _ = s.mtu();
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    let mut s = PppSession::new(config(&mut c));
    let base = Instant::now();
    let mut now = base;
    let mut m = Model::default();

    for _ in 0..MAX_OPS {
        if c.is_empty() {
            break;
        }
        let tag = c.u8();
        let mut timed = false;
        match tag % 8 {
            // Trame brute.
            0 => {
                let n = usize::from(c.u8());
                let f = Bytes::copy_from_slice(c.take(n));
                s.handle_frame(now, f);
            }
            // Avance de l'horloge (jusqu'à ~65 s × 2) puis handle_timeout.
            1 => {
                now += Duration::from_millis(u64::from(c.u16()) * 2);
                s.handle_timeout(now);
                timed = true;
            }
            // Saut à la prochaine échéance.
            2 => {
                if let Some(t) = s.poll_timeout() {
                    now = now.max(t);
                }
                s.handle_timeout(now);
                timed = true;
            }
            3 => s.open(now),
            4 => {
                m.close_called = true;
                s.close(now);
            }
            // Ack (éventuellement altéré) de notre dernière Configure-Request.
            5 => {
                let arg = c.u8();
                let (proto, idx) = if arg & 1 == 0 {
                    (Protocol::LCP, 0)
                } else {
                    (Protocol::IPCP, 1)
                };
                if let Some((id, opts)) = m.last_req[idx].clone() {
                    let code = match (arg >> 1) % 4 {
                        0 | 1 => Code::ConfigureAck,
                        2 => Code::ConfigureNak,
                        _ => Code::ConfigureReject,
                    };
                    let id = if arg & 0x80 != 0 {
                        id.wrapping_add(1)
                    } else {
                        id
                    };
                    s.handle_frame(now, control_frame(proto, code, id, &opts));
                }
            }
            // Paquet de contrôle du pair (code, id, options arbitraires).
            6 => {
                let arg = c.u8();
                let proto = if arg & 1 == 0 {
                    Protocol::LCP
                } else {
                    Protocol::IPCP
                };
                let code = Code::from(c.u8() % 13);
                let id = c.u8();
                let n = usize::from(c.u8());
                let body = c.take(n).to_vec();
                s.handle_frame(now, control_frame(proto, code, id, &body));
            }
            // Grande trame synthétique (jusqu'à MAX_PPP_LEN), longueur LCP cohérente.
            _ => {
                let proto = c.u16();
                let code = c.u8();
                let len = usize::from(c.u16()).clamp(2, MAX_PPP_LEN);
                let mut f = BytesMut::with_capacity(len);
                f.put_u16(proto);
                let body_len = len - 2;
                if body_len >= 4 {
                    f.put_u8(code);
                    f.put_u8(c.u8());
                    f.put_u16(u16::try_from(body_len).unwrap());
                    f.put_bytes(0xa5, body_len - 4);
                } else {
                    f.put_bytes(code, body_len);
                }
                s.handle_frame(now, f.freeze());
            }
        }
        if env_flag(&DEBUG, "FUZZ_DEBUG") {
            eprintln!("op {tag} -> {s:?}");
        }
        drain(&mut s, &mut m);
        if timed && let Some(t) = s.poll_timeout() {
            assert!(t > now, "échéance déjà passée après handle_timeout");
        }
        assert!(now >= base);
    }
});
