//! Invariants du framing 0x5050 et du PPP vérifiés par `proptest` (story 5.2).
//!
//! Complément stable des cibles `fuzz/` (cargo-fuzz, nightly) : mêmes invariants, exécutés
//! par `cargo test`. Les vecteurs `docs/vectors/*.hex` servent de graines (mutées).

mod common;

use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use proptest::prelude::*;
use proto::frame::{FrameDecoder, FrameError, MAX_PPP_LEN, decode_frame, encode_frame};
use proto::ppp::{
    Code, ConfigOption, ControlPacket, IpcpOption, LcpOption, Packet, PppConfig, PppEvent,
    PppFrame, PppSession, Protocol, encode_options, parse_options,
};

/// Octets `0x5050` des vecteurs valides (hors `err_*`).
fn wire_vectors() -> Vec<Vec<u8>> {
    let mut v: Vec<_> = common::all()
        .into_values()
        .filter(|v| !v.name.starts_with("err_") && !v.name.ends_with("_raw_ip"))
        .map(|v| v.bytes)
        .collect();
    v.sort();
    v
}

/// Trames PPP (sans en-tête) des vecteurs.
fn ppp_vectors() -> Vec<Vec<u8>> {
    wire_vectors()
        .into_iter()
        .filter(|w| w.len() >= 7 && w[2..4] == [0x50, 0x50])
        .map(|w| w[6..].to_vec())
        .collect()
}

/// Vecteur éventuellement muté (octets remplacés, tronqué, prolongé).
fn mutated(seeds: Vec<Vec<u8>>) -> impl Strategy<Value = Vec<u8>> {
    (
        prop::sample::select(seeds),
        prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..4),
        any::<prop::sample::Index>(),
        prop::collection::vec(any::<u8>(), 0..8),
    )
        .prop_map(|(mut v, muts, cut, tail)| {
            if !v.is_empty() {
                for (i, b) in muts {
                    let i = i.index(v.len());
                    v[i] = b;
                }
                let keep = cut.index(v.len() + 1);
                if keep < v.len() && !tail.is_empty() {
                    v.truncate(keep);
                }
            }
            v.extend(tail);
            v
        })
}

fn any_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

/// Décodage de référence (flux complet d'un coup).
fn decode_all(stream: &[u8]) -> (Vec<Bytes>, Option<FrameError>, Vec<u8>) {
    let mut buf = BytesMut::from(stream);
    let mut frames = Vec::new();
    loop {
        match decode_frame(&mut buf) {
            Ok(Some(f)) => frames.push(f),
            Ok(None) => return (frames, None, buf.to_vec()),
            Err(e) => return (frames, Some(e), buf.to_vec()),
        }
    }
}

/// Décodage avec des `push` découpés selon `cuts`.
fn decode_chunked(stream: &[u8], cuts: &[prop::sample::Index]) -> (Vec<Bytes>, Option<FrameError>) {
    let mut points: Vec<usize> = cuts.iter().map(|c| c.index(stream.len() + 1)).collect();
    points.push(0);
    points.push(stream.len());
    points.sort_unstable();
    points.dedup();
    let mut dec = FrameDecoder::new();
    let mut frames = Vec::new();
    for w in points.windows(2) {
        dec.push(&stream[w[0]..w[1]]);
        loop {
            match dec.next_frame() {
                Ok(Some(f)) => frames.push(f),
                Ok(None) => {
                    assert!(dec.buffered().len() < 65535, "tampon non borné");
                    break;
                }
                Err(e) => return (frames, Some(e)),
            }
        }
    }
    (frames, None)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// decode(encode(x)) == x et encode(decode(w)) == w, pour toute trame PPP non vide.
    #[test]
    fn frame_encode_decode_roundtrip(ppp in prop::collection::vec(any::<u8>(), 1..3000)) {
        let mut wire = BytesMut::new();
        encode_frame(&ppp, &mut wire).unwrap();
        prop_assert_eq!(wire.len(), ppp.len() + 6);
        let copy = wire.clone();
        let f = decode_frame(&mut wire).unwrap().unwrap();
        prop_assert_eq!(&f[..], &ppp[..]);
        prop_assert!(wire.is_empty());
        let mut again = BytesMut::new();
        encode_frame(&f, &mut again).unwrap();
        prop_assert_eq!(again, copy);
    }

    /// Suite de trames (vecteurs + aléatoires) suivie d'un reliquat arbitraire :
    /// même résultat quel que soit le découpage des push ; trames + reliquat == flux.
    #[test]
    fn decoder_is_split_invariant(
        frames in prop::collection::vec(
            prop_oneof![
                prop::sample::select(ppp_vectors()),
                prop::collection::vec(any::<u8>(), 1..300),
            ],
            0..6,
        ),
        tail in any_bytes(40),
        cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..20),
    ) {
        let mut stream = BytesMut::new();
        for f in &frames {
            encode_frame(f, &mut stream).unwrap();
        }
        stream.extend_from_slice(&tail);
        let (ref_frames, ref_err, rest) = decode_all(&stream);
        // Toutes les trames encodées sont restituées, dans l'ordre.
        prop_assert!(ref_frames.len() >= frames.len());
        for (a, b) in ref_frames.iter().zip(&frames) {
            prop_assert_eq!(&a[..], &b[..]);
        }
        let consumed: usize = ref_frames.iter().map(|f| f.len() + 6).sum();
        prop_assert_eq!(&stream[consumed..], &rest[..]);

        let (got, err) = decode_chunked(&stream, &cuts);
        prop_assert_eq!(got, ref_frames);
        // Seule tolérance : statut HTTP pas encore reçu au moment de l'erreur.
        let partial_http = matches!(
            (&err, &ref_err),
            (Some(FrameError::HttpResponse { status: None }), Some(FrameError::HttpResponse { .. }))
        );
        if !partial_http {
            prop_assert_eq!(err, ref_err);
        }
    }

    /// Flux totalement arbitraire (et vecteurs mutés) : pas de panic, découpage
    /// indifférent, erreurs non consommatrices et persistantes.
    #[test]
    fn decoder_arbitrary_stream(
        stream in prop_oneof![any_bytes(400), mutated(wire_vectors())],
        cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..20),
    ) {
        let (ref_frames, ref_err, rest) = decode_all(&stream);
        let (got, err) = decode_chunked(&stream, &cuts);
        prop_assert_eq!(got, ref_frames);
        if let Some(e) = ref_err {
            let mut buf = BytesMut::from(&rest[..]);
            prop_assert_eq!(decode_frame(&mut buf), Err(e.clone()));
            prop_assert_eq!(&buf[..], &rest[..]);
            if !matches!(e, FrameError::HttpResponse { .. }) {
                prop_assert_eq!(err, Some(e));
            }
        }
    }

    /// Packet : parse → encode → parse idempotent ; l'encodage est un point fixe.
    #[test]
    fn packet_parse_encode_idempotent(
        frame in prop_oneof![any_bytes(300), mutated(ppp_vectors())],
    ) {
        let input = Bytes::from(frame);
        if let Ok(p) = Packet::parse(input.clone()) {
            let enc = p.to_bytes();
            prop_assert!(enc.len() <= input.len() + 1);
            prop_assert!(!enc.starts_with(&[0xff, 0x03]));
            let p2 = Packet::parse(enc.clone()).unwrap();
            prop_assert_eq!(&p2, &p);
            prop_assert_eq!(p2.to_bytes(), enc);
        }
        if let Ok(f) = PppFrame::parse(input) {
            let enc = f.to_bytes();
            prop_assert_eq!(PppFrame::parse(enc).unwrap(), f);
        }
    }

    /// Code-Reject / Protocol-Reject : bornés par `max_len` et ré-analysables.
    #[test]
    fn rejects_are_bounded(info in any_bytes(600), max_len in 0usize..2000, code in any::<u8>()) {
        let p = ControlPacket::new(Code::from(code), 1, Bytes::from(info.clone())).unwrap();
        let cr = ControlPacket::code_reject(2, &p, max_len);
        prop_assert!(cr.len() <= max_len.max(4));
        let pr = ControlPacket::protocol_reject(3, Protocol::IPV6CP, &info, max_len);
        prop_assert!(pr.len() <= max_len.max(6));
        for r in [cr, pr] {
            let mut e = BytesMut::new();
            r.encode(&mut e);
            prop_assert_eq!(ControlPacket::parse(&e.freeze()).unwrap(), r);
        }
    }

    /// Options : parse ∘ encode == id (exactement les octets d'entrée) ; options typées
    /// LCP/IPCP bijectives.
    #[test]
    fn options_roundtrip(
        data in prop_oneof![
            any_bytes(300),
            mutated(ppp_vectors().into_iter().filter(|p| p.len() > 6).map(|p| p[6..].to_vec()).collect()),
            prop::collection::vec((any::<u8>(), any_bytes(20)), 0..8).prop_map(|opts| {
                let opts: Vec<_> = opts
                    .into_iter()
                    .map(|(k, v)| ConfigOption::new(k, Bytes::from(v)).unwrap())
                    .collect();
                let mut b = BytesMut::new();
                encode_options(&opts, &mut b);
                b.to_vec()
            }),
        ],
    ) {
        let data = Bytes::from(data);
        if let Ok(opts) = parse_options(&data) {
            let mut enc = BytesMut::new();
            encode_options(&opts, &mut enc);
            prop_assert_eq!(&enc[..], &data[..]);
            for o in &opts {
                prop_assert_eq!(&LcpOption::from_option(o).to_option(), o);
                prop_assert_eq!(&IpcpOption::from_option(o).to_option(), o);
            }
        }
    }
}

#[derive(Debug, Clone)]
enum Op {
    Frame(Vec<u8>),
    Advance(u16),
    Jump,
    Open,
    Close,
    /// Ack (ou Nak/Reject) de notre dernière Configure-Request LCP (`false`) / IPCP.
    Answer(bool, u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => mutated(ppp_vectors()).prop_map(Op::Frame),
        1 => any_bytes(64).prop_map(Op::Frame),
        2 => any::<u16>().prop_map(Op::Advance),
        2 => Just(Op::Jump),
        1 => Just(Op::Open),
        1 => Just(Op::Close),
        3 => (any::<bool>(), any::<u8>()).prop_map(|(i, c)| Op::Answer(i, c)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Séquence arbitraire d'événements : pas de panic, sorties bornées et encapsulables,
    /// `Down` unique puis automate inerte, `IpcpUp` unique, pas d'échéance passée après
    /// `handle_timeout`.
    #[test]
    fn session_survives_arbitrary_events(ops in prop::collection::vec(op(), 0..80)) {
        let mut s = PppSession::new(PppConfig::new(NonZeroU32::new(0x1a2b_3c4d).unwrap()));
        let base = Instant::now();
        let mut now = base;
        let mut down = false;
        let mut ipcp_up = false;
        let mut last_req: [Option<ControlPacket>; 2] = [None, None];
        // Ouverture d'emblée ; `Op::Open` répété doit être sans effet.
        s.open(now);
        for op in ops {
            let mut timed = false;
            match op {
                Op::Frame(f) => s.handle_frame(now, Bytes::from(f)),
                Op::Advance(ms) => {
                    now += Duration::from_millis(u64::from(ms) * 2);
                    s.handle_timeout(now);
                    timed = true;
                }
                Op::Jump => {
                    if let Some(t) = s.poll_timeout() {
                        now = now.max(t);
                    }
                    s.handle_timeout(now);
                    timed = true;
                }
                Op::Open => s.open(now),
                Op::Close => s.close(now),
                Op::Answer(ipcp, c) => {
                    let (idx, proto) = if ipcp { (1, Protocol::IPCP) } else { (0, Protocol::LCP) };
                    if let Some(req) = &last_req[idx] {
                        let code = match c % 4 {
                            0 | 1 => Code::ConfigureAck,
                            2 => Code::ConfigureNak,
                            _ => Code::ConfigureReject,
                        };
                        let p = ControlPacket::new(code, req.id(), req.data().clone()).unwrap();
                        s.handle_frame(now, p.to_frame(proto));
                    }
                }
            }
            let mut n = 0;
            while let Some(f) = s.poll_transmit() {
                n += 1;
                prop_assert!(n <= 4);
                prop_assert!(!down, "trame émise après Down");
                prop_assert!(f.len() <= MAX_PPP_LEN);
                let mut w = BytesMut::new();
                prop_assert!(encode_frame(&f, &mut w).is_ok());
                match Packet::parse(f).unwrap() {
                    Packet::Lcp(p) if p.code() == Code::ConfigureRequest => last_req[0] = Some(p),
                    Packet::Ipcp(p) if p.code() == Code::ConfigureRequest => last_req[1] = Some(p),
                    Packet::Lcp(_) | Packet::Ipcp(_) => {}
                    other => prop_assert!(false, "émission inattendue {:?}", other),
                }
            }
            let mut e = 0;
            while let Some(ev) = s.poll_event() {
                e += 1;
                prop_assert!(e <= 2);
                prop_assert!(!down, "événement après Down");
                match ev {
                    PppEvent::Down(_) => down = true,
                    PppEvent::IpcpUp { mtu, .. } => {
                        prop_assert!(!ipcp_up, "IpcpUp en double");
                        prop_assert!(mtu <= proto::ppp::DEFAULT_MRU);
                        ipcp_up = true;
                    }
                    PppEvent::Ipv4(_) => prop_assert!(ipcp_up),
                }
            }
            prop_assert_eq!(s.is_closed(), down);
            if s.is_ip_up() {
                prop_assert!(ipcp_up && !down);
            }
            if timed && let Some(t) = s.poll_timeout() {
                prop_assert!(t > now, "échéance passée après handle_timeout");
            }
        }
    }
}
