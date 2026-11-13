//! Flux 0x5050 arbitraire, découpé arbitrairement en `push`.
//!
//! Entrée : `seed(4) | flux…`. Le seed pilote le découpage du flux.
//!
//! Invariants :
//! - jamais de panic ni de boucle infinie ;
//! - même résultat (trames, erreur, reliquat) quel que soit le découpage
//!   (référence : `decode_frame` sur le flux complet) ;
//! - conservation : chaque trame renvoyée ré-encodée (`encode_frame`) est exactement la
//!   portion du flux consommée ; trames + reliquat == flux ;
//! - tampon borné : après `Ok(None)`, `buffered() < 65535` ;
//! - une erreur ne consomme rien et se répète à l'identique.
#![no_main]

use bytes::BytesMut;
use fuzz_common::Rng;
use libfuzzer_sys::fuzz_target;
use proto::frame::{FrameDecoder, decode_frame, encode_frame};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let mut rng = Rng::new(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
    let stream = &data[4..];

    // Référence : tout le flux d'un coup.
    let mut whole = BytesMut::from(stream);
    let mut ref_frames = Vec::new();
    let ref_err = loop {
        match decode_frame(&mut whole) {
            Ok(Some(f)) => {
                assert!(!f.is_empty(), "trame PPP vide acceptée");
                ref_frames.push(f);
            }
            Ok(None) => break None,
            Err(e) => {
                let before = whole.len();
                assert_eq!(
                    decode_frame(&mut whole),
                    Err(e.clone()),
                    "erreur non stable"
                );
                assert_eq!(whole.len(), before, "l'erreur a consommé des octets");
                break Some(e);
            }
        }
    };

    // Conservation + encode∘decode == identité sur la portion consommée.
    let mut off = 0usize;
    for f in &ref_frames {
        let mut enc = BytesMut::new();
        encode_frame(f, &mut enc).expect("trame décodée non ré-encodable");
        assert_eq!(
            &stream[off..off + enc.len()],
            &enc[..],
            "encode(decode(x)) != x"
        );
        off += enc.len();
    }
    assert_eq!(&stream[off..], &whole[..], "trames + reliquat != flux");

    // Découpage arbitraire.
    let mut dec = FrameDecoder::new();
    let mut frames = Vec::new();
    let mut err = None;
    let mut pos = 0usize;
    'outer: while pos < stream.len() {
        let r = rng.next_u32();
        let n = match r % 8 {
            0 => stream.len() - pos,
            1..=3 => 1 + (r >> 8) as usize % 4,
            _ => 1 + (r >> 8) as usize % 64,
        }
        .min(stream.len() - pos);
        dec.push(&stream[pos..pos + n]);
        pos += n;
        // Borne explicite sur le nombre d'itérations (anti boucle infinie).
        for _ in 0..=stream.len() {
            match dec.next_frame() {
                Ok(Some(f)) => frames.push(f),
                Ok(None) => {
                    assert!(dec.buffered().len() < 65535, "tampon non borné");
                    continue 'outer;
                }
                Err(e) => {
                    err = Some(e);
                    break 'outer;
                }
            }
        }
        panic!("next_frame ne converge pas");
    }
    if err.is_none() && pos == stream.len() {
        // Le flux est entièrement poussé ; un dernier appel ne doit rien changer.
        match dec.next_frame() {
            Ok(None) => {}
            Ok(Some(_)) => panic!("trame restée en attente après Ok(None)"),
            Err(e) => err = Some(e),
        }
    }
    assert_eq!(frames, ref_frames, "trames différentes selon le découpage");
    if let Some(e) = &err {
        // Le décodeur découpé peut s'arrêter avant d'avoir tout poussé : l'erreur doit
        // néanmoins être celle de la référence (même position, même en-tête).
        // Exception : HttpResponse dont le statut n'était pas encore reçu.
        match (e, &ref_err) {
            (
                proto::FrameError::HttpResponse { status: None },
                Some(proto::FrameError::HttpResponse { .. }),
            ) => {}
            _ => assert_eq!(
                Some(e),
                ref_err.as_ref(),
                "erreur différente selon le découpage"
            ),
        }
        assert_eq!(
            dec.next_frame().err().as_ref(),
            Some(e),
            "erreur non persistante"
        );
    } else {
        assert_eq!(ref_err, None);
        assert_eq!(dec.buffered(), &whole[..], "reliquat différent");
    }
});
