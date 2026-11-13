//! Framing 0x5050 contre `docs/vectors/*.hex` (§7).

mod common;

use bytes::BytesMut;
use proto::frame::{FrameDecoder, FrameError, decode_frame, encode_frame, encode_ppp_frame};
use proto::ppp::Protocol;

/// Tous les vecteurs valides (hors `err_*`, `stream_*` et paquets IP nus) se décodent
/// en une trame dont le réencodage redonne les mêmes octets.
#[test]
fn every_valid_vector_roundtrips() {
    let mut checked = 0;
    for v in common::all().into_values() {
        if v.name.starts_with("err_")
            || v.name.starts_with("stream_")
            || v.name.ends_with("_raw_ip")
        {
            continue;
        }
        let mut dec = FrameDecoder::new();
        dec.push(&v.bytes);
        let frame = dec
            .next_frame()
            .unwrap_or_else(|e| panic!("{}: {e}", v.name))
            .unwrap_or_else(|| panic!("{}: trame incomplète", v.name));
        assert_eq!(&frame[..], &v.bytes[6..], "{}", v.name);
        assert!(dec.buffered().is_empty(), "{}", v.name);
        assert_eq!(dec.next_frame(), Ok(None));

        let mut out = BytesMut::new();
        encode_frame(&frame, &mut out).unwrap();
        assert_eq!(&out[..], &v.bytes[..], "{}", v.name);
        checked += 1;
    }
    assert_eq!(checked, 28, "nombre de vecteurs valides");
}

#[test]
fn ipv4_data_path_adds_exactly_8_bytes() {
    let raw = common::wire("ipv4_icmp_echo_request_raw_ip");
    let mut out = BytesMut::new();
    encode_ppp_frame(Protocol::IPV4, &raw, &mut out).unwrap();
    assert_eq!(&out[..], &common::wire("ipv4_icmp_echo_request")[..]);
    assert_eq!(out.len(), raw.len() + 8);
}

fn stream_frames() -> Vec<Vec<u8>> {
    vec![
        common::ppp("lcp_confreq_gateway"),
        common::ppp("lcp_echo_request_gateway"),
        common::ppp("ipv4_icmp_echo_reply"),
    ]
}

#[test]
fn stream_three_frames_in_one_read() {
    let stream = common::wire("stream_three_frames");
    let mut dec = FrameDecoder::new();
    dec.push(&stream);
    let mut got = Vec::new();
    while let Some(f) = dec.next_frame().unwrap() {
        got.push(f.to_vec());
    }
    assert_eq!(got, stream_frames());
    assert!(dec.buffered().is_empty());
}

#[test]
fn stream_three_frames_split_at_every_position() {
    let stream = common::wire("stream_three_frames");
    for cut in 0..=stream.len() {
        let mut dec = FrameDecoder::new();
        let mut got = Vec::new();
        for part in [&stream[..cut], &stream[cut..]] {
            dec.push(part);
            while let Some(f) = dec.next_frame().unwrap() {
                got.push(f.to_vec());
            }
        }
        assert_eq!(got, stream_frames(), "coupure à {cut}");
    }
}

#[test]
fn stream_three_frames_byte_by_byte_with_decode_frame() {
    let stream = common::wire("stream_three_frames");
    let mut buf = BytesMut::new();
    let mut got = Vec::new();
    for b in stream {
        buf.extend_from_slice(&[b]);
        while let Some(f) = decode_frame(&mut buf).unwrap() {
            got.push(f.to_vec());
        }
    }
    assert_eq!(got, stream_frames());
}

fn decode_err(name: &str) -> FrameError {
    let mut dec = FrameDecoder::new();
    dec.push(&common::wire(name));
    dec.next_frame().expect_err(name)
}

#[test]
fn err_bad_magic() {
    assert_eq!(
        decode_err("err_bad_magic"),
        FrameError::BadMagic([0x50, 0x51])
    );
}

#[test]
fn err_inconsistent_lengths() {
    assert_eq!(
        decode_err("err_inconsistent_lengths"),
        FrameError::InconsistentLength {
            total: 23,
            ppp_len: 16
        }
    );
}

#[test]
fn err_total_too_small() {
    assert_eq!(
        decode_err("err_total_too_small"),
        FrameError::TotalTooSmall(6)
    );
}

#[test]
fn err_http_instead_of_ppp() {
    assert_eq!(
        decode_err("err_http_instead_of_ppp"),
        FrameError::HttpResponse { status: Some(403) }
    );
    // Seuls les 6 premiers octets suffisent à détecter HTTP ; le tampon reste intact.
    let wire = common::wire("err_http_instead_of_ppp");
    let mut dec = FrameDecoder::new();
    dec.push(&wire[..5]);
    assert_eq!(dec.next_frame(), Ok(None));
    dec.push(&wire[5..6]);
    assert_eq!(
        dec.next_frame(),
        Err(FrameError::HttpResponse { status: None })
    );
    dec.push(&wire[6..]);
    assert_eq!(
        dec.next_frame(),
        Err(FrameError::HttpResponse { status: Some(403) })
    );
    assert_eq!(dec.buffered(), &wire[..]);
}

#[test]
fn errors_detected_on_header_only() {
    // L'erreur est levée dès les 6 octets d'en-tête, sans attendre la charge utile.
    for name in [
        "err_bad_magic",
        "err_inconsistent_lengths",
        "err_total_too_small",
    ] {
        let mut dec = FrameDecoder::new();
        dec.push(&common::wire(name)[..6]);
        assert!(dec.next_frame().is_err(), "{name}");
    }
}

#[test]
fn valid_frame_followed_by_error() {
    let mut dec = FrameDecoder::new();
    dec.push(&common::wire("lcp_confreq_gateway"));
    dec.push(&common::wire("err_bad_magic"));
    assert!(dec.next_frame().unwrap().is_some());
    assert!(dec.next_frame().is_err());
}
