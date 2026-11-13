//! Enveloppe `0x5050` du flux tunnel (`docs/protocol.md` §7).
//!
//! ```text
//! | total_len (u16 BE) | 50 50 | ppp_len (u16 BE) | trame PPP (ppp_len octets) |
//! ```
//! avec `total_len = 6 + ppp_len`. La trame PPP commence par le protocole sur 2 octets,
//! sans `ff 03`, FCS ni échappement HDLC.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::ppp::Protocol;

/// Taille de l'en-tête `0x5050`.
pub const HEADER_LEN: usize = 6;
/// Octets magiques de l'en-tête.
pub const MAGIC: [u8; 2] = [0x50, 0x50];
/// Longueur maximale d'une trame PPP encapsulable (`total_len` ≤ 65535).
pub const MAX_PPP_LEN: usize = u16::MAX as usize - HEADER_LEN;
/// Préfixe d'une réponse HTTP reçue à la place du flux binaire (§6).
pub const HTTP_PREFIX: &[u8; 6] = b"HTTP/1";

/// Erreur de décodage du flux `0x5050`. Toutes sont fatales pour le tunnel.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// La passerelle a répondu en HTTP au lieu de basculer en mode tunnel
    /// (cookie invalide/expiré, mode tunnel refusé…). `status` est le code de statut
    /// s'il est déjà présent dans le tampon (`HTTP/1.x NNN`).
    #[error("réponse HTTP reçue à la place du tunnel (statut {status:?})")]
    HttpResponse {
        /// Code de statut HTTP, si déjà reçu.
        status: Option<u16>,
    },
    /// Octets magiques différents de `50 50`.
    #[error("en-tête de trame invalide : magic {0:02x?}")]
    BadMagic([u8; 2]),
    /// `total_len` inférieur à 7 (trame sans charge utile).
    #[error("en-tête de trame invalide : longueur totale {0} < 7")]
    TotalTooSmall(u16),
    /// `total_len != 6 + ppp_len`.
    #[error("en-tête de trame invalide : longueur totale {total} != 6 + {ppp_len}")]
    InconsistentLength {
        /// Longueur totale annoncée.
        total: u16,
        /// Longueur PPP annoncée.
        ppp_len: u16,
    },
}

/// Erreur d'encodage d'une trame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// Trame PPP vide (la passerelle la rejetterait : `total_len < 7`).
    #[error("trame PPP vide")]
    Empty,
    /// Trame PPP plus longue que [`MAX_PPP_LEN`].
    #[error("trame PPP trop longue : {0} octets (max {MAX_PPP_LEN})")]
    TooLong(usize),
}

fn put_header(ppp_len: usize, dst: &mut BytesMut) -> Result<(), EncodeError> {
    if ppp_len == 0 {
        return Err(EncodeError::Empty);
    }
    let len = u16::try_from(ppp_len)
        .ok()
        .filter(|&l| usize::from(l) <= MAX_PPP_LEN)
        .ok_or(EncodeError::TooLong(ppp_len))?;
    // `len <= MAX_PPP_LEN` garantit l'absence de débordement.
    let total = len + 6;
    dst.reserve(HEADER_LEN + ppp_len);
    dst.put_u16(total);
    dst.put_slice(&MAGIC);
    dst.put_u16(len);
    Ok(())
}

/// Ajoute à `dst` l'en-tête `0x5050` suivi de la trame PPP `ppp` (protocole inclus).
///
/// N'émet jamais de préfixe `ff 03`.
pub fn encode_frame(ppp: &[u8], dst: &mut BytesMut) -> Result<(), EncodeError> {
    put_header(ppp.len(), dst)?;
    dst.put_slice(ppp);
    Ok(())
}

/// Variante de [`encode_frame`] qui renvoie un nouveau tampon.
pub fn frame_to_bytes(ppp: &[u8]) -> Result<Bytes, EncodeError> {
    let mut dst = BytesMut::with_capacity(HEADER_LEN + ppp.len());
    encode_frame(ppp, &mut dst)?;
    Ok(dst.freeze())
}

/// Ajoute à `dst` une trame complète `0x5050` + protocole PPP (2 octets) + `payload`,
/// sans copie intermédiaire. Chemin de données : `encode_ppp_frame(Protocol::IPV4, ip, dst)`
/// ajoute exactement 8 octets devant le paquet IP (§9.6).
pub fn encode_ppp_frame(
    protocol: Protocol,
    payload: &[u8],
    dst: &mut BytesMut,
) -> Result<(), EncodeError> {
    let ppp_len = payload.len().saturating_add(2);
    put_header(ppp_len, dst)?;
    dst.put_u16(protocol.0);
    dst.put_slice(payload);
    Ok(())
}

/// Extrait le code de statut d'une ligne `HTTP/1.x NNN` si elle est présente.
pub fn parse_http_status(buf: &[u8]) -> Option<u16> {
    let rest = buf.strip_prefix(HTTP_PREFIX)?;
    // ".1 403" ou ".0 403"
    let rest = rest.get(2..)?.strip_prefix(b" ")?;
    let digits = rest.get(..3)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0u16, |acc, d| {
        acc.checked_mul(10)?.checked_add(u16::from(d - b'0'))
    })
}

/// Décode une trame depuis `src` (signature compatible avec
/// `tokio_util::codec::Decoder::decode`).
///
/// - `Ok(Some(trame_ppp))` : une trame complète a été retirée de `src` ; la valeur
///   renvoyée est la trame PPP (protocole inclus, sans l'en-tête `0x5050`).
/// - `Ok(None)` : données insuffisantes, rien n'est consommé.
/// - `Err(_)` : flux invalide (§7.2) ; **rien n'est consommé**, ce qui permet à
///   l'appelant de lire la réponse HTTP complète en cas de [`FrameError::HttpResponse`].
pub fn decode_frame(src: &mut BytesMut) -> Result<Option<Bytes>, FrameError> {
    if src.len() < HEADER_LEN {
        // Détection précoce d'une réponse HTTP partielle inutile : on attend 6 octets.
        return Ok(None);
    }
    if src.starts_with(HTTP_PREFIX) {
        return Err(FrameError::HttpResponse {
            status: parse_http_status(src),
        });
    }
    let total = u16::from_be_bytes([src[0], src[1]]);
    let magic = [src[2], src[3]];
    let ppp_len = u16::from_be_bytes([src[4], src[5]]);
    if magic != MAGIC {
        return Err(FrameError::BadMagic(magic));
    }
    if total < 7 {
        return Err(FrameError::TotalTooSmall(total));
    }
    if usize::from(total) != HEADER_LEN + usize::from(ppp_len) {
        return Err(FrameError::InconsistentLength { total, ppp_len });
    }
    let total = usize::from(total);
    if src.len() < total {
        src.reserve(total - src.len());
        return Ok(None);
    }
    let mut frame = src.split_to(total);
    frame.advance(HEADER_LEN);
    Ok(Some(frame.freeze()))
}

/// Décodeur incrémental du flux `0x5050`.
///
/// Accumule les octets lus sur TLS ([`push`](Self::push)) et restitue les trames PPP
/// complètes ([`next_frame`](Self::next_frame)), quel que soit le découpage. Après une
/// erreur, le décodeur reste en erreur (le tunnel doit être fermé).
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: BytesMut,
}

impl FrameDecoder {
    /// Crée un décodeur vide.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ajoute des octets reçus.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Renvoie la prochaine trame PPP complète, `None` s'il en manque une partie.
    pub fn next_frame(&mut self) -> Result<Option<Bytes>, FrameError> {
        decode_frame(&mut self.buf)
    }

    /// Octets reçus et non encore consommés (ex. réponse HTTP après
    /// [`FrameError::HttpResponse`]).
    pub fn buffered(&self) -> &[u8] {
        &self.buf
    }

    /// Accès au tampon interne (lecture directe depuis le socket, sans copie).
    pub fn buffer_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_rejects_empty_and_too_long() {
        let mut dst = BytesMut::new();
        assert_eq!(encode_frame(&[], &mut dst), Err(EncodeError::Empty));
        let big = vec![0u8; MAX_PPP_LEN + 1];
        assert_eq!(
            encode_frame(&big, &mut dst),
            Err(EncodeError::TooLong(MAX_PPP_LEN + 1))
        );
        assert!(dst.is_empty());
        let max = vec![0u8; MAX_PPP_LEN];
        encode_frame(&max, &mut dst).unwrap();
        assert_eq!(&dst[..6], &[0xff, 0xff, 0x50, 0x50, 0xff, 0xf9]);
        let mut dst = BytesMut::new();
        assert_eq!(
            encode_ppp_frame(Protocol::IPV4, &max, &mut dst),
            Err(EncodeError::TooLong(MAX_PPP_LEN + 2))
        );
    }

    #[test]
    fn max_frame_roundtrip() {
        let ppp = vec![0xabu8; MAX_PPP_LEN];
        let mut wire = BytesMut::new();
        encode_frame(&ppp, &mut wire).unwrap();
        let mut dec = FrameDecoder::new();
        dec.push(&wire);
        assert_eq!(dec.next_frame().unwrap().unwrap(), ppp);
        assert!(dec.buffered().is_empty());
    }

    #[test]
    fn http_status_parsing() {
        assert_eq!(parse_http_status(b"HTTP/1.1 403 Forbidden"), Some(403));
        assert_eq!(parse_http_status(b"HTTP/1.0 200"), Some(200));
        assert_eq!(parse_http_status(b"HTTP/1.1 4"), None);
        assert_eq!(parse_http_status(b"HTTP/1"), None);
        assert_eq!(parse_http_status(b"HTTP/1.1 abc"), None);
        assert_eq!(parse_http_status(b"XTTP/1.1 403"), None);
    }

    #[test]
    fn errors_do_not_consume() {
        let mut dec = FrameDecoder::new();
        dec.push(&[0x00, 0x16, 0x50, 0x51, 0, 0x10]);
        assert_eq!(dec.next_frame(), Err(FrameError::BadMagic([0x50, 0x51])));
        assert_eq!(dec.next_frame(), Err(FrameError::BadMagic([0x50, 0x51])));
        assert_eq!(dec.buffered().len(), 6);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn arbitrary_input_never_panics() {
        // Générateur pseudo-aléatoire déterministe (xorshift).
        let mut x: u32 = 0x1234_5678;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for _ in 0..2000 {
            let mut dec = FrameDecoder::new();
            let n = (next() % 64) as usize;
            for _ in 0..n {
                let chunk: Vec<u8> = (0..(next() % 16)).map(|_| next() as u8).collect();
                dec.push(&chunk);
                while let Ok(Some(_)) = dec.next_frame() {}
            }
        }
    }
}
