//! Trames et paquets de contrôle PPP (§9.1).

use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};

use super::options::{ConfigOption, encode_options, parse_options};

/// Numéro de protocole PPP (toujours émis sur 2 octets).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Protocol(pub u16);

impl Protocol {
    /// Datagramme IPv4.
    pub const IPV4: Self = Self(0x0021);
    /// Datagramme IPv6.
    pub const IPV6: Self = Self(0x0057);
    /// IP Control Protocol.
    pub const IPCP: Self = Self(0x8021);
    /// IPv6 Control Protocol.
    pub const IPV6CP: Self = Self(0x8057);
    /// Link Control Protocol.
    pub const LCP: Self = Self(0xc021);
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::IPV4 => "IPv4",
            Self::IPV6 => "IPv6",
            Self::IPCP => "IPCP",
            Self::IPV6CP => "IPV6CP",
            Self::LCP => "LCP",
            _ => return write!(f, "Protocol({:#06x})", self.0),
        };
        f.write_str(name)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Erreur d'analyse ou de construction d'un paquet PPP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PacketError {
    /// Données trop courtes pour l'en-tête attendu.
    #[error("paquet PPP tronqué")]
    Truncated,
    /// Champ longueur incohérent avec les données reçues.
    #[error("longueur PPP invalide : annoncée {declared}, disponible {available}")]
    InvalidLength {
        /// Longueur annoncée.
        declared: usize,
        /// Octets disponibles.
        available: usize,
    },
    /// Option TLV mal formée (longueur < 2 ou dépassant le paquet).
    #[error("option de configuration mal formée")]
    MalformedOption,
    /// Valeur d'option trop longue (> 253 octets).
    #[error("valeur d'option trop longue : {0} octets")]
    OptionTooLong(usize),
    /// Données de paquet de contrôle trop longues (> [`MAX_CONTROL_DATA`]).
    #[error("données de paquet de contrôle trop longues : {0} octets")]
    DataTooLong(usize),
}

/// Trame PPP brute : protocole + information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppFrame {
    /// Protocole.
    pub protocol: Protocol,
    /// Information (paquet de contrôle ou datagramme).
    pub payload: Bytes,
}

impl PppFrame {
    /// Analyse une trame PPP extraite de l'enveloppe `0x5050`.
    ///
    /// Tolère (§7.3) un préfixe adresse/contrôle `ff 03` et un protocole compressé
    /// sur 1 octet (premier octet impair).
    pub fn parse(frame: Bytes) -> Result<Self, PacketError> {
        let frame = if frame.starts_with(&[0xff, 0x03]) {
            frame.slice(2..)
        } else {
            frame
        };
        match frame.first() {
            None => Err(PacketError::Truncated),
            Some(&b) if b & 1 == 1 => Ok(Self {
                protocol: Protocol(u16::from(b)),
                payload: frame.slice(1..),
            }),
            Some(&hi) => {
                let lo = *frame.get(1).ok_or(PacketError::Truncated)?;
                Ok(Self {
                    protocol: Protocol(u16::from_be_bytes([hi, lo])),
                    payload: frame.slice(2..),
                })
            }
        }
    }

    /// Sérialise (protocole sur 2 octets, jamais de `ff 03`).
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(2 + self.payload.len());
        dst.put_u16(self.protocol.0);
        dst.put_slice(&self.payload);
    }

    /// Sérialise dans un nouveau tampon.
    pub fn to_bytes(&self) -> Bytes {
        let mut dst = BytesMut::new();
        self.encode(&mut dst);
        dst.freeze()
    }
}

/// Code d'un paquet de contrôle (§9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// 1
    ConfigureRequest,
    /// 2
    ConfigureAck,
    /// 3
    ConfigureNak,
    /// 4
    ConfigureReject,
    /// 5
    TerminateRequest,
    /// 6
    TerminateAck,
    /// 7
    CodeReject,
    /// 8 (LCP)
    ProtocolReject,
    /// 9 (LCP)
    EchoRequest,
    /// 10 (LCP)
    EchoReply,
    /// 11 (LCP)
    DiscardRequest,
    /// Code non reconnu.
    Unknown(u8),
}

impl From<u8> for Code {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::ConfigureRequest,
            2 => Self::ConfigureAck,
            3 => Self::ConfigureNak,
            4 => Self::ConfigureReject,
            5 => Self::TerminateRequest,
            6 => Self::TerminateAck,
            7 => Self::CodeReject,
            8 => Self::ProtocolReject,
            9 => Self::EchoRequest,
            10 => Self::EchoReply,
            11 => Self::DiscardRequest,
            other => Self::Unknown(other),
        }
    }
}

impl From<Code> for u8 {
    fn from(c: Code) -> Self {
        match c {
            Code::ConfigureRequest => 1,
            Code::ConfigureAck => 2,
            Code::ConfigureNak => 3,
            Code::ConfigureReject => 4,
            Code::TerminateRequest => 5,
            Code::TerminateAck => 6,
            Code::CodeReject => 7,
            Code::ProtocolReject => 8,
            Code::EchoRequest => 9,
            Code::EchoReply => 10,
            Code::DiscardRequest => 11,
            Code::Unknown(v) => v,
        }
    }
}

/// Longueur maximale des données d'un paquet de contrôle (`length` u16 − 4).
pub const MAX_CONTROL_DATA: usize = u16::MAX as usize - 4;

/// Paquet de contrôle LCP/IPCP : `code | id | length | données`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    code: Code,
    id: u8,
    data: Bytes,
}

impl ControlPacket {
    /// Construit un paquet ; échoue si `data` dépasse [`MAX_CONTROL_DATA`].
    pub fn new(code: Code, id: u8, data: Bytes) -> Result<Self, PacketError> {
        if data.len() > MAX_CONTROL_DATA {
            return Err(PacketError::DataTooLong(data.len()));
        }
        Ok(Self { code, id, data })
    }

    /// Paquet Configure-* portant `options`.
    pub fn configure(code: Code, id: u8, options: &[ConfigOption]) -> Result<Self, PacketError> {
        let mut data = BytesMut::new();
        encode_options(options, &mut data);
        Self::new(code, id, data.freeze())
    }

    /// Echo-Request / Echo-Reply / Discard-Request : `magic` puis `data`.
    pub fn echo(code: Code, id: u8, magic: u32, data: &[u8]) -> Result<Self, PacketError> {
        let mut buf = BytesMut::with_capacity(4 + data.len());
        buf.put_u32(magic);
        buf.put_slice(data);
        Self::new(code, id, buf.freeze())
    }

    /// Protocol-Reject (LCP) de `rejected` dont l'information est `info`, tronqué pour
    /// que le paquet LCP complet tienne dans `max_len` octets (MRU du pair).
    pub fn protocol_reject(id: u8, rejected: Protocol, info: &[u8], max_len: usize) -> Self {
        let room = max_len.min(u16::MAX.into()).saturating_sub(6);
        let info = &info[..info.len().min(room)];
        let mut buf = BytesMut::with_capacity(2 + info.len());
        buf.put_u16(rejected.0);
        buf.put_slice(info);
        Self {
            code: Code::ProtocolReject,
            id,
            data: buf.freeze(),
        }
    }

    /// Code-Reject du paquet `rejected` (recopié depuis son code), tronqué à `max_len`.
    pub fn code_reject(id: u8, rejected: &Self, max_len: usize) -> Self {
        let room = max_len.min(u16::MAX.into()).saturating_sub(4);
        let mut buf = BytesMut::new();
        rejected.encode(&mut buf);
        buf.truncate(room);
        Self {
            code: Code::CodeReject,
            id,
            data: buf.freeze(),
        }
    }

    /// Analyse l'information d'une trame LCP/IPCP. Le bourrage au-delà de `length` est
    /// ignoré ; `length` < 4 ou > données disponibles est une erreur.
    pub fn parse(info: &Bytes) -> Result<Self, PacketError> {
        let header = info.get(..4).ok_or(PacketError::Truncated)?;
        let declared = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if declared < 4 || declared > info.len() {
            return Err(PacketError::InvalidLength {
                declared,
                available: info.len(),
            });
        }
        Ok(Self {
            code: Code::from(header[0]),
            id: header[1],
            data: info.slice(4..declared),
        })
    }

    /// Code.
    pub fn code(&self) -> Code {
        self.code
    }

    /// Identifiant.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Données (après l'en-tête de 4 octets).
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Longueur sérialisée (champ `length`).
    pub fn len(&self) -> usize {
        4 + self.data.len()
    }

    /// Toujours faux (un paquet fait au moins 4 octets) ; fourni pour l'API.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Options TLV (Configure-*).
    pub fn options(&self) -> Result<Vec<ConfigOption>, PacketError> {
        parse_options(&self.data)
    }

    /// `(magic, données)` d'un Echo-* / Discard-Request.
    pub fn magic_and_data(&self) -> Option<(u32, Bytes)> {
        let m = self.data.get(..4)?;
        Some((
            u32::from_be_bytes([m[0], m[1], m[2], m[3]]),
            self.data.slice(4..),
        ))
    }

    /// `(protocole rejeté, information)` d'un Protocol-Reject.
    pub fn rejected_protocol(&self) -> Option<(Protocol, Bytes)> {
        let p = self.data.get(..2)?;
        Some((
            Protocol(u16::from_be_bytes([p[0], p[1]])),
            self.data.slice(2..),
        ))
    }

    /// Sérialise `code | id | length | données`.
    pub fn encode(&self, dst: &mut BytesMut) {
        // `data.len() <= MAX_CONTROL_DATA` est garanti par construction.
        let len = u16::try_from(self.len()).unwrap_or(u16::MAX);
        dst.reserve(self.len());
        dst.put_u8(self.code.into());
        dst.put_u8(self.id);
        dst.put_u16(len);
        dst.put_slice(&self.data);
    }

    /// Trame PPP complète (protocole + paquet), sans en-tête `0x5050`.
    pub fn to_frame(&self, protocol: Protocol) -> Bytes {
        let mut dst = BytesMut::with_capacity(2 + self.len());
        dst.put_u16(protocol.0);
        self.encode(&mut dst);
        dst.freeze()
    }
}

/// Trame PPP classée par protocole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// LCP (`c0 21`).
    Lcp(ControlPacket),
    /// IPCP (`80 21`).
    Ipcp(ControlPacket),
    /// Datagramme IPv4 (`00 21`), sans les 2 octets de protocole.
    Ipv4(Bytes),
    /// Tout autre protocole (IPV6CP, IPv6, CCP…).
    Other(PppFrame),
}

impl Packet {
    /// Analyse une trame PPP (sortie de [`crate::frame::decode_frame`]).
    pub fn parse(frame: Bytes) -> Result<Self, PacketError> {
        let f = PppFrame::parse(frame)?;
        Ok(match f.protocol {
            Protocol::LCP => Self::Lcp(ControlPacket::parse(&f.payload)?),
            Protocol::IPCP => Self::Ipcp(ControlPacket::parse(&f.payload)?),
            Protocol::IPV4 => Self::Ipv4(f.payload),
            _ => Self::Other(f),
        })
    }

    /// Trame PPP sérialisée (protocole sur 2 octets).
    pub fn to_bytes(&self) -> Bytes {
        match self {
            Self::Lcp(p) => p.to_frame(Protocol::LCP),
            Self::Ipcp(p) => p.to_frame(Protocol::IPCP),
            Self::Ipv4(ip) => PppFrame {
                protocol: Protocol::IPV4,
                payload: ip.clone(),
            }
            .to_bytes(),
            Self::Other(f) => f.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppp_frame_tolerates_ff03_and_short_protocol() {
        let f = PppFrame::parse(Bytes::from_static(&[0xff, 0x03, 0xc0, 0x21, 1])).unwrap();
        assert_eq!(f.protocol, Protocol::LCP);
        assert_eq!(&f.payload[..], &[1]);
        let f = PppFrame::parse(Bytes::from_static(&[0x21, 0x45])).unwrap();
        assert_eq!(f.protocol, Protocol::IPV4);
        assert_eq!(&f.payload[..], &[0x45]);
        assert_eq!(
            PppFrame::parse(Bytes::from_static(&[0xff, 0x03])),
            Err(PacketError::Truncated)
        );
        assert_eq!(
            PppFrame::parse(Bytes::from_static(&[0xc0])),
            Err(PacketError::Truncated)
        );
        // Jamais de ff 03 en émission.
        assert_eq!(&f.to_bytes()[..], &[0x00, 0x21, 0x45]);
    }

    #[test]
    fn control_packet_length_rules() {
        // Bourrage ignoré.
        let p = ControlPacket::parse(&Bytes::from_static(&[5, 3, 0, 4, 0xaa, 0xbb])).unwrap();
        assert_eq!(p.code(), Code::TerminateRequest);
        assert!(p.data().is_empty());
        // length > disponible.
        assert_eq!(
            ControlPacket::parse(&Bytes::from_static(&[5, 3, 0, 9, 0])),
            Err(PacketError::InvalidLength {
                declared: 9,
                available: 5
            })
        );
        // length < 4.
        assert!(ControlPacket::parse(&Bytes::from_static(&[5, 3, 0, 3])).is_err());
        assert_eq!(
            ControlPacket::parse(&Bytes::from_static(&[5, 3, 0])),
            Err(PacketError::Truncated)
        );
        assert!(
            ControlPacket::new(
                Code::EchoRequest,
                0,
                Bytes::from(vec![0; MAX_CONTROL_DATA + 1])
            )
            .is_err()
        );
    }

    #[test]
    fn code_roundtrip() {
        for v in 0..=u8::MAX {
            assert_eq!(u8::from(Code::from(v)), v);
        }
    }

    #[test]
    fn rejects_are_truncated() {
        let info = [0u8; 100];
        let p = ControlPacket::protocol_reject(1, Protocol::IPV6CP, &info, 50);
        assert_eq!(p.len(), 50);
        let p = ControlPacket::protocol_reject(1, Protocol::IPV6CP, &info, 0);
        assert_eq!(p.len(), 6);
        let inner = ControlPacket::new(Code::Unknown(42), 1, Bytes::from(vec![0; 100])).unwrap();
        let p = ControlPacket::code_reject(2, &inner, 40);
        assert_eq!(p.len(), 40);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn arbitrary_input_never_panics() {
        let mut x: u32 = 0x9e37_79b9;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for _ in 0..5000 {
            let len = (next() % 40) as usize;
            let mut v: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if v.len() >= 2 && next() % 2 == 0 {
                v[0] = 0xc0;
                v[1] = 0x21;
            }
            if let Ok(Packet::Lcp(p) | Packet::Ipcp(p)) = Packet::parse(Bytes::from(v)) {
                let _ = p.options();
                let _ = p.magic_and_data();
                let _ = p.rejected_protocol();
            }
        }
    }
}
