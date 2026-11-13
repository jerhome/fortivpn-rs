//! Encodage/décodage des messages IKEv2 (RFC 7296), sans I/O.
//!
//! Toutes les longueurs lues sont validées contre le tampon et bornées ;
//! aucun chemin de décodage ne panique.

use crate::error::{Error, Result};

/// Taille de l'en-tête IKE.
pub const HEADER_LEN: usize = 28;
/// Taille maximale d'un message IKE acceptée.
pub const MAX_MESSAGE_LEN: usize = 65_535;
const MAX_PAYLOADS: usize = 32;
const MAX_PROPOSALS: usize = 16;
const MAX_TRANSFORMS: usize = 64;
const MAX_CP_ATTRS: usize = 256;
const MAX_SELECTORS: usize = 64;

/// Types d'échange.
pub mod exchange {
    pub const IKE_SA_INIT: u8 = 34;
    pub const IKE_AUTH: u8 = 35;
    pub const CREATE_CHILD_SA: u8 = 36;
    pub const INFORMATIONAL: u8 = 37;
}

/// Bits de flags de l'en-tête.
pub mod flags {
    pub const INITIATOR: u8 = 0x08;
    pub const RESPONSE: u8 = 0x20;
}

/// Types de payload.
pub mod ptype {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 33;
    pub const KE: u8 = 34;
    pub const IDI: u8 = 35;
    pub const IDR: u8 = 36;
    pub const CERT: u8 = 37;
    pub const CERTREQ: u8 = 38;
    pub const AUTH: u8 = 39;
    pub const NONCE: u8 = 40;
    pub const NOTIFY: u8 = 41;
    pub const DELETE: u8 = 42;
    pub const VENDOR: u8 = 43;
    pub const TSI: u8 = 44;
    pub const TSR: u8 = 45;
    pub const SK: u8 = 46;
    pub const CP: u8 = 47;
    pub const EAP: u8 = 48;
}

/// Types de notification notables.
pub mod notify {
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    pub const INITIAL_CONTACT: u16 = 16384;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const COOKIE: u16 = 16390;
    pub const REKEY_SA: u16 = 16393;
    pub const TS_UNACCEPTABLE: u16 = 38;
    pub const NO_ADDITIONAL_SAS: u16 = 35;
    pub const TEMPORARY_FAILURE: u16 = 43;
    pub const CHILD_SA_NOT_FOUND: u16 = 44;
    pub const IKEV2_FRAGMENTATION_SUPPORTED: u16 = 16430;
    /// RFC 7427 §4 : algorithmes de hachage acceptés pour les signatures (méthode AUTH 14).
    pub const SIGNATURE_HASH_ALGORITHMS: u16 = 16431;
}

/// Types d'attributs CP.
pub mod cp_attr {
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;
    pub const INTERNAL_DNS_DOMAIN: u16 = 25;
}

/// En-tête IKE (28 octets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub spi_i: [u8; 8],
    pub spi_r: [u8; 8],
    pub next_payload: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

impl Header {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        if buf[17] >> 4 != 2 {
            return Err(Error::Unsupported("version IKE majeure != 2"));
        }
        let length = be32(&buf[24..28]);
        if (length as usize) < HEADER_LEN || length as usize > MAX_MESSAGE_LEN {
            return Err(Error::Malformed("longueur IKE invalide"));
        }
        if length as usize != buf.len() {
            return Err(Error::Malformed("longueur IKE != taille du datagramme"));
        }
        Ok(Self {
            spi_i: arr8(&buf[0..8]),
            spi_r: arr8(&buf[8..16]),
            next_payload: buf[16],
            exchange_type: buf[18],
            flags: buf[19],
            message_id: be32(&buf[20..24]),
            length,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.spi_i);
        out.extend_from_slice(&self.spi_r);
        out.push(self.next_payload);
        out.push(0x20);
        out.push(self.exchange_type);
        out.push(self.flags);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
    }
}

/// Transform d'une proposition SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    /// 1 ENCR, 2 PRF, 3 INTEG, 4 KE, 5 ESN.
    pub ty: u8,
    pub id: u16,
    /// Attribut Key Length (type 14), en bits.
    pub key_len: Option<u16>,
}

/// Proposition SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub number: u8,
    /// 1 IKE, 2 AH, 3 ESP.
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

/// Attribut de Configuration Payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpAttr {
    pub ty: u16,
    pub value: Vec<u8>,
}

/// Configuration Payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cp {
    /// 1 REQUEST, 2 REPLY, 3 SET, 4 ACK.
    pub cfg_type: u8,
    pub attrs: Vec<CpAttr>,
}

impl Cp {
    /// Requête client : IP, masque, DNS, sous-réseaux, domaines (attributs vides).
    pub fn request() -> Self {
        let attrs = [
            cp_attr::INTERNAL_IP4_ADDRESS,
            cp_attr::INTERNAL_IP4_NETMASK,
            cp_attr::INTERNAL_IP4_DNS,
            cp_attr::INTERNAL_IP4_SUBNET,
            cp_attr::INTERNAL_DNS_DOMAIN,
        ]
        .into_iter()
        .map(|ty| CpAttr {
            ty,
            value: Vec::new(),
        })
        .collect();
        Self { cfg_type: 1, attrs }
    }

    fn ip4s(&self, ty: u16) -> Vec<[u8; 4]> {
        self.attrs
            .iter()
            .filter(|a| a.ty == ty && a.value.len() == 4)
            .map(|a| arr4(&a.value))
            .collect()
    }
    pub fn ip4_address(&self) -> Option<[u8; 4]> {
        self.ip4s(cp_attr::INTERNAL_IP4_ADDRESS).into_iter().next()
    }
    pub fn ip4_netmask(&self) -> Option<[u8; 4]> {
        self.ip4s(cp_attr::INTERNAL_IP4_NETMASK).into_iter().next()
    }
    pub fn ip4_dns(&self) -> Vec<[u8; 4]> {
        self.ip4s(cp_attr::INTERNAL_IP4_DNS)
    }
    /// Sous-réseaux (adresse, masque).
    pub fn ip4_subnets(&self) -> Vec<([u8; 4], [u8; 4])> {
        self.attrs
            .iter()
            .filter(|a| a.ty == cp_attr::INTERNAL_IP4_SUBNET && a.value.len() == 8)
            .map(|a| (arr4(&a.value[..4]), arr4(&a.value[4..])))
            .collect()
    }
    /// Domaines DNS (INTERNAL_DNS_DOMAIN, RFC 8598 : FQDN en ASCII/UTF-8 ; les
    /// valeurs non UTF-8 sont ignorées).
    pub fn dns_domains(&self) -> Vec<String> {
        self.attrs
            .iter()
            .filter(|a| a.ty == cp_attr::INTERNAL_DNS_DOMAIN)
            .filter_map(|a| String::from_utf8(a.value.clone()).ok())
            .filter(|d| valid_domain(d))
            .take(MAX_DNS_DOMAINS)
            .collect()
    }
}

/// Nombre maximal de domaines DNS retenus depuis un CP.
pub const MAX_DNS_DOMAINS: usize = 8;

/// Nom de domaine plausible : 1..=253 octets, caractères `[A-Za-z0-9._-]` uniquement.
fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Traffic selector IPv4 (type 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSelector {
    pub protocol: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start: [u8; 4],
    pub end: [u8; 4],
}

impl TrafficSelector {
    /// Sélecteur bien formé : plages d'adresses et de ports non inversées.
    pub fn is_valid(&self) -> bool {
        u32::from_be_bytes(self.start) <= u32::from_be_bytes(self.end)
            && self.start_port <= self.end_port
    }

    /// Sélecteur « tout » 0.0.0.0-255.255.255.255, tous ports.
    pub fn any() -> Self {
        Self {
            protocol: 0,
            start_port: 0,
            end_port: 65535,
            start: [0; 4],
            end: [255; 4],
        }
    }
}

/// Notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub ty: u16,
    pub data: Vec<u8>,
}

impl Notify {
    pub fn new(ty: u16, data: Vec<u8>) -> Self {
        Self {
            protocol: 0,
            spi: Vec::new(),
            ty,
            data,
        }
    }
}

/// Payload IKE typé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Sa(Vec<Proposal>),
    Ke {
        group: u16,
        data: Vec<u8>,
    },
    Nonce(Vec<u8>),
    /// `responder` : IDr (36) au lieu de IDi (35). `data` : corps après les 4 octets type+réservé.
    Id {
        responder: bool,
        id_type: u8,
        data: Vec<u8>,
    },
    Auth {
        method: u8,
        data: Vec<u8>,
    },
    /// CERT (37) : `encoding` (4 = certificat X.509 DER) et données.
    Cert {
        encoding: u8,
        data: Vec<u8>,
    },
    /// CERTREQ (38) : `encoding` et liste (éventuellement vide) d'empreintes SHA-1 de SPKI d'AC.
    CertReq {
        encoding: u8,
        data: Vec<u8>,
    },
    Notify(Notify),
    Vendor(Vec<u8>),
    Ts {
        responder: bool,
        selectors: Vec<TrafficSelector>,
    },
    Cp(Cp),
    /// Paquet EAP brut (Code, Id, Length, Type, données).
    Eap(Vec<u8>),
    /// Payload SK : `next` = premier payload interne ; `data` = IV | chiffré | ICV.
    Sk {
        next: u8,
        data: Vec<u8>,
    },
    /// Payload inconnu non critique.
    Unknown {
        ty: u8,
        data: Vec<u8>,
    },
}

impl Payload {
    fn type_code(&self) -> u8 {
        match self {
            Payload::Sa(_) => ptype::SA,
            Payload::Ke { .. } => ptype::KE,
            Payload::Nonce(_) => ptype::NONCE,
            Payload::Id { responder, .. } => {
                if *responder {
                    ptype::IDR
                } else {
                    ptype::IDI
                }
            }
            Payload::Auth { .. } => ptype::AUTH,
            Payload::Cert { .. } => ptype::CERT,
            Payload::CertReq { .. } => ptype::CERTREQ,
            Payload::Notify(_) => ptype::NOTIFY,
            Payload::Vendor(_) => ptype::VENDOR,
            Payload::Ts { responder, .. } => {
                if *responder {
                    ptype::TSR
                } else {
                    ptype::TSI
                }
            }
            Payload::Cp(_) => ptype::CP,
            Payload::Eap(_) => ptype::EAP,
            Payload::Sk { .. } => ptype::SK,
            Payload::Unknown { ty, .. } => *ty,
        }
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        match self {
            Payload::Sa(props) => {
                for (i, p) in props.iter().enumerate() {
                    let last = i + 1 == props.len();
                    encode_proposal(&mut b, p, last)?;
                }
            }
            Payload::Ke { group, data } => {
                b.extend_from_slice(&group.to_be_bytes());
                b.extend_from_slice(&[0, 0]);
                b.extend_from_slice(data);
            }
            Payload::Nonce(d)
            | Payload::Vendor(d)
            | Payload::Eap(d)
            | Payload::Unknown { data: d, .. } => {
                b.extend_from_slice(d);
            }
            Payload::Id { id_type, data, .. } => {
                b.extend_from_slice(&[*id_type, 0, 0, 0]);
                b.extend_from_slice(data);
            }
            Payload::Auth { method, data } => {
                b.extend_from_slice(&[*method, 0, 0, 0]);
                b.extend_from_slice(data);
            }
            Payload::Cert { encoding, data } | Payload::CertReq { encoding, data } => {
                b.push(*encoding);
                b.extend_from_slice(data);
            }
            Payload::Notify(n) => {
                let spi_len = u8::try_from(n.spi.len()).map_err(|_| Error::TooLarge("SPI"))?;
                b.extend_from_slice(&[n.protocol, spi_len]);
                b.extend_from_slice(&n.ty.to_be_bytes());
                b.extend_from_slice(&n.spi);
                b.extend_from_slice(&n.data);
            }
            Payload::Ts { selectors, .. } => {
                let n = u8::try_from(selectors.len()).map_err(|_| Error::TooLarge("TS"))?;
                b.extend_from_slice(&[n, 0, 0, 0]);
                for s in selectors {
                    b.extend_from_slice(&[7, s.protocol, 0, 16]);
                    b.extend_from_slice(&s.start_port.to_be_bytes());
                    b.extend_from_slice(&s.end_port.to_be_bytes());
                    b.extend_from_slice(&s.start);
                    b.extend_from_slice(&s.end);
                }
            }
            Payload::Cp(cp) => {
                b.extend_from_slice(&[cp.cfg_type, 0, 0, 0]);
                for a in &cp.attrs {
                    let len =
                        u16::try_from(a.value.len()).map_err(|_| Error::TooLarge("attribut CP"))?;
                    b.extend_from_slice(&(a.ty & 0x7fff).to_be_bytes());
                    b.extend_from_slice(&len.to_be_bytes());
                    b.extend_from_slice(&a.value);
                }
            }
            Payload::Sk { data, .. } => b.extend_from_slice(data),
        }
        Ok(b)
    }
}

fn encode_proposal(out: &mut Vec<u8>, p: &Proposal, last: bool) -> Result<()> {
    let mut body = Vec::new();
    let spi_len = u8::try_from(p.spi.len()).map_err(|_| Error::TooLarge("SPI"))?;
    let ntr = u8::try_from(p.transforms.len()).map_err(|_| Error::TooLarge("transforms"))?;
    body.extend_from_slice(&[p.number, p.protocol, spi_len, ntr]);
    body.extend_from_slice(&p.spi);
    for (i, t) in p.transforms.iter().enumerate() {
        let tl = if t.key_len.is_some() { 12u16 } else { 8 };
        body.push(if i + 1 == p.transforms.len() { 0 } else { 3 });
        body.push(0);
        body.extend_from_slice(&tl.to_be_bytes());
        body.push(t.ty);
        body.push(0);
        body.extend_from_slice(&t.id.to_be_bytes());
        if let Some(k) = t.key_len {
            body.extend_from_slice(&0x800eu16.to_be_bytes());
            body.extend_from_slice(&k.to_be_bytes());
        }
    }
    let len = u16::try_from(body.len() + 4).map_err(|_| Error::TooLarge("proposition"))?;
    out.extend_from_slice(&[if last { 0 } else { 2 }, 0]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(())
}

/// Encode une chaîne de payloads ; renvoie (type du premier, octets).
pub fn encode_chain(payloads: &[Payload]) -> Result<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let first = payloads.first().map_or(ptype::NONE, Payload::type_code);
    for (i, p) in payloads.iter().enumerate() {
        let next = payloads.get(i + 1).map_or(ptype::NONE, Payload::type_code);
        let body = p.encode_body()?;
        let len = u16::try_from(body.len() + 4).map_err(|_| Error::TooLarge("payload"))?;
        // Un SK porte en « next » le premier payload interne, pas le suivant.
        let next = if let Payload::Sk { next: inner, .. } = p {
            *inner
        } else {
            next
        };
        out.extend_from_slice(&[next, 0]);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
    }
    Ok((first, out))
}

/// Décode une chaîne de payloads commençant par le type `first`.
pub fn decode_chain(first: u8, mut buf: &[u8]) -> Result<Vec<Payload>> {
    let mut out = Vec::new();
    let mut ty = first;
    while ty != ptype::NONE {
        if out.len() >= MAX_PAYLOADS {
            return Err(Error::TooLarge("trop de payloads"));
        }
        if buf.len() < 4 {
            return Err(Error::Truncated);
        }
        let next = buf[0];
        let critical = buf[1] & 0x80 != 0;
        let len = usize::from(be16(&buf[2..4]));
        if len < 4 || len > buf.len() {
            return Err(Error::Malformed("longueur de payload invalide"));
        }
        let body = &buf[4..len];
        let p = decode_body(ty, critical, next, body)?;
        let is_sk = matches!(p, Payload::Sk { .. });
        out.push(p);
        buf = &buf[len..];
        if is_sk {
            // SK est toujours le dernier ; `next` désigne le 1er payload interne.
            if !buf.is_empty() {
                return Err(Error::Malformed("données après SK"));
            }
            break;
        }
        ty = next;
    }
    if !buf.is_empty() && ty == ptype::NONE {
        return Err(Error::Malformed("octets en trop après le dernier payload"));
    }
    Ok(out)
}

fn decode_body(ty: u8, critical: bool, next: u8, b: &[u8]) -> Result<Payload> {
    Ok(match ty {
        ptype::SA => Payload::Sa(decode_sa(b)?),
        ptype::KE => {
            if b.len() < 4 {
                return Err(Error::Truncated);
            }
            Payload::Ke {
                group: be16(&b[..2]),
                data: b[4..].to_vec(),
            }
        }
        ptype::NONCE => {
            if !(16..=256).contains(&b.len()) {
                return Err(Error::Malformed("taille de nonce hors 16..256"));
            }
            Payload::Nonce(b.to_vec())
        }
        ptype::IDI | ptype::IDR => {
            if b.len() < 4 {
                return Err(Error::Truncated);
            }
            Payload::Id {
                responder: ty == ptype::IDR,
                id_type: b[0],
                data: b[4..].to_vec(),
            }
        }
        ptype::AUTH => {
            if b.len() < 4 {
                return Err(Error::Truncated);
            }
            Payload::Auth {
                method: b[0],
                data: b[4..].to_vec(),
            }
        }
        ptype::CERT | ptype::CERTREQ => {
            let Some((&encoding, rest)) = b.split_first() else {
                return Err(Error::Truncated);
            };
            let data = rest.to_vec();
            if ty == ptype::CERT {
                Payload::Cert { encoding, data }
            } else {
                Payload::CertReq { encoding, data }
            }
        }
        ptype::NOTIFY => {
            if b.len() < 4 {
                return Err(Error::Truncated);
            }
            let spi_len = usize::from(b[1]);
            if 4 + spi_len > b.len() {
                return Err(Error::Malformed("SPI de notification tronqué"));
            }
            Payload::Notify(Notify {
                protocol: b[0],
                spi: b[4..4 + spi_len].to_vec(),
                ty: be16(&b[2..4]),
                data: b[4 + spi_len..].to_vec(),
            })
        }
        ptype::VENDOR => Payload::Vendor(b.to_vec()),
        ptype::TSI | ptype::TSR => Payload::Ts {
            responder: ty == ptype::TSR,
            selectors: decode_ts(b)?,
        },
        ptype::CP => Payload::Cp(decode_cp(b)?),
        ptype::EAP => Payload::Eap(b.to_vec()),
        ptype::SK => Payload::Sk {
            next,
            data: b.to_vec(),
        },
        _ if critical => return Err(Error::UnsupportedCritical(ty)),
        _ => Payload::Unknown {
            ty,
            data: b.to_vec(),
        },
    })
}

fn decode_sa(mut b: &[u8]) -> Result<Vec<Proposal>> {
    let mut props = Vec::new();
    loop {
        if props.len() >= MAX_PROPOSALS {
            return Err(Error::TooLarge("trop de propositions"));
        }
        if b.len() < 8 {
            return Err(Error::Truncated);
        }
        let more = b[0];
        let len = usize::from(be16(&b[2..4]));
        if len < 8 || len > b.len() {
            return Err(Error::Malformed("longueur de proposition invalide"));
        }
        let (number, protocol, spi_len, ntr) = (b[4], b[5], usize::from(b[6]), usize::from(b[7]));
        if ntr > MAX_TRANSFORMS {
            return Err(Error::TooLarge("trop de transforms"));
        }
        if 8 + spi_len > len {
            return Err(Error::Malformed("SPI de proposition tronqué"));
        }
        let spi = b[8..8 + spi_len].to_vec();
        let mut t = &b[8 + spi_len..len];
        let mut transforms = Vec::new();
        for _ in 0..ntr {
            if t.len() < 8 {
                return Err(Error::Truncated);
            }
            let tl = usize::from(be16(&t[2..4]));
            if tl < 8 || tl > t.len() {
                return Err(Error::Malformed("longueur de transform invalide"));
            }
            let mut key_len = None;
            let mut a = &t[8..tl];
            while !a.is_empty() {
                if a.len() < 4 {
                    return Err(Error::Truncated);
                }
                let at = be16(&a[..2]);
                if at & 0x8000 != 0 {
                    if at & 0x7fff == 14 {
                        key_len = Some(be16(&a[2..4]));
                    }
                    a = &a[4..];
                } else {
                    let al = usize::from(be16(&a[2..4]));
                    if al > a.len() - 4 {
                        return Err(Error::Malformed("attribut TLV tronqué"));
                    }
                    a = &a[4 + al..];
                }
            }
            transforms.push(Transform {
                ty: t[4],
                id: be16(&t[6..8]),
                key_len,
            });
            t = &t[tl..];
        }
        props.push(Proposal {
            number,
            protocol,
            spi,
            transforms,
        });
        b = &b[len..];
        if more == 0 {
            break;
        }
        if more != 2 {
            return Err(Error::Malformed("marqueur de proposition invalide"));
        }
    }
    Ok(props)
}

fn decode_cp(b: &[u8]) -> Result<Cp> {
    if b.len() < 4 {
        return Err(Error::Truncated);
    }
    let cfg_type = b[0];
    let mut r = &b[4..];
    let mut attrs = Vec::new();
    while !r.is_empty() {
        if attrs.len() >= MAX_CP_ATTRS {
            return Err(Error::TooLarge("trop d'attributs CP"));
        }
        if r.len() < 4 {
            return Err(Error::Truncated);
        }
        let ty = be16(&r[..2]) & 0x7fff;
        let len = usize::from(be16(&r[2..4]));
        if len > r.len() - 4 {
            return Err(Error::Malformed("attribut CP tronqué"));
        }
        attrs.push(CpAttr {
            ty,
            value: r[4..4 + len].to_vec(),
        });
        r = &r[4 + len..];
    }
    Ok(Cp { cfg_type, attrs })
}

fn decode_ts(b: &[u8]) -> Result<Vec<TrafficSelector>> {
    if b.len() < 4 {
        return Err(Error::Truncated);
    }
    let n = usize::from(b[0]);
    if n > MAX_SELECTORS {
        return Err(Error::TooLarge("trop de selectors"));
    }
    let mut r = &b[4..];
    let mut out = Vec::new();
    for _ in 0..n {
        if r.len() < 8 {
            return Err(Error::Truncated);
        }
        let len = usize::from(be16(&r[2..4]));
        if len < 8 || len > r.len() {
            return Err(Error::Malformed("longueur de selector invalide"));
        }
        if r[0] == 7 {
            if len != 16 {
                return Err(Error::Malformed("TS_IPV4_ADDR_RANGE de taille != 16"));
            }
            out.push(TrafficSelector {
                protocol: r[1],
                start_port: be16(&r[4..6]),
                end_port: be16(&r[6..8]),
                start: arr4(&r[8..12]),
                end: arr4(&r[12..16]),
            });
        } // autres types (IPv6…) ignorés
        r = &r[len..];
    }
    Ok(out)
}

/// Message IKE décodé (le contenu d'un SK reste opaque : voir [`crate::sk`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub payloads: Vec<Payload>,
}

impl Message {
    /// Décode un message complet (un datagramme, sans marqueur non-ESP).
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let header = Header::parse(buf)?;
        let payloads = decode_chain(header.next_payload, &buf[HEADER_LEN..])?;
        Ok(Self { header, payloads })
    }

    /// Encode ; `next_payload` et `length` de l'en-tête sont recalculés.
    pub fn encode(header: &Header, payloads: &[Payload]) -> Result<Vec<u8>> {
        let (first, body) = encode_chain(payloads)?;
        let total = HEADER_LEN + body.len();
        if total > MAX_MESSAGE_LEN {
            return Err(Error::TooLarge("message IKE"));
        }
        let mut h = header.clone();
        h.next_payload = first;
        h.length = u32::try_from(total).map_err(|_| Error::TooLarge("message IKE"))?;
        let mut out = Vec::with_capacity(total);
        h.write(&mut out);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn notifies(&self) -> impl Iterator<Item = &Notify> {
        self.payloads.iter().filter_map(|p| {
            if let Payload::Notify(n) = p {
                Some(n)
            } else {
                None
            }
        })
    }
}

/// Valeur NAT_DETECTION_*_IP : SHA1(SPIi | SPIr | IP | port).
pub fn nat_detection_hash(spi_i: &[u8; 8], spi_r: &[u8; 8], ip: [u8; 4], port: u16) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(spi_i);
    h.update(spi_r);
    h.update(ip);
    h.update(port.to_be_bytes());
    h.finalize().into()
}

/// Corps d'un payload ID prêt pour l'AUTH (IDx') : type | 000 | données.
pub fn id_body(id_type: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![id_type, 0, 0, 0];
    v.extend_from_slice(data);
    v
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn arr8(b: &[u8]) -> [u8; 8] {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    a
}
fn arr4(b: &[u8]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}

/// Payload Delete (RFC 7296 §3.11) prêt à insérer dans un message : `protocol` 1 (IKE, sans SPI)
/// ou 3 (ESP, SPI de 4 octets = SPI entrant de l'émetteur).
pub fn delete_payload(protocol: u8, spis: &[u32]) -> Payload {
    let mut d = Vec::new();
    let size: u8 = if protocol == 1 { 0 } else { 4 };
    let n = if protocol == 1 { 0 } else { spis.len() };
    d.push(protocol);
    d.push(size);
    d.extend_from_slice(&u16::try_from(n).unwrap_or(0).to_be_bytes());
    if protocol != 1 {
        for s in spis {
            d.extend_from_slice(&s.to_be_bytes());
        }
    }
    Payload::Unknown {
        ty: ptype::DELETE,
        data: d,
    }
}

/// Décode un payload Delete ([`Payload::Unknown`] de type 42) : (protocole, SPI ESP de 4 octets).
pub fn parse_delete(p: &Payload) -> Option<(u8, Vec<u32>)> {
    let Payload::Unknown { ty, data } = p else {
        return None;
    };
    if *ty != ptype::DELETE || data.len() < 4 {
        return None;
    }
    let (proto, size) = (data[0], usize::from(data[1]));
    let n = usize::from(u16::from_be_bytes([data[2], data[3]]));
    let body = &data[4..];
    if proto == 1 {
        return Some((1, Vec::new()));
    }
    if size != 4 || body.len() != n * 4 {
        return None;
    }
    let spis = body
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    Some((proto, spis))
}
