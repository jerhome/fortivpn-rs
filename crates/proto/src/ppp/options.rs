//! Options de configuration TLV `type | length | valeur` (§9.1, §9.2, §9.4).

use std::net::Ipv4Addr;

use bytes::{BufMut, Bytes, BytesMut};

use super::packet::PacketError;

/// Option brute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigOption {
    kind: u8,
    value: Bytes,
}

impl ConfigOption {
    /// Longueur maximale d'une valeur (`length` sur 1 octet, TLV inclus).
    pub const MAX_VALUE_LEN: usize = 253;

    /// Construit une option ; échoue si la valeur dépasse 253 octets.
    pub fn new(kind: u8, value: Bytes) -> Result<Self, PacketError> {
        if value.len() > Self::MAX_VALUE_LEN {
            return Err(PacketError::OptionTooLong(value.len()));
        }
        Ok(Self { kind, value })
    }

    /// Type.
    pub fn kind(&self) -> u8 {
        self.kind
    }

    /// Valeur (sans type ni longueur).
    pub fn value(&self) -> &Bytes {
        &self.value
    }

    fn from_slice(kind: u8, value: &[u8]) -> Self {
        // Appelé uniquement avec des valeurs de taille fixe ≤ 4.
        Self {
            kind,
            value: Bytes::copy_from_slice(value),
        }
    }

    pub(crate) fn value_u16(&self) -> Option<u16> {
        let v: [u8; 2] = self.value[..].try_into().ok()?;
        Some(u16::from_be_bytes(v))
    }

    pub(crate) fn value_u32(&self) -> Option<u32> {
        let v: [u8; 4] = self.value[..].try_into().ok()?;
        Some(u32::from_be_bytes(v))
    }

    pub(crate) fn value_ipv4(&self) -> Option<Ipv4Addr> {
        self.value_u32().map(Ipv4Addr::from)
    }

    fn encoded_len(&self) -> u8 {
        // value.len() <= 253 garanti par construction.
        u8::try_from(self.value.len() + 2).unwrap_or(u8::MAX)
    }
}

/// Analyse une suite d'options. Erreur si une option a une longueur < 2 ou déborde.
pub fn parse_options(data: &Bytes) -> Result<Vec<ConfigOption>, PacketError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let kind = data[pos];
        let len = usize::from(*data.get(pos + 1).ok_or(PacketError::MalformedOption)?);
        if len < 2 || pos + len > data.len() {
            return Err(PacketError::MalformedOption);
        }
        out.push(ConfigOption {
            kind,
            value: data.slice(pos + 2..pos + len),
        });
        pos += len;
    }
    Ok(out)
}

/// Sérialise une suite d'options.
pub fn encode_options(options: &[ConfigOption], dst: &mut BytesMut) {
    for o in options {
        dst.put_u8(o.kind);
        dst.put_u8(o.encoded_len());
        dst.put_slice(&o.value);
    }
}

/// Option LCP typée (RFC 1661).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LcpOption {
    /// 1 : Maximum-Receive-Unit.
    Mru(u16),
    /// 2 : Async-Control-Character-Map.
    Accm(u32),
    /// 3 : Authentication-Protocol (valeur brute).
    AuthProtocol(Bytes),
    /// 5 : Magic-Number.
    MagicNumber(u32),
    /// 7 : Protocol-Field-Compression.
    Pfc,
    /// 8 : Address-and-Control-Field-Compression.
    Acfc,
    /// Option inconnue ou de longueur invalide.
    Other(ConfigOption),
}

impl LcpOption {
    /// Type MRU.
    pub const MRU: u8 = 1;
    /// Type ACCM.
    pub const ACCM: u8 = 2;
    /// Type Authentication-Protocol.
    pub const AUTH: u8 = 3;
    /// Type Magic-Number.
    pub const MAGIC: u8 = 5;
    /// Type PFC.
    pub const PFC: u8 = 7;
    /// Type ACFC.
    pub const ACFC: u8 = 8;

    /// Interprète une option brute ; longueur non conforme → [`LcpOption::Other`].
    pub fn from_option(o: &ConfigOption) -> Self {
        match o.kind {
            Self::MRU => o.value_u16().map(Self::Mru),
            Self::ACCM => o.value_u32().map(Self::Accm),
            Self::AUTH if o.value.len() >= 2 => Some(Self::AuthProtocol(o.value.clone())),
            Self::MAGIC => o.value_u32().map(Self::MagicNumber),
            Self::PFC if o.value.is_empty() => Some(Self::Pfc),
            Self::ACFC if o.value.is_empty() => Some(Self::Acfc),
            _ => None,
        }
        .unwrap_or_else(|| Self::Other(o.clone()))
    }

    /// Option brute.
    pub fn to_option(&self) -> ConfigOption {
        match self {
            Self::Mru(v) => ConfigOption::from_slice(Self::MRU, &v.to_be_bytes()),
            Self::Accm(v) => ConfigOption::from_slice(Self::ACCM, &v.to_be_bytes()),
            Self::AuthProtocol(v) => ConfigOption {
                kind: Self::AUTH,
                value: v.slice(..v.len().min(ConfigOption::MAX_VALUE_LEN)),
            },
            Self::MagicNumber(v) => ConfigOption::from_slice(Self::MAGIC, &v.to_be_bytes()),
            Self::Pfc => ConfigOption::from_slice(Self::PFC, &[]),
            Self::Acfc => ConfigOption::from_slice(Self::ACFC, &[]),
            Self::Other(o) => o.clone(),
        }
    }
}

/// Option IPCP typée (RFC 1332, RFC 1877).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcpOption {
    /// 3 : IP-Address.
    IpAddress(Ipv4Addr),
    /// 129 : Primary-DNS-Address.
    PrimaryDns(Ipv4Addr),
    /// 131 : Secondary-DNS-Address.
    SecondaryDns(Ipv4Addr),
    /// Option inconnue (VJ, NBNS…) ou de longueur invalide.
    Other(ConfigOption),
}

impl IpcpOption {
    /// Type IP-Address.
    pub const IP_ADDRESS: u8 = 3;
    /// Type Primary-DNS-Address.
    pub const PRIMARY_DNS: u8 = 129;
    /// Type Secondary-DNS-Address.
    pub const SECONDARY_DNS: u8 = 131;

    /// Interprète une option brute ; longueur non conforme → [`IpcpOption::Other`].
    pub fn from_option(o: &ConfigOption) -> Self {
        match o.kind {
            Self::IP_ADDRESS => o.value_ipv4().map(Self::IpAddress),
            Self::PRIMARY_DNS => o.value_ipv4().map(Self::PrimaryDns),
            Self::SECONDARY_DNS => o.value_ipv4().map(Self::SecondaryDns),
            _ => None,
        }
        .unwrap_or_else(|| Self::Other(o.clone()))
    }

    /// Option brute.
    pub fn to_option(&self) -> ConfigOption {
        match self {
            Self::IpAddress(a) => ConfigOption::from_slice(Self::IP_ADDRESS, &a.octets()),
            Self::PrimaryDns(a) => ConfigOption::from_slice(Self::PRIMARY_DNS, &a.octets()),
            Self::SecondaryDns(a) => ConfigOption::from_slice(Self::SECONDARY_DNS, &a.octets()),
            Self::Other(o) => o.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_options_are_errors() {
        assert!(parse_options(&Bytes::from_static(&[1])).is_err());
        assert!(parse_options(&Bytes::from_static(&[1, 1])).is_err());
        assert!(parse_options(&Bytes::from_static(&[1, 5, 0, 0])).is_err());
        assert!(parse_options(&Bytes::new()).unwrap().is_empty());
    }

    #[test]
    fn typed_roundtrip() {
        for o in [
            LcpOption::Mru(1354),
            LcpOption::Accm(0),
            LcpOption::MagicNumber(0x1a2b_3c4d),
            LcpOption::Pfc,
            LcpOption::Acfc,
            LcpOption::AuthProtocol(Bytes::from_static(&[0xc0, 0x23])),
        ] {
            assert_eq!(LcpOption::from_option(&o.to_option()), o);
        }
        // Longueur invalide -> Other.
        let bad = ConfigOption::new(1, Bytes::from_static(&[5])).unwrap();
        assert_eq!(LcpOption::from_option(&bad), LcpOption::Other(bad.clone()));
        for o in [
            IpcpOption::IpAddress(Ipv4Addr::new(10, 10, 0, 2)),
            IpcpOption::PrimaryDns(Ipv4Addr::new(10, 0, 0, 53)),
            IpcpOption::SecondaryDns(Ipv4Addr::new(10, 0, 0, 54)),
        ] {
            assert_eq!(IpcpOption::from_option(&o.to_option()), o);
        }
        assert!(ConfigOption::new(1, Bytes::from(vec![0; 254])).is_err());
    }
}
