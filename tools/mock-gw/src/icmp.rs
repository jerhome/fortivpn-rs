//! Réponse aux ICMP Echo Request IPv4 (docs/protocol.md §9.6, vecteurs `ip.hex`).

use std::net::Ipv4Addr;

/// TTL des réponses générées.
pub const REPLY_TTL: u8 = 64;

const IPPROTO_ICMP: u8 = 1;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;

/// Raison pour laquelle un paquet IPv4 ne reçoit pas de réponse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpDrop {
    /// En-tête IPv4 invalide (version, IHL, longueur, somme de contrôle).
    MalformedIp,
    /// Fragment (MF ou offset non nul) : non réassemblé.
    Fragment,
    /// Pas de l'ICMP.
    NotIcmp,
    /// ICMP tronqué ou somme de contrôle ICMP invalide.
    MalformedIcmp,
    /// ICMP autre qu'Echo Request (type 8, code 0).
    NotEchoRequest,
}

/// Somme de contrôle Internet (RFC 1071) de `data`.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // `sum` tient sur 16 bits après le repliement.
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// Adresses source et destination d'un paquet IPv4 (sans validation complète).
pub fn ipv4_addrs(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let src: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
    let dst: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
    Some((Ipv4Addr::from(src), Ipv4Addr::from(dst)))
}

/// Construit l'Echo Reply d'un ICMP Echo Request IPv4.
///
/// Source et destination échangées, type 0, mêmes identifiant/séquence/données, TTL
/// [`REPLY_TTL`], identifiant IP `ip_id`, TOS et drapeaux (DF) recopiés, options IP
/// recopiées, sommes de contrôle IP et ICMP recalculées. Le bourrage au-delà de la
/// longueur totale IP est ignoré.
pub fn icmp_echo_reply(request: &[u8], ip_id: u16) -> Result<Vec<u8>, IcmpDrop> {
    let first = *request.first().ok_or(IcmpDrop::MalformedIp)?;
    let ihl = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || ihl < 20 || request.len() < ihl {
        return Err(IcmpDrop::MalformedIp);
    }
    let total = usize::from(u16::from_be_bytes([request[2], request[3]]));
    if total < ihl || total > request.len() || internet_checksum(&request[..ihl]) != 0 {
        return Err(IcmpDrop::MalformedIp);
    }
    let flags_frag = u16::from_be_bytes([request[6], request[7]]);
    if flags_frag & 0x3fff != 0 {
        return Err(IcmpDrop::Fragment);
    }
    if request[9] != IPPROTO_ICMP {
        return Err(IcmpDrop::NotIcmp);
    }
    let icmp = &request[ihl..total];
    if icmp.len() < 8 || internet_checksum(icmp) != 0 {
        return Err(IcmpDrop::MalformedIcmp);
    }
    if icmp[0] != ICMP_ECHO_REQUEST || icmp[1] != 0 {
        return Err(IcmpDrop::NotEchoRequest);
    }

    let mut reply = request[..total].to_vec();
    reply[4..6].copy_from_slice(&ip_id.to_be_bytes());
    reply[8] = REPLY_TTL;
    reply[10..12].fill(0);
    let (src, dst) = (request[12..16].to_vec(), request[16..20].to_vec());
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);
    let ip_sum = internet_checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let icmp = &mut reply[ihl..];
    icmp[0] = ICMP_ECHO_REPLY;
    icmp[2..4].fill(0);
    let icmp_sum = internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_sum.to_be_bytes());
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071_example() {
        // Exemple de la RFC 1071 §3 : somme 0xddf2 -> complément 0x220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), 0x220d);
        // Longueur impaire : octet final complété par 0.
        assert_eq!(internet_checksum(&[0xff]), 0x00ff);
        assert_eq!(internet_checksum(&[]), 0xffff);
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        assert_eq!(icmp_echo_reply(&[], 1), Err(IcmpDrop::MalformedIp));
        assert_eq!(icmp_echo_reply(&[0x45], 1), Err(IcmpDrop::MalformedIp));
        assert_eq!(icmp_echo_reply(&[0x60; 40], 1), Err(IcmpDrop::MalformedIp));
        assert_eq!(icmp_echo_reply(&[0x44; 40], 1), Err(IcmpDrop::MalformedIp));
        for len in 0u8..64 {
            let buf: Vec<u8> = (0..len)
                .map(|i| i.wrapping_mul(37).wrapping_add(0x45))
                .collect();
            let _ = icmp_echo_reply(&buf, 1);
        }
    }
}
