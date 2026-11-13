//! Appels système Windows (IP Helper, registre NRPT et journal, cache DNS)
//! encapsulés dans des fonctions sûres, et leur assemblage en [`WinOps`] et
//! [`RegistryStore`].
//!
//! Règles : chaque bloc `unsafe` est minimal et justifié (`// SAFETY:`) ; les
//! `HKEY` sont possédés par [`OwnedKey`] (fermeture garantie au `Drop`) ; aucun
//! pointeur passé à l'OS ne survit à l'appel.
#![allow(unsafe_code)]

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use fortivpn_core::NetError;
use ipnet::{Ipv4Net, Ipv6Net};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_HOST_UNREACHABLE, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
    ERROR_NETWORK_UNREACHABLE, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED,
    ERROR_OBJECT_ALREADY_EXISTS, ERROR_PATH_NOT_FOUND, NO_ERROR, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceGuidToLuid, ConvertInterfaceIndexToLuid,
    ConvertInterfaceLuidToGuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER,
    DNS_SETTING_SEARCHLIST, DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, GetBestRoute2,
    GetIpForwardEntry2, GetIpInterfaceEntry, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IpDadStatePreferred,
    MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_MULTI_SZ,
    REG_OPEN_CREATE_OPTIONS, REG_OPTION_NON_VOLATILE, REG_OPTION_VOLATILE, REG_SZ, REG_VALUE_TYPE,
    RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW, RegEnumKeyExW,
    RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};
use windows_sys::core::GUID;

use crate::engine::{Action, Applied, SystemOps, Underlay};
use crate::plan::{self, NrptRule};
use crate::state::{self, Installed, JournalStore};

// ---------------------------------------------------------------------------
// Erreurs et conversions
// ---------------------------------------------------------------------------

fn win_err(op: &'static str, code: WIN32_ERROR) -> NetError {
    NetError::Io {
        op,
        // Les codes Win32 tiennent sur 31 bits : conversion sans perte.
        source: io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
    }
}

fn check(op: &'static str, code: WIN32_ERROR) -> Result<(), NetError> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(win_err(op, code))
    }
}

/// Codes signifiant « objet (ou interface) introuvable ».
fn is_absent(code: WIN32_ERROR) -> bool {
    matches!(
        code,
        ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND
    )
}

/// Retrait tolérant : un objet déjà absent n'est pas une erreur.
fn check_removed(op: &'static str, code: WIN32_ERROR) -> Result<(), NetError> {
    if code == NO_ERROR || is_absent(code) {
        Ok(())
    } else {
        Err(win_err(op, code))
    }
}

fn net_luid(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

fn luid_value(luid: NET_LUID_LH) -> u64 {
    // SAFETY: les deux membres de l'union recouvrent les mêmes 8 octets de
    // données entières ; tout motif de bits est un `u64` valide.
    unsafe { luid.Value }
}

fn sockaddr_v4(addr: Ipv4Addr) -> SOCKADDR_INET {
    // Part d'une union entièrement à zéro (pas d'octets non initialisés
    // transmis à l'OS), puis écrit la variante IPv4 (écriture sûre).
    let mut sa = SOCKADDR_INET::default();
    sa.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                // Ordre réseau : les octets en mémoire sont ceux de l'adresse.
                S_addr: u32::from_ne_bytes(addr.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    sa
}

fn sockaddr_v6(addr: Ipv6Addr) -> SOCKADDR_INET {
    // Même principe que `sockaddr_v4` : union à zéro puis variante IPv6.
    let mut sa = SOCKADDR_INET::default();
    sa.Ipv6 = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: addr.octets(),
            },
        },
        ..SOCKADDR_IN6::default()
    };
    sa
}

fn sockaddr_to_v4(sa: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    // SAFETY: `si_family` est le premier champ (u16) commun à toutes les
    // variantes ; lecture d'un entier, tout motif de bits est valide.
    let family = unsafe { sa.si_family };
    if family != AF_INET {
        return None;
    }
    // SAFETY: famille AF_INET : la variante `Ipv4` est active ; `S_addr` est un
    // entier (tout motif de bits valide).
    let raw = unsafe { sa.Ipv4.sin_addr.S_un.S_addr };
    Some(Ipv4Addr::from(raw.to_ne_bytes()))
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/// `NET_LUID` d'une interface à partir de son index.
pub(crate) fn luid_from_index(index: u32) -> Result<u64, NetError> {
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `luid` est une sortie locale valide pour l'écriture.
    let code = unsafe { ConvertInterfaceIndexToLuid(index, &raw mut luid) };
    check("luid_from_index", code)?;
    Ok(luid_value(luid))
}

/// `NET_LUID` d'une interface à partir de son nom (alias).
pub(crate) fn luid_from_alias(alias: &str) -> Result<u64, NetError> {
    let wide = plan::to_wide(alias);
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `wide` est terminé par NUL et vit pendant l'appel ; `luid` est
    // une sortie locale valide.
    let code = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &raw mut luid) };
    check("luid_from_alias", code)?;
    Ok(luid_value(luid))
}

/// `NET_LUID` de l'interface de GUID `guid` ; `Ok(None)` si elle n'existe pas.
///
/// Sert à identifier notre adaptateur Wintun sans passer par son alias (que
/// n'importe quelle autre interface peut porter : revue 5.3, F3).
pub(crate) fn luid_from_guid(guid: u128) -> Result<Option<u64>, NetError> {
    let guid = GUID::from_u128(guid);
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `guid` et `luid` sont des valeurs locales valides pour la
    // lecture / l'écriture pendant l'appel.
    let code = unsafe { ConvertInterfaceGuidToLuid(&raw const guid, &raw mut luid) };
    if is_absent(code) || code == ERROR_INVALID_PARAMETER {
        return Ok(None);
    }
    check("luid_from_guid", code)?;
    Ok(Some(luid_value(luid)))
}

/// GUID de l'interface ; `Ok(None)` si elle n'existe plus.
fn guid_from_luid(luid: u64) -> Result<Option<GUID>, NetError> {
    let luid = net_luid(luid);
    let mut guid = GUID::from_u128(0);
    // SAFETY: `luid` et `guid` sont des valeurs locales valides pour la
    // lecture / l'écriture pendant l'appel.
    let code = unsafe { ConvertInterfaceLuidToGuid(&raw const luid, &raw mut guid) };
    if is_absent(code) {
        return Ok(None);
    }
    check("luid_to_guid", code)?;
    Ok(Some(guid))
}

/// MTU IPv4 et métrique fixe de l'interface.
fn set_interface(luid: u64, mtu: u16, metric: u32) -> Result<(), NetError> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: `row` est une structure locale valide, initialisée par l'API.
    unsafe { InitializeIpInterfaceEntry(&raw mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = net_luid(luid);
    // SAFETY: `row` est valide en lecture/écriture ; Family et InterfaceLuid
    // sont renseignés comme l'exige l'API.
    check("get_interface", unsafe {
        GetIpInterfaceEntry(&raw mut row)
    })?;
    row.NlMtu = u32::from(mtu);
    row.UseAutomaticMetric = false;
    row.Metric = metric;
    // Exigé pour IPv4, sinon ERROR_INVALID_PARAMETER.
    row.SitePrefixLength = 0;
    // SAFETY: `row` est une ligne complète obtenue de GetIpInterfaceEntry.
    check("set_interface", unsafe {
        SetIpInterfaceEntry(&raw mut row)
    })
}

/// Active IPv6 sur l'interface : métrique fixe, MTU si ≥ 1280 (minimum IPv6).
/// `Ok(false)` si la pile IPv6 n'est pas liée à l'interface.
fn set_interface_v6(luid: u64, mtu: u16, metric: u32) -> Result<bool, NetError> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: `row` est une structure locale valide, initialisée par l'API.
    unsafe { InitializeIpInterfaceEntry(&raw mut row) };
    row.Family = AF_INET6;
    row.InterfaceLuid = net_luid(luid);
    // SAFETY: `row` est valide en lecture/écriture ; Family et InterfaceLuid
    // sont renseignés comme l'exige l'API.
    let code = unsafe { GetIpInterfaceEntry(&raw mut row) };
    if is_absent(code) {
        return Ok(false);
    }
    check("get_interface6", code)?;
    if mtu >= 1280 {
        row.NlMtu = u32::from(mtu);
    }
    row.UseAutomaticMetric = false;
    row.Metric = metric;
    // SAFETY: `row` est une ligne complète obtenue de GetIpInterfaceEntry.
    check("set_interface6", unsafe {
        SetIpInterfaceEntry(&raw mut row)
    })?;
    Ok(true)
}

/// Vrai si une route IPv6 vers l'Internet existe (aucun paquet émis).
fn has_ipv6_route() -> Result<bool, NetError> {
    // 2001:4860:4860::8888 : adresse globale quelconque, seule la table de
    // routage est consultée.
    let dst = sockaddr_v6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut src = SOCKADDR_INET::default();
    // SAFETY: `dst`, `row` et `src` sont des valeurs locales valides ; LUID et
    // adresse source nuls sont autorisés.
    let code = unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &raw const dst,
            0,
            &raw mut row,
            &raw mut src,
        )
    };
    match code {
        NO_ERROR => Ok(true),
        c if is_absent(c)
            || matches!(
                c,
                ERROR_NETWORK_UNREACHABLE
                    | ERROR_HOST_UNREACHABLE
                    | ERROR_NOT_SUPPORTED
                    | ERROR_INVALID_PARAMETER
            ) =>
        {
            Ok(false)
        }
        c => Err(win_err("best_route6", c)),
    }
}

// ---------------------------------------------------------------------------
// Adresses et routes
// ---------------------------------------------------------------------------

fn unicast_row(luid: u64, address: Ipv4Net) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` est une structure locale valide, initialisée par l'API.
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };
    row.Address = sockaddr_v4(address.addr());
    row.InterfaceLuid = net_luid(luid);
    row.OnLinkPrefixLength = address.prefix_len();
    // Pas de détection de doublon : l'adresse est utilisable immédiatement.
    row.DadState = IpDadStatePreferred;
    row
}

fn add_address(luid: u64, address: Ipv4Net) -> Result<Applied, NetError> {
    let row = unicast_row(luid, address);
    // SAFETY: `row` est une ligne valide (InitializeUnicastIpAddressEntry +
    // champs requis) qui vit pendant l'appel.
    let code = unsafe { CreateUnicastIpAddressEntry(&raw const row) };
    if code == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(Applied::AlreadyPresent);
    }
    check("add_address", code)?;
    Ok(Applied::Created)
}

fn remove_address(luid: u64, address: Ipv4Net) -> Result<(), NetError> {
    let row = unicast_row(luid, address);
    // SAFETY: `row` est une ligne valide (clé : interface + adresse).
    let code = unsafe { DeleteUnicastIpAddressEntry(&raw const row) };
    check_removed("remove_address", code)
}

/// Clé d'une route (interface, préfixe, prochain saut), IPv4 ou IPv6.
#[derive(Clone, Copy)]
struct RouteKey {
    luid: u64,
    prefix: SOCKADDR_INET,
    prefix_len: u8,
    next_hop: SOCKADDR_INET,
}

impl RouteKey {
    fn v4(luid: u64, dest: Ipv4Net, next_hop: Ipv4Addr) -> Self {
        Self {
            luid,
            prefix: sockaddr_v4(dest.network()),
            prefix_len: dest.prefix_len(),
            next_hop: sockaddr_v4(next_hop),
        }
    }

    /// Route IPv6 on-link (prochain saut `::`).
    fn v6(luid: u64, dest: Ipv6Net) -> Self {
        Self {
            luid,
            prefix: sockaddr_v6(dest.network()),
            prefix_len: dest.prefix_len(),
            next_hop: sockaddr_v6(Ipv6Addr::UNSPECIFIED),
        }
    }

    /// Clé d'une entrée de journal de type route.
    fn of(item: &Installed) -> Option<Self> {
        match item {
            Installed::Route {
                luid,
                dest,
                next_hop,
            } => Some(Self::v4(*luid, *dest, *next_hop)),
            Installed::Route6 { luid, dest } => Some(Self::v6(*luid, *dest)),
            _ => None,
        }
    }

    fn row(&self, metric: u32) -> MIB_IPFORWARD_ROW2 {
        let mut row = MIB_IPFORWARD_ROW2::default();
        // SAFETY: `row` est une structure locale valide, initialisée par l'API
        // (durées de vie infinies, valeurs par défaut).
        unsafe { InitializeIpForwardEntry(&raw mut row) };
        row.InterfaceLuid = net_luid(self.luid);
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: self.prefix,
            PrefixLength: self.prefix_len,
        };
        row.NextHop = self.next_hop;
        row.Metric = metric;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row
    }
}

fn add_route(key: &RouteKey, metric: u32) -> Result<Applied, NetError> {
    let row = key.row(metric);
    // SAFETY: `row` est une ligne valide qui vit pendant l'appel.
    let code = unsafe { CreateIpForwardEntry2(&raw const row) };
    if code == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(Applied::AlreadyPresent);
    }
    check("add_route", code)?;
    Ok(Applied::Created)
}

fn remove_route(key: &RouteKey) -> Result<(), NetError> {
    let row = key.row(0);
    // SAFETY: `row` est une ligne valide (clé : interface, préfixe, prochain saut).
    let code = unsafe { DeleteIpForwardEntry2(&raw const row) };
    check_removed("remove_route", code)
}

/// Vrai si la route existe avec nos marques (protocole `NETMGMT`, métrique
/// [`plan::ROUTE_METRIC`]) : condition pour la retirer d'après un journal
/// relu (revue 5.3, E1).
fn route_is_ours(key: &RouteKey) -> Result<bool, NetError> {
    let mut row = key.row(0);
    // SAFETY: `row` est une ligne locale valide en lecture/écriture ; la clé
    // (interface, préfixe, prochain saut) est renseignée comme l'exige l'API.
    let code = unsafe { GetIpForwardEntry2(&raw mut row) };
    if is_absent(code) {
        return Ok(false);
    }
    check("get_route", code)?;
    Ok(row.Protocol == MIB_IPPROTO_NETMGMT && row.Metric == plan::ROUTE_METRIC)
}

fn best_route(dest: Ipv4Addr) -> Result<Underlay, NetError> {
    let dst = sockaddr_v4(dest);
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut src = SOCKADDR_INET::default();
    // SAFETY: `dst`, `row` et `src` sont des valeurs locales valides ; LUID et
    // adresse source nuls sont autorisés (« toute interface / toute source »).
    let code = unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &raw const dst,
            0,
            &raw mut row,
            &raw mut src,
        )
    };
    check("best_route", code)?;
    let next_hop = sockaddr_to_v4(&row.NextHop).ok_or_else(|| NetError::Os {
        op: "best_route",
        reason: format!("prochain saut non IPv4 vers {dest}"),
    })?;
    Ok(Underlay {
        luid: luid_value(row.InterfaceLuid),
        next_hop,
    })
}

// ---------------------------------------------------------------------------
// DNS de l'interface
// ---------------------------------------------------------------------------

fn set_interface_dns(luid: u64, servers: &str, search: &str) -> Result<(), NetError> {
    let Some(guid) = guid_from_luid(luid)? else {
        return Err(win_err("set_dns", ERROR_NOT_FOUND));
    };
    write_interface_dns(guid, servers, search)
}

fn clear_interface_dns(luid: u64) -> Result<(), NetError> {
    match guid_from_luid(luid)? {
        // Interface disparue : ses réglages DNS aussi.
        None => Ok(()),
        Some(guid) => match write_interface_dns(guid, "", "") {
            Err(NetError::Io { source, .. })
                if source
                    .raw_os_error()
                    .and_then(|c| u32::try_from(c).ok())
                    .is_some_and(is_absent) =>
            {
                Ok(())
            }
            other => other,
        },
    }
}

fn write_interface_dns(guid: GUID, servers: &str, search: &str) -> Result<(), NetError> {
    let mut servers_w = plan::to_wide(servers);
    let mut search_w = plan::to_wide(search);
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST),
        NameServer: servers_w.as_mut_ptr(),
        SearchList: search_w.as_mut_ptr(),
        ..DNS_INTERFACE_SETTINGS::default()
    };
    // SAFETY: `settings` et les chaînes UTF-16 terminées par NUL qu'elle pointe
    // vivent jusqu'au retour ; l'API ne conserve pas les pointeurs ; seuls les
    // champs annoncés par `Flags` sont lus.
    let code = unsafe { SetInterfaceDnsSettings(guid, &raw const settings) };
    check("set_dns", code)
}

// ---------------------------------------------------------------------------
// Registre (NRPT)
// ---------------------------------------------------------------------------

/// Racine des règles NRPT locales (hors stratégie de groupe).
const NRPT_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// Racine des règles NRPT de stratégie de groupe : dès qu'elle contient des
/// règles, Windows ignore les règles locales. Lue seulement, jamais écrite
/// (décision produit, revue 5.3 M3).
const NRPT_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

/// `ConfigOptions` : utiliser `GenericDNSServers`.
const NRPT_CONFIG_GENERIC_DNS: u32 = 0x8;
/// Version du format de règle.
const NRPT_RULE_VERSION: u32 = 0x2;

/// Clé de registre ouverte, fermée au `Drop`.
#[derive(Debug)]
struct OwnedKey(HKEY);

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: la clé a été ouverte par RegCreateKeyExW/RegOpenKeyExW, est
        // possédée exclusivement par ce wrapper et n'est fermée qu'ici, une fois.
        let code = unsafe { RegCloseKey(self.0) };
        if code != NO_ERROR {
            tracing::warn!(code, "RegCloseKey a échoué");
        }
    }
}

/// Crée (ou ouvre) une clé sous `HKLM` en écriture. Une clé volatile
/// (`REG_OPTION_VOLATILE`) disparaît au redémarrage ; l'option est ignorée si
/// la clé existe déjà.
fn create_key(
    op: &'static str,
    path: &str,
    options: REG_OPEN_CREATE_OPTIONS,
) -> Result<OwnedKey, NetError> {
    let wpath = plan::to_wide(path);
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `wpath` est terminé par NUL et vit pendant l'appel ; `key` est
    // une sortie locale valide ; classe, attributs de sécurité et disposition
    // facultatifs (pointeurs nuls autorisés).
    let code = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            wpath.as_ptr(),
            0,
            ptr::null(),
            options,
            KEY_WRITE,
            ptr::null(),
            &raw mut key,
            ptr::null_mut(),
        )
    };
    check(op, code)?;
    Ok(OwnedKey(key))
}

/// Ouvre une clé en lecture ; `Ok(None)` si elle n'existe pas.
fn open_key_read(path: &str) -> Result<Option<OwnedKey>, NetError> {
    let wpath = plan::to_wide(path);
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `wpath` est terminé par NUL et vit pendant l'appel ; `key` est
    // une sortie locale valide.
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wpath.as_ptr(),
            0,
            KEY_READ,
            &raw mut key,
        )
    };
    if is_absent(code) {
        return Ok(None);
    }
    check("nrpt_open", code)?;
    Ok(Some(OwnedKey(key)))
}

fn set_value(
    key: &OwnedKey,
    name: &str,
    kind: REG_VALUE_TYPE,
    data: &[u8],
) -> Result<(), NetError> {
    let wname = plan::to_wide(name);
    let len = u32::try_from(data.len()).map_err(|_| NetError::Os {
        op: "reg_set_value",
        reason: "valeur trop grande".into(),
    })?;
    // SAFETY: clé ouverte en écriture ; `wname` terminé par NUL ; `data` est
    // lisible sur `len` octets ; aucun pointeur conservé après l'appel.
    let code = unsafe { RegSetValueExW(key.0, wname.as_ptr(), 0, kind, data.as_ptr(), len) };
    check("reg_set_value", code)
}

fn set_sz(key: &OwnedKey, name: &str, value: &str) -> Result<(), NetError> {
    set_value(key, name, REG_SZ, &plan::wide_bytes(&plan::to_wide(value)))
}

fn set_multi_sz(key: &OwnedKey, name: &str, values: &[String]) -> Result<(), NetError> {
    set_value(
        key,
        name,
        REG_MULTI_SZ,
        &plan::wide_bytes(&plan::to_multi_sz(values)),
    )
}

fn set_dword(key: &OwnedKey, name: &str, value: u32) -> Result<(), NetError> {
    set_value(key, name, REG_DWORD, &value.to_le_bytes())
}

fn delete_key(path: &str) -> Result<(), NetError> {
    let wpath = plan::to_wide(path);
    // SAFETY: `wpath` est terminé par NUL et vit pendant l'appel.
    let code = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, wpath.as_ptr()) };
    check_removed("nrpt_delete", code)
}

fn rule_path(name: &str) -> Result<String, NetError> {
    // Défense en profondeur : jamais d'écriture/suppression hors de nos règles.
    if !plan::is_our_nrpt_rule(name) {
        return Err(NetError::Os {
            op: "nrpt",
            reason: format!("nom de règle NRPT inattendu : {name}"),
        });
    }
    Ok(format!(r"{NRPT_KEY}\{name}"))
}

fn write_nrpt_rule(rule: &NrptRule) -> Result<Applied, NetError> {
    let path = rule_path(&rule.name)?;
    // Parent non volatil (une clé volatile ne peut pas avoir de sous-clé
    // persistante : ne pas gêner `Add-DnsClientNrptRule` ensuite) ; notre
    // règle volatile : elle disparaît au redémarrage même après un crash
    // (revue 5.3, F5 — prise en compte par Dnscache à valider en 3.W).
    drop(create_key(
        "nrpt_create",
        NRPT_KEY,
        REG_OPTION_NON_VOLATILE,
    )?);
    let key = create_key("nrpt_create", &path, REG_OPTION_VOLATILE)?;
    let result = (|| {
        set_dword(&key, "Version", NRPT_RULE_VERSION)?;
        set_multi_sz(&key, "Name", &rule.namespaces)?;
        set_sz(
            &key,
            "GenericDNSServers",
            &plan::nrpt_servers_value(&rule.servers),
        )?;
        set_dword(&key, "ConfigOptions", NRPT_CONFIG_GENERIC_DNS)?;
        set_sz(&key, "IPSECCARestriction", "")?;
        set_sz(&key, "DisplayName", plan::NRPT_DISPLAY_NAME)?;
        set_sz(&key, "Comment", plan::NRPT_DISPLAY_NAME)
    })();
    drop(key);
    if let Err(e) = result {
        if let Err(de) = delete_key(&path) {
            tracing::warn!(error = %de, "règle NRPT incomplète non supprimée");
        }
        return Err(e);
    }
    // Une règle de même nom (résidu) est écrasée : le préfixe nous appartient.
    Ok(Applied::Created)
}

fn list_nrpt_rules() -> Result<Vec<String>, NetError> {
    list_subkeys(NRPT_KEY)
}

/// Vrai si la racine NRPT de stratégie de groupe contient au moins une règle.
fn nrpt_policy_active() -> Result<bool, NetError> {
    Ok(!list_subkeys(NRPT_POLICY_KEY)?.is_empty())
}

/// Noms des sous-clés de `HKLM\path` (vide si la clé n'existe pas). Les noms
/// de plus de 255 caractères sont ignorés.
fn list_subkeys(path: &str) -> Result<Vec<String>, NetError> {
    let Some(key) = open_key_read(path)? else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    // Les noms de clé font au plus 255 caractères.
    let mut buf = [0u16; 256];
    for index in 0u32.. {
        let mut len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: clé ouverte en lecture ; `buf` est inscriptible sur `len`
        // unités UTF-16 ; les sorties facultatives (classe, date) sont nulles.
        let code = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                buf.as_mut_ptr(),
                &raw mut len,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        match code {
            NO_ERROR => {
                let n = usize::try_from(len).unwrap_or(0).min(buf.len());
                names.push(String::from_utf16_lossy(&buf[..n]));
            }
            ERROR_NO_MORE_ITEMS => break,
            // Nom trop long : ne peut pas être une de nos règles.
            ERROR_MORE_DATA => {}
            other => return Err(win_err("nrpt_enum", other)),
        }
    }
    Ok(names)
}

/// Vide le cache du résolveur DNS sans lancer de processus
/// (`dnsapi!DnsFlushResolverCache`, non documentée mais stable, utilisée par
/// `ipconfig /flushdns`).
fn flush_resolver_cache() -> Result<(), NetError> {
    use libloading::os::windows::{LOAD_LIBRARY_SEARCH_SYSTEM32, Library};

    let os_err = |e: libloading::Error| NetError::Os {
        op: "flush_dns",
        reason: e.to_string(),
    };
    // SAFETY: DLL système chargée depuis System32 uniquement (aucun
    // détournement par le chemin de recherche) ; son DllMain n'a pas de
    // précondition.
    let lib = unsafe { Library::load_with_flags("dnsapi.dll", LOAD_LIBRARY_SEARCH_SYSTEM32) }
        .map_err(os_err)?;
    // SAFETY: `DnsFlushResolverCache` est exportée par dnsapi.dll avec la
    // signature `BOOL WINAPI DnsFlushResolverCache(void)`.
    let flush =
        unsafe { lib.get::<unsafe extern "system" fn() -> i32>(b"DnsFlushResolverCache\0") }
            .map_err(os_err)?;
    // SAFETY: fonction sans argument ; `flush` emprunte `lib`, qui reste donc
    // chargée pendant l'appel.
    let ok = unsafe { flush() };
    if ok == 0 {
        return Err(NetError::Io {
            op: "flush_dns",
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Journal d'état (registre)
// ---------------------------------------------------------------------------

/// Journal dans la valeur `REG_SZ` `HKLM\SOFTWARE\fortivpn-rs\NetwinState`
/// (revue 5.3, C1) : clé modifiable par les seuls administrateurs / SYSTEM
/// (ACL héritée de `HKLM\SOFTWARE`), aucune opération sur le système de
/// fichiers, écriture d'une valeur atomique. Contenu borné à la relecture
/// ([`state::decode_state`]).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RegistryStore;

/// Taille maximale acceptée de la valeur (UTF-16 + NUL), en octets.
const STATE_MAX_VALUE_BYTES: usize = (state::MAX_STATE_BYTES + 1) * 2;

impl JournalStore for RegistryStore {
    fn load(&mut self) -> Result<Vec<Installed>, NetError> {
        let Some(key) = open_key_read(state::STATE_REG_KEY)? else {
            return Ok(Vec::new());
        };
        let wname = plan::to_wide(state::STATE_REG_VALUE);
        // Taille d'abord : rien n'est alloué au-delà de la borne.
        let mut size: u32 = 0;
        // SAFETY: clé ouverte en lecture ; `wname` terminé par NUL ; tampon
        // nul + `size` : l'API ne retourne que la taille requise.
        let code = unsafe {
            RegGetValueW(
                key.0,
                ptr::null(),
                wname.as_ptr(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut size,
            )
        };
        if is_absent(code) {
            return Ok(Vec::new());
        }
        check("state_read", code)?;
        let len = usize::try_from(size).unwrap_or(usize::MAX);
        if len > STATE_MAX_VALUE_BYTES {
            return Err(NetError::Os {
                op: "state_read",
                reason: format!("journal trop grand : {len} octets"),
            });
        }
        // +1 unité : marge pour le NUL qu'ajoute RegGetValueW s'il manque.
        let mut buf = vec![0u16; len.div_ceil(2) + 1];
        let mut size = u32::try_from(buf.len() * 2).unwrap_or(0);
        // SAFETY: `buf` est inscriptible sur `size` octets ; RRF_RT_REG_SZ
        // garantit une chaîne terminée par NUL si elle tient dans le tampon
        // (sinon ERROR_MORE_DATA, traité comme une erreur).
        let code = unsafe {
            RegGetValueW(
                key.0,
                ptr::null(),
                wname.as_ptr(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        if is_absent(code) {
            return Ok(Vec::new());
        }
        check("state_read", code)?;
        let units = usize::try_from(size).unwrap_or(0).min(buf.len() * 2) / 2;
        let text = &buf[..units];
        let text = text.split(|&c| c == 0).next().unwrap_or_default();
        let json = String::from_utf16(text).map_err(|e| NetError::Os {
            op: "state_parse",
            reason: e.to_string(),
        })?;
        state::decode_state(&json)
    }

    fn save(&mut self, items: &[Installed]) -> Result<(), NetError> {
        if items.is_empty() {
            let Some(key) = open_key_write(state::STATE_REG_KEY)? else {
                return Ok(());
            };
            let wname = plan::to_wide(state::STATE_REG_VALUE);
            // SAFETY: clé ouverte en écriture ; `wname` terminé par NUL.
            let code = unsafe { RegDeleteValueW(key.0, wname.as_ptr()) };
            return check_removed("state_remove", code);
        }
        let json = state::encode_state(items)?;
        // Non volatile : le journal doit survivre à un redémarrage si les
        // objets qu'il décrit y survivent (à observer en 3.W).
        let key = create_key("state_write", state::STATE_REG_KEY, REG_OPTION_NON_VOLATILE)?;
        set_sz(&key, state::STATE_REG_VALUE, &json)
    }
}

/// Ouvre une clé existante en écriture ; `Ok(None)` si elle n'existe pas.
fn open_key_write(path: &str) -> Result<Option<OwnedKey>, NetError> {
    let wpath = plan::to_wide(path);
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `wpath` est terminé par NUL et vit pendant l'appel ; `key` est
    // une sortie locale valide.
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wpath.as_ptr(),
            0,
            KEY_WRITE,
            &raw mut key,
        )
    };
    if is_absent(code) {
        return Ok(None);
    }
    check("reg_open", code)?;
    Ok(Some(OwnedKey(key)))
}

// ---------------------------------------------------------------------------
// Assemblage
// ---------------------------------------------------------------------------

/// [`SystemOps`] réel (IP Helper + registre).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WinOps;

impl SystemOps for WinOps {
    fn set_interface(&mut self, luid: u64, mtu: u16, metric: u32) -> Result<(), NetError> {
        set_interface(luid, mtu, metric)
    }

    fn set_interface_v6(&mut self, luid: u64, mtu: u16, metric: u32) -> Result<bool, NetError> {
        set_interface_v6(luid, mtu, metric)
    }

    fn has_ipv6_route(&mut self) -> Result<bool, NetError> {
        has_ipv6_route()
    }

    fn best_route(&mut self, dest: Ipv4Addr) -> Result<Underlay, NetError> {
        best_route(dest)
    }

    fn add(&mut self, action: &Action) -> Result<Applied, NetError> {
        match action {
            Action::Address { luid, address } => add_address(*luid, *address),
            Action::Route {
                luid,
                dest,
                next_hop,
                metric,
            } => add_route(&RouteKey::v4(*luid, *dest, *next_hop), *metric),
            Action::Route6 { luid, dest, metric } => {
                add_route(&RouteKey::v6(*luid, *dest), *metric)
            }
            Action::InterfaceDns {
                luid,
                servers,
                search,
            } => {
                set_interface_dns(
                    *luid,
                    &plan::interface_servers_value(servers),
                    &plan::interface_search_value(search),
                )?;
                Ok(Applied::Created)
            }
            Action::Nrpt(rule) => write_nrpt_rule(rule),
        }
    }

    fn remove(&mut self, item: &Installed) -> Result<(), NetError> {
        match item {
            Installed::Address { luid, address } => remove_address(*luid, *address),
            Installed::Route { .. } | Installed::Route6 { .. } => match RouteKey::of(item) {
                Some(key) => remove_route(&key),
                None => Ok(()),
            },
            Installed::InterfaceDns { luid } => clear_interface_dns(*luid),
            Installed::NrptRule { name } => delete_key(&rule_path(name)?),
        }
    }

    fn route_is_ours(&mut self, item: &Installed) -> Result<bool, NetError> {
        RouteKey::of(item).map_or(Ok(false), |key| route_is_ours(&key))
    }

    fn list_nrpt_rules(&mut self) -> Result<Vec<String>, NetError> {
        list_nrpt_rules()
    }

    fn nrpt_policy_active(&mut self) -> Result<bool, NetError> {
        nrpt_policy_active()
    }

    fn flush_dns(&mut self) -> Result<(), NetError> {
        flush_resolver_cache()
    }
}
