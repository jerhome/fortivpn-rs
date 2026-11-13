//! FFI WFP : session dynamique, sous-couche et filtres décrits par [`crate::wfp`].
//!
//! Le handle de moteur (`FwpmEngineOpen0`) est possédé par [`Firewall`] et
//! fermé à son `Drop` (`FwpmEngineClose0`). La session est dynamique : le
//! système retire sous-couche et filtres à la fermeture du handle, y compris
//! si le processus meurt. Aucun pointeur passé à l'OS ne survit à l'appel.
#![allow(unsafe_code)]

use std::io;
use std::net::IpAddr;
use std::ptr;

use fortivpn_core::NetError;
use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL,
    FWP_MATCH_FLAGS_ALL_SET, FWP_MATCH_NOT_EQUAL, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_UINT64,
    FWP_VALUE0, FWP_VALUE0_0, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_NONE, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

use crate::plan::to_wide;
use crate::wfp::{self, Condition, FilterSpec, Layer, Verdict};

fn wfp_err(op: &'static str, code: u32) -> NetError {
    NetError::Io {
        op,
        // Les codes WFP (FWP_E_*) sont des HRESULT : réinterprétation bit à bit.
        #[allow(clippy::cast_possible_wrap)]
        source: io::Error::from_raw_os_error(code as i32),
    }
}

fn check(op: &'static str, code: u32) -> Result<(), NetError> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(wfp_err(op, code))
    }
}

/// Session WFP dynamique ouverte. Sa destruction retire tous nos filtres.
#[derive(Debug)]
pub(crate) struct Firewall {
    engine: HANDLE,
}

// SAFETY: un handle de moteur WFP est un handle RPC utilisable depuis
// n'importe quel thread (les appels Fwpm* sont thread-safe) ; `Firewall` en
// est l'unique propriétaire et ne l'expose pas.
unsafe impl Send for Firewall {}

impl Drop for Firewall {
    fn drop(&mut self) {
        // SAFETY: `engine` est un handle valide, ouvert par `FwpmEngineOpen0`
        // et jamais fermé ailleurs ; Drop s'exécute une seule fois.
        let rc = unsafe { FwpmEngineClose0(self.engine) };
        if rc != NO_ERROR {
            tracing::warn!(code = rc, "FwpmEngineClose0 a échoué");
        }
    }
}

fn open_dynamic_session() -> Result<Firewall, NetError> {
    let mut name = to_wide("fortivpn-rs");
    let session = FWPM_SESSION0 {
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: ptr::null_mut(),
        },
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        ..empty_session()
    };
    let mut engine: HANDLE = ptr::null_mut();
    // SAFETY: `session` et `name` vivent pendant l'appel ; `engine` est un
    // pointeur de sortie valide ; serveur et identité nuls = machine locale,
    // identité du processus.
    let rc = unsafe {
        FwpmEngineOpen0(
            ptr::null(),
            RPC_C_AUTHN_WINNT,
            ptr::null(),
            &raw const session,
            &raw mut engine,
        )
    };
    check("FwpmEngineOpen0", rc)?;
    Ok(Firewall { engine })
}

fn empty_session() -> FWPM_SESSION0 {
    // SAFETY: FWPM_SESSION0 est une structure C (entiers, pointeurs, GUID) :
    // le motif tout-à-zéro est valide (pointeurs nuls, clé nulle).
    unsafe { std::mem::zeroed() }
}

fn layer_guid(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::RecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::RecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

fn zero_filter() -> FWPM_FILTER0 {
    // SAFETY: FWPM_FILTER0 est une structure C (entiers, pointeurs, unions de
    // scalaires/pointeurs) : le motif tout-à-zéro est valide.
    unsafe { std::mem::zeroed() }
}

fn zero_condition() -> FWPM_FILTER_CONDITION0 {
    // SAFETY: structure C de scalaires/pointeurs/GUID : tout-à-zéro valide.
    unsafe { std::mem::zeroed() }
}

/// Valeurs référencées par pointeur par une condition (doivent vivre jusqu'à
/// l'ajout du filtre).
#[derive(Default)]
struct Slot {
    luid: u64,
    v6: FWP_BYTE_ARRAY16,
}

fn to_condition(cond: Condition, slot: &mut Slot) -> FWPM_FILTER_CONDITION0 {
    let mut c = zero_condition();
    match cond {
        Condition::LocalInterfaceNot(value) => {
            slot.luid = value;
            c.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
            c.matchType = FWP_MATCH_NOT_EQUAL;
            c.conditionValue = FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint64: ptr::from_mut(&mut slot.luid),
                },
            };
        }
        Condition::Loopback => {
            c.fieldKey = FWPM_CONDITION_FLAGS;
            c.matchType = FWP_MATCH_FLAGS_ALL_SET;
            c.conditionValue = FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            };
        }
        Condition::RemoteAddr(IpAddr::V4(ip)) => {
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            c.matchType = FWP_MATCH_EQUAL;
            // IPv4 : entier 32 bits en ordre d'octets de l'hôte (valeur numérique).
            c.conditionValue = FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: u32::from(ip),
                },
            };
        }
        Condition::RemoteAddr(IpAddr::V6(ip)) => {
            slot.v6.byteArray16 = ip.octets();
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue = FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteArray16: ptr::from_mut(&mut slot.v6),
                },
            };
        }
        Condition::Protocol(p) => {
            c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue = FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: p },
            };
        }
        Condition::RemotePort(p) | Condition::LocalPort(p) => {
            c.fieldKey = if matches!(cond, Condition::RemotePort(_)) {
                FWPM_CONDITION_IP_REMOTE_PORT
            } else {
                FWPM_CONDITION_IP_LOCAL_PORT
            };
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue = FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: p },
            };
        }
    }
    c
}

fn add_filter(engine: HANDLE, spec: &FilterSpec, sublayer: u128) -> Result<(), NetError> {
    // Une case par condition : les pointeurs restent valables jusqu'à l'appel
    // (`slots` n'est ni déplacé ni réalloué après la boucle).
    let mut slots: Vec<Slot> = spec.conditions.iter().map(|_| Slot::default()).collect();
    let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(spec.conditions.len());
    for (cond, slot) in spec.conditions.iter().zip(slots.iter_mut()) {
        conds.push(to_condition(*cond, slot));
    }
    let mut name = to_wide(&spec.name);
    let mut filter = zero_filter();
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr(),
        description: ptr::null_mut(),
    };
    filter.flags = FWPM_FILTER_FLAG_NONE;
    filter.layerKey = layer_guid(spec.layer);
    filter.subLayerKey = GUID::from_u128(sublayer);
    filter.weight = FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 { uint8: spec.weight },
    };
    filter.numFilterConditions = u32::try_from(conds.len()).unwrap_or(u32::MAX);
    filter.filterCondition = conds.as_mut_ptr();
    filter.action.r#type = match spec.verdict {
        Verdict::Permit => FWP_ACTION_PERMIT,
        Verdict::Block => FWP_ACTION_BLOCK,
    };
    let mut id = 0u64;
    // SAFETY: `engine` est un handle ouvert ; `filter`, `name`, `conds` et
    // `slots` (cibles des pointeurs) vivent jusqu'à la fin de l'appel, qui
    // copie la structure ; SD nul = descripteur par défaut ; `id` sortie valide.
    let rc = unsafe { FwpmFilterAdd0(engine, &raw const filter, ptr::null_mut(), &raw mut id) };
    check("FwpmFilterAdd0", rc)
}

fn add_sublayer(engine: HANDLE, sublayer: u128) -> Result<(), NetError> {
    let mut name = to_wide("fortivpn-rs kill-switch");
    // SAFETY: structure C, tout-à-zéro valide.
    let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sub.subLayerKey = GUID::from_u128(sublayer);
    sub.displayData = FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr(),
        description: ptr::null_mut(),
    };
    sub.weight = wfp::SUBLAYER_WEIGHT;
    // SAFETY: `engine` ouvert ; `sub` et `name` valides pendant l'appel ;
    // SD nul = défaut.
    let rc = unsafe { FwpmSubLayerAdd0(engine, &raw const sub, ptr::null_mut()) };
    check("FwpmSubLayerAdd0", rc)
}

fn install_all(engine: HANDLE, specs: &[FilterSpec], sublayer: u128) -> Result<(), NetError> {
    add_sublayer(engine, sublayer)?;
    specs
        .iter()
        .try_for_each(|s| add_filter(engine, s, sublayer))
}

/// Installe `specs` dans une session dynamique, en une transaction atomique.
/// Retourne `None` si `specs` est vide (aucune session ouverte). Échec : rien
/// n'est installé et le handle est fermé.
pub(crate) fn install(specs: &[FilterSpec]) -> Result<Option<Firewall>, NetError> {
    install_in(specs, wfp::SUBLAYER_GUID)
}

/// Comme [`install`], dans la sous-couche `sublayer` (la protection de
/// reconnexion a la sienne : elle coexiste avec les filtres du tunnel).
pub(crate) fn install_in(
    specs: &[FilterSpec],
    sublayer: u128,
) -> Result<Option<Firewall>, NetError> {
    if specs.is_empty() {
        return Ok(None);
    }
    let fw = open_dynamic_session()?;
    // SAFETY: `fw.engine` est un handle ouvert.
    check("FwpmTransactionBegin0", unsafe {
        FwpmTransactionBegin0(fw.engine, 0)
    })?;
    if let Err(e) = install_all(fw.engine, specs, sublayer) {
        // SAFETY: transaction ouverte ci-dessus sur ce handle.
        let _ = unsafe { FwpmTransactionAbort0(fw.engine) };
        return Err(e);
    }
    // SAFETY: transaction ouverte sur ce handle.
    check("FwpmTransactionCommit0", unsafe {
        FwpmTransactionCommit0(fw.engine)
    })?;
    tracing::info!(
        filters = specs.len(),
        "filtres WFP installés (session dynamique)"
    );
    Ok(Some(fw))
}
