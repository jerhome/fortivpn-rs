//! Adaptateur Wintun et relais ring buffers ↔ [`PacketChannel`].
//!
//! - Lecture (OS → tunnel) : `Session::receive_blocking` est bloquante, donc un
//!   thread dédié `wintun-rx` ; il pousse les paquets dans le canal via
//!   `Handle::block_on` (le canal tokio n'a pas besoin des drivers du runtime).
//! - Écriture (tunnel → OS) : tâche tokio ; l'allocation dans l'anneau
//!   d'émission ne bloque pas (anneau plein : paquet abandonné, comme un lien
//!   saturé).
//!
//! - Seuls les paquets IPv4 sont relayés vers le tunnel ; les autres (IPv6
//!   attiré par les routes de blocage du full-tunnel, revue 5.3 E2) sont
//!   abandonnés et comptés.
//!
//! Arrêt : quand le cœur libère son extrémité, la tâche d'écriture se termine
//! et signale l'arrêt de session (`Session::shutdown`), ce qui débloque le
//! thread de lecture. Le dernier `Arc<Session>` libéré termine la session
//! (`WintunEndSession`) puis ferme l'adaptateur (`WintunCloseAdapter`), ce qui
//! le supprime avec ses adresses, routes et DNS.
#![allow(unsafe_code)]

use std::fs::File;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use fortivpn_core::{
    NetError, PacketChannel, PacketReceiver, PacketSender, TunDevice, TunInfo, TunOptions,
};
use tokio::runtime::Handle;

use super::{ffi, security};
use crate::{integrity, plan};

/// `FILE_SHARE_READ` : pendant le chargement, personne ne peut modifier,
/// renommer ni supprimer `wintun.dll`.
const FILE_SHARE_READ: u32 = 0x1;

/// Type de tunnel affiché par Windows pour l'adaptateur.
const TUNNEL_TYPE: &str = "fortivpn-rs";

/// Taille de l'anneau Wintun (4 Mio, puissance de deux dans les bornes).
const RING_CAPACITY: u32 = 0x40_0000;

fn wintun_err(op: &'static str) -> impl FnOnce(wintun::Error) -> NetError {
    move |e| NetError::Os {
        op,
        reason: e.to_string(),
    }
}

/// Vérifie l'installation (revue 5.3, M4) : dossier de l'exécutable, dossier
/// de la DLL et DLL réservés aux administrateurs.
fn check_install(dll: &Path) -> Result<(), NetError> {
    let exe = std::env::current_exe().map_err(|source| NetError::Io {
        op: "current_exe",
        source,
    })?;
    let mut dirs = Vec::new();
    for d in [exe.parent(), dll.parent()].into_iter().flatten() {
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    for d in dirs {
        security::check_admin_only(d)?;
    }
    security::check_admin_only(dll)
}

/// Charge `wintun.dll` depuis un chemin absolu, après vérification des ACL et
/// de l'empreinte SHA-256 (si `expected_sha256`). Le fichier reste ouvert en
/// `FILE_SHARE_READ` du hachage jusqu'à la fin du chargement : il ne peut pas
/// être remplacé entre la vérification et `LoadLibraryExW`.
fn load_wintun(
    path: &Path,
    expected_sha256: Option<&[u8; 32]>,
) -> Result<wintun::Wintun, NetError> {
    use libloading::os::windows::{
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, Library,
    };

    if !path.is_absolute() {
        return Err(NetError::Os {
            op: "wintun_load",
            reason: format!("chemin non absolu : {}", path.display()),
        });
    }
    check_install(path)?;
    let pinned = File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|source| NetError::Io {
            op: "wintun_open",
            source,
        })?;
    let digest = integrity::sha256_reader(&pinned).map_err(|source| NetError::Io {
        op: "wintun_hash",
        source,
    })?;
    tracing::info!(sha256 = %integrity::to_hex(&digest), path = %path.display(), "wintun.dll");
    integrity::check_digest(&digest, expected_sha256).map_err(|reason| NetError::Os {
        op: "wintun_hash",
        reason: format!("{} : {reason}", path.display()),
    })?;
    if expected_sha256.is_none() {
        tracing::warn!("empreinte de wintun.dll non épinglée (WINTUN_DLL_SHA256 à renseigner)");
    }
    // SAFETY: wintun.dll est chargée par chemin absolu, dans un dossier dont
    // le propriétaire et la DACL viennent d'être vérifiés (administrateurs
    // seulement), après contrôle d'empreinte éventuel ; `pinned` empêche toute
    // modification jusqu'au retour. Ses dépendances ne sont cherchées que dans
    // son répertoire et System32. Son DllMain n'a pas de précondition.
    let lib = unsafe {
        Library::load_with_flags(
            path,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
    .map_err(|e| NetError::Os {
        op: "wintun_load",
        reason: format!("{} : {e}", path.display()),
    })?;
    drop(pinned);
    // SAFETY: `lib` est wintun.dll ; le crate résout les symboles `Wintun*`
    // avec les signatures de l'API officielle.
    unsafe { wintun::load_from_library(lib) }.map_err(wintun_err("wintun_load"))
}

/// Signale l'arrêt de la session au `Drop` (débloque le thread de lecture).
struct StopOnDrop(Arc<wintun::Session>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        if let Err(e) = self.0.shutdown() {
            tracing::warn!(error = %e, "arrêt de session Wintun");
        }
    }
}

/// Crée l'adaptateur, démarre la session et les relais. Appel bloquant, à
/// lancer depuis un contexte tokio (`spawn_blocking`).
pub(crate) fn create_tun(
    runtime: &Handle,
    dll: &Path,
    expected_sha256: Option<&[u8; 32]>,
    options: &TunOptions,
) -> Result<TunDevice, NetError> {
    plan::check_adapter_name(&options.name)?;
    let wintun = load_wintun(dll, expected_sha256)?;
    let adapter = wintun::Adapter::create(
        &wintun,
        &options.name,
        TUNNEL_TYPE,
        Some(plan::adapter_guid(&options.name)),
    )
    .map_err(wintun_err("wintun_create_adapter"))?;
    // Le crate wintun résout le LUID par l'alias, que porte peut-être déjà une
    // autre interface (revue 5.3, F3) : on exige qu'il désigne bien
    // l'interface de notre GUID.
    // SAFETY: les deux membres de l'union NET_LUID_LH recouvrent les mêmes 8
    // octets entiers ; tout motif de bits est un `u64` valide.
    let alias_luid = unsafe { adapter.get_luid().Value };
    let guid_luid = ffi::luid_from_guid(plan::adapter_guid(&options.name))?;
    if guid_luid != Some(alias_luid) {
        return Err(NetError::Os {
            op: "wintun_create_adapter",
            reason: format!(
                "l'alias « {} » désigne une autre interface que l'adaptateur créé \
                 (LUID {alias_luid:#x} ≠ {guid_luid:x?}) : renommer l'interface existante",
                options.name
            ),
        });
    }
    let index = adapter
        .get_adapter_index()
        .map_err(wintun_err("wintun_adapter_index"))?;
    let session = Arc::new(
        adapter
            .start_session(RING_CAPACITY)
            .map_err(wintun_err("wintun_start_session"))?,
    );
    // La session garde l'adaptateur en vie.
    drop(adapter);

    let (ours, theirs) = PacketChannel::pair(options.queue_capacity);
    let (to_core, from_core) = theirs.split();

    let reader_session = Arc::clone(&session);
    let reader_rt = runtime.clone();
    std::thread::Builder::new()
        .name("wintun-rx".into())
        .spawn(move || reader_loop(&reader_session, &to_core, &reader_rt))
        .map_err(|source| NetError::Io {
            op: "wintun_reader",
            source,
        })?;
    let stop = StopOnDrop(Arc::clone(&session));
    runtime.spawn(writer_loop(session, from_core, stop));

    tracing::info!(name = %options.name, index, "adaptateur Wintun créé");
    Ok(TunDevice {
        info: TunInfo {
            name: options.name.clone(),
            index: Some(index),
        },
        packets: ours,
    })
}

/// Vrai pour un paquet IPv4 (seul protocole transporté par le tunnel).
fn is_ipv4(packet: &[u8]) -> bool {
    packet.first().is_some_and(|b| b >> 4 == 4)
}

fn reader_loop(session: &Arc<wintun::Session>, to_core: &PacketSender, runtime: &Handle) {
    let mut dropped_non_ipv4: u64 = 0;
    loop {
        let packet = match session.receive_blocking() {
            Ok(p) => p,
            Err(wintun::Error::ShuttingDown) => break,
            Err(e) => {
                tracing::error!(error = %e, "lecture Wintun");
                break;
            }
        };
        if !is_ipv4(packet.bytes()) {
            dropped_non_ipv4 += 1;
            tracing::debug!(
                version = packet.bytes().first().map(|b| b >> 4),
                total = dropped_non_ipv4,
                "paquet non IPv4 abandonné"
            );
            continue;
        }
        let bytes = Bytes::copy_from_slice(packet.bytes());
        // Libère le paquet dans l'anneau avant d'attendre le canal.
        drop(packet);
        if runtime.block_on(to_core.send(bytes)).is_err() {
            break;
        }
    }
    tracing::debug!(dropped_non_ipv4, "relais Wintun → tunnel arrêté");
}

async fn writer_loop(
    session: Arc<wintun::Session>,
    mut from_core: PacketReceiver,
    _stop: StopOnDrop,
) {
    while let Some(packet) = from_core.recv().await {
        let Ok(len) = u16::try_from(packet.len()) else {
            tracing::warn!(len = packet.len(), "paquet trop grand ignoré");
            continue;
        };
        if len == 0 {
            continue;
        }
        match session.allocate_send_packet(len) {
            Ok(mut out) => {
                out.bytes_mut().copy_from_slice(&packet);
                session.send_packet(out);
            }
            Err(e) => tracing::debug!(error = %e, "anneau Wintun plein : paquet abandonné"),
        }
    }
    tracing::debug!("relais tunnel → Wintun arrêté");
}
