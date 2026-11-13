//! Journal persistant de ce qui a été installé, pour purger les résidus après
//! un crash (`recover_stale`).
//!
//! Journal « write-ahead » : une entrée est écrite **avant** l'appel système
//! qui crée l'objet, et retirée après sa suppression. Au pire, la récupération
//! tente de supprimer un objet jamais créé (absent : ignoré).
//!
//! Stockage (Windows) : valeur `REG_SZ` [`STATE_REG_VALUE`] de la clé
//! `HKLM\`[`STATE_REG_KEY`] (revue 5.3, C1 : plus de fichier dans
//! `%ProgramData%`, exposé aux jonctions / liens symboliques). Une écriture de
//! valeur de registre est atomique. Le contenu reste **non fiable** à la
//! relecture (E1) : taille et nombre d'entrées bornés ici, chaque entrée
//! vérifiée contre l'état du système par `engine::Tracker::resume`.
//!
//! Ce module (sérialisation, bornes) est pur : compilé et testé partout.

use std::net::Ipv4Addr;

use fortivpn_core::NetError;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

/// Version du format du journal (2 : stockage registre, routes IPv6).
const STATE_VERSION: u32 = 2;

/// Taille maximale du JSON du journal (octets UTF-8), à l'écriture comme à la
/// lecture. Environ 650 routes au format compact.
pub(crate) const MAX_STATE_BYTES: usize = 64 * 1024;

/// Nombre maximal d'entrées du journal.
pub(crate) const MAX_STATE_ENTRIES: usize = 1024;

/// Clé du journal sous `HKEY_LOCAL_MACHINE` (modifiable par les seuls
/// administrateurs / SYSTEM). Non configurable.
pub(crate) const STATE_REG_KEY: &str = r"SOFTWARE\fortivpn-rs";

/// Nom de la valeur `REG_SZ` contenant le journal JSON.
pub(crate) const STATE_REG_VALUE: &str = "NetwinState";

/// Objet système installé, avec ce qu'il faut pour le retirer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Installed {
    /// Adresse unicast sur une interface.
    Address {
        /// `NET_LUID` de l'interface.
        luid: u64,
        /// Adresse et préfixe on-link.
        address: Ipv4Net,
    },
    /// Route IPv4 (clé IP Helper : interface, préfixe, prochain saut).
    Route {
        /// `NET_LUID` de l'interface.
        luid: u64,
        /// Destination.
        dest: Ipv4Net,
        /// Prochain saut (`0.0.0.0` : on-link).
        next_hop: Ipv4Addr,
    },
    /// Route IPv6 on-link (blocage IPv6 en full-tunnel : `::/1`, `8000::/1`).
    Route6 {
        /// `NET_LUID` de l'interface.
        luid: u64,
        /// Destination.
        dest: Ipv6Net,
    },
    /// Serveurs DNS / liste de recherche posés sur l'interface.
    InterfaceDns {
        /// `NET_LUID` de l'interface.
        luid: u64,
    },
    /// Règle NRPT locale (sous-clé de `DnsPolicyConfig`).
    NrptRule {
        /// Nom de la sous-clé.
        name: String,
    },
}

impl Installed {
    /// Vrai pour les objets DNS (un vidage du cache suit leur retrait).
    pub(crate) fn is_dns(&self) -> bool {
        matches!(self, Self::InterfaceDns { .. } | Self::NrptRule { .. })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateDoc {
    version: u32,
    /// Processus ayant écrit le journal (diagnostic).
    pid: u32,
    items: Vec<Installed>,
}

fn state_err(op: &'static str, reason: impl Into<String>) -> NetError {
    NetError::Os {
        op,
        reason: reason.into(),
    }
}

/// Sérialise le journal (JSON compact), bornes vérifiées.
pub(crate) fn encode_state(items: &[Installed]) -> Result<String, NetError> {
    if items.len() > MAX_STATE_ENTRIES {
        return Err(state_err(
            "state_serialize",
            format!(
                "journal trop grand : {} entrées (max {MAX_STATE_ENTRIES})",
                items.len()
            ),
        ));
    }
    let doc = StateDoc {
        version: STATE_VERSION,
        pid: std::process::id(),
        items: items.to_vec(),
    };
    let json =
        serde_json::to_string(&doc).map_err(|e| state_err("state_serialize", e.to_string()))?;
    if json.len() > MAX_STATE_BYTES {
        return Err(state_err(
            "state_serialize",
            format!(
                "journal trop grand : {} octets (max {MAX_STATE_BYTES})",
                json.len()
            ),
        ));
    }
    Ok(json)
}

/// Désérialise le journal ; refuse tout ce qui dépasse les bornes ou n'est pas
/// au format attendu (le contenu n'est pas fiable).
pub(crate) fn decode_state(json: &str) -> Result<Vec<Installed>, NetError> {
    if json.len() > MAX_STATE_BYTES {
        return Err(state_err(
            "state_parse",
            format!("journal trop grand : {} octets", json.len()),
        ));
    }
    let doc: StateDoc =
        serde_json::from_str(json).map_err(|e| state_err("state_parse", e.to_string()))?;
    if doc.version != STATE_VERSION {
        return Err(state_err(
            "state_parse",
            format!("version de journal inconnue : {}", doc.version),
        ));
    }
    if doc.items.len() > MAX_STATE_ENTRIES {
        return Err(state_err(
            "state_parse",
            format!("journal trop grand : {} entrées", doc.items.len()),
        ));
    }
    Ok(doc.items)
}

/// Persistance du journal.
pub(crate) trait JournalStore {
    /// Entrées persistées (vide si rien).
    fn load(&mut self) -> Result<Vec<Installed>, NetError>;
    /// Remplace le journal ; une liste vide le supprime.
    fn save(&mut self, items: &[Installed]) -> Result<(), NetError>;
}

/// Journal en mémoire (tests, ou absence de persistance).
#[derive(Debug, Clone, Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct MemStore {
    pub(crate) items: Vec<Installed>,
    /// Nombre d'écritures (tests).
    pub(crate) saves: usize,
    /// Échoue à la n-ième écriture (tests).
    pub(crate) fail_on_save: Option<usize>,
}

impl JournalStore for MemStore {
    fn load(&mut self) -> Result<Vec<Installed>, NetError> {
        Ok(self.items.clone())
    }

    fn save(&mut self, items: &[Installed]) -> Result<(), NetError> {
        self.saves += 1;
        if self.fail_on_save == Some(self.saves) {
            return Err(state_err("state_write", "échec injecté"));
        }
        // Mêmes bornes que le stockage réel.
        encode_state(items)?;
        self.items = items.to_vec();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> Vec<Installed> {
        vec![
            Installed::Address {
                luid: 0x0006_8000_0000_0001,
                address: "10.212.134.200/32".parse().unwrap(),
            },
            Installed::Route {
                luid: 7,
                dest: "203.0.113.10/32".parse().unwrap(),
                next_hop: Ipv4Addr::new(192, 168, 1, 1),
            },
            Installed::Route6 {
                luid: 0x0006_8000_0000_0001,
                dest: "8000::/1".parse().unwrap(),
            },
            Installed::InterfaceDns {
                luid: 0x0006_8000_0000_0001,
            },
            Installed::NrptRule {
                name: crate::plan::nrpt_rule_name(0),
            },
        ]
    }

    fn route(i: u32) -> Installed {
        Installed::Route {
            luid: u64::MAX,
            dest: Ipv4Net::new(Ipv4Addr::from(i), 32).unwrap(),
            next_hop: Ipv4Addr::BROADCAST,
        }
    }

    #[test]
    fn round_trip() {
        let json = encode_state(&items()).unwrap();
        assert!(!json.contains('\n'), "format compact");
        assert_eq!(decode_state(&json).unwrap(), items());
        assert_eq!(decode_state(&encode_state(&[]).unwrap()).unwrap(), vec![]);
    }

    #[test]
    fn json_format_is_stable() {
        assert_eq!(
            serde_json::to_value(&items()[1]).unwrap(),
            serde_json::json!({
                "kind": "route",
                "luid": 7,
                "dest": "203.0.113.10/32",
                "next_hop": "192.168.1.1",
            })
        );
        assert_eq!(
            serde_json::to_value(&items()[4]).unwrap(),
            serde_json::json!({
                "kind": "nrpt_rule",
                "name": "{666f7274-6976-706e-2d72-730000000000}",
            })
        );
    }

    #[test]
    fn corrupt_or_unknown_state_is_an_error() {
        assert!(decode_state("{not json").is_err());
        assert!(decode_state(r#"{"version":1,"pid":1,"items":[]}"#).is_err());
        assert!(decode_state(r#"{"version":2,"pid":1,"items":[],"x":0}"#).is_err());
        assert!(
            decode_state(r#"{"version":2,"pid":1,"items":[{"kind":"file","path":"C:\\x"}]}"#)
                .is_err()
        );
        assert!(decode_state(r#"{"version":2,"pid":1,"items":[]}"#).is_ok());
    }

    #[test]
    fn size_and_count_are_bounded() {
        // Trop d'octets à la lecture (avant toute analyse).
        let big = format!(
            r#"{{"version":2,"pid":1,"items":[],"pad":"{}"}}"#,
            "x".repeat(MAX_STATE_BYTES)
        );
        assert!(decode_state(&big).is_err());

        // Trop d'entrées.
        let many: Vec<Installed> = (0..=u32::try_from(MAX_STATE_ENTRIES).unwrap())
            .map(route)
            .collect();
        assert!(encode_state(&many).is_err());

        // Trop d'octets à l'écriture : refusé (sinon illisible ensuite).
        let n = MAX_STATE_BYTES / 80;
        let heavy: Vec<Installed> = (0..u32::try_from(n).unwrap()).map(route).collect();
        assert!(encode_state(&heavy).is_err());

        // Ce qui est écrit est toujours relisible.
        let ok: Vec<Installed> = (0..500).map(route).collect();
        assert_eq!(decode_state(&encode_state(&ok).unwrap()).unwrap(), ok);
    }

    #[test]
    fn mem_store_applies_the_same_bounds() {
        let mut store = MemStore::default();
        let many: Vec<Installed> = (0..2000).map(route).collect();
        assert!(store.save(&many).is_err());
        assert!(store.items.is_empty());
    }
}
