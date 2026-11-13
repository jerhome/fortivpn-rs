//! Chargeur des vecteurs `docs/vectors/*.hex` (format : `docs/vectors/README.md`).

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;

/// Un vecteur `@frame`.
#[derive(Debug, Clone)]
pub(crate) struct Vector {
    pub(crate) name: String,
    pub(crate) dir: String,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectors")
}

/// Analyse le contenu d'un fichier `.hex` ; vérifie `len=` pour chaque vecteur.
pub(crate) fn parse_hex(text: &str) -> Vec<Vector> {
    let mut out: Vec<(Vector, usize)> = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("@frame") {
            let mut parts = rest.split_whitespace();
            let name = parts.next().expect("nom de vecteur").to_owned();
            let mut dir = String::new();
            let mut len = None;
            for kv in parts {
                if let Some(v) = kv.strip_prefix("dir=") {
                    v.clone_into(&mut dir);
                } else if let Some(v) = kv.strip_prefix("len=") {
                    len = Some(v.parse::<usize>().expect("len numérique"));
                }
            }
            let len = len.unwrap_or_else(|| panic!("ligne {}: len= manquant", lineno + 1));
            out.push((
                Vector {
                    name,
                    dir,
                    bytes: Vec::new(),
                },
                len,
            ));
            continue;
        }
        let (cur, _) = out
            .last_mut()
            .unwrap_or_else(|| panic!("ligne {}: octets hors @frame", lineno + 1));
        for tok in line.split_whitespace() {
            let b = u8::from_str_radix(tok, 16)
                .unwrap_or_else(|_| panic!("ligne {}: octet invalide {tok:?}", lineno + 1));
            cur.bytes.push(b);
        }
    }
    out.into_iter()
        .map(|(v, len)| {
            assert_eq!(v.bytes.len(), len, "vecteur {} : len= incohérent", v.name);
            v
        })
        .collect()
}

/// Charge un fichier de `docs/vectors/`.
pub(crate) fn load(file: &str) -> Vec<Vector> {
    let path = vectors_dir().join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("lecture {}: {e}", path.display()));
    parse_hex(&text)
}

/// Tous les vecteurs `.hex`, indexés par nom (noms uniques entre fichiers).
pub(crate) fn all() -> HashMap<String, Vector> {
    let mut map = HashMap::new();
    for f in ["framing.hex", "lcp.hex", "ipcp.hex", "ip.hex"] {
        for v in load(f) {
            let name = v.name.clone();
            assert!(map.insert(name.clone(), v).is_none(), "nom dupliqué {name}");
        }
    }
    map
}

/// Octets d'un vecteur (flux TLS, en-tête 0x5050 inclus).
pub(crate) fn wire(name: &str) -> Vec<u8> {
    all()
        .remove(name)
        .unwrap_or_else(|| panic!("vecteur {name} introuvable"))
        .bytes
}

/// Trame PPP d'un vecteur (sans les 6 octets d'en-tête 0x5050).
pub(crate) fn ppp(name: &str) -> Vec<u8> {
    wire(name)[6..].to_vec()
}

#[test]
fn parser_handles_format() {
    let v = parse_hex("# c\n@frame a dir=c2g len=3\n00 01\n02\n\n@frame b dir=g2c len=0\n");
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].bytes, [0, 1, 2]);
    assert_eq!(v[0].dir, "c2g");
    assert!(v[1].bytes.is_empty());
}
