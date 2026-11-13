#!/usr/bin/env bash
# Empaquetage des binaires (Linux/WSL uniquement ; rien n'est exécuté sous Windows).
# Usage : scripts/package.sh <version> [--release] [--skip-check]
#   <version>      ex. 0.1.0 (sans le « v »)
#   --release      crée le tag annoté v<version> et une PRÉ-release GitHub (gh) avec les archives.
#   --skip-check   ne lance pas scripts/check.sh (déconseillé).
# Sortie : dist/<version>/ (ignoré par git) : zip Windows, tar.gz Linux, SHA256SUMS.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION=""
RELEASE=0
CHECK=1
for a in "$@"; do
    case "$a" in
        --release) RELEASE=1 ;;
        --skip-check) CHECK=0 ;;
        -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
        -*) echo "option inconnue : $a" >&2; exit 2 ;;
        *) [[ -z "$VERSION" ]] || { echo "une seule version attendue" >&2; exit 2; }; VERSION=$a ;;
    esac
done
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
    echo "version invalide (attendu : X.Y.Z[-suffixe]) : '$VERSION'" >&2; exit 2
fi
[[ "$(uname -s)" == "Linux" ]] || { echo "à lancer sous Linux (WSL2)." >&2; exit 1; }
for t in zip tar sha256sum; do command -v "$t" >/dev/null || { echo "$t requis" >&2; exit 1; }; done

WIN_TARGET=x86_64-pc-windows-gnu
LIN_TARGET=x86_64-unknown-linux-gnu
OUT="dist/$VERSION"
WIN_NAME="fortivpn-$VERSION-windows-x86_64"
LIN_NAME="fortivpn-$VERSION-linux-x86_64"
TAG="v$VERSION"

step() { printf '\n==> %s\n' "$*"; }

if (( RELEASE )); then
    # Échec rapide avant le long build.
    command -v gh >/dev/null || { echo "gh requis pour --release" >&2; exit 1; }
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        echo "le tag $TAG existe déjà" >&2; exit 1
    fi
    if [[ -n "$(git status --porcelain)" ]]; then
        echo "arbre git non propre : commiter avant --release" >&2; exit 1
    fi
fi

for f in README.md LICENSE THIRD-PARTY-LICENSES.md docs/guide-utilisateur.md; do
    [[ -f "$f" ]] || { echo "fichier manquant : $f" >&2; exit 1; }
done

if (( CHECK )); then
    step "scripts/check.sh"
    scripts/check.sh
fi

step "cargo build --release (Linux)"
cargo build --release --locked -p cli -p gui --target "$LIN_TARGET"
step "cargo build --release (Windows, cross)"
cargo build --release --locked -p cli -p gui --target "$WIN_TARGET"

LIN_BIN="target/$LIN_TARGET/release"
WIN_BIN="target/$WIN_TARGET/release"
for f in "$LIN_BIN/fortivpn" "$LIN_BIN/fortivpn-gui" "$WIN_BIN/fortivpn.exe" "$WIN_BIN/fortivpn-gui.exe"; do
    [[ -f "$f" ]] || { echo "binaire absent : $f" >&2; exit 1; }
done

rm -rf "$OUT"
STAGE="$OUT/.stage"
mkdir -p "$STAGE/$WIN_NAME/docs" "$STAGE/$LIN_NAME/docs"

write_config() {
    cat > "$1" <<'TOML'
# Exemple de configuration fortivpn-rs (à copier puis adapter).
# Emplacement par défaut :
#   Windows : %APPDATA%\fortivpn-rs\config.toml
#   Linux   : ~/.config/fortivpn-rs/config.toml
# Les clés inconnues sont refusées. AUCUN secret ici (pas de mot de passe, OTP, cookie) :
# le mot de passe est saisi à chaque connexion.

# Nom d'hôte ou adresse de la passerelle (obligatoire).
host = "vpn.example.com"
# Port TLS (défaut 443).
port = 443
# Identifiant (obligatoire).
username = "utilisateur"
# Realm (optionnel).
# realm = "staff"

# Empreinte SHA-256 du certificat de la passerelle : 64 caractères hexadécimaux minuscules.
# Une chaîne, ou une liste pour une rotation de certificat.
trusted_cert = "0000000000000000000000000000000000000000000000000000000000000000"
# trusted_cert = ["<empreinte-actuelle>", "<empreinte-suivante>"]

# Nom de l'interface TUN (défaut fortivpn, 15 caractères max).
# interface = "fortivpn"
# error | warn | info | debug | trace
log_level = "info"

# Mode proxy sans droits administrateur (aucune interface, route ni DNS modifié).
# [proxy]
# socks = "127.0.0.1:1080"        # "off" désactive le SOCKS
# forward = ["127.0.0.1:13389=srv.example.com:3389"]

# Reconnexion automatique.
[reconnect]
enabled = true
max_backoff_secs = 60
# max_attempts = 5
TOML
}

for d in "$WIN_NAME" "$LIN_NAME"; do
    cp README.md LICENSE THIRD-PARTY-LICENSES.md "$STAGE/$d/"
    cp docs/guide-utilisateur.md "$STAGE/$d/docs/"
    write_config "$STAGE/$d/config.example.toml"
done
cp "$WIN_BIN/fortivpn.exe" "$WIN_BIN/fortivpn-gui.exe" "$STAGE/$WIN_NAME/"
cp "$LIN_BIN/fortivpn" "$LIN_BIN/fortivpn-gui" "$STAGE/$LIN_NAME/"
chmod 755 "$STAGE/$LIN_NAME/fortivpn" "$STAGE/$LIN_NAME/fortivpn-gui"

cat > "$STAGE/$WIN_NAME/LISEZMOI-wintun.txt" <<'TXT'
wintun.dll (mode service uniquement)
====================================

Le mode service (« fortivpn.exe service install ») utilise le pilote Wintun. wintun.dll
n'est PAS fournie dans cette archive. Les modes proxy (sans droits administrateur) et
l'interface graphique en mode proxy n'en ont pas besoin.

1. Télécharger wintun 0.14.1 depuis le site officiel : https://www.wintun.net/
   (archive wintun-0.14.1.zip).
2. Vérifier la provenance : n'utiliser que le site officiel ; contrôler la signature
   numérique du fichier (clic droit > Propriétés > Signatures numériques) et, si
   possible, l'empreinte SHA-256 publiée par le projet.
3. Extraire wintun\bin\amd64\wintun.dll et le placer À CÔTÉ de fortivpn.exe.
4. Installer le tout dans un dossier modifiable par les seuls administrateurs, par exemple
   C:\Program Files\fortivpn-rs\ ; le service refuse sinon de démarrer.

Voir docs\guide-utilisateur.md (« Mode 3 : service »).
TXT

step "archives"
(cd "$STAGE" && zip -qr -X "../$WIN_NAME.zip" "$WIN_NAME")
(cd "$STAGE" && tar --owner=0 --group=0 --numeric-owner --sort=name -czf "../$LIN_NAME.tar.gz" "$LIN_NAME")
rm -rf "$STAGE"
(cd "$OUT" && sha256sum "$WIN_NAME.zip" "$LIN_NAME.tar.gz" > SHA256SUMS && cat SHA256SUMS)

if (( ! RELEASE )); then
    step "OK : archives dans $OUT (sans --release : ni tag ni publication)"
    exit 0
fi

step "tag annoté $TAG et pré-release GitHub"
NOTES_SRC="docs/release-notes/$VERSION.md"
NOTES="$OUT/notes.md"
if [[ -f "$NOTES_SRC" ]]; then
    cp "$NOTES_SRC" "$NOTES"
else
    printf 'Pré-release %s.\n' "$TAG" > "$NOTES"
fi
printf '\nSHA256 :\n\n```\n%s\n```\n' "$(cat "$OUT/SHA256SUMS")" >> "$NOTES"
git tag -a "$TAG" -m "fortivpn-rs $TAG"
git push origin "$TAG"
gh release create "$TAG" --prerelease --verify-tag --title "fortivpn-rs $TAG" \
    --notes-file "$NOTES" \
    "$OUT/$WIN_NAME.zip" "$OUT/$LIN_NAME.tar.gz" "$OUT/SHA256SUMS"
step "OK : pré-release $TAG publiée"
