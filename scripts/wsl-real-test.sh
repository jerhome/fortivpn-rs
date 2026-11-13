#!/usr/bin/env bash
# Test réel de fortivpn dans WSL contre la vraie passerelle — lancé PAR L'UTILISATEUR.
#
# Usage :
#   scripts/wsl-real-test.sh [-c config.toml] [-t IP_INTERNE]... [-d DUREE_S] [-r]
#
#   -c  fichier de config (défaut : ~/.config/fortivpn-rs/config.toml)
#   -t  IP interne à tester (ping + port TCP 443/22/3389) ; répétable
#   -d  durée de la session une fois le tunnel monté (défaut : 60 s)
#   -r  recompiler le binaire release avant le test
#
# Le mot de passe est saisi au clavier (sans écho) par fortivpn lui-même ; il n'apparaît
# dans aucun fichier. Les logs sont écrits dans ~/fortivpn-tests/<date>/ ; donne-moi ce
# chemin (je peux le lire directement depuis WSL).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$HOME/.config/fortivpn-rs/config.toml"
DURATION=60
REBUILD=0
TARGETS=()

while getopts "c:t:d:rh" opt; do
  case "$opt" in
    c) CFG="$OPTARG" ;;
    t) TARGETS+=("$OPTARG") ;;
    d) DURATION="$OPTARG" ;;
    r) REBUILD=1 ;;
    *) sed -n '2,15p' "$0"; exit 2 ;;
  esac
done

[[ "$DURATION" =~ ^[0-9]+$ ]] || { echo "durée invalide : $DURATION" >&2; exit 2; }
for t in "${TARGETS[@]}"; do
  [[ "$t" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "IP invalide : $t" >&2; exit 2; }
done
[[ -f "$CFG" ]] || { echo "config introuvable : $CFG" >&2; exit 3; }
CFG="$(readlink -f "$CFG")"

# --- Binaire figé (les agents recompilent target/ en continu) -------------------------
if (( REBUILD )); then
  (cd "$REPO" && cargo build --release -p cli)
fi
BIN="$HOME/bin/fortivpn"
mkdir -p "$HOME/bin"
cp "$REPO/target/release/fortivpn" "$BIN"

STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="$HOME/fortivpn-tests/$STAMP"
mkdir -p "$LOG"
CLIENT_LOG="$LOG/client.log"
DIAG="$LOG/diagnostics.txt"
SUMMARY="$LOG/summary.txt"
: > "$CLIENT_LOG"

section() { printf '\n===== %s — %s =====\n' "$1" "$(date +%T.%3N)" >> "$DIAG"; }
run() { { echo "\$ $*"; "$@" 2>&1 || echo "(code $?)"; } >> "$DIAG"; }

# --- Contexte ----------------------------------------------------------------------
section "contexte"
run uname -a
run "$BIN" version
run sha256sum "$BIN"
run "$BIN" -c "$CFG" check-config
section "réseau AVANT"
run ip -4 addr
run ip -4 route
run ip -6 route

echo "Mot de passe sudo (une seule fois, mis en cache) :"
sudo -v

# --- Diagnostics en arrière-plan : attendent le tunnel, testent, puis arrêtent ------
diagnostics() {
  local t0 up=0
  t0=$(date +%s)
  while (( $(date +%s) - t0 < 120 )); do
    if grep -q "connecté en" "$CLIENT_LOG" 2>/dev/null; then up=1; break; fi
    if ! pgrep -f "$BIN -c $CFG -vv connect" >/dev/null; then break; fi
    sleep 0.5
  done
  if (( up )); then
    section "réseau PENDANT (tunnel monté)"
    run ip -4 addr
    run ip -4 route
    run ip -6 route
    run cat /etc/resolv.conf
    for t in "${TARGETS[@]}"; do
      section "cible $t"
      run ip route get "$t"
      run ping -c 4 -W 2 "$t"
      for p in 443 22 3389 445; do
        run timeout 4 bash -c "exec 3<>/dev/tcp/$t/$p && echo 'port $p ouvert'"
      done
    done
    section "session en cours ($DURATION s)"
    sleep "$DURATION"
  else
    section "tunnel NON monté dans les 120 s"
  fi
  section "arrêt (SIGINT)"
  sudo pkill -INT -f "$BIN -c $CFG -vv connect" || true
}

diagnostics &
DIAG_PID=$!

echo
echo ">>> Connexion : saisis ton mot de passe VPN quand il est demandé."
echo ">>> La session s'arrêtera seule après ${DURATION} s (ou Ctrl+C)."
echo
set +e
# Le mot de passe est lu sur le terminal par fortivpn (rpassword) : rien n'est journalisé.
sudo "$BIN" -c "$CFG" -vv connect 2>&1 | tee -a "$CLIENT_LOG"
RC=${PIPESTATUS[0]}
set -e
wait "$DIAG_PID" 2>/dev/null || true

section "réseau APRÈS (nettoyage attendu)"
run ip -4 addr
run ip -4 route
run ip -6 route

# --- Ceinture et bretelles : masquer tout ce qui ressemblerait à un cookie ----------
sed -i -E 's/(SVPNCOOKIE=)[^; ]+/\1<masqué>/g' "$CLIENT_LOG" "$DIAG"

{
  echo "date        : $STAMP"
  echo "code sortie : $RC"
  echo "durées      : $(grep -m1 'connecté en' "$CLIENT_LOG" || echo 'tunnel non monté')"
  echo "reconnexions: $(grep -c -i 'reconnect' "$CLIENT_LOG" || true)"
  echo "erreurs     :"
  grep -iE 'error|erreur|échec|refus' "$CLIENT_LOG" | head -20 || true
  for t in "${TARGETS[@]}"; do
    echo "ping $t     : $(grep -A6 "ping -c 4 -W 2 $t" "$DIAG" | grep -m1 'packet loss' || echo '?')"
  done
} > "$SUMMARY"

echo
echo "================ RÉSUMÉ ================"
cat "$SUMMARY"
echo "========================================"
echo "Logs complets : $LOG"
echo "Donne-moi ce chemin : je lirai les fichiers directement."
