#!/usr/bin/env bash
# Vérifications complètes du workspace (à lancer dans WSL/Linux uniquement).
# Usage : scripts/check.sh [--fix] [--fuzz SECONDES]
#   --fix            lance `cargo fmt --all` avant les vérifications.
#   --fuzz SECONDES  lance ensuite chaque cible cargo-fuzz (fuzz/) pendant SECONDES
#                    (nightly + cargo-fuzz requis ; non exécuté par défaut).
# Le code Windows est seulement compilé/analysé en cross : rien n'est exécuté.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

FIX=0
FUZZ_SECS=0
while (( $# )); do
    case "$1" in
        --fix) FIX=1 ;;
        --fuzz)
            if [[ $# -lt 2 || ! "$2" =~ ^[1-9][0-9]*$ ]]; then
                echo "--fuzz attend une durée en secondes (entier > 0)" >&2; exit 2
            fi
            FUZZ_SECS=$2; shift ;;
        --fuzz=*)
            FUZZ_SECS=${1#--fuzz=}
            if [[ ! "$FUZZ_SECS" =~ ^[1-9][0-9]*$ ]]; then
                echo "--fuzz attend une durée en secondes (entier > 0)" >&2; exit 2
            fi ;;
        -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
        *) echo "argument inconnu : $1" >&2; exit 2 ;;
    esac
    shift
done

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "check.sh doit être lancé sous Linux (WSL2)." >&2
    exit 1
fi

WIN_TARGET=x86_64-pc-windows-gnu

step() { printf '\n==> %s\n' "$*"; }

if (( FIX )); then
    step "cargo fmt --all"
    cargo fmt --all
fi

step "cargo fmt --all --check"
cargo fmt --all --check

step "cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

step "cargo test --workspace"
cargo test --workspace

step "cargo clippy -p netwin -p fortivpn-service -p cli -p netproxy --target $WIN_TARGET -- -D warnings"
if ! rustup target list --installed 2>/dev/null | grep -qx "$WIN_TARGET"; then
    echo "cible $WIN_TARGET absente : rustup target add $WIN_TARGET" >&2
    exit 1
fi
cargo clippy -p netwin -p fortivpn-service -p cli -p netproxy --target "$WIN_TARGET" --all-targets -- -D warnings

if (( FUZZ_SECS > 0 )); then
    # Crate fuzz/ hors workspace : n'affecte pas les étapes précédentes (stable).
    if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
        echo "cargo-fuzz/nightly absents : rustup toolchain install nightly && cargo install cargo-fuzz" >&2
        exit 1
    fi
    if [[ ! -d fuzz/seeds ]]; then
        step "génération du corpus seed (fuzz/gen_seeds.py)"
        python3 -I fuzz/gen_seeds.py
    fi
    FUZZ_TARGETS=(frame_decoder ppp_packet ppp_options ppp_session)
    step "cargo +nightly fuzz build"
    (cd fuzz && cargo +nightly fuzz build)
    for t in "${FUZZ_TARGETS[@]}"; do
        step "cargo +nightly fuzz run $t (${FUZZ_SECS} s)"
        mkdir -p "fuzz/corpus/$t"
        # Résumé seulement ; en cas de crash, l'entrée est dans fuzz/artifacts/$t/.
        (
            set +e
            cd fuzz
            cargo +nightly fuzz run "$t" "corpus/$t" "seeds/$t" -- \
                -max_total_time="$FUZZ_SECS" -max_len=8192 -timeout=10 -rss_limit_mb=2048 \
                -print_final_stats=1 2>&1 |
                grep -E '^#[0-9]+[[:space:]]+DONE|stat::(number_of_executed_units|average_exec_per_sec|peak_rss_mb)|panicked|ERROR|SUMMARY|Test unit written|^ +[0-9]+: '
            exit "${PIPESTATUS[0]}"
        )
    done
fi

step "OK : toutes les vérifications sont passées"
