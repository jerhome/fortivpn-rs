# Fuzzing de `proto` (story 5.2)

Crate hors workspace (nightly + `cargo install cargo-fuzz`), lancé depuis WSL uniquement.

| Cible | Entrée | Invariants principaux |
|---|---|---|
| `frame_decoder` | `seed(4) \| flux` | pas de panic/boucle, résultat indépendant du découpage des `push`, `encode(decode(x)) == x`, trames + reliquat == flux, tampon < 65535, erreurs non consommatrices et persistantes |
| `ppp_packet` | `max_len(2) \| trame PPP` | parse → encode → parse idempotent, encodage point fixe, jamais de `ff 03` émis, Code-/Protocol-Reject bornés par `max_len` |
| `ppp_options` | options TLV | `encode(parse(x)) == x`, options LCP/IPCP typées bijectives, `ConfigOption::new` ⇔ ≤ 253 o |
| `ppp_session` | `cfg \| ops…` (voir l'en-tête du fichier) | pas de panic, ≤ 4 trames et ≤ 2 événements par op, trames émises encapsulables (≤ `MAX_PPP_LEN`), `Down`/`IpcpUp` uniques, pas d'échéance passée après `handle_timeout` |

```sh
python3 -I fuzz/gen_seeds.py                 # régénère fuzz/seeds/ depuis docs/vectors/*.hex
cd fuzz
cargo +nightly fuzz run ppp_session corpus/ppp_session seeds/ppp_session -- -max_total_time=180 -max_len=8192
FUZZ_DEBUG=1 cargo +nightly fuzz run ppp_session <entrée>   # trace l'état après chaque op
```

`scripts/check.sh --fuzz SECONDES` lance brièvement les quatre cibles.

`regressions/` : entrées reproduisant des bugs ouverts (elles **font échouer** `ppp_session`
tant que le bug n'est pas corrigé ; `FUZZ_IGNORE_KNOWN=1` tolère ce bug pour explorer
au-delà). Tests équivalents : `crates/proto/tests/fuzz_regressions.rs` (`#[ignore]`).
