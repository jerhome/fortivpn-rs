# fortivpn-rs

Client Fortinet SSL VPN en Rust, destiné à remplacer FortiClient sous Windows 11.
Référence fonctionnelle : openfortivpn (client Linux, C).

## Règles impératives

- **Tout le développement, la compilation et les tests se font dans WSL2 (Linux).**
- **Ne JAMAIS exécuter un binaire sous Windows** (`*.exe`, `cmd.exe`, `powershell.exe`, `/mnt/c/...`)
  sans demande explicite de l'utilisateur. Le code Windows est seulement **compilé** et
  analysé (clippy) en cross-compilation : `--target x86_64-pc-windows-gnu`.
- Ne jamais se connecter à la vraie passerelle VPN de l'entreprise sans demande explicite.
  Les tests utilisent `tools/mock-gw`.
- Aucun secret (mot de passe, cookie, OTP) dans les logs, les tests ou le dépôt.
- **Commits / push** : le coordinateur peut commiter et pousser librement sur `jerhome/fortivpn-rs` (dépôt perso public, accord de l'utilisateur du 2026-11-13) après `scripts/check.sh` vert et vérification de l'absence de données perso/employeur. Les sous-agents ne commitent jamais.
  Identité de commit : compte personnel « jerhome » (configurée en local au dépôt), jamais l'identité
  git globale professionnelle.

## Architecture

```
crates/proto     # Auth HTTPS, XML config, framing 0x5050, PPP LCP/IPCP — pur, sans I/O OS
crates/core      # Session, boucle tunnel tokio, reconnexion ; traits Transport + NetBackend
crates/ipsec     # Transport IPsec (IKE + ESP espace utilisateur) — Epic 6
crates/netlinux  # NetBackend Linux (TUN, ip route, resolv) — tests e2e dans WSL (netns)
crates/netwin    # NetBackend Windows (Wintun, IP Helper, NRPT) — cfg(windows), compilé seulement
crates/cli       # Binaire `fortivpn`
tools/mock-gw    # Fausse passerelle FortiGate (TLS + auth + XML + PPP)
docs/            # protocol.md (spec), BACKLOG.md
```

`core` ne connaît que le trait `NetBackend` ; le backend est choisi à la compilation selon l'OS.

## Commandes de vérification (toutes dans WSL)

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo clippy -p netwin -p cli --target x86_64-pc-windows-gnu -- -D warnings
```

Les tests e2e nécessitant TUN/netns sont marqués `#[ignore]` et lancés via
`sudo -E cargo test -- --ignored` uniquement si l'utilisateur l'accepte.

## Sous-agents

protocol-analyst → (rust-proto | windows-net) → test-harness → security-reviewer.
