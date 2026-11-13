# À faire par l'utilisateur (tenu à jour par Claude)

Dernière mise à jour : 2026-11-13 20h05. Rien ici ne bloque les agents ; à traiter quand tu as un moment.

## Questions en attente

1. ~~Commit~~ : fait (poussé sur `jerhome/fortivpn-rs`).
2. ~~« annule »~~ : rien à annuler.
3. **Temps de connexion FortiClient** (story S0.2) : « semble bien meilleur » avec fortivpn-rs (~100 ms) — chiffre FortiClient à confirmer.
4. **Relevé de jetons** (%) vers 21h00, pour réajuster le nombre d'agents.

## Tests à faire

### T1 — Terminer le test réel dans WSL (5 min)
```bash
cd ~/claude/vpn-rust
scripts/wsl-real-test.sh -t <IP interne connue> -d 60
```
- Laisser aller jusqu'au bout (déconnexion automatique après 60 s) puis me dire « fini » : je lis `~/fortivpn-tests/` (nettoyage des routes, pings, stabilité).
- Si tu ne connais pas d'IP interne : sans `-t`, on valide déjà la tenue de session et le nettoyage.

### T2 — Mode proxy sous Windows, sans droits admin (10 min) — après la story 7.2
- Je ferai recompiler `fortivpn.exe` (dans `~/fortivpn-dist/`) avec les derniers correctifs avant ce test.
- Config `%APPDATA%\fortivpn-rs\config.toml` : la même qu'en WSL + une section :
  ```toml
  [proxy]
  socks = "127.0.0.1:1080"
  # forward = ["127.0.0.1:13389=<serveur RDP interne>:3389"]
  ```
- Lancer `fortivpn.exe -v connect` (terminal normal, **pas** admin), puis configurer le navigateur (ou une extension type FoxyProxy) sur SOCKS5 `127.0.0.1:1080` et ouvrir un site interne.

### T3 — Avec l'admin (lundi/mardi) : service Windows + recette 3.W
- L'admin lance une fois : `fortivpn.exe service install` (exe + `wintun.dll` dans `C:\Program Files\fortivpn-rs\`, config dans `%ProgramData%\fortivpn-rs\config.toml`).
- Ensuite, sans admin : `fortivpn connect --service`, `fortivpn status`, `fortivpn disconnect`.
- La checklist complète de recette est dans `docs/BACKLOG.md` (story 3.W).
