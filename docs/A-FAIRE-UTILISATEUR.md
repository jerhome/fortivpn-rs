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
- Copier l'exe dans un dossier local (ex. `%USERPROFILE%\fortivpn\`), pas de `wintun.dll` nécessaire en mode proxy ; `trusted_cert` comme en WSL.
- Lancer `.\fortivpn.exe -v connect` (PowerShell normal, **pas** admin ; SmartScreen : « Informations complémentaires → Exécuter quand même »). Arrêter tout fortivpn WSL qui occuperait le port 1080.
- Tester : `curl.exe --socks5-hostname 127.0.0.1:1080 http://<site interne>` ou Firefox (SOCKS v5 127.0.0.1:1080 + « DNS distant »).

### T1-bis — Résultat WSL du 2026-11-13 20h41
- Lancé sans `sudo` : auth 188 ms, config (split, 2 routes, 2 DNS), PPP OK, puis échec attendu de création TUN (EPERM, code 6) et déconnexion propre.
- À refaire : `sudo ~/fortivpn-dist/fortivpn-linux -c ~/.config/fortivpn-rs/config.toml connect`, ou mode proxy sans sudo (`[proxy]` dans la config + `curl --socks5-hostname 127.0.0.1:1080 ...`).

### T3 — Avec l'admin (lundi/mardi) : service Windows + recette 3.W
- L'admin lance une fois : `fortivpn.exe service install` (exe + `wintun.dll` dans `C:\Program Files\fortivpn-rs\`, config dans `%ProgramData%\fortivpn-rs\config.toml`).
- Ensuite, sans admin : `fortivpn connect --service`, `fortivpn status`, `fortivpn disconnect`.
- La checklist complète de recette est dans `docs/BACKLOG.md` (story 3.W).

### T1-ter — Après le correctif 2.6 (filtre IPv6 + trace `-vv`)
- Cause probable des coupures trouvée : des paquets IPv6 émis par Linux sur la TUN partaient dans le tunnel comme s'ils étaient IPv4 ; désormais filtrés.
- Avant de lancer : `ip route show <IP passerelle>/32` ; si une route est là (résidu d'un run précédent) : `sudo ip route del <IP passerelle>/32`.
- Lancer avec le **nouveau** binaire (`~/fortivpn-dist/fortivpn-linux`, recompilé après la GUI) :
  `sudo ~/fortivpn-dist/fortivpn-linux -c ~/.config/fortivpn-rs/config.toml -vv connect 2>&1 | tee ~/fortivpn-tests/trace-$(date +%H%M).log`
- Laisser tourner ≥ 3 min, puis Ctrl+C. Me donner le fichier : je cherche les lignes « trame PPP de contrôle », « fin du tunnel » et « paquet non IPv4 ignoré ».
