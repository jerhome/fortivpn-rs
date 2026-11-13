# Guide de test — à faire par l'utilisateur

Dernière mise à jour : 2026-11-13 ~23h. Binaires dans `~/fortivpn-dist/` (voir `BUILD.txt`) ;
depuis Windows : `\\wsl.localhost\Debian\home\<utilisateur>\fortivpn-dist\`.
Rien ici ne bloque les agents. Les logs ne contiennent jamais ton mot de passe.

## Linux / WSL

### L1 — Stabilité du tunnel complet (CLI, ~5 min) — prioritaire
Valide le correctif « filtre IPv6 » (coupures à ~40 s auparavant).
1. Si besoin, retirer une route résiduelle : `ip route show <IP passerelle>/32` → si présente : `sudo ip route del <IP passerelle>/32`.
2. `sudo ~/fortivpn-dist/fortivpn-linux -vv connect 2>&1 | tee ~/fortivpn-tests/trace-$(date +%H%M).log`
   (plus besoin de `-c` : sous sudo, ta config est trouvée automatiquement).
3. Laisser tourner **≥ 3 min** (idéalement 10), faire un `ping` vers une IP interne dans un autre terminal, puis Ctrl+C.
4. Me dire « fini » : je lis la trace (`trame PPP de contrôle`, `fin du tunnel`, `paquet non IPv4 ignoré`).

### L2 — Interface graphique Linux (WSLg, 2 min)
1. `~/fortivpn-dist/fortivpn-gui-linux` (**sans sudo**).
2. Vérifier : Réglages s'ouvre, mode Proxy, connexion, écran « Connecté », « À propos » (Made with Slint), déconnexion.
3. Test : `curl --socks5-hostname 127.0.0.1:<port socks> http://<site interne>`.

### L3 — Second compte VPN refusé sans cookie (diagnostic, 1 min)
1. Mettre ce compte dans la config (ou me demander de le faire).
2. `sudo ~/fortivpn-dist/fortivpn-linux -vv connect` → me coller la ligne « réponse logincheck » (résumé sans secret) et le message d'erreur final.

## Windows (sans droits admin : mode proxy)

### W1 — Interface graphique (5 min)
1. Copier `fortivpn-gui.exe` dans un dossier local (ex. `%USERPROFILE%\fortivpn\`), puis dans PowerShell : `Unblock-File $env:USERPROFILE\fortivpn\fortivpn-gui.exe`.
2. Double-clic : au premier lancement, **Réglages s'ouvre tout seul** → passerelle, port 443, utilisateur, port SOCKS (**18080** recommandé, voir W2) → Enregistrer.
3. Mode **Proxy**, mot de passe, Connecter. Si le certificat est refusé : bouton « Épingler cette empreinte » (après vérification).
4. Navigateur : **Firefox** → Paramètres réseau → proxy manuel, SOCKS v5 `127.0.0.1` port `18080`, cocher « DNS distant ». Ouvrir un site interne.

### W2 — Message de port (1 min)
1. Si l'interface affiche une erreur de port : noter le code `os error 10013` (port **réservé par Windows**) ou `10048` (**déjà utilisé**).
2. PowerShell : `netsh int ipv4 show excludedportrange protocol=tcp` → me dire si 1080 est dans une plage.

### W3 — Avec l'admin : tunnel complet via le service
1. L'admin copie `fortivpn.exe` + `wintun.dll` (wintun.net, 0.14.1, `bin\amd64`) dans `C:\Program Files\fortivpn-rs\`, crée `%ProgramData%\fortivpn-rs\config.toml`, puis lance `fortivpn.exe service install`.
2. Ensuite, sans admin : interface en mode **Service**, ou `fortivpn.exe connect --service` / `status` / `disconnect`.
3. Checklist complète : story 3.W de `docs/BACKLOG.md`.

## Ce qu'il faut me renvoyer
- L1 : « fini » (je lis `~/fortivpn-tests/`) ; L3 : 2 lignes de log ; W1/W2 : messages d'erreur ; ton ressenti vs FortiClient (temps de connexion).

## Questions en attente
- Temps de connexion de FortiClient (pour comparaison) — fortivpn-rs : ~100–300 ms mesurés.
- Test d'interopérabilité strongSwan (IPsec 6.4) : nécessite `sudo` + installation de strongSwan → ton accord.
