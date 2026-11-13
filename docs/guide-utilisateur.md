# Guide utilisateur

Le binaire s'appelle `fortivpn`. `fortivpn --help` liste les commandes et les codes de sortie.

## Configuration

Fichier TOML, cherché par défaut à :

- Windows : `%APPDATA%\fortivpn-rs\config.toml`
- Linux : `~/.config/fortivpn-rs/config.toml` (ou `$XDG_CONFIG_HOME/fortivpn-rs/config.toml`)

Autre emplacement : `fortivpn --config CHEMIN ...`. Les clés inconnues sont refusées.
**Aucun secret** dans ce fichier : une clé `password`, `otp`, `cookie`... est une erreur.
Le mot de passe est saisi à chaque connexion (sans écho) ; il n'existe aucune option, variable d'environnement ou fichier pour le fournir.

```toml
host = "vpn.example.com"   # obligatoire : nom d'hôte ou adresse IP de la passerelle
port = 443                 # optionnel (défaut 443)
username = "utilisateur"   # obligatoire
realm = "staff"            # optionnel
# Empreinte SHA-256 du certificat de la passerelle : 64 caractères hexadécimaux minuscules.
# Une chaîne, ou une liste pour une rotation de certificat.
trusted_cert = "<empreinte-sha256-64-hex>"
# trusted_cert = ["<empreinte-actuelle>", "<empreinte-suivante>"]
interface = "fortivpn"     # optionnel : nom de l'interface TUN (défaut fortivpn, 15 caractères max)
log_level = "info"         # optionnel : error | warn | info | debug | trace

# Mode proxy sans droits administrateur (aucune interface, route ni DNS modifié).
[proxy]
socks = "127.0.0.1:1080"                      # défaut ; "off" désactive le SOCKS
forward = ["127.0.0.1:13389=srv.example.com:3389"]  # redirections TCP locale=distante
allow_non_loopback = false                    # true : autorise l'écoute hors loopback (déconseillé)

# Reconnexion automatique
[reconnect]
enabled = true             # défaut true
max_backoff_secs = 60      # 1 à 600, défaut 60
# max_attempts = 5         # >= 1 ; défaut : illimité
```

`fortivpn check-config` valide et affiche la configuration (sans secret). `-v` / `-vv` augmentent la verbosité (debug / trace).

## Mode 1 : Linux / WSL (avec sudo)

La création de l'interface TUN, des routes et des adresses exige les droits root :

```
sudo fortivpn connect        # connect est la commande par défaut
```

Le mot de passe est demandé puis `Ctrl+C` déconnecte proprement et restaure les routes.
Le DNS interne du tunnel n'est pas appliqué (voir Dépannage) : le fichier `/etc/resolv.conf` n'est jamais modifié.

## Mode 2 : Windows, mode proxy (sans administrateur)

Aucune interface virtuelle, route ni DNS n'est modifié : le tunnel est exposé par un proxy SOCKS5 local et des redirections de ports. Limites : TCP et IPv4 uniquement (pas d'UDP ni d'ICMP) ; tout le trafic passant par le proxy va dans le tunnel.

1. Ajouter une section `[proxy]` à `%APPDATA%\fortivpn-rs\config.toml` (voir ci-dessus).
2. Dans un terminal normal (pas administrateur) : `fortivpn.exe -v connect`, saisir le mot de passe.
3. Configurer les applications :
   - **Navigateur** : proxy SOCKS5 `127.0.0.1`, port `1080` (réglages réseau, ou extension de type FoxyProxy). Cocher « DNS via le proxy » (SOCKS5h) pour que les noms internes soient résolus par les DNS du tunnel.
   - **SSH** : `ssh -o ProxyCommand="ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p" utilisateur@srv.example.com` (ou `ProxyCommand` équivalent dans `~/.ssh/config`).
   - **RDP** : ajouter `forward = ["127.0.0.1:13389=srv.example.com:3389"]`, puis ouvrir le client Bureau à distance sur `127.0.0.1:13389`.
4. `Ctrl+C` pour se déconnecter.

## Mode 3 : Windows, service installé par un administrateur

Un administrateur installe le service une fois ; ensuite les utilisateurs se connectent sans élévation. Le service tourne en SYSTEM, lit `%ProgramData%\fortivpn-rs\config.toml` et ne reçoit de l'utilisateur que le mot de passe (via un named pipe réservé à la session).

Administrateur (une fois) :

```
fortivpn.exe service install     # démarrage automatique + démarrage immédiat
fortivpn.exe service uninstall   # arrêt et suppression
fortivpn.exe service start | stop
```

L'exécutable et `wintun.dll` doivent se trouver dans un dossier modifiable par les seuls administrateurs (par exemple `C:\Program Files\fortivpn-rs\`) ; le service refuse sinon de démarrer.

Utilisateur :

```
fortivpn connect --service   # saisie du mot de passe, aucune élévation
fortivpn status              # état, étapes et durées
fortivpn disconnect
```

> Ce mode n'a pas encore été testé en réel sous Windows.

### wintun.dll

Le mode service utilise le pilote Wintun. Télécharger `wintun.dll` (amd64) depuis le site officiel <https://www.wintun.net/>, le placer **à côté de `fortivpn.exe`**. Vérifier la provenance (signature du fichier) ; ne pas utiliser une copie obtenue ailleurs. Le mode proxy n'en a pas besoin.

## Épinglage du certificat

Par défaut, le certificat de la passerelle est validé par les racines du système. Si la passerelle présente un certificat d'une autorité interne ou auto-signé, la connexion échoue (voir Dépannage). Pour épingler :

1. Obtenir l'empreinte SHA-256 du certificat, par un canal fiable (votre DSI) ou en la calculant puis en la faisant confirmer :
   ```
   openssl s_client -connect vpn.example.com:443 </dev/null 2>/dev/null \
     | openssl x509 -noout -fingerprint -sha256
   ```
2. Reporter la valeur dans `trusted_cert`, en 64 caractères hexadécimaux **minuscules, sans les deux-points** (la sortie d'openssl est en majuscules séparées par des `:`).
3. Pendant une rotation de certificat, lister l'ancienne et la nouvelle empreinte.

## Codes de sortie

| Code | Signification |
|---|---|
| 0 | arrêt demandé (Ctrl+C, fermeture de la console) ou commande réussie |
| 1 | erreur interne |
| 2 | ligne de commande invalide |
| 3 | configuration absente ou invalide |
| 4 | authentification refusée |
| 5 | erreur réseau côté passerelle (connexion, TLS, tunnel refusé ou perdu) |
| 6 | erreur réseau locale (interface TUN, routes, DNS ; droits insuffisants ?) |
| 7 | une autre instance de fortivpn-rs est déjà active |
| 8 | double authentification (OTP, challenge) non prise en charge |

## Dépannage

- **Certificat `UnknownIssuer` (code 5)** : le certificat de la passerelle n'est pas signé par une autorité connue du système (autorité interne, auto-signé). Ne pas contourner la validation : faire confirmer l'empreinte par la DSI et l'épingler avec `trusted_cert`.
- **Connexion impossible / timeout (code 5)** : vérifier `host` et `port` (la passerelle n'écoute pas toujours sur 443, par exemple 10443), la résolution du nom, et qu'un pare-feu ou proxy d'entreprise ne bloque pas le port. Relancer avec `-vv`.
- **Authentification refusée (code 4)** : identifiant, mot de passe ou `realm` incorrects.
- **Double authentification (code 8)** : OTP / FortiToken / challenge ne sont pas pris en charge. Il faut un compte ou un profil de passerelle en mot de passe seul.
- **Droits insuffisants (code 6)** sous Linux : lancer avec `sudo`.
- **Code 7** : une autre instance est active (autre fenêtre ou service) ; la fermer d'abord.
- **DNS interne sous Linux** : le DNS du tunnel est seulement journalisé, `/etc/resolv.conf` n'est pas modifié. Utiliser des adresses IP, ou le mode proxy (le SOCKS5 résout les noms via les DNS du tunnel).

## Interface graphique sous Linux (X11 / Wayland)

Installation locale, sans droits administrateur (`fortivpn-gui` doit être dans le `PATH`,
par ex. `~/.local/bin`) :

```
install -Dm755 target/release/fortivpn-gui ~/.local/bin/fortivpn-gui
install -Dm644 packaging/linux/fortivpn-gui.desktop ~/.local/share/applications/fortivpn-gui.desktop
install -Dm644 packaging/linux/fortivpn-gui.svg ~/.local/share/icons/hicolor/scalable/apps/fortivpn-gui.svg
update-desktop-database ~/.local/share/applications 2>/dev/null || true
```

- L'icône de notification utilise le protocole StatusNotifierItem (D-Bus, sans GTK). Elle
  nécessite un hôte SNI : KDE, XFCE, ou GNOME avec l'extension « AppIndicator ». Sans hôte
  (par ex. WSLg), elle est ignorée silencieusement et fermer la fenêtre quitte l'application.
- Le thème est toujours sombre. Le message `Error watching for xdg color schemes`, émis par
  Slint sur la sortie d'erreur quand le portail XDG est absent, est sans conséquence.
