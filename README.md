# fortivpn-rs

Client **Fortinet SSL-VPN** écrit en Rust, conçu pour remplacer FortiClient sous Windows 11.
La référence fonctionnelle est [openfortivpn](https://github.com/adrienverge/openfortivpn) (client Linux, C).

Mesure indicative : établissement de la connexion en **environ 100 à 300 ms** (authentification, configuration, tunnel) contre une vraie passerelle, depuis WSL.
Le chrono de chaque étape est visible avec `fortivpn -v connect` et `fortivpn status`.

> **Avertissement** : ce projet n'est **pas affilié à Fortinet**. Utilisez-le uniquement avec l'accord de votre DSI.

## Fonctionnalités

- Authentification par identifiant et mot de passe (HTTPS, cookie de session) ; le mot de passe est demandé à chaque connexion, sans écho, et n'est jamais stocké.
- Validation TLS par les racines système, avec épinglage optionnel de l'empreinte SHA-256 du certificat (rotation possible).
- Récupération de la configuration XML (IP, routes split ou full tunnel, DNS), tunnel PPP (LCP/IPCP) encapsulé en trames `0x5050`.
- Double authentification OTP / FortiToken (code saisi ou notification push).
- Reconnexion automatique (veille, changement de réseau, perte de keepalive), avec backoff configurable.
- Trois modes d'utilisation : Linux/WSL (TUN, sudo), Windows en mode proxy sans droits administrateur (SOCKS5 et redirections de ports), Windows via un service installé une fois par un administrateur.
- Nettoyage garanti des routes, DNS et filtres à l'arrêt ou au démarrage suivant après un crash.
- Journalisation `tracing` avec durée de chaque étape ; aucun secret dans les logs.

## État du projet

Trois niveaux de confiance, à ne pas confondre : **validé en réel** (contre une vraie passerelle), **testé en simulation** (passerelle ou pair simulé, `tools/mock-gw` ou répondeur IPsec de test), **seulement compilé** (jamais exécuté).

| Élément | État |
|---|---|
| SSL-VPN sous Linux/WSL (auth, config, tunnel PPP, routes, nettoyage) | **Validé en réel** depuis WSL (connexion ~100-300 ms). Des coupures ont été observées en session (RST après ~40 s, puis DeadPeer) ; un correctif « filtre IPv6 » (paquets IPv6 envoyés à tort dans le tunnel comme de l'IPv4) est en place mais **en attente de validation terrain** (story 2.6) |
| Reconnexion automatique | Testée en simulation ; observée en réel (ré-authentification après cookie refusé) |
| OTP / FortiToken (code et push) | Testé en simulation (`mock-gw`) ; jamais testé contre une vraie passerelle |
| Mode proxy SOCKS5 + redirections de ports (sans droits admin) | Testé en simulation ; recette réelle sous Windows à faire |
| Windows : Wintun, routes, DNS/NRPT, filtres WFP, service SYSTEM + pipe | **Seulement compilé** et analysé (clippy) en cross-compilation ; jamais exécuté sous Windows (recette 3.W) |
| Interface graphique Slint (`fortivpn-gui`) | **Compilée** pour Windows, **jamais lancée sous Windows** ; utilisable sous Linux via WSLg. Zone de notification et distribution (8.2, 8.3) à faire |
| IPsec IKEv2 / ESP (crate `ipsec`) | Testé contre un simulateur ; **jamais contre un vrai FortiGate** ni strongSwan (6.4 non faite) ; secondaire, non prioritaire |
| DTLS | **Reporté** (étude : `docs/protocol-dtls.md`) |
| SAML/SSO, certificat client | Non pris en charge |

Détail des stories : `docs/BACKLOG.md`. Note de terrain : `docs/field/`.

## Binaires et compilation

Deux binaires :

- `fortivpn` : client en ligne de commande (`crates/cli`) ;
- `fortivpn-gui` : interface graphique Slint (`crates/gui`).

Tout le développement et les tests se font sous Linux (WSL2). Prérequis : Rust stable (édition 2024, >= 1.85).

```
cargo build --release -p cli                 # Linux : target/release/fortivpn
cargo build --release -p gui                 # Linux (WSLg) : target/release/fortivpn-gui

# Cross-compilation Windows (depuis Linux/WSL) : ne jamais exécuter les .exe sans décision explicite
rustup target add x86_64-pc-windows-gnu
cargo build --release -p cli --target x86_64-pc-windows-gnu
cargo build --release -p gui --target x86_64-pc-windows-gnu
```

Le profil `dev` est allégé (`debug = "line-tables-only"`, pas de débogage pour les dépendances, pas d'incrémental) pour limiter l'espace disque.

Vérifications :

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo clippy -p netwin -p cli --target x86_64-pc-windows-gnu -- -D warnings
```

Les tests e2e nécessitant TUN/netns sont marqués `#[ignore]` (`sudo -E cargo test -- --ignored`).
Les tests utilisent `tools/mock-gw`, une fausse passerelle FortiGate.

## Documentation

- [Guide utilisateur](docs/guide-utilisateur.md) : configuration, modes d'utilisation, dépannage.
- [Architecture](docs/architecture.md).
- [Spécification du protocole](docs/protocol.md).

## Sécurité

Les constats des revues de sécurité (lecture seule, aucune faille exploitée en pratique) et leur statut à jour sont dans [`docs/security/SYNTHESE.md`](docs/security/SYNTHESE.md) ; rapports détaillés dans [`docs/security/`](docs/security/) et décisions de report dans [`docs/securite-versions-futures.md`](docs/securite-versions-futures.md).

> **Mode proxy depuis WSL vers Windows** : par défaut (`[proxy] owner_check = true`), le proxy n'accepte que les connexions du même compte. Un navigateur Windows qui utilise un proxy lancé **dans WSL** est donc refusé, car WSL ne voit pas le propriétaire de la connexion. Marche à suivre : mettre `[proxy] owner_check = false` dans `config.toml`, ou décocher « Vérifier que les connexions au proxy viennent de mon compte » dans Réglages de la GUI. Il est préférable d'utiliser la GUI Windows, qui n'est pas concernée.

### Limites de conception

- **Pas de kill-switch hors WFP full-tunnel** : seuls les filtres WFP du mode full-tunnel Windows (IPv6, LLMNR/NBT-NS/mDNS, et blocage pendant la reconnexion) font office de coupe-circuit ; en split-tunnel, en mode proxy et sous Linux, une coupure laisse le trafic repartir hors VPN.
- **NRPT imposée par GPO** : si une stratégie de groupe définit déjà des règles NRPT, on avertit et on continue ; nos règles DNS sont sans effet. En tunnel complet la fuite DNS est bloquée par le pare-feu ; en split-tunnel, les noms internes peuvent être résolus par le DNS local.
- **SOCKS5 sans authentification** (loopback uniquement par défaut) : seuls les processus du même compte sont acceptés (`owner_check`) ; avec `owner_check = false`, tout processus local peut passer par le tunnel.
- **PSK IPsec de groupe** : un détenteur du PSK peut se faire passer pour la passerelle (voir 6.5 M1) ; l'authentification du répondeur par certificat épinglé existe (`CertPinned`, épinglage seul, sans validation de chaîne ni de dates) mais n'est pas le mode par défaut : en `Psk` ou `PskAndCertPinned` la protection n'existe pas, utiliser `CertPinned`.
- **Épinglage de certificat à renouveler** : l'empreinte épinglée doit être mise à jour quand la passerelle change de certificat (plusieurs empreintes possibles pour une rotation sans coupure) ; un certificat épinglé est accepté même expiré.
- **Code Windows jamais exécuté en réel** : Wintun, IP Helper, NRPT, WFP, service, pipe et interface graphique sont seulement compilés ; les correctifs de sécurité correspondants ne sont pas validés avant la recette 3.W.
- **DTLS absent** : le tunnel passe uniquement par TLS/TCP.
- **Mot de passe gardé en mémoire pendant la session** (nécessaire à la reconnexion), avec des copies résiduelles possibles (tampons de bibliothèques) ; il n'est jamais écrit sur disque, ni dans les logs.

## Licence

Le projet est distribué sous licence [Apache 2.0](LICENSE).

**Note sur Slint** : l'interface graphique (`fortivpn-gui`) embarque [Slint](https://slint.dev), disponible sous GPLv3 ou sous la licence « Slint Royalty-free », qui impose une attribution. Conformité : **conforme**, écran « À propos » (accessible depuis Réglages) avec le widget `AboutSlint` ; licence Slint Royalty-free, voir `THIRD-PARTY-LICENSES.md`.
