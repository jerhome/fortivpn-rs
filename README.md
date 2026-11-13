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

## Sécurité — failles potentielles et limites connues

Liste issue des revues de sécurité en lecture seule (passes 5.3-1 et 5.3-2, 6.5 IPsec, 7.1 netproxy) et de `docs/securite-versions-futures.md`. Aucune faille n'a été exploitée en pratique : ce sont des constats de revue. Les dépendances n'ont pas pu être vérifiées contre RustSec (`cargo audit`/`deny` absents) : à ajouter en CI.

Statuts : **corrigé** ; **corrigé, à valider sous Windows** (correctif écrit et compilé, jamais exécuté sous Windows) ; **reporté** (non traité, décision ou story ouverte) ; **accepté par conception**.

### Passe 5.3-1 ([rapport](docs/security/review-5.3-pass1.md))

| Réf. | Sévérité | Résumé | Statut |
|---|---|---|---|
| C1 | Critique | Journal d'état dans `%ProgramData%` : suppression/écrasement de fichier arbitraire par le processus admin (liens, variable d'environnement) | Corrigé, à valider sous Windows (journal dans HKLM) |
| E1 | Élevé | Journal non authentifié : suppression de routes/IP/DNS arbitraires au recover | Corrigé, à valider sous Windows |
| E2 | Élevé | Fuite IPv6 en full-tunnel (Windows et Linux) | Linux : corrigé ; Windows : corrigé (filtres WFP), à valider sous Windows |
| M1 | Moyen | Pas de verrou d'instance unique (une 2e instance démonte les routes de la 1re) | Corrigé, à valider sous Windows (voir 5.3-2 M4) |
| M2 | Moyen | DNS du tunnel non couvert par les routes (requêtes en clair) | Corrigé (Linux et Windows, route /32), à valider sous Windows |
| M3 | Moyen | NRPT locale ignorée si une NRPT GPO existe : fuite DNS | **Accepté par conception** : avertissement seulement, on n'écrit jamais sous la clé GPO |
| M4 | Moyen | Intégrité de `wintun.dll` et du dossier d'installation non vérifiée | Corrigé, à valider sous Windows |
| F1 | Faible | Linux : `resolv.conf` suivi par lien / TOCTOU | Corrigé (fd, `O_NOFOLLOW`) |
| F2 | Faible | Données poussées par la passerelle peu bornées (domaines, routes, `local_ip`) | Partiellement corrigé (bornes XML via 5.3-2 M1) ; le reste (suffixes publics, validations d'adresses) non vérifié : reporté |
| F3 | Faible | LUID Wintun résolu par alias (mauvaise interface possible) | Corrigé, à valider sous Windows |
| F4 | Faible | LLMNR/NBT-NS/mDNS actifs hors tunnel en full-tunnel | Corrigé (filtres WFP), à valider sous Windows |
| F5 | Faible | Règles NRPT non volatiles | Reporté : à observer en recette 3.W |

### Passe 5.3-2 ([rapport](docs/security/review-5.3-pass2.md))

| Réf. | Sévérité | Résumé | Statut |
|---|---|---|---|
| M1 | Moyen | DoS CPU/mémoire par XML hostile (routes/exclusions/domaines) | Corrigé (bornes) |
| M2 | Moyen | Fuite hors tunnel pendant la reconnexion (WFP retiré) | Corrigé, à valider sous Windows |
| M3 | Moyen | Pipe du service ouvert à tout utilisateur interactif (déconnexion d'autrui, essais de mots de passe) | Corrigé, à valider sous Windows (propriétaire de session, limitation d'essais) |
| M4 | Moyen | Verrou d'instance squattable (mutex `Global\`) : DoS persistant | Corrigé, à valider sous Windows (verrou par fichier admin-only) |
| F1 | Faible | ACL des dossiers ancêtres non contrôlée (remplacement de l'exe du service) | Corrigé, à valider sous Windows |
| F2 | Faible | Décodage HTTP chunked quadratique | Corrigé (parseur incrémental) |
| F3 | Faible | Tampon sortant non borné face à une passerelle hostile | Corrigé |
| F4 | Faible | Copies résiduelles du mot de passe en mémoire ; mot de passe gardé toute la session | Reporté ; limite documentée ci-dessous |
| F4b | Faible | `service.log` non borné, messages de la passerelle non assainis (caractères de contrôle) | Reporté |
| F5 | Faible | Certificat épinglé accepté même expiré ; une seule empreinte | Corrigé (liste `trusted_cert`) ; l'acceptation d'un certificat épinglé expiré reste un choix **accepté par conception** |

### Passe 6.5 — IPsec ([rapport](docs/security/review-6.5-ipsec.md)) : 0 critique, 0 élevé

Les correctifs relèvent de la story 6.S, non réalisée : tous restent **reportés**.

| Réf. | Sévérité | Résumé | Statut |
|---|---|---|---|
| M1 | Moyen | PSK de groupe : un détenteur du PSK peut usurper la passerelle et obtenir la NT-Response MS-CHAPv2 (crackable hors ligne) | Reporté (pistes : certificat épinglé, PSK par passerelle, `expected_idr`) ; limite de conception |
| F1 | Faible | Erreurs IKE_SA_INIT non authentifiées traitées comme fatales ; cookie non borné | Reporté |
| F2 | Faible | Rekey CHILD sans PFS accepté | Reporté |
| F3 | Faible | Secrets non effacés (exposant DH, plaintext SK, clés ESP reconstruites) | Reporté |
| F4 | Faible | `num-bigint` non constant-time pour MODP-2048 (risque pratique faible) | Reporté |
| F5 | Faible | Pas de test de sous-groupe pour MODP14 (sans conséquence sur la clé) | Reporté |
| F6 | Faible | Réponse en cache rejouable sans authentifier la requête (impact négligeable) | Reporté |
| F7 | Faible | Contenu CP/TS de la passerelle (IP, DNS, domaines) non validé | Reporté |
| F8 | Faible | Paquet IPv4 interne ESP non validé ; seuil de rekey à vérifier | Reporté |
| I1 | Info | Ordre de dérivation de la MSK confirmé seulement par le simulateur | Reporté : à valider contre un vrai FortiGate/strongSwan |

### Passe 7.1 — mode proxy ([rapport](docs/security/review-7.1-netproxy.md))

| Réf. | Sévérité | Résumé | Statut |
|---|---|---|---|
| E1 | Élevé | Port d'écoute sans `SO_EXCLUSIVEADDRUSE` : vol de port par un autre processus local (identifiants RDP/SSH) | Reporté : story 7.S ouverte (bind exclusif + information claire de l'utilisateur) |
| M1 | Moyen | SOCKS5 sans authentification : tout processus local peut utiliser le tunnel | Reporté ; **accepté par conception** pour l'instant (voir limites) |
| M2 | Moyen | Épuisement des 256 connexions (clients muets, pas de délai d'inactivité) | Reporté |
| F1 | Faible | `allow_non_loopback` sans avertissement | Reporté |
| F2 | Faible | Noms d'hôtes cibles journalisés en debug | Reporté |
| F3 | Faible | `ProxyCleanup::stop` sans contrôle de génération (déni de service à la reconnexion) | Reporté |

Les décisions de report sont détaillées dans [`docs/securite-versions-futures.md`](docs/securite-versions-futures.md).

### Limites de conception

- **Pas de kill-switch hors WFP full-tunnel** : seuls les filtres WFP du mode full-tunnel Windows (IPv6, LLMNR/NBT-NS/mDNS, et blocage pendant la reconnexion) font office de coupe-circuit ; en split-tunnel, en mode proxy et sous Linux, une coupure laisse le trafic repartir hors VPN.
- **NRPT imposée par GPO** : si une stratégie de groupe définit déjà des règles NRPT, on avertit et on continue ; nos règles DNS sont alors sans effet et une **fuite DNS est possible**.
- **SOCKS5 sans authentification** (loopback uniquement par défaut) : tout processus local, autre session RDP ou WSL en mode mirrored peut passer par le tunnel.
- **PSK IPsec de groupe** : un détenteur du PSK peut se faire passer pour la passerelle (voir 6.5 M1) ; l'authentification du répondeur par certificat n'est pas implémentée.
- **Épinglage de certificat à renouveler** : l'empreinte épinglée doit être mise à jour quand la passerelle change de certificat (plusieurs empreintes possibles pour une rotation sans coupure) ; un certificat épinglé est accepté même expiré.
- **Code Windows jamais exécuté en réel** : Wintun, IP Helper, NRPT, WFP, service, pipe et interface graphique sont seulement compilés ; les correctifs de sécurité correspondants ne sont pas validés avant la recette 3.W.
- **DTLS absent** : le tunnel passe uniquement par TLS/TCP.
- **Mot de passe gardé en mémoire pendant la session** (nécessaire à la reconnexion), avec des copies résiduelles possibles (tampons de bibliothèques) ; il n'est jamais écrit sur disque, ni dans les logs.

## Licence

Le projet est distribué sous licence [Apache 2.0](LICENSE).

**Note sur Slint** : l'interface graphique (`fortivpn-gui`) embarque [Slint](https://slint.dev), disponible sous GPLv3 ou sous la licence « Slint Royalty-free », qui impose une attribution. Conformité : **conforme**, écran « À propos » (accessible depuis Réglages) avec le widget `AboutSlint` ; licence Slint Royalty-free, voir `THIRD-PARTY-LICENSES.md`.
