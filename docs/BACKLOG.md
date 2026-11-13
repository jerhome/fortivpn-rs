# Backlog fortivpn-rs

Légende agent : PA = protocol-analyst, RP = rust-proto, WN = windows-net,
TH = test-harness, SR = security-reviewer. **MVP** = périmètre de la première version utilisable.

## Questions ouvertes (bloquantes pour Epic 1)

- [x] Mode d'authentification : **mot de passe seul** (1.2, 1.4, 1.5 déprioritisées).
- [x] SSL-VPN ou IPsec ? → **l'utilisateur utilise SSL-VPN** (confirmé 2026-11-13). SSL-VPN est la priorité ;
      IPsec (Epic 6) reste développé mais **secondaire** : priorité basse, exigences de test allégées.
- [ ] Contrôle de conformité (EMS / host check) exigé par la passerelle ?

## Décisions produit (utilisateur, 2026-11-13)

- **Périmètre autonome** : MVP SSL-VPN → stories SSL-VPN hors MVP (4.1, 4.2, 4.3, 1.2, 2.5…) → IPsec (Epic 6) + revues sécurité.
- **NRPT GPO présente** : avertir clairement et continuer ; ne jamais écrire sous la clé Policies de l'entreprise ; ne pas refuser le full-tunnel.
- **Identifiants CLI** : fichier TOML (hôte, port, utilisateur, realm, épinglage optionnel) ; **mot de passe demandé à chaque connexion**, jamais stocké (pas de Credential Manager / keyring, pas de variable d'environnement).

## Principe d'architecture multi-transport

`core` manipule un trait `Transport` (connect/authenticate → config réseau + flux de paquets IP).
Deux implémentations : `SslVpnTransport` (Epics 1–2) et `IpsecTransport` (Epic 6).
Le `NetBackend` (Epic 3) est commun aux deux.

## Epic 0 — Cadrage

- [x] **S0.1** (PA) Spec du protocole `docs/protocol.md` à partir des sources openfortivpn, avec vecteurs de test. **MVP**
- [ ] **S0.2** Mesure de référence : temps de connexion FortiClient vs openfortivpn (à faire par l'utilisateur).
- [x] **S0.3** (TH) Workspace Cargo, `rustfmt`/`clippy`, script `scripts/check.sh` (Linux + cross-check Windows). **MVP**

## Epic 1 — Authentification

- [x] **1.1** (RP) `POST /remote/logincheck` login/mot de passe → `SVPNCOOKIE`. **MVP**
- [x] **1.2** (RP) Second facteur OTP / FortiToken (challenge `tokeninfo`). _(proto+core+mock-gw faits ; branchement CLI/GUI à faire avec 8.1)_
- [x] **1.3** (RP) Validation TLS (racines système) + épinglage SHA-256 optionnel. **MVP**
- [ ] **1.4** (RP) SAML/SSO : navigateur + récupération du cookie via listener local (si requis).
- [ ] **1.5** (WN) Certificat client depuis le magasin Windows (si requis).

## Epic 2 — Configuration & tunnel

- [x] **2.1** (RP) `GET /remote/fortisslvpn_xml` → IP, routes split-tunnel, DNS, domaines. **MVP**
- [x] **2.2** (RP) `GET /remote/sslvpn-tunnel` + framing (len total, `0x5050`, len PPP, trame). **MVP** _(framing fait ; requête sslvpn-tunnel en cours avec 1.1)_
- [x] **2.3** (RP) Machine à états PPP : LCP (MRU, magic, echo) + IPCP (IP, DNS). **MVP**
- [x] **2.4** (RP) Boucle async TUN ↔ TLS (tokio), keepalive LCP echo. **MVP**
- [ ] **2.6** (RP) **PRIORITAIRE** _(correctif filtre IPv6 + trace -vv faits ; validation terrain à faire, T1-ter)_ Stabilité du tunnel réel : la passerelle coupe après ~40 s (RST) puis DeadPeer (voir docs/field/2026-11-13-wsl-tunnel-drops.md) ; audit LCP Echo/Discard/Reply vs openfortivpn/openconnect, correctif, option de trace des trames PPP de contrôle (`-vv`, sans secret) ; route /32 passerelle EEXIST.
- [ ] **2.5** (RP) Option DTLS. _(étude faite : docs/protocol-dtls.md — reportée : pas de crate DTLS pur Rust adaptée, suites FortiOS inconnues ; à reconsidérer après une capture réelle)_

## Epic 3 — Intégration réseau

Trait `NetBackend` (create_tun, set_addr/mtu, add_routes, set_dns, teardown) défini dans `core`.

- [x] **3.0** (RP) Définition du trait `NetBackend` + implémentation fictive en mémoire pour tests. **MVP**
- [x] **3.L** (TH) `netlinux` : TUN, routes, DNS — sert aux tests e2e dans WSL (netns). **MVP**
- [x] **3.1** (WN) `netwin` : carte Wintun, IP, MTU. **MVP**
- [x] **3.2** (WN) Routes split/full via IP Helper (`CreateIpForwardEntry2`), conservation route vers passerelle. **MVP**
- [x] **3.3** (WN) DNS de l'interface + règles NRPT pour domaines internes. **MVP**
- [x] **3.4** (WN) Nettoyage garanti (Drop, Ctrl+C, crash au démarrage suivant). **MVP**

Note : `netwin` est seulement compilé/clippé depuis WSL. Validation réelle sous Windows
uniquement sur demande explicite de l'utilisateur (story **3.W**).

- [x] **3.S** (WN) Correctifs sécurité netwin avant recette (revue 5.3) : C1+E1 journal d'état (HKLM + filtrage recover),
      M1 mutex instance unique, E2 blocage IPv6 full-tunnel, M2 /32 vers DNS tunnel, M3 NRPT GPO, M4 intégrité wintun.dll, F3 LUID. **MVP**
- [x] **3.S-L** (TH) Correctifs sécurité netlinux : E2 blackhole IPv6, M2 /32 DNS, F1 resolv par fd/O_NOFOLLOW.
- [x] **3.F** (WN) Filtres WFP en session dynamique : blocage IPv6 hors tunnel (ALE_AUTH_CONNECT_V6/RECV_ACCEPT_V6), LLMNR/NBT-NS/mDNS (UDP 5355/137/5353) hors tunnel en full-tunnel ; sert de kill-switch. (revue 5.3 E2/F4)
- [x] **3.S2** Correctifs revue 5.3 passe 2 (docs/security/review-5.3-pass2.md), par priorité : M3 pipe (propriétaire de session + limitation d'essais), M2 WFP maintenu pendant Reconnecting, M1 bornes XML/routes, M4 verrou d'instance par fichier admin-only, F1 ACL des ancêtres + contrôle au démarrage du service, F3 borne du tampon `out`, F2 parseur chunked incrémental, F5 plusieurs `trusted_cert`.
- [ ] **3.W** Recette sous Windows (déclenchée par l'utilisateur). Points ajoutés par 3.S2 partie B :
  - M3 : 2 comptes (RDP/changement rapide) : B ne peut ni `disconnect` ni voir tunnel/étapes de la session de A (`status` = état seul) ; un admin élevé peut couper ; `ImpersonateNamedPipeClient` à SECURITY_IDENTIFICATION donne bien SID + groupe Administrateurs activé ; 3 mots de passe faux -> 30 s, 4 -> 60 s, 5 -> blocage 15 min (message `rate_limited`), sans mot de passe dans `service.log`.
  - M4 : un utilisateur standard ne peut pas créer/ouvrir `%ProgramData%\fortivpn-rs\instance.lock` ni le dossier ; 2e instance (service + CLI admin) -> « autre instance active » ; après crash, le fichier résiduel est rouvert ; le dossier créé par `create_admin_dir` a la DACL SY+BA héritée.
  - F1 : `service install`/`service run` refusés si un ancêtre du dossier de l'exe accorde DELETE_CHILD/WRITE_DAC aux Users (ex. `C:\Tools` modifiable) ; acceptés sous `C:\Program Files` ; la racine `C:\` (Users : create folders) n'est pas refusée à tort ; `\\?\` canonicalisé accepté par GetNamedSecurityInfoW.
  - M2 : full-tunnel, couper la connexion TLS (RST) : pendant `Reconnecting` aucun paquet hors passerelle/DHCP/bouclage (IPv6, LLMNR, DNS) ; la passerelle reste joignable ; après reconnexion le trafic passe par le tunnel et le bloc disparaît ; `disconnect` pendant Reconnecting retire tout (`FwpmEngineClose0`) ; FWP_BYTE_ARRAY16 (passerelle IPv6) et UINT32 (IPv4, ordre hôte) acceptés par FwpmFilterAdd0.
  - F5 : `trusted_cert = ["a", "b"]` accepté ; ancien format chaîne inchangé. 7.1 : config service avec `[proxy]` -> erreur `config` claire.

## Epic 4 — Robustesse & confort

- [x] **4.1** (RP) Reconnexion auto (veille, changement de réseau, perte d'echo).
- [x] **4.2** (RP) Config TOML (hôte, port, utilisateur, realm, trusted-cert) ; mot de passe saisi à chaque connexion sans écho, jamais stocké.
- [x] **4.3** (WN) Service Windows (SYSTEM) + CLI non-admin via named pipe.
- [x] **4.4** (RP) Logs `tracing` + chronométrage de chaque étape de connexion. **MVP**
- [x] **4.6** (RP) Finitions : variantes d'erreur dédiées (`TransportError::SecondFactorRequired`, `NetError::AlreadyRunning`) et codes de sortie CLI associés ; affichage lisible de `ClockJump` ; option TOML `[reconnect]` (activer/désactiver, backoff max) ; `disconnect_timeout` ≤ 4 s sous Windows (arrêt système).
- [ ] **4.7** (RP) Message clair sur `EPERM` à la création de la TUN : « droits insuffisants : lancez avec sudo (Linux) / via le service (Windows), ou utilisez le mode proxy ([proxy] dans la config) ». Et sous sudo sans `-c` : chercher la config de `SUDO_USER` (ou le suggérer dans le message d'erreur). GUI lancée en root (sudo) : avertir « inutile de lancer l'interface avec sudo (mode proxy) » et utiliser la config de `SUDO_USER`.
- [ ] **4.5** Icône zone de notification (plus tard).

## Epic 7 — Mode sans droits administrateur

L'utilisateur n'est pas administrateur de son poste Windows (2026-11-13).

- [x] **7.1** (RP) Mode proxy en espace utilisateur (sans TUN, sans admin) : pile TCP/IP `smoltcp` alimentée par le `PacketChannel` du tunnel ; proxy **SOCKS5** local (CONNECT TCP, résolution DNS via les DNS du tunnel) + **redirections de ports** `local:port → hôte:port` ; config TOML `[proxy]` ; aucune route/DNS système modifié. Fonctionne sous Windows non-admin et dans WSL.
- [x] **7.S** (RP) Port d'écoute du proxy (revue 7.1, E1) : bind exclusif sous Windows (SO_EXCLUSIVEADDRUSE) et, en cas de conflit/détection d'un autre écouteur sur le même port, **informer clairement l'utilisateur** (message CLI/GUI + log) plutôt que de démarrer silencieusement. Les autres constats (M1, M2, F1–F3) sont reportés : docs/securite-versions-futures.md.
- [x] **7.2** (TH) Tests e2e du mode proxy contre mock-gw (pair TCP simulé côté passerelle).

## Epic 8 — Interface graphique (demandée 2026-11-13, après les stories en cours ; prioritaire sur la fin d'IPsec)

Une seule base de code Rust multiplateforme en **Slint** (choix validé par l'utilisateur le 2026-11-13), design **dark et moderne**.
- [x] **8.0** Maquettes et design : écrans connexion / état (étapes + durées) / journal / réglages, thème sombre. _(maquette validée : docs/gui/maquette.html)_
- [x] **8.1** GUI Windows : connexion (mot de passe saisi, jamais stocké), état temps réel, déconnexion, journal, réglages (config TOML, mode proxy) ; fonctionne **sans droits admin** (mode proxy, ou via le service 4.3 une fois installé).
- [x] **8.5** Licence Slint « Royalty-free » (choix utilisateur 2026-11-13) : écran « À propos » avec le widget `AboutSlint` / mention « Made with Slint », fichier de licences tierces (Slint + dépendances), README mis à jour.
- [ ] **8.6** (RP) Première utilisation guidée (retour terrain Windows 2026-11-13) : config absente → ouvrir directement Réglages avec un assistant (passerelle, port, utilisateur, épinglage proposé après 1re connexion) au lieu d'une erreur ; mode Service grisé avec explication si le service n'est pas installé, mode Proxy sélectionné par défaut ; mémoriser le dernier mode choisi.
- [ ] **8.2** Icône de zone de notification + notifications (fusionne 4.5).
- [ ] **8.3** Distribution Windows : exe portable (+ wintun.dll pour le mode service), icône, version.
- [ ] **8.4** (priorité basse) GUI Linux X11/Wayland — même base de code, tests dans WSLg.

## Epic 5 — Qualité

- [x] **5.4** (TH) Interop core::tunnel ↔ mock-gw `PppPeer` (en mémoire, tous les `PppFault`), puis e2e complet SslVpnTransport ↔ MockGateway (TLS + épinglage) une fois `SslVpnTransport` disponible.

- [x] **5.1** (TH) `tools/mock-gw` : TLS, auth, XML, PPP, trafic ICMP en écho. **MVP**
- [x] **5.2** (TH) Fuzzing du framing et du PPP (`cargo-fuzz`).
- [ ] **5.3** (SR) _(passes 1 et 2 faites ; 1re passe : netwin/netlinux/proto frame+ppp/core base — 1 critique, 2 élevés)_ Revue sécurité par epic : TLS, secrets (`zeroize`), `unsafe`, privilèges.

## Epic 6 — IPsec (dialup FortiGate) — SECONDAIRE

Priorité basse : ne prend un créneau d'agent que si aucune story SSL-VPN n'est débloquée.
Tests allégés : tests unitaires sur vecteurs + un test d'interop strongSwan « happy path » suffisent ;
pas de fuzzing ni de couverture exhaustive des cas d'erreur ; revue sécurité en fin d'epic seulement.

- [x] **6.0** (PA) Étude : variantes utilisées par FortiClient (IKEv1 aggressive + XAuth + mode-config,
      IKEv2 + EAP, NAT-T UDP 4500, IKE/ESP sur TCP FortiOS 7.4+), suites crypto, référence
      strongSwan/libreswan. Spec `docs/protocol-ipsec.md`.
- [ ] **6.1** (RP) Crate `ipsec` : IKEv2 + PSK + EAP-MSCHAPv2 (variante retenue en 6.0, voir protocol-ipsec.md) — échange, auth PSK + XAuth/EAP mot de passe, mode-config.
- [x] **6.2** (RP) ESP en espace utilisateur sur UDP 4500 (AES-GCM / AES-CBC+HMAC), anti-rejeu, DPD.
- [x] **6.3** (RP) Rekey IKE/CHILD SA.
- [x] **6.T** (RP) `IpsecTransport` : implémentation du trait core `Transport` (sockets UDP 500/4500 tokio, pilotage IkeInitiator + EspTunnel, timers, DPD/rekey) ; test e2e contre le répondeur simulé sur vraies sockets UDP locales.
- [ ] **6.4** (TH) Interop strongSwan « happy path » dans un netns WSL (pas de mock-gw IPsec).
- [x] **6.5** (SR) Revue crypto. _(docs/security/review-6.5-ipsec.md : 0 critique/élevé, 1 moyen, 8 faibles)_
- [x] **6.S** (RP) Correctifs revue 6.5 : M1 (PSK minimal + `expected_idr` recommandé, préparer auth répondeur par certificat épinglé), F1 (erreurs IKE_SA_INIT non authentifiées ignorées jusqu'au timeout, cookie ≤ 64 o), F2 (PFS exigé au rekey CHILD), F3 (zeroize + chiffreur ESP en cache), F4 (ECP-256 en tête), F7/F8 (validation CP/TS et paquet IPv4 interne), I4 (tests négatifs).

## Ordre de réalisation proposé

1. S0.3, S0.1
2. 5.1 (mock-gw minimal) ∥ 2.2 + 2.3 (proto pur, testable sur vecteurs)
3. 1.1, 1.3, 2.1
4. 3.0, 2.4, 3.L → **premier tunnel e2e dans WSL contre mock-gw**
5. 3.1–3.4 (cross-compilé), 4.4, revue SR
6. 3.W (sur demande) → MVP SSL-VPN livré
7. 6.0 (peut démarrer dès le début en parallèle) → 6.1–6.5 → MVP IPsec
