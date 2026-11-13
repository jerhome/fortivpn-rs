# Revue sécurité 5.3 — 1re passe (2026-11-13)

Périmètre : crates/netwin, crates/netlinux, proto::frame, proto::ppp, core::{net,config,packet,transport,error}.
Aucun secret exposé dans ce périmètre. proto::frame/ppp jugés solides. Blocs `unsafe` de netwin : SAFETY pertinents.

## CRITIQUE

**C1 — Journal state.json : suppression/écrasement arbitraire de fichiers par le processus admin**
`netwin/src/state.rs:198-199` (%ProgramData% lu dans l'environnement), `:133` create_dir_all, `:146` File::create .tmp, `:150` rename, `:126` remove_file, `:106` read.
- `%ProgramData%` peut être masqué par une variable utilisateur (HKCU\Environment) héritée à l'élévation UAC.
- Dossier préexistant réutilisé sans vérifier propriétaire ni point de reparse ; opérations par chemin (suivent les liens).
- Exploitation : jonction vers `\RPC Control` + lien symbolique objet → `remove_file(state.json)` supprime une cible arbitraire en admin (→ SYSTEM via Config.msi) ; `.tmp` tronque un fichier arbitraire.
- Correctif recommandé : journal dans **`HKLM\SOFTWARE\fortivpn-rs`** (valeur REG_SZ JSON, RegSetValueExW). Sinon : SHGetKnownFolderPath(FOLDERID_ProgramData), CreateDirectoryW avec SDDL `O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, refus si reparse point ou propriétaire ≠ SY/BA, E/S par handle avec FILE_FLAG_OPEN_REPARSE_POINT.

## ÉLEVÉ

**E1 — Contenu du journal non authentifié → suppression de routes/adresses/DNS arbitraires**
`engine.rs:172` load, `:185` → `ffi.rs:211-216` remove_address, `:250-255` remove_route, `:296-312` clear_interface_dns.
ACL par défaut de C:\ProgramData : Users peuvent créer des fichiers dans les sous-dossiers. Un utilisateur forge state.json → l'admin supprime l'IP statique / route par défaut / DNS de la carte physique.
Correctif : C1 + dans `recover` : ne supprimer une Route que si GetIpForwardEntry2 la retrouve avec Protocol == MIB_IPPROTO_NETMGMT et Metric == ROUTE_METRIC ; ignorer Address/InterfaceDns dont le LUID n'est pas notre adaptateur (ConvertInterfaceGuidToLuid(adapter_guid(name))) ; borner taille (64 Kio) et nombre d'entrées.

**E2 — Fuite IPv6 en full-tunnel (Windows et Linux)**
`netwin/src/plan.rs:143-154`, `netlinux/src/plan.rs:180-206` : seules 0/1 et 128/1 sont installées ; l'IPv6 physique reste actif (AAAA préférés, faux RA mitm6).
Correctif : Windows robuste = filtres WFP en session dynamique (ALE_AUTH_CONNECT_V6 / RECV_ACCEPT_V6 hors tunnel) ; minimal = routes `::/1` + `8000::/1` sur Wintun et abandon des paquets IPv6 dans le relais. Linux = blackhole `::/1` + `8000::/1`.

## MOYEN

**M1 — Pas de verrou d'instance unique** (`engine.rs:383`, `win/mod.rs:181`, `plan.rs:216`, `tun.rs:96`) : une 2e instance rejoue le journal de la 1re et démonte ses routes/NRPT → trafic en clair.
Correctif : mutex nommé `Global\fortivpn-rs-netwin` (DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)`), refus si ERROR_ALREADY_EXISTS, pris avant recover_stale/apply, gardé toute la vie du processus (WAIT_ABANDONED = acquis).

**M2 — Serveur DNS du tunnel non couvert par les routes** (`netwin/src/plan.rs:118-166, 260-270`, `netlinux/src/plan.rs:170-179`) : requêtes DNS internes en clair sur la carte physique → usurpation, capture NTLM.
Correctif : route /32 Via::Tunnel pour chaque DNS IPv4 non couvert par une inclusion (et en full s'il tombe dans une exclusion) ; exception DNS == passerelle (avertissement).

**M3 — NRPT locale ignorée si une NRPT GPO existe** (`ffi.rs:336`) : sur poste d'entreprise, la règle `.` du full-tunnel est sans effet → fuite DNS.
Correctif : détecter des sous-clés sous `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig` ; si présent, écrire aussi nos règles sous la clé GPO + `RefreshPolicyEx(TRUE, RP_FORCE)`, journalisées avec leur racine ; à défaut avertir / refuser le full-tunnel.

**M4 — Intégrité de wintun.dll et du dossier d'installation** (`win/tun.rs:47-66`, `win/mod.rs:31-34`) : le SAFETY suppose un dossier admin-only sans le vérifier.
Correctif : vérifier (GetNamedSecurityInfoW) que le dossier de l'exe et wintun.dll appartiennent à SY/BA/TrustedInstaller sans ACE d'écriture pour Users/Authenticated Users/Everyone/INTERACTIVE ; épingler SHA-256 de wintun.dll officielle (amd64 0.14.1) en gardant le fichier ouvert share_mode(FILE_SHARE_READ) pendant le chargement (ou WinVerifyTrust, signataire WireGuard LLC) ; SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) en début de main ; wintun_dll/state_path jamais fixables par un client du named pipe (4.3).

## FAIBLE

- **F1 — Linux resolv : liens suivis + TOCTOU** (`netlinux/src/dns.rs:114-130, 156-175, 178-190`). Correctif : parent ouvert O_DIRECTORY|O_NOFOLLOW (root, pas g+w/o+w), openat O_NOFOLLOW, garder le fd dans Undo::Dns, restaurer par ftruncate+pwrite.
- **F2 — Données poussées par la passerelle peu bornées** (`netwin/src/plan.rs:200-213, 260-270`, `core/src/config.rs:90-110`, `proto/src/ppp/session.rs:775`) : domaine `com` → NRPT `.com` ; milliers de routes/domaines ; local_ip = passerelle/loopback/LAN ; /0 accepté. Correctif : refuser domaines à un label et suffixes publics, liste blanche optionnelle, bornes (~64 domaines, ~1024 routes), validate() refuse loopback/link-local/local==gateway et DNS non spécifiés/loopback/multicast.
- **F3 — LUID Wintun résolu par alias** (crate wintun 0.5.1 `adapter.rs:95-96`, `tun.rs:99`) : si l'alias existe déjà, mauvaise interface. Correctif : comparer adapter.get_luid() à ConvertInterfaceGuidToLuid(adapter_guid(name)).
- **F4 — LLMNR/NBT-NS/mDNS actifs sur la carte physique en full-tunnel** : bloquer UDP 5355/137/5353 hors tunnel via WFP, ou documenter.
- **F5 — Règles NRPT non volatiles** (`ffi.rs:370`) : utiliser REG_OPTION_VOLATILE (à valider en 3.W).

## INFO
- `ffi.rs:545` DnsFlushResolverCache : SetLastError non documenté. Crate wintun : fuite de handle si alias_to_luid échoue.
- Pas de kill-switch (les filtres WFP de E2/F4 en tiendraient lieu).
- Pour core::tunnel (hors périmètre) : borner l'accumulation après FrameError::HttpResponse ; vider poll_transmit à chaque trame.
- Recommandé : `cargo deny check advisories` en CI.

## À corriger avant la recette Windows (3.W)
1. C1 + E1  2. M1  3. E2  4. M2  5. M3  6. M4  7. F3.
À observer en 3.W : icacls du dossier ProgramData, persistance des routes IP Helper après reboot, NRPT locale vs GPO, clé NRPT volatile, alias Wintun déjà existant.
