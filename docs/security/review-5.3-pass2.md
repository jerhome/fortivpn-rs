# Revue sécurité 5.3 - 2e passe (2026-11-13)

Périmètre : proto::{http,auth,config}, core::{sslvpn/*,tunnel,session,session/reconnect}, cli (config, svc, logs),
crates/service (pipe, SCM, protocole), netwin::{wfp, win/wfp, win/security, integrity}. Hors périmètre : netproxy.
Lecture seule ; `cargo audit`/`cargo deny` non installés, advisory-db absente (dépendances non vérifiées ici).

## Points validés (aucun constat)
- TLS : TLS1.2+ (rustls/ring), vérificateur custom correct : épingle comparée en temps constant sur tout le tableau, signatures
  de handshake vérifiées, nom d'hôte vérifié par WebPki hors épinglage, pas de repli silencieux, SNI découplé du nom vérifié.
- Secrets : requêtes HTTP en Zeroizing à capacité fixe, Debug masqués (cookie, Set-Cookie, Request::Connect, Credentials),
  cookie validé (0x21..0x7e, sans `;`) donc pas d'injection d'en-tête, pas de secret dans TOML/argv, erreurs sans écho de l'entrée.
- HTTP : tailles bornées (tête 64 Kio, réponse 1 Mio, 128 en-têtes, chunk 8 hex), Content-Length multiples refusés, délai global 30 s.
- XML : quick-xml sans résolution d'entités ; domaines validés (pas d'injection resolv/NRPT par caractères).
- Pipe : DACL protégée sans FILE_CREATE_PIPE_INSTANCE, FIRST_PIPE_INSTANCE, clients distants refusés, SECURITY_IDENTIFICATION,
  PID serveur vérifié avant toute écriture (et à chaque connexion), message <= 16 Kio, une requête/connexion, config = fichier admin-only.
- WFP : session dynamique, transaction atomique, structures zéro-initialisées, durées de vie des pointeurs correctes.

## MOYEN
M1 - DoS CPU/mémoire par XML hostile : `core/src/sslvpn/config.rs:46-56` (include_minus_exclude) + `proto/src/config.rs:219,194-217`.
  Scénario : la passerelle (ou un MITM sans épinglage) envoie <= 1 Mio de XML : 1 include `0.0.0.0/0` + ~23 000 excludes /32 ;
  `subtract` éclate en ~32 préfixes par exclude, boucle O(n*m) (~10^10 opérations, minutes de CPU bloquant le thread du runtime,
  en mode service runtime mono-thread) puis ~700 000 routes à installer via IP Helper. Idem ~100 000 domaines distincts (push_unique/
  eq_ignore_ascii_case en O(n^2)) puis règles NRPT. Complète F2 de la passe 1.
  Correctif : dans parse_config refuser > 1024 routes (include+exclude), > 64 domaines, > 9 DNS ; borner la sortie de
  include_minus_exclude (ex. 4096) -> erreur ConfigError ; utiliser un HashSet pour la déduplication.
M2 - Fuite hors tunnel pendant la reconnexion : `netwin/src/win/mod.rs:259,266-275` (filtres WFP retirés dans teardown) +
  `core/src/session.rs` (config réseau annulée à chaque reconnexion, attente jusqu'à 60 s).
  Scénario : un attaquant sur le chemin coupe la connexion TLS (RST) ; la session annule routes, NRPT et filtres WFP, donc IPv6/LLMNR/DNS
  et tout le trafic repartent en clair pendant le backoff et le connect. Les filtres E2/F4 de la passe 1 n'existent pas à ce moment.
  Correctif : garder la session WFP et un bloc "tout sauf tunnel/passerelle/loopback/DHCP" pendant Reconnecting (Firewall découplé
  du cycle apply/teardown, retiré seulement à disconnect), au minimum conserver les blocs IPv6 et 137/5353/5355.
M3 - Pipe ouvert à tout utilisateur interactif : `service/src/protocol.rs:46` (SDDL `(A;;0x12019b;;;IU)`), `controller.rs:95-108`.
  Scénario : sur poste multi-sessions (RDP, changement rapide d'utilisateur) ou avec un malware du même utilisateur, un autre compte
  interactif envoie `disconnect` (coupe le VPN d'autrui, repli en clair, cf. M2) ou boucle sur `connect` avec des mots de passe devinés
  pour le compte configuré (verrouillage du compte VPN, DoS ; le service sert de relais SYSTEM).
  Correctif : enregistrer le SID du demandeur (GetNamedPipeClientProcessId puis jeton, ou DACL limitée à un groupe local
  "fortivpn-users"/SID de l'installateur), refuser disconnect d'un autre SID, limiter les échecs d'authentification (ex. 3 puis 30 s).
M4 - Verrou d'instance squattable : `netwin/src/win/security.rs:85-141`. Un mutex `Global\` n'exige pas SeCreateGlobalPrivilege (réservé aux
  file-mapping/symlinks) : un utilisateur standard crée `Global\fortivpn-rs-netwin` avant le service ; `CreateMutexW` du service renvoie
  ERROR_ALREADY_EXISTS -> "une autre instance est active", le service ne purge plus les résidus et plus aucune connexion n'est possible
  (DoS persistant, reproductible au boot). L'affirmation du commentaire (lignes 92-96) est inexacte. À valider en 3.W.
  Correctif : verrou par fichier exclusif (share_mode(0), FILE_FLAG_DELETE_ON_CLOSE) dans le dossier admin-only, ou vérifier le
  propriétaire de l'objet existant (OpenMutexW + GetSecurityInfo) et ne pas faire confiance au nom ; le pipe FIRST_PIPE_INSTANCE sert déjà d'exclusion pour le service.

## FAIBLE
F1 - Vérification d'ACL limitée à la cible : `win/security.rs:240-285`, appelée par `cli/src/svc.rs:383-389,231`. Les ancêtres ne sont pas
  contrôlés : exe installé dans `C:\Tools\fortivpn\` (dossier admin-only) sous un parent où Users ont FILE_DELETE_CHILD/ADD_SUBDIR ;
  l'utilisateur renomme le dossier et le remplace (service SYSTEM lancera son exe/wintun.dll). Contrôle fait seulement à `install`,
  pas à chaque démarrage. Correctif : remonter la chaîne jusqu'à la racine du volume (refuser si un ancêtre est modifiable) et
  rejouer le contrôle de l'exe/dll au démarrage du service ; idéalement imposer `%ProgramFiles%`.
F2 - Re-décodage quadratique : `proto/src/http.rs:526-575` (decode_chunked, parse_head rappelés à chaque push). Une passerelle envoyant
  un corps chunked en chunks de 1 octet via des enregistrements TLS d'1 octet force ~10^10 opérations (borné par les 30 s, mais
  rejoué à chaque reconnexion/retry). Correctif : parseur chunked incrémental (offset consommé mémorisé), ne pas reparser
  l'en-tête incomplet tant que de nouveaux CRLFCRLF n'apparaissent pas.
F3 - Accumulation sortante non bornée : `core/src/tunnel.rs:374-380,501-521`. Les réponses PPP (Echo-Reply, Protocol-Reject) sont
  mises dans `out` sans tenir compte de WRITE_HIGH_WATER ; une passerelle qui n'acquitte plus TCP mais envoie des Echo-Request en
  continu fait croître `out` (et `PppSession::transmit`) sans limite (1 octet reçu -> ~1 octet en mémoire). La question de passe 1 sur
  `HttpResponse` est en revanche close (lecture bornée à 1 Kio / 1 s dans `refused`/`write_failed`). Correctif : si `out.len()` >
  ~1 Mio, ignorer les Echo-Request/Reject (ou terminer avec DeadPeer) ; borner `transmit`.
F4 - Mot de passe : copies résiduelles non effacées : serde_json (tampon `scratch` si le mot de passe contient des échappements `\"`, `\\`,
  `\uXXXX`) `service/src/protocol.rs:253-256`, buffers internes rustls/tokio ; mot de passe gardé toute la session
  (`core/src/session.rs:27`). Scénario : dump mémoire/swap du service SYSTEM. Correctif : désérialiser le mot de passe à la main
  (`&RawValue`/format binaire), VirtualLock du processus ou désactivation du pagefile ; documenter la limite.
F4b - Journal `service.log` (`cli/src/svc.rs:405-416`) : append non borné, niveau Info fixe, ouverture sans FILE_FLAG_OPEN_REPARSE_POINT
  (dossier admin-only, donc risque limité) ; messages d'erreur issus de la passerelle (raison TLS, noms quick-xml) non assainis :
  caractères de contrôle/ANSI relayés au terminal du client par le pipe (`svc.rs:277`). Correctif : rotation/taille max, filtrer
  `char::is_control` dans Outcome.message et Response::Error.
F5 - Épinglage : un certificat épinglé est accepté même expiré/révoqué et sans contrôle du nom (choix documenté `tls.rs:9-17`) ; une seule
  empreinte acceptée côté CLI (`cli/src/config.rs:118`), donc rotation impossible sans fenêtre d'indisponibilité. Correctif : accepter
  une liste `trusted_cert` (la crate la supporte déjà), avertir si le certificat épinglé est expiré.

## INFO
- Dépendances : Cargo.lock = rustls 0.23.46, rustls-webpki 0.103.17, ring 0.17.14, quick-xml 0.42.0, tokio 1.54.1 ; vérification RustSec
  impossible hors ligne (cargo-audit/deny absents). Ajouter `cargo deny check advisories` en CI.
- `rustls_native_certs` sous Linux lit SSL_CERT_FILE/SSL_CERT_DIR : à ignorer si le binaire tourne via `sudo -E`.
- `Status` expose interface/adresse du tunnel à tout utilisateur interactif (sans impact grave).

## Correctifs priorisés
1. M3 (propriétaire de session + limitation d'essais du pipe)   2. M2 (filtres WFP maintenus pendant Reconnecting)
3. M1 (bornes sur le XML et la soustraction de routes)   4. M4 (verrou d'instance non squattable)   5. F1 (ACL des ancêtres + contrôle au démarrage)
6. F3 (borne de `out`)   7. F2 (parseur chunked incrémental)   8. F5, F4/F4b, dépendances en CI.
