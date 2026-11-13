# Étude DTLS — Fortinet SSL-VPN (story 2.5)

Statut : **étude**, aucune implémentation. Sources : openconnect (`fortinet.c`, `ppp.c`,
`dtls.c`, `gnutls-dtls.c`, `openssl-dtls.c`, `www/fortinet.xml`, commit `70d1e79`) ; lecture du
code uniquement, **aucune capture de passerelle réelle**. openfortivpn ne gère **pas** DTLS
(aucune occurrence de « dtls » dans son arbre ni son CHANGELOG ; il délègue à pppd sur TLS).
Hôtes/cookies anonymisés. Complète `docs/protocol.md` (§4 auth, §5-§9 PPP, §13 extensions).

## 1. Négociation

1. L'auth et `GET /remote/fortisslvpn_xml` se font **comme en TLS** (protocol.md §4).
2. La réponse XML annonce DTLS (exemple openconnect, FortiOS 5.6.6) :
   ```xml
   <sslvpn-tunnel ver="2" dtls="1" patch="1">
     <dtls-config heartbeat-interval="10" heartbeat-fail-count="10"
                  heartbeat-idle-timeout="10" client-hello-timeout="10"/>
     <tunnel-method value="ppp"/><tunnel-method value="tun"/>
   ```
3. Règles openconnect : DTLS tenté si `sslvpn-tunnel@dtls` vaut un entier non nul. **Port : le
   même que le port TLS, en UDP** (aucun attribut de port ; openconnect commente
   « DTLS always uses same port as TLS? » -> hypothèse non confirmée). Seul
   `dtls-config@heartbeat-interval` est lu (-> intervalle DPD, en secondes, s'il est non nul).
   `heartbeat-fail-count`, `heartbeat-idle-timeout`, `client-hello-timeout` sont **ignorés** par
   openconnect (sémantique supposée : nb d'échecs avant coupure, inactivité avant heartbeat,
   délai de l'attente du hello ; à valider).
4. Pas de négociation de suite par en-tête HTTP (contrairement à AnyConnect) : aucun secret ni
   session ID n'est échangé. L'authentification DTLS repose sur le **cookie `SVPNCOOKIE`**
   renvoyé dans le premier message applicatif (§2).
5. **Quand basculer** (openconnect) : DTLS est tenté **avant** le tunnel TCP. Le
   `GET /remote/sslvpn-tunnel` TCP est différé tant que DTLS n'a pas échoué ; si DTLS n'est pas
   « établi » dans les **5 s** après la config, on ouvre le tunnel TLS (repli, §3). Si DTLS
   réussit, **le tunnel TCP n'est jamais ouvert** et le PPP est (re)négocié sur DTLS.
6. Comme le XML de la passerelle peut avoir `dtls="0"` (option `dtls-tunnel` désactivée côté
   FortiGate ; valeur par défaut selon version : non vérifié), le client doit simplement rester
   en TLS dans ce cas. Commentaire openconnect : certains serveurs ne supportent pas la
   « reconnexion » (2e connexion avec le même cookie) -> DTLS échoue, TLS reste utilisé.

## 2. Handshake DTLS

- Transport : socket UDP `connect()`ée vers `<gw>:<port>`. Un seul datagramme = un enregistrement.
- **Le handshake DTLS est un DTLS standard à certificat** (« anon » dans openconnect = pas de
  PSK/session reprise, contrairement à AnyConnect) : le client réutilise le contexte de
  validation de certificat de la session HTTPS (même vérification d'hôte/épinglage). Aucun
  certificat client n'est envoyé spécifiquement (identique à HTTPS si configuré).
- **Version** : openconnect n'impose rien pour Fortinet (`dtls12=1` -> ne force pas DTLS 1.0).
  GnuTLS : priorités par défaut avec DTLS 1.0 et 1.2 ; OpenSSL : `dtlsver=0` (méthode DTLS
  générique, min/max libres) et `SECLEVEL 0` si OpenSSL >= 3.1 pour permettre DTLS 1.0. Cela
  suggère que **certains FortiGate négocient DTLS 1.0** (ou au moins n'étaient pas
  garantis en 1.2). Version/suites réellement choisies par FortiOS 6.x/7.x : **non vérifié**
  (FortiOS >= 7.2 mentionne DTLS 1.2 dans sa doc, à confirmer par capture).
- **Suites** : liste du ClientHello = la priority string par défaut de la bibliothèque (pas de
  liste Fortinet dédiée). Tout ce qui est attendu (RSA/ECDHE-RSA, AES-CBC-SHA, AES-GCM) est
  possible : certificat serveur typiquement RSA.
- Pas de ClientHello « spécial » : GnuTLS est initialisé avec `GNUTLS_NO_EXTENSIONS`
  (aucune extension envoyée) ; OpenSSL envoie ses extensions normales. La passerelle accepte
  donc les deux. Retransmissions du handshake : timers DTLS standard (RFC 6347 §4.2.4).
- **Hello applicatif** (envoyé en `application_data` DTLS dès handshake terminé), format
  octet par octet, cookie `C` de longueur `n` (valeur de `SVPNCOOKIE`, chaîne ASCII) :

  ```
  offset  taille  contenu
  0       2       be16 = 2 + 27 + n + 1  (longueur TOTALE, ce champ inclus)
  2       27      "GFtype\0clthello\0SVPNCOOKIE"   (47 46 74 79 70 65 00 63 6c 74 68 65 6c 6c 6f 00
                                                    53 56 50 4e 43 4f 4f 4b 49 45 ; + 1 octet 00 final
                                                    du littéral = 27 octets au total)
  29      n       valeur du cookie
  29+n    1       00
  ```
  Exemple avec cookie anonymisé `abc` : `00 21 | GFtype\0clthello\0SVPNCOOKIE\0 | abc\0` (0x21 = 33).
  Note : le littéral `"GFtype\0clthello\0SVPNCOOKIE"` + son NUL implicite fait 27 octets ;
  le NUL séparant « SVPNCOOKIE » et la valeur est donc ce NUL de fin du littéral.
- **Réponse** : datagramme `be16 len | "GFtype\0svrhello\0handshake\0" (26 o) | "ok\0"`, soit
  `00 1f` + 26 + 3 = 31 octets. Tout autre statut (ex. `fail`) ou format -> DTLS abandonné.
- **Retransmission** : le client renvoie le clthello **chaque seconde** jusqu'à la réponse (le
  serveur ne renvoie pas le `ok` perdu). Échec si rien après **5 s** -> fermeture DTLS.
  Tolérance openconnect : un datagramme PPP reçu avant le `ok` est ignoré (voire pris comme
  succès implicite, TODO non codé).
- Vecteurs à produire à l'implémentation : `docs/vectors/dtls_clthello.hex`,
  `dtls_svrhello_ok.hex` (calculés d'après ce document, non capturés).

## 3. Encapsulation PPP, keepalive, repli

- **Même en-tête 0x5050 qu'en TLS** (`PPP_ENCAP_FORTINET` partagé par les deux transports) :
  `be16 total(=payload+6) | be16 0x5050 | be16 payload | trame PPP (proto 2 o + données)`
  (protocol.md §5). Sur DTLS, un datagramme porte **une** trame ; la boucle de lecture accepte
  des trames concaténées (champ `next`) et rejette un datagramme tronqué (pas de réassemblage
  possible, contrairement à TLS). Pas de HDLC.
- Après `svrhello ok`, openconnect **remet à zéro le PPP** (`ppp_reset`) et relance toute la
  négociation LCP/IPCP/IP6CP **sur DTLS** : la session PPP TCP n'a jamais existé (tunnel TCP
  différé). Le MRU/MTU négocié par PPP reste valable ; openconnect suppose une base de 1500
  octets moins IP (20/40) + UDP (8) puis l'overhead d'enregistrement (`dtls_set_mtu`), et
  note lui-même que cette détection de MTU est à améliorer -> **fragmentation/MTU DTLS à
  concevoir** (MRU proposé <= ~1400 par prudence ; valeur Fortinet non vérifiée).
- **Keepalive/DPD** (code ppp commun) : si l'intervalle DPD (`heartbeat-interval`, déf. 10 s)
  est atteint sans réception -> **LCP Echo-Request** (magic en données) ; keepalive simple =
  **LCP Discard-Request**. Pas de paquets `AC_PKT_DPD` (c'est AnyConnect). Mort du lien si
  pas de réponse après les délais openconnect (`keepalive_action`) : fermeture DTLS.
- **LCP Terminate** : 3 tentatives (1 s d'intervalle) sur DTLS avant abandon.
- **Repli sur TLS** : échec handshake, `svrhello` absent/`fail`, ou mort DPD en cours de session
  -> `dtls_close`, état « sleeping » ; la boucle TCP rouvre alors le tunnel TLS
  (`GET /remote/sslvpn-tunnel` + PPP, protocol.md §6) et DTLS peut être retenté
  périodiquement (période openconnect, non vérifiée ici). Un seul transport actif à la fois.
- Autre point : le cookie reste valable pour la connexion TLS de repli (même `SVPNCOOKIE`).

## 4. Faisabilité en Rust, cross-compilation `x86_64-pc-windows-gnu`

Contraintes : **client** DTLS, certificat serveur **RSA** probable validé par PKI/épinglage,
DTLS 1.0 et/ou 1.2, suites CBC-SHA/GCM RSA ou ECDHE-RSA, enregistrements applicatifs 1/datagramme.
(Versions relevées sur crates.io le 2026-11-13.)

| Crate | Ver./maj | DTLS | Suites/Certs | Verdict |
|---|---|---|---|---|
| `dimpl` | 0.9.0 (2026-10) | 1.2 et 1.3, sans 1.0 | AEAD seul (GCM/ChaCha), ECDHE, **ECDSA seul : « non-goals : RSA, DHE, DTLS 1.0 »**, EMS imposé | Pur Rust, sans unsafe, Sans-IO (s'intègre bien à tokio), actif ; **incompatible** avec un FortiGate à cert RSA |
| `webrtc-dtls` | 0.12.0 (2025-05) | 1.2 | ECDHE-ECDSA/PSK AES-GCM/CCM, orienté WebRTC (certs auto-signés) ; RSA/CBC non pris en charge (à re-vérifier) | Pur Rust ; projet webrtc-rs peu maintenu ; **incompatible** idem |
| `openssl` (0.10.82) + `openssl-src` `vendored` | actif | 1.0/1.2 (si OpenSSL le permet) | Tout (RSA, CBC, GCM) | Compile OpenSSL **C** via gcc/perl/make : cross-mingw faisable mais ce n'est **pas** « sans OpenSSL C » ; `SslStream` exige un adaptateur datagramme (1 `write` = 1 datagramme, `read_ahead`). `openssl-src` 400.x = OpenSSL 4.x : support DTLS 1.0 à vérifier |
| `boring` (5.5.0) | actif | 1.0/1.2 | Complet | C++/cmake/clang ; cross-mingw pénible ; surdimensionné |
| `rustls` | 0.24-dev | **aucun DTLS** | - | Exclu |
| `mbedtls` (fortanix), `tinydtls-sys` | - | 1.2 | tinydtls : PSK/ECDSA | C, peu pertinent |

Conclusion : **aucun crate pur Rust ne couvre le profil Fortinet actuel** (cert RSA + DTLS 1.0/1.2
CBC/RSA possible). Options : (a) `openssl` vendored (C, accepté seulement en dehors du binaire
« 100 % Rust »), (b) étendre `dimpl` (RSA-sign/vérif, ECDHE-RSA-GCM ; DTLS 1.0/CBC peu probable
à upstream), (c) écrire/forker un client DTLS 1.2 minimal sur RustCrypto (ECDHE-RSA-AES-GCM)
~2-3 k lignes + revue sécu. Point bloquant commun : **ignorer quelle(s) suite(s) FortiOS
accepte** ; sans capture, impossible de trancher entre (b)/(c).
Le `security-reviewer` devra auditer toute implémentation maison (DTLS = surface crypto sensible).

## 5. Gain attendu et recommandation

- **Gain** : supprime le TCP-over-TCP (pertes -> retransmissions TCP imbriquées, head-of-line
  blocking, effondrement de débit à partir de ~1 % de pertes/RTT élevé, latence irrégulière).
  Sur lien sain (LAN/fibre, RTT < 30 ms), débit **proche de TLS** et la limite devient le
  chiffrement/boucle Wintun ; gain surtout sur Wi-Fi/4G/VPN longue distance (x2 à x10 en
  conditions dégradées, ordre de grandeur général, **non mesuré** pour Fortinet). Latence :
  pas de HoL, sensible aux jeux/VoIP/RDP.
- **Coûts** : 2e transport dans `core` (état DTLS/TLS, repli, re-tentatives, MTU), tests
  mock-gw UDP/DTLS, dépendance crypto lourde ou code maison.
- **Recommandation : PAS MAINTENANT.** (1) bloqué par le choix de crate/suites inconnues,
  (2) le MVP et l'Epic 6 (IPsec, UDP/ESP natif, déjà prévu pur Rust) offrent le même gain
  « UDP » sans DTLS, (3) la passerelle de l'entreprise peut ne pas annoncer `dtls="1"`.
  **Pré-requis avant de relancer** : capture anonymisée (sur accord explicite) du `dtls=` du XML
  et du ClientHello/ServerHello/suite DTLS d'un client réel (ex. openconnect `--protocol=fortinet
  -vv` ou Wireshark UDP) ; re-évaluer alors dimpl (cert ECDSA + GCM) ou openssl vendored.
- **Complexité (si GO)** : crate `proto` (hello applicatif, plumbing 0x5050 : réutilisation
  directe) 1-2 j ; transport `core` (état, repli TLS, DPD) 3-4 j ; mock-gw DTLS 2-3 j ; DTLS via
  openssl vendored 2 j de plomberie, via dimpl étendu/maison 2-3 semaines + revue sécurité.
  Total : **~1 sem. (openssl vendored) à ~4 sem. (pur Rust)**. Le choix d'architecture à
  préserver dès maintenant : `Transport` expose déjà un flux de paquets IP ; DTLS = une
  implémentation de plus, framing 0x5050 inchangé.

## Points non vérifiés

1. Port UDP : identique au port TLS (déduit du seul code openconnect), pas d'attribut XML.
2. Version DTLS et suites réellement négociées par FortiOS 6.x/7.x (1.0 vs 1.2 ; RSA vs ECDSA).
3. Sémantique de `heartbeat-fail-count`, `heartbeat-idle-timeout`, `client-hello-timeout`
   (non lus par openconnect) ; durée réelle d'attente du serveur pour le clthello.
4. Valeur par défaut de `dtls-tunnel` selon FortiOS et conditions où `dtls="1"` est annoncé.
5. Tolérance serveur à un 2e usage du même cookie (DTLS puis repli TLS) ; « certains serveurs ne
   supportent pas la reconnexion » (commentaire openconnect, sans précision).
6. MRU/MTU PPP optimal sur DTLS ; un datagramme PPP peut-il contenir plusieurs trames côté
   serveur ; limite de taille de la trame.
7. Absence de DPD/keepalive applicatifs propres à Fortinet (hors LCP Echo/Discard).
8. Vecteurs hex DTLS calculés, non capturés ; support DTLS 1.0 d'`openssl-src` 4.x ; capacités
   exactes de `webrtc-dtls` (issues de la doc/mémoire, pas relues dans le code).
