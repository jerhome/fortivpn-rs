# Spécification IPsec (accès distant FortiClient → FortiGate) — Epic 6

Statut : **secondaire**. L'utilisateur a confirmé que sa passerelle est en **SSL-VPN** ; ce document
sert de base si un transport IPsec devient nécessaire (par ex. migration FortiOS 7.6, où le mode
tunnel SSL-VPN est retiré). Les tests IPsec sont volontairement allégés (§5).

Conventions : octets en hexadécimal, entiers big-endian (ordre réseau), `|` = concaténation.
Adresses d'exemple : documentation RFC 5737 uniquement (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
domaines `*.example.test`. Aucune donnée réelle.

Sources consultées (novembre 2026) :
- Docs Fortinet : *FortiOS 7.6 Administration Guide* (« FortiClient as dialup client »,
  « Encapsulate ESP packets within TCP headers », « IKE Mode Config clients », « IPsec split DNS »),
  *FortiOS 7.6 SSL VPN to IPsec VPN Migration* (pages « IKEv1 or IKEv2? », « Authentication method »,
  « LDAP-based user authentication », « Part 2: … VPN wizard », « FortiClient endpoint configuration
  migration », « Tunneling protocol and encapsulation »), *FortiClient 7.4 XML Reference*
  (« IKE settings », « IPsec settings »), *FortiClient 7.4.3 Admin Guide* (« Configuring an IPsec VPN
  connection », comparatif version gratuite / licenciée), *FortiClient 7.4 New features*
  (« EAP-TTLS support for IPsec VPN 7.4.3 »).
- Fortinet Community : « How to use TCP as transport for IKE/IPsec traffic », « How to configure
  IPsec over TCP ».
- RFC 7296 (IKEv2), 7383 (fragmentation IKEv2), 3948 (UDP encap ESP), 4303 (ESP), 4106 (AES-GCM ESP),
  4868 (HMAC-SHA2 IPsec), 5282 (GCM pour IKEv2), 8229 et 9329 (TCP), 2759 (MS-CHAPv2), 3079 (clés
  MPPE), draft-kamath-pppext-eap-mschapv2, 5281 (EAP-TTLS), 2409 (IKEv1), 3947 (NAT-T IKEv1), 3706 (DPD),
  draft-ietf-ipsec-isakmp-xauth-06, draft-dukes-ike-mode-cfg-02.
- Code : strongSwan (commit `eab0c41`) — `ike_vendor.c`, `isakmp_vendor.c`, `eap_mschapv2.c`,
  `unity_handler.c`, `attributes.h`, `attr_provider.c` ; libreswan (`769dd6d`) — `vendorid.c`,
  `iface_tcp.c`, `ikev2_eap.c`.

---

## 1. Synthèse

### 1.1 Variantes possibles

| # | Variante | Auth utilisateur | Transport | Où on la rencontre |
|---|----------|------------------|-----------|--------------------|
| A | **IKEv2 + PSK (passerelle) + EAP-MSCHAPv2** + config payload | mot de passe via EAP-MSCHAPv2 (utilisateurs locaux, RADIUS) | ESP-in-UDP 4500 (NAT-T) | **Assistant FortiOS 7.4/7.6 (IKEv2 par défaut)**, migrations SSL-VPN → IPsec |
| A-TCP | A sur TCP (RFC 8229/9329) | idem | IKE + ESP dans un flux TCP, port 4500 (≤ 7.6.0) ou **443 (≥ 7.6.1)** | FortiOS ≥ 7.4.2 (dialup TCP documenté à partir de 7.4.4–7.4.6), FortiClient **licencié** ≥ 7.4.1 |
| A-TTLS | A avec EAP-TTLS/PAP au lieu de MSCHAPv2 | mot de passe en clair dans un tunnel TLS | idem A | Obligatoire si annuaire **LDAP** ; FortiClient ≥ 7.4.3 (`<eap_method>2</eap_method>`) |
| B | **IKEv1 aggressive (ou main) + PSK + XAuth + mode-config** | XAuth (user/pass) | ESP-in-UDP 4500 | Déploiements « dialup » historiques (FortiOS ≤ 7.2, FortiClient ≤ 7.4.3) |
| C | IKEv2 + SAML (`ike_saml_port`) / certificats | navigateur / certificat | — | Hors périmètre (auth mot de passe seul) |

Faits établis (docs Fortinet citées ci-dessus) :
- « starting with FortiClient 7.4.4, IKEv1 is no longer supported on the client » ; l'assistant VPN
  FortiOS 7.6 propose IKEv2 par défaut ; Fortinet recommande IKEv2 + TCP 443 pour l'accès distant.
- FortiClient IKEv2 : `eap_method` 1 = EAP-MSCHAPv2 (**défaut**), 2 = EAP-TTLS/PAP. Les journaux
  FortiClient montrent « vendor 0 method 26 (MSCHAPV2) » / « method 21 (TTLS) … Phase2 type: PAP ».
  EAP-GTC est aussi chargé (probablement pour les jetons OTP — non vérifié).
- Encapsulation TCP compatible FortiClient = RFC 8229 ; l'option propriétaire `fortinet-esp`
  (faux en-tête TCP) n'est **pas** supportée par FortiClient.
- La version gratuite « FortiClient VPN » (≥ 7.4.3) **ne supporte pas IPsec over TCP** : un poste
  qui utilise la version gratuite est donc en UDP.
- Mode tunnel SSL-VPN : supprimé en 7.6.0 sur les modèles ≤ 2 Go de RAM, puis sur tous les modèles
  en 7.6.3 (d'après des sources secondaires ; la doc Fortinet 7.6.0 ne mentionne que les ≤ 2 Go).

### 1.2 Variante la plus probable par version

| FortiOS | FortiClient | Variante probable |
|---------|-------------|-------------------|
| ≤ 7.2 | 6.x / 7.0 / 7.2 | B (IKEv1 aggressive + XAuth), parfois A |
| 7.4.x | 7.2 / 7.4 | A ou B selon l'âge de la conf ; A-TCP si licencié et UDP bloqué |
| 7.6.x / 8.0 | ≥ 7.4.4 | **A** (B impossible côté client), A-TCP port 443 fréquent |

### 1.3 Recommandation

1. **Variante A en UDP 4500** d'abord (spec §2). C'est la cible de toute migration SSL-VPN → IPsec,
   seule variante compatible avec les FortiClient récents, protocole IKEv2 le plus propre (4 messages
   + tours EAP), testable contre strongSwan sans adaptation.
2. **A-TCP** ensuite (transport additionnel, la machine IKE/ESP est inchangée ; §3.1).
3. **A-TTLS** seulement si la passerelle authentifie sur LDAP (§3.2).
4. **B (IKEv1)** seulement sur besoin avéré (§3.3) : protocole plus ancien, plus de cas spéciaux,
   coût proche d'une seconde implémentation.

Complexité relative (SSL-VPN = 1, i.e. TLS via rustls + HTTP + PPP/framing) :
- A (IKE_SA_INIT/IKE_AUTH, EAP-MSCHAPv2, CP, ESP userland, DPD, rekey) : **≈ 2,5 à 3**.
  Toute la crypto (DH, prf+, AEAD, anti-rejeu) est à notre charge, contrairement au SSL-VPN où rustls
  fait tout.
- A-TCP : + 0,3. A-TTLS : + 0,4 (rustls en mémoire). B : + 2.

---

## 2. Spécification de la variante prioritaire : IKEv2 + PSK + EAP-MSCHAPv2 + CP + ESP-in-UDP

### 2.1 Configuration FortiGate de référence (forme assistant « Remote Access / FortiClient »)

Reconstituée à partir des exemples Fortinet. Les valeurs sont celles que le client doit savoir
négocier ; aucune n'est spécifique à un site réel.

```
config vpn ipsec phase1-interface
    edit "ra-ikev2"
        set type dynamic
        set interface "wan1"
        set ike-version 2
        set peertype any
        set net-device disable            # ou enable selon assistant
        set mode-cfg enable
        set proposal aes128-sha256 aes256-sha256 aes128-sha1 aes256-sha1   # défaut assistant (P1)
        set dhgrp 14 5                    # défaut historique ; 20 21 recommandés (voir §6)
        set eap enable
        set eap-identity send-request
        set authusrgrp "vpn-users"
        set transport udp                 # ou auto / tcp (§3.1)
        set ipv4-start-ip 10.10.2.1
        set ipv4-end-ip 10.10.2.200
        set ipv4-netmask 255.255.255.255
        set dns-mode manual
        set ipv4-dns-server1 10.20.0.53
        set ipv4-split-include "corp-net"         # split tunnel (10.20.0.0/24 par ex.)
        set internal-domain-list "corp.example.test"   # split DNS (IKEv2 uniquement)
        set dpd on-idle
        set dpd-retryinterval 60
        set psksecret <PSK de groupe>
        set keylife 86400                 # IKE SA
    next
end
config vpn ipsec phase2-interface
    edit "ra-ikev2"
        set phase1name "ra-ikev2"
        set proposal aes128-sha1 aes256-sha1 aes128-sha256 aes256-sha256 aes128gcm aes256gcm
        set pfs enable                    # défaut ; dhgrp = celui de P1
        set keylifeseconds 43200
        set replay enable
    next
end
```

Identifiants que l'utilisateur doit fournir au client : adresse de la passerelle, **PSK de groupe**,
nom d'utilisateur, mot de passe. Optionnel : `network-id` (si plusieurs tunnels IKEv2 dialup sur la
même interface, cf. §6).

### 2.2 Transport UDP et sockets

- Socket UDP unique, port local éphémère. Envoi d'IKE_SA_INIT vers `gw:500` (message IKE brut).
- Dès IKE_AUTH, **tout** passe par `gw:4500` (« port floating ») : IKE précédé du marqueur non-ESP
  `00 00 00 00`, ESP sans marqueur (premier mot = SPI ≠ 0). Voir `docs/vectors/ipsec/framing.txt`.
- On utilise un second socket (port local éphémère distinct) ou le même ; FortiGate accepte un
  changement de port source au passage à 4500 (il voit un NAT).
- Démultiplexage en réception sur 4500 : longueur 1 et octet `ff` → keepalive (ignorer) ; 4 premiers
  octets nuls → IKE ; sinon ESP.

### 2.3 Algorithmes à implémenter

Identifiants IANA (registre IKEv2) :

| Type de transform | Valeurs à proposer | Notes |
|-------------------|--------------------|-------|
| 1 ENCR | 12 `ENCR_AES_CBC` (attribut Key Length type 14, TV `800e 0080`/`0100`), 20 `ENCR_AES_GCM_16` (IKE et ESP) | GCM pour IKE = `aes128gcm-prfsha256` côté FortiOS (pas dans le défaut assistant) |
| 2 PRF | 5 `PRF_HMAC_SHA2_256`, 2 `PRF_HMAC_SHA1` ; option 6/7 (SHA-384/512) | |
| 3 INTEG | 12 `AUTH_HMAC_SHA2_256_128`, 2 `AUTH_HMAC_SHA1_96` | absent si ENCR AEAD |
| 4 KE (DH) | 14 MODP-2048, 19 ECP-256, 20 ECP-384, 21 ECP-521 ; option 5 MODP-1536, 31 Curve25519 | |
| 5 ESN | 0 (pas d'ESN) | ESP uniquement |

Propositions client recommandées (une proposition IKE, plusieurs transforms) :
- IKE : ENCR {AES-CBC-128, AES-CBC-256}, PRF {SHA256, SHA1}, INTEG {SHA256-128, SHA1-96},
  KE {14, 20, 21, 19, 5} + seconde proposition AEAD : ENCR {GCM-16-128, GCM-16-256}, PRF {SHA256, SHA384}, KE {…}.
- ESP : proposition 1 AEAD {GCM-16-128, GCM-16-256}, ESN 0 ; proposition 2 {AES-CBC-128/256} ×
  {SHA256-128, SHA1-96}, ESN 0. Inclure KE {groupe de l'IKE SA} dans les propositions ESP
  (sert au rekey avec PFS ; ignoré par le pair pour la CHILD SA créée dans IKE_AUTH, RFC 7296 §1.2).

Le payload KE d'IKE_SA_INIT ne porte qu'**un** groupe : envoyer d'abord le premier de la liste ;
si la réponse est `N(INVALID_KE_PAYLOAD)` (type 17, donnée = groupe attendu sur 2 octets), recommencer
IKE_SA_INIT avec ce groupe (nouveau nonce, même SPIi autorisé), en gardant ce message comme
« RealMessage1 » pour l'AUTH.

### 2.4 Séquence d'échanges

Notations RFC 7296. Message ID : 0 pour IKE_SA_INIT, puis incrémenté de 1 à chaque requête du
client (les requêtes de la passerelle ont leur propre compteur). Flags en-tête : I (0x08) sur les
messages du client initiateur, R (0x20) sur les réponses. Version `0x20`.

```
(1) C→G  udp/500   HDR(SPIi, 0, IKE_SA_INIT=34, MID 0)
                    SAi1, KEi, Ni(32 o), N(NAT_DETECTION_SOURCE_IP 16388), N(NAT_DETECTION_DESTINATION_IP 16389)
                    [N(IKEV2_FRAGMENTATION_SUPPORTED 16430)] [N(SIGNATURE_HASH_ALGORITHMS 16431) inutile en PSK]
(2) G→C            HDR(SPIi, SPIr, 34, MID 0, R)
                    SAr1, KEr, Nr, N(NAT_D src), N(NAT_D dst), [CERTREQ], [V(Fortigate)], [N(16430)]
                    — ou N(INVALID_KE_PAYLOAD) / N(COOKIE 16390) → renvoyer (1) avec le cookie en 1er payload
--- dérivation des clés (§2.5), passage sur udp/4500 ---
(3) C→G  udp/4500  HDR(IKE_AUTH=35, MID 1) SK{ IDi, [N(INITIAL_CONTACT 16384)], CP(CFG_REQUEST),
                    SAi2, TSi, TSr }                       ← PAS de payload AUTH : annonce EAP
(4) G→C            SK{ IDr, AUTH(méthode 2 « Shared Key MIC », clé = PSK), EAP(Request/Identity) }
(5) C→G  MID 2     SK{ EAP(Response/Identity = nom d'utilisateur) }
(6) G→C            SK{ EAP(Request, type 26 MS-CHAPv2, opcode 1 Challenge) }
(7) C→G  MID 3     SK{ EAP(Response, 26, opcode 2 Response) }
(8) G→C            SK{ EAP(Request, 26, opcode 3 Success « S=<40 hex> M=… ») }
(9) C→G  MID 4     SK{ EAP(Response, 26, opcode 3) }
(10) G→C           SK{ EAP(Success, code 3) }
(11) C→G MID 5     SK{ AUTH(méthode 2, clé = MSK) }
(12) G→C           SK{ AUTH(méthode 2, clé = MSK), CP(CFG_REPLY), SAr2, TSi, TSr, [N(ESP_TFC_PADDING_NOT_SUPPORTED)] }
```

Contrôles côté client :
- (4) : vérifier l'AUTH PSK de la passerelle **avant** d'envoyer l'identité EAP. Échec →
  abandon (pas de repli). IDr peut être de type ID_IPV4_ADDR (1) ou ID_FQDN (2) : n'imposer une valeur
  que si l'utilisateur l'a configurée.
- (6)–(8) : si la passerelle répond `opcode 4 Failure` (« E=691 … ») ou `EAP Failure` (code 4) →
  mot de passe refusé, terminer l'IKE SA proprement (ne pas réessayer en boucle, cf. verrouillage
  de compte).
- (12) : vérifier l'AUTH MSK de la passerelle, puis installer la CHILD SA.
- Un `N(AUTHENTICATION_FAILED 24)` peut arriver en (4), (10), (12).

Payloads (types IKEv2) : SA 33, KE 34, IDi 35, IDr 36, CERTREQ 38, AUTH 39, Nonce 40, Notify 41,
Delete 42, Vendor ID 43, TSi 44, TSr 45, SK 46, CP 47, EAP 48, SKF 53.

**IDi** : FortiGate avec `eap-identity send-request` et `peertype any` n'utilise pas IDi pour
identifier l'utilisateur (c'est l'identité EAP qui compte). Envoyer ID_FQDN (2) avec une valeur
configurable (défaut : nom d'hôte générique, ex. `fortivpn-client`) ou ID_IPV4_ADDR de l'IP locale.
Si `peertype one` + `peerid` est configuré côté FortiGate, IDi doit valoir ce peerid (équivalent du
« Local ID » FortiClient).

**Traffic selectors** (type 7 TS_IPV4_ADDR_RANGE, protocole 0, ports 0–65535) :
- TSi = 0.0.0.0–255.255.255.255 (la passerelle le restreint à l'IP attribuée) ;
- TSr = 0.0.0.0–255.255.255.255 (la passerelle peut le restreindre aux sous-réseaux split-include).
- Le diagnostic FortiGate de l'exemple Fortinet montre côté passerelle `src 0.0.0.0-255.255.255.255`
  → `dst <IP client>/32` : un seul selecteur « tout » vers l'IP client.

**Forçage de l'encapsulation UDP** : notre ESP est en espace utilisateur et ne peut pas émettre de
l'ESP brut (protocole IP 50, sockets raw indisponibles/limités sous Windows). Il faut donc que la
passerelle **croie** à un NAT côté client : envoyer dans (1) un `NAT_DETECTION_SOURCE_IP` délibérément
faux (SHA1 calculé sur un port aléatoire), comme `encap = yes` de strongSwan. FortiGate
(`nattraversal enable`, défaut) active alors ESP-in-UDP 4500 et attend des keepalives. Vecteurs de
calcul NAT-D : `docs/vectors/ipsec/nat-d.txt`. `NAT_DETECTION_DESTINATION_IP` doit être correct.

### 2.5 Dérivation de clés IKEv2 (RFC 7296 §2.13–2.14)

```
g^ir      = secret DH (MODP : entier big-endian sur la taille du groupe, zéros en tête conservés ;
            ECP 19/20/21 : coordonnée x seule, RFC 5903 ; Curve25519 : 32 octets, RFC 8031)
SKEYSEED  = prf(Ni | Nr, g^ir)                   (Ni, Nr = données de nonce, sans en-tête de payload)
{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
prf+(K, S) = T1 | T2 | …,  T1 = prf(K, S | 0x01),  Tn = prf(K, Tn-1 | S | n)
```
Longueurs : SK_d, SK_pi, SK_pr = taille de sortie du PRF ; SK_a* = clé INTEG (32 pour SHA256-128,
20 pour SHA1-96 ; absentes en AEAD) ; SK_e* = clé ENCR (16/32 en CBC ; **16/32 + 4 octets de sel**
en GCM, RFC 5282). Pour PRF HMAC, la clé `Ni | Nr` est utilisée telle quelle (longueur variable).

**Payload SK (46)** : en-tête générique (Next Payload = 1er payload interne), IV, données chiffrées,
padding + Pad Length, ICV.
- AES-CBC : IV 16 octets aléatoire ; padding à un multiple de 16 (octets de padding quelconques,
  Pad Length en dernier) ; ICV = HMAC tronqué sur **tout le message IKE** de l'en-tête IKE jusqu'à la
  fin des données chiffrées ; Length de l'en-tête IKE inclut l'ICV.
- AES-GCM-16 (RFC 5282) : IV explicite 8 octets (compteur unique), nonce = sel(4) | IV(8),
  AAD = en-tête IKE | en-tête générique du SK (de l'octet 0 du message jusqu'à l'IV exclu),
  ICV 16 octets.

**AUTH** (méthode 2, Shared Key Message Integrity Code) :
```
InitiatorSignedOctets = RealMessage1 | Nr | prf(SK_pi, IDi')
ResponderSignedOctets = RealMessage2 | Ni | prf(SK_pr, IDr')
IDx'  = corps du payload ID à partir de l'octet ID Type (type(1) | réservé(3) | données)
AUTH  = prf( prf(K, "Key Pad for IKEv2"), <SignedOctets> )      ("Key Pad for IKEv2" = 17 octets ASCII, sans NUL)
```
- (4) passerelle : K = PSK (octets ASCII ; si la conf FortiGate utilise `0x…`, K = valeur hexa
  décodée) sur ResponderSignedOctets.
- (11) client et (12) passerelle : K = **MSK** EAP (64 octets, §2.6), sur Initiator- / ResponderSignedOctets.
  RealMessage1/2 = octets exacts des messages IKE_SA_INIT (le dernier envoyé/reçu si retry).

### 2.6 EAP-MSCHAPv2 (type 26)

En-tête EAP (RFC 3748) : Code(1) 1=Request 2=Response 3=Success 4=Failure, Identifier(1) (recopier
celui de la requête), Length(2), Type(1). Identity : Type 1, données = nom d'utilisateur UTF-8.

Corps MS-CHAPv2 (après Type=26) : OpCode(1), MS-CHAPv2-ID(1), MS-Length(2) (= Length EAP − 5), données.

| OpCode | Sens | Données |
|--------|------|---------|
| 1 Challenge | G→C | Value-Size(1)=16, Authenticator Challenge(16), Name(serveur) |
| 2 Response | C→G | Value-Size(1)=49, Peer-Challenge(16 aléatoire), Reserved(8)=0, NT-Response(24), Flags(1)=0, Name(utilisateur) |
| 3 Success | G→C | `S=<AuthenticatorResponse 40 hex majuscules> M=<message>` |
| 3 Success | C→G | aucune donnée (le corps se réduit à OpCode = 3) |
| 4 Failure | G→C | `E=eeeeeeeeee R=r C=<32 hex> V=3 M=<message>` |

Calculs (RFC 2759 §8) :
```
PasswordHash      = MD4(UTF-16LE(mot de passe))                       16 octets
ChallengeHash     = SHA1(PeerChallenge | AuthenticatorChallenge | UserName)[0..8]
                    UserName = nom sans préfixe « DOMAINE\ »
NT-Response       = DES(ChallengeHash, k1) | DES(.., k2) | DES(.., k3)
                    k1..k3 = PasswordHash complété à 21 octets par des zéros, découpé en 3 × 7 octets,
                    chaque bloc de 7 octets étendu à une clé DES de 8 octets (bits de parité)
PasswordHashHash  = MD4(PasswordHash)
AuthenticatorResponse = "S=" | HEX( SHA1( SHA1(PasswordHashHash | NT-Response | Magic1) | ChallengeHash | Magic2 ) )
                    Magic1/Magic2 = constantes ASCII de RFC 2759 §8.7 (« Magic server to client signing constant »,
                    « Pad to make it do more than one iteration »)
```
Le client **doit** vérifier `S=` (authentification mutuelle) avant d'envoyer l'opcode 3.

MSK (RFC 3079 §3.4, ordre tel qu'implémenté par strongSwan `eap_mschapv2.c` / Windows) :
```
MasterKey        = SHA1(PasswordHashHash | NT-Response | Magic1_3079)[0..16]
MasterReceiveKey = SHA1(MasterKey | SHSpad1 | Magic2_3079 | SHSpad2)[0..16]
MasterSendKey    = SHA1(MasterKey | SHSpad1 | Magic3_3079 | SHSpad2)[0..16]
MSK              = MasterReceiveKey | MasterSendKey | 32 octets nuls          (64 octets)
```
(Magic1/2/3_3079 = « This is the MPPE Master Key », « On the client side, this is the send key; on
the server side, it is the receive key. », « On the client side, this is the receive key; on the
server side, it is the send key. » ; SHSpad1 = 40 × 00, SHSpad2 = 40 × f2.) Les deux extrémités
calculent la même concaténation (pas d'inversion côté client).

Vecteurs : RFC 2759 §9.2 (User / clientPass → NT-Response, AuthenticatorResponse) et RFC 3079 §3.5
(MasterKey, clés de session) à recopier depuis les RFC dans les tests unitaires de `crates/ipsec`.

### 2.7 Configuration Payload (CP, type 47)

CP : CFG Type(1) (1 = CFG_REQUEST, 2 = CFG_REPLY), Réservé(3), attributs. Attribut : bit R(1)=0 +
type(15), Length(2), valeur.

Requête (3) — attributs vides (Length 0) :

| Type | Nom | Usage |
|------|-----|-------|
| 1 | INTERNAL_IP4_ADDRESS | IP virtuelle |
| 2 | INTERNAL_IP4_NETMASK | FortiGate envoie souvent 255.255.255.255 |
| 3 | INTERNAL_IP4_DNS | DNS (jusqu'à 3) |
| 13 | INTERNAL_IP4_SUBNET | split-include (adresse 4 + masque 4) |
| 25 | INTERNAL_DNS_DOMAIN | split DNS (RFC 8598) — voir §6 |
| 7 | APPLICATION_VERSION | facultatif ; ne pas usurper « FortiClient » |

Réponse (12) : appliquer IP + masque à l'interface TUN ; DNS ; routes = union des
INTERNAL_IP4_SUBNET et des TSr reçus (si TSr = 0.0.0.0/0 et aucun SUBNET → tunnel complet ; garder
alors une route hôte vers la passerelle via la passerelle locale d'origine). Ignorer les attributs
inconnus (y compris types privés ≥ 16384).

### 2.8 ESP en espace utilisateur (RFC 4303, 3948, 4106)

Clés CHILD SA :
```
KEYMAT = prf+(SK_d, Ni | Nr)                          (SA créée dans IKE_AUTH : Ni/Nr d'IKE_SA_INIT)
KEYMAT = prf+(SK_d, g^ir(new) | Ni | Nr)              (rekey avec PFS, nonces du CREATE_CHILD_SA)
ordre : ENCR_i→r | INTEG_i→r | ENCR_r→i | INTEG_r→i    (i = client initiateur de la CHILD SA)
GCM : ENCR = clé AES (16/32) | sel (4)
```
SPI : chaque côté choisit le SPI **entrant** qu'il annonce dans sa proposition ESP (4 octets).
Le client émet avec le SPI de la passerelle (SAr2) et reçoit sur le sien (SAi2).

Paquet sortant (paquet IPv4 lu sur le TUN) :
```
SPI(4) | Seq(4, commence à 1, jamais de rebouclage sans rekey) | IV | chiffré( payload | padding | PadLen | NextHeader=4 ) | ICV
```
- GCM-16 : IV 8 octets (on peut utiliser le numéro de séquence étendu à 64 bits, unique par clé) ;
  nonce = sel | IV ; AAD = SPI | Seq ; ICV 16 ; padding pour aligner (payload + 2) sur 4 octets.
- CBC + HMAC : IV 16 aléatoire ; padding à 16 ; ICV = HMAC(SPI | Seq | IV | chiffré) tronqué (16 pour
  SHA256-128, 12 pour SHA1-96). Vérifier l'ICV **avant** de déchiffrer, en temps constant.
- Octets de padding : 1, 2, 3, … (RFC 4303 §2.4), à vérifier en réception.
- Next Header 59 (« no next header ») = paquet factice TFC/dummy : à jeter.
- Encapsulation : charge UDP vers gw:4500, sans marqueur. Somme de contrôle UDP : celle de l'OS.
- Anti-rejeu : fenêtre glissante ≥ 64 (FortiGate utilise 2048) mise à jour **après** vérification d'ICV.
- MTU TUN : 1400 recommandé (FortiClient : `mtu_size` 1300 par défaut ; overhead ESP-in-UDP GCM ≈
  20 IP + 8 UDP + 8 ESP + 8 IV + 2 + ≤3 pad + 16 ICV = 65 octets).
- Keepalive NAT-T : un octet `ff` vers gw:4500 toutes les 10 à 20 s d'inactivité sortante
  (FortiGate `keepalive` défaut 10 s).

### 2.9 DPD, INFORMATIONAL, rekey, fermeture

- **DPD passerelle** (`dpd on-idle`) : requête INFORMATIONAL (37) avec SK vide. Le client **doit**
  répondre (même MID, flag R, SK vide) sinon FortiGate coupe le tunnel après ses retries.
- **DPD client** : après 30 s sans trafic entrant, envoyer un INFORMATIONAL vide ; retransmissions
  (§2.10) ; pas de réponse après ~5 essais → tunnel mort → reconnexion (réauthentification EAP
  complète : le mot de passe doit rester disponible en mémoire protégée/zeroize, ou être redemandé).
- **Rekey CHILD SA** (client initiateur, avant 90 % de la durée de vie locale, défaut 8 h < 43 200 s) :
  `CREATE_CHILD_SA (36)`: SK{ N(REKEY_SA 16393, protocole ESP, SPI = ancien SPI entrant), SA, Ni,
  [KEi si PFS], TSi, TSr } → réponse SA, Nr, [KEr], TSi, TSr. Puis INFORMATIONAL Delete(ESP, ancien
  SPI). Continuer à accepter l'ancienne SA jusqu'à la suppression.
- **Rekey IKE SA** (avant 23 h < 86 400 s) : CREATE_CHILD_SA avec SA (protocole IKE, SPI 8 octets),
  Ni, KEi ; `SKEYSEED' = prf(SK_d(ancien), g^ir(new) | Ni | Nr)`, SPIs = nouveaux ; transfert des
  CHILD SA ; Delete de l'ancienne IKE SA.
- La passerelle peut aussi initier ces rekey : le client doit savoir **répondre** à CREATE_CHILD_SA
  et gérer les collisions (RFC 7296 §2.8.1 : la SA issue du plus petit nonce est supprimée).
- `N(AUTH_LIFETIME)` (RFC 4478, 16403) si `reauth enable` sur la passerelle : refaire une IKE SA
  complète avant l'échéance.
- Déconnexion : INFORMATIONAL SK{ Delete(IKE) } puis fermeture des sockets.

### 2.10 Timeouts et retransmissions

- Requêtes IKE : retransmission à 2 s, 4 s, 8 s, 16 s (backoff ×2), abandon après 5 envois (~30 s).
  Seul l'initiateur d'une requête retransmet ; une requête reçue en double reçoit la même réponse
  (garder la dernière réponse en cache).
- Saisie EAP : FortiGate impose un délai (`xauth_timeout` côté FortiClient : 120 s défaut, IKEv1) ;
  ne pas laisser l'IKE_AUTH en attente plus de ~60 s.
- Taille des messages : avec PSK, IKE_AUTH tient sous 1 280 octets ; la fragmentation RFC 7383 n'est
  pas requise au départ (l'annoncer seulement une fois implémentée).

### 2.11 Erreurs et diagnostics à exposer

| Situation | Indice protocolaire | Message utilisateur |
|-----------|---------------------|---------------------|
| PSK fausse | AUTH (4) invalide, ou `AUTHENTICATION_FAILED` | « clé partagée (PSK) incorrecte » |
| Mot de passe faux | MS-CHAPv2 Failure `E=691` / EAP Failure | « identifiants refusés » |
| Pas de proposition commune | `NO_PROPOSAL_CHOSEN` (14) | lister les algos proposés |
| Mauvais groupe DH | `INVALID_KE_PAYLOAD` (17) | (géré automatiquement) |
| Plusieurs tunnels dialup / network-id requis | `AUTHENTICATION_FAILED` ou silence | « network ID / local ID requis » (§6) |
| Pas de réponse en UDP | timeouts IKE_SA_INIT | suggérer transport TCP (§3.1) |

---

## 3. Autres variantes (résumé)

### 3.1 A-TCP : IKEv2 et ESP sur TCP (RFC 8229 / 9329)

- FortiGate : `set transport tcp` (ou `auto` = UDP puis repli TCP après `auto-transport-threshold`,
  15 s par défaut) ; port `config system settings / set ike-tcp-port` : défaut 4500 jusqu'à 7.6.0,
  **443 à partir de 7.6.1**. IKEv2 uniquement. `fortinet-esp` doit rester désactivé (FortiClient ne le
  supporte pas).
- Client = initiateur TCP : connexion TCP vers `gw:port`, envoi du préfixe `IKETCP`
  (`49 4b 45 54 43 50`) une fois par connexion, puis chaque message précédé d'un Length 16 bits
  (longueur + 2). IKE : marqueur non-ESP 4 × 00 après Length ; ESP : directement. Hexdumps :
  `docs/vectors/ipsec/framing.txt`.
- NAT-D : envoyer les mêmes notifications calculées avec les ports TCP ; pas de keepalive NAT sur TCP
  (ne pas envoyer, ignorer `ff`). Pas de fragmentation IKE sur TCP.
- Perte de la connexion : c'est l'initiateur TCP (le client) qui rouvre une connexion, renvoie
  `IKETCP` et continue avec les mêmes SA.
- Le mode `auto` côté client : tenter UDP, basculer sur TCP après ~10 s sans réponse à IKE_SA_INIT
  avec un **nouvel** IKE_SA_INIT (nouveau SPIi).
- Pas de TLS autour du flux (non vérifié sur FortiOS, cf. §6).

### 3.2 A-TTLS : EAP-TTLS/PAP (type 21)

Requis pour l'authentification LDAP. Le tunnel TLS est transporté dans des messages EAP (RFC 5281,
fragmentation avec flags L/M/S) ; à l'intérieur, AVP User-Name (1) et User-Password (2, complété à
un multiple de 16 avec des zéros, en clair dans TLS). MSK = PRF TLS(« ttls keying material »,
client_random | server_random)[0..64] = exporteur RFC 5705 sans contexte en TLS 1.2 (rustls
`export_keying_material`). Le certificat TLS de la passerelle doit être validé (même politique que
pour le SSL-VPN). TLS 1.3 dans EAP-TTLS (RFC 9427) dérive le MSK différemment : à prévoir seulement
si FortiOS négocie TLS 1.3 ici (non vérifié).

### 3.3 B : IKEv1 aggressive + PSK + XAuth + mode-config (legacy)

Config FortiGate de référence (exemple Fortinet « FortiClient as dialup client ») : `ike-version 1`,
`mode aggressive`, `peertype one` + `peerid`, `xauthtype auto`, `mode-cfg enable`,
`proposal aes128-sha256 aes256-sha256 aes128-sha1 aes256-sha1`, `dpd on-idle`, `unity-support`
(split DNS suffix), phase 2 `aes128-sha1 aes256-sha1 aes128-sha256 aes256-sha256 aes128gcm aes256gcm`.

Séquence (RFC 2409, 3947, drafts XAuth / mode-cfg) :
```
Aggressive (UDP 500) :
  C→G  HDR, SA, KE, Ni, IDii(ID_FQDN/ID_KEY_ID = Local ID), VID(RFC 3947, draft-02\n, XAUTH, DPD, [Unity], [FRAGMENTATION])
  G→C  HDR, SA, KE, Nr, IDir, VID(…, Fortigate), NAT-D, NAT-D, HASH_R
  C→G  HDR, NAT-D, NAT-D, HASH_I        (port 4500 + marqueur si NAT ; chiffré ou non selon pair)
Transaction (type 6) XAuth, initiée par la passerelle :
  G→C  HDR*, HASH, ATTR(CFG_REQUEST: XAUTH_TYPE 16520?, XAUTH_USER_NAME 16521, XAUTH_USER_PASSWORD 16522)
  C→G  HDR*, HASH, ATTR(CFG_REPLY: nom, mot de passe)
  G→C  HDR*, HASH, ATTR(CFG_SET: XAUTH_STATUS 16527 = 1)
  C→G  HDR*, HASH, ATTR(CFG_ACK)
Transaction mode-config (« pull », client) :
  C→G  ATTR(CFG_REQUEST: INTERNAL_IP4_ADDRESS 1, NETMASK 2, DNS 3, UNITY_SPLIT_INCLUDE 28676, UNITY_DEF_DOMAIN 28674, UNITY_SPLITDNS_NAME 28675, UNITY_BANNER 28672, UNITY_SAVE_PASSWD 28673)
  G→C  ATTR(CFG_REPLY: …)
Quick Mode : HDR*, HASH(1), SA, Ni, [KE si PFS], IDci(IP virtuelle/32), IDcr(0.0.0.0/0) ; HASH(2)… ; HASH(3)
```
Clés : `SKEYID = prf(PSK, Ni_b | Nr_b)` ; `SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 00)` ;
`SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 01)` ;
`SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 02)` ; clé de chiffrement = début de
`K1 | K2 …` (K1 = prf(SKEYID_e, 00), Kn = prf(SKEYID_e, Kn-1)) si SKEYID_e est trop court ;
`HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)` ; IV phase 1 = hash(g^xi | g^xr) ;
IV de chaque échange phase 2/transaction = hash(dernier bloc chiffré phase 1 | M-ID) ;
`HASH(1)` transaction = prf(SKEYID_a, M-ID | ATTR) ; Quick Mode
`KEYMAT = prf(SKEYID_d, [g(qm)^xy |] proto | SPI | Ni_b | Nr_b)` étendu par chaînage.
UNITY_SPLIT_INCLUDE : entrées de 14 octets = réseau(4) | masque(4) | 6 octets (protocole/ports,
ignorés par strongSwan). DPD : notify R-U-THERE 36136 / R-U-THERE-ACK 36137 (RFC 3706) avec numéro
de séquence 32 bits. NAT-T : payload NAT-D type 20 (RFC 3947), mode d'encapsulation UDP-Tunnel = 3.
FortiClient ≥ 7.4.4 ne supporte plus cette variante.

### 3.4 Vendor IDs

Voir `docs/vectors/ipsec/vendor-ids.txt`. FortiGate envoie `1d6e178f6c2c0be284985465450fe9d4`
(IKEv1 et IKEv2 ; strongSwan l'étiquette « Fortigate »). Le client n'a pas à envoyer de VID
Fortinet ; en IKEv1 envoyer RFC 3947, draft-02\n, XAUTH, DPD.

---

## 4. Crates Rust proposées

Pas de crate IKE réutilisable et maintenue :
- `ipsec-parser` 0.7 (rusticata) : analyseur IKEv2/ESP en lecture seule, dernière version 2021.
  Utile comme référence, pas comme dépendance.
- `ryke`, `jkipsec`, `fynx-proto`, `isakmp` : projets récents, quelques dizaines de téléchargements,
  non audités. Ne pas en dépendre.
→ Écrire l'encodage/décodage et la machine d'états **sans I/O** dans `crates/ipsec` (même style que
`crates/proto`).

Crypto (RustCrypto, purs Rust, compilables pour `x86_64-pc-windows-gnu`) :

| Besoin | Crate |
|--------|-------|
| AES-GCM ESP/IKE | `aes-gcm` |
| AES-CBC | `aes` + `cbc` |
| ChaCha20-Poly1305 (option) | `chacha20poly1305` |
| HMAC / PRF | `hmac` + `sha1`, `sha2` |
| ECDH 19/20/21 | `p256`, `p384`, `p521` (feature `ecdh`) |
| Curve25519 (groupe 31) | `x25519-dalek` |
| MODP 5/14 | `crypto-bigint` (modexp temps constant) ; `num-bigint-dig` en repli |
| MS-CHAPv2 | `md4`, `des`, `sha1` |
| EAP-TTLS | `rustls` (déjà utilisé par le SSL-VPN), `export_keying_material` |
| Aléa, secrets | `rand_core`/`getrandom`, `zeroize`, `subtle` (comparaison d'ICV) |

---

## 5. Stratégie de test (allégée)

1. **Tests unitaires sur vecteurs** (`cargo test`, aucun réseau) :
   - MS-CHAPv2 : RFC 2759 §9.2 ; clés MPPE : RFC 3079 §3.5 ;
   - prf+ / SKEYSEED : vecteurs générés une fois avec strongSwan (journal `charon` en niveau `ike 4`
     sur la passerelle de test du point 2) et figés dans `docs/vectors/ipsec/` ;
   - AES-GCM ESP : vecteurs RFC 4106 / « The Galois/Counter Mode » (McGrew-Viega) ; HMAC : RFC 4231 ;
   - NAT-D, framing UDP/TCP, VIDs : `docs/vectors/ipsec/*.txt` ;
   - aller-retour encode/décode de chaque payload, et rejet des longueurs incohérentes.
2. **Un seul test d'interop « happy path »** (`#[ignore]`, lancé sur demande) : strongSwan (charon)
   dans un conteneur Docker sur WSL, configuré comme ci-dessous ; le test se connecte, vérifie l'IP
   attribuée et les routes, puis envoie **un ping ICMP construit à la main dans l'ESP** vers
   l'adresse interne du conteneur et attend l'écho — pas besoin de TUN ni de `sudo` côté test.
   Le conteneur a besoin de `--cap-add NET_ADMIN` ; si les modules `xfrm_user`/`esp4` du noyau WSL
   ne se chargent pas, utiliser le plugin `kernel-libipsec` de strongSwan (ESP en espace utilisateur
   côté passerelle). strongSwan ne fait pas de TCP RFC 8229 (libreswan oui, mais via le module noyau
   `espintcp`, absent du noyau WSL) : la variante TCP reste couverte par les tests unitaires et
   éventuellement par mock-gw.

Configuration strongSwan imitant un FortiGate dialup IKEv2 (`/etc/swanctl/conf.d/fgt.conf`,
valeurs factices) :

```
connections {
    fgt-dialup {
        version = 2
        local_addrs = 198.51.100.1
        proposals = aes128-sha256-modp2048, aes256-sha256-modp2048, aes128-sha1-modp1536
        pools = ra-pool
        send_certreq = no
        dpd_delay = 20s
        encap = no                       # c'est le client qui force l'encapsulation
        local {
            auth = psk
            id = gw.example.test
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            ra {
                local_ts = 10.20.0.0/24
                esp_proposals = aes128gcm16-aes256gcm16-modp2048, aes128-sha256-modp2048, aes256-sha1-modp2048
                rekey_time = 12h
                dpd_action = clear
            }
        }
    }
}
pools {
    ra-pool {
        addrs = 10.10.2.1-10.10.2.200
        dns = 10.20.0.53
        subnet = 10.20.0.0/24           # INTERNAL_IP4_SUBNET (13)
        25 = corp.example.test          # INTERNAL_DNS_DOMAIN (syntaxe numérique : à valider)
    }
}
secrets {
    ike-gw { id = gw.example.test  secret = "test-psk-not-real" }
    eap-u1 { id = vpnuser1          secret = "test-password-not-real" }
}
```
Plugins nécessaires : `eap-mschapv2`, `md4`, `des` (ou `openssl`), `attr`, `kernel-netlink` ou
`kernel-libipsec`. Interface `dummy` 10.20.0.1/24 dans le conteneur comme cible du ping.

---

## 6. Points non vérifiés

1. **Groupes DH par défaut** de l'assistant FortiOS 7.4/7.6 (`14 5` historique vs `20 21`) et
   propositions IKEv2 exactes générées : à confirmer par `show full vpn ipsec phase1-interface` ;
   d'où la négociation large + gestion d'INVALID_KE_PAYLOAD.
2. **Split-include IKEv2** : FortiGate l'exprime-t-il par INTERNAL_IP4_SUBNET (13), par
   rétrécissement de TSr, ou les deux ? Le client fait l'union (§2.7).
3. **Split DNS IKEv2** (`internal-domain-list`) : attribut standard INTERNAL_DNS_DOMAIN (25,
   RFC 8598) supposé ; possible attribut privé Fortinet. À capturer.
4. **Attributs/notifications privés FortiClient** : `network-id` (tunnels multiples IKEv2),
   numéro de série EMS (`ems-sn-check`, `sase_mode`), tags de posture : transportés par des payloads
   non documentés. Si la passerelle les exige, un client tiers échouera — aucune parade possible sans
   capture.
5. **FortiGate exige-t-il PFS au rekey** quand `pfs enable` et le client propose KE dans les
   propositions ESP initiales ? Supposé compatible (strongSwan/Windows natif interopèrent).
6. **XAuth `xauthtype auto`** (IKEv1) : la passerelle peut-elle demander CHAP (XAUTH_TYPE 1 +
   XAUTH_CHALLENGE) ? Le client ne supportera que le type générique (0, mot de passe en clair).
   IKEv1 : message 3 d'aggressive chiffré ou non attendu par FortiGate — strongSwan l'envoie en clair
   et interopère (rapporté par de nombreuses configs publiques, non revérifié).
7. **TCP** : versions minimales incohérentes entre sources Fortinet (7.4.2 IKE TCP ; RFC 8229 à
   partir de 7.4.4 ; dialup TCP « à partir de 7.4.6 ») ; absence de TLS autour du flux TCP supposée
   (RFC 8229 sans TLS) ; IKE sur **UDP 443** annoncé pour 7.6.5 (non étudié).
8. **EAP-TTLS** : version TLS négociée par FortiOS (1.2 vs 1.3) et donc formule de MSK ; validation
   attendue du certificat serveur par FortiClient.
9. **EAP-GTC** chargé par FortiClient : vraisemblablement pour FortiToken/OTP en IKEv2 (hors
   périmètre mot de passe seul).
10. **Valeur de VID `1d6e178f…`** : origine (hash de quelle chaîne) inconnue ; le contenu exact de
    VIDs émis par FortiClient n'a pas été observé.
11. Retrait du mode tunnel SSL-VPN sur **tous** les modèles en 7.6.3 : rapporté par des sources
    secondaires ; la doc Fortinet consultée ne confirme que les modèles ≤ 2 Go en 7.6.0.
12. Comportement FortiGate face à un `NAT_DETECTION_SOURCE_IP` volontairement faux : standard
    (RFC 7296 §2.23 l'autorise explicitement) et utilisé par strongSwan `encap=yes`, mais non testé
    contre un FortiGate.
