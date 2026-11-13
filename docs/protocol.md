# Protocole Fortinet SSL-VPN (mode tunnel PPP « v1 ») — spécification d'implémentation

Statut : S0.1, rédigé à partir du code source (pas de capture sur passerelle réelle).
Public : `crates/proto` (rust-proto), `crates/core`, `tools/mock-gw` (test-harness).

## 0. Portée, sources, conventions

**Dans le périmètre (MVP)** : TLS + authentification login/mot de passe → `SVPNCOOKIE` →
configuration XML → tunnel PPP-sur-TLS encapsulé `0x5050` → LCP/IPCP → trafic IPv4 →
déconnexion.

**Hors MVP** (positionnés au §13) : OTP/FortiToken, SAML, certificat client, DTLS,
protocole tunnel « v2 » (non PPP), IPv6, host-check.

**Sources de référence** (lecture seule, jamais exécutées contre une passerelle) :

| Projet | Commit | Fichiers |
|---|---|---|
| openfortivpn (adrienverge/openfortivpn) | `866c0eab271cc84f6b743b6fef037e95dd8c9013` (2026-11-10) | `src/http.c`, `src/tunnel.c`, `src/io.c`, `src/hdlc.c`, `src/xml.c`, `src/ipv4.c`, `src/main.c`, `src/config.h` |
| openconnect (gitlab openconnect/openconnect) | `70d1e79d1e55849dfc71dcc199b1edb535b547e4` (2026-07-19) | `fortinet.c`, `ppp.c`, `ppp.h`, `tests/fake-fortinet-server.py`, `www/fortinet.xml` |
| RFC | — | 1661 (PPP/LCP), 1662 (HDLC-like framing), 1332 (IPCP), 1877 (DNS IPCP), 5072 (IPV6CP) |

**Conventions** :
- « openfortivpn fait X » = comportement lu dans le code ; « RECOMMANDÉ » = choix proposé
  pour fortivpn-rs ; **[NV]** = non vérifié, voir §14.
- Entiers multi-octets : **big-endian** (ordre réseau) partout.
- C→G = client vers passerelle ; G→C = passerelle vers client.
- Vecteurs : `docs/vectors/` (format dans `docs/vectors/README.md`). Référence notée
  `lcp.hex:lcp_confreq_client`.

---

## 1. Séquence complète

```
 Client                                            Passerelle (vpn.example.com:443)
   |  TCP connect, TLS handshake (SNI)  [conn #1]          |
   |  POST /remote/logincheck  (username, credential...)  |
   |<----------- 200 OK, Set-Cookie: SVPNCOOKIE=..., ret=1 |
   |  GET /remote/index        (Cookie)    [openfortivpn]  |
   |  GET /remote/fortisslvpn  (Cookie)    [openfortivpn]  |
   |  -- fermeture conn #1, nouvelle connexion TLS [conn #2] --
   |  GET /remote/fortisslvpn_xml (Cookie)                 |
   |<----------------------------- 200 OK, <sslvpn-tunnel> |
   |  GET /remote/sslvpn-tunnel (Host: sslvpn, Cookie)     |
   |        (aucune réponse HTTP si succès)                |
   |==== flux binaire : trames 0x5050 dans les 2 sens ====|
   |  LCP ConfReq  <------------------------> LCP ConfReq  |
   |  LCP ConfAck  <------------------------> LCP ConfAck  |
   |  IPCP ConfReq(0.0.0.0, DNS 0, 0) ---->                |
   |  <---- IPCP ConfReq (adresse passerelle ou vide)      |
   |  IPCP ConfAck ---->                                   |
   |  <---- IPCP ConfNak (IP, DNS1, DNS2)                  |
   |  IPCP ConfReq(IP, DNS1, DNS2) ---->                   |
   |  <---- IPCP ConfAck            => interface UP        |
   |  <===== paquets IPv4 (proto 0x0021) =====>            |
   |  LCP Echo-Request/Reply (keepalive)                   |
   |  LCP Terminate-Request/Ack, fermeture TLS conn #2     |
   |  -- nouvelle connexion TLS [conn #3] --               |
   |  GET /remote/logout (Cookie)                          |
```

openfortivpn (`tunnel.c`, `run_tunnel`) : étape 0 résolution DNS (IPv4 uniquement,
`AF_INET`), étape 1 TLS, étape 2 auth, « allocation » (`/remote/index` puis
`/remote/fortisslvpn`), **reconnexion TLS** (`ssl_connect` ferme puis rouvre), étape 3
config XML, étape 4 lancement pppd, étape 5 `GET /remote/sslvpn-tunnel` sur la **même**
connexion que la config, étape 6 boucle I/O. À la fin : nouvelle connexion TLS puis
`/remote/logout`.

RECOMMANDÉ : reproduire exactement cette séquence (y compris l'allocation et la
reconnexion), puisque c'est le comportement le plus éprouvé. openconnect saute
l'allocation et rouvre aussi une connexion TLS dédiée avant `sslvpn-tunnel` ; les deux
marchent selon leurs auteurs. Garder la séquence openfortivpn comme défaut et rendre
l'allocation désactivable si besoin.

---

## 2. Transport : TCP et TLS

### 2.1 TCP
- Port par défaut **443** (souvent 10443 en pratique, configurable). openfortivpn ne
  résout que l'IPv4 de la passerelle.
- `TCP_NODELAY` activé sur le socket une fois en mode tunnel (gain ×3 mesuré par
  openfortivpn). RECOMMANDÉ dès la connexion.
- Proxy HTTP (openfortivpn) : si `https_proxy`/`HTTPS_PROXY`/`all_proxy`/`ALL_PROXY`,
  envoi de `CONNECT <ip>:<port> HTTP/1.1\r\nHost: <ip>:<port>\r\n\r\n`, attente d'une
  réponse contenant `200` puis `\r\n\r\n`. Hors MVP.

### 2.2 TLS
- Méthode générique (`TLS_client_method`), **version minimale TLS 1.2** par défaut.
- Liste de suites openfortivpn par défaut : `HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4`
  (désactivable via `--insecure-ssl` / `--seclevel-1`). RECOMMANDÉ : config par défaut de
  rustls (TLS 1.2/1.3, AEAD uniquement) ; un FortiGate récent l'accepte **[NV]**.
- **SNI** = nom d'hôte de la passerelle (ou valeur `--sni` si fournie). openfortivpn
  l'envoie même si l'hôte est une IP littérale ; rustls ne le fait pas (conforme RFC 6066) :
  sans impact attendu.
- Pas de certificat client dans le MVP (cf. §13).
- Fermeture : `SSL_shutdown` (close_notify) puis `close`.

### 2.3 Validation du certificat et épinglage (`ssl_verify_cert`)
Algorithme exact d'openfortivpn :
1. Validation PKI standard (magasin système + `--ca-file` optionnel) **ET**
   `X509_check_host(cert, gateway_host)` (nom dans SAN/CN). Si les deux réussissent :
   accepté, **la liste d'épinglage n'est pas consultée**.
2. Sinon : calcul de `SHA-256( DER(certificat feuille) )` — empreinte du **certificat
   entier** encodé en DER (`X509_digest(cert, EVP_sha256())`), **pas** de la clé publique
   (SPKI) — encodée en **64 caractères hexadécimaux minuscules** sans séparateur.
3. Accepté si cette chaîne est égale (comparaison binaire `memcmp`, donc sensible à la
   casse) à une entrée `trusted-cert` de la configuration. Sinon refus, avec affichage de
   l'empreinte, du sujet et de l'émetteur pour que l'utilisateur puisse l'ajouter.

RECOMMANDÉ pour fortivpn-rs (story 1.3) : même sémantique (« trusted-cert » = exception
pour certificat non validable), normaliser la saisie (minuscules, retirer `:`), et
optionnellement un mode strict « épinglage obligatoire même si PKI valide ».
Vecteur de test : générer un certificat auto-signé dans le test et comparer à
`sha256sum` de sa forme DER.

---

## 3. Couche HTTP commune

### 3.1 Requête (gabarit openfortivpn `do_http_request`)
Toutes les requêtes HTTP sauf `sslvpn-tunnel` utilisent exactement ce gabarit (lignes
terminées par CRLF) :

```
<METHOD> <URI> HTTP/1.1
Host: <gateway_host>:<gateway_port>
User-Agent: Mozilla/5.0 SV1
Accept: */*
Accept-Encoding: identity
Pragma: no-cache
Cache-Control: no-store, no-cache, must-revalidate
If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT
Content-Type: application/x-www-form-urlencoded
Cookie: <cookie>
Content-Length: <len(body)>

<body>
```

- `Host` inclut **toujours** le port, même 443.
- `User-Agent` par défaut `Mozilla/5.0 SV1` (configurable ; openconnect force la même
  valeur). Certaines passerelles filtrent l'UA **[NV]** : le rendre configurable.
- `Cookie:` vaut `SVPNCOOKIE=<valeur>` après auth ; **vide** (`Cookie: ` puis CRLF) avant.
  RECOMMANDÉ : omettre l'en-tête quand il est vide.
- `Content-Type` et `Content-Length: 0` sont envoyés aussi pour les GET.
- Plusieurs requêtes successives sur la même connexion TLS (keep-alive HTTP/1.1
  implicite). Si l'écriture/lecture TLS échoue, openfortivpn **reconnecte TLS et
  rejoue** la requête une fois (`http_request`).

### 3.2 Réponse (`http_receive`)
- Lecture jusqu'à `\r\n\r\n`, puis corps selon `Content-Length` (recherche d'en-tête
  insensible à la casse) ou `Transfer-Encoding: chunked` (fin détectée naïvement par
  `\r\n0\r\n\r\n`). Sans aucun des deux, openfortivpn considère le corps vide.
  RECOMMANDÉ : parseur HTTP/1.1 correct (httparse) gérant les deux, plus `Connection: close`
  (lire jusqu'à EOF).
- Pas de gestion `gzip` (on demande `identity`).
- Pas de suivi automatique des redirections.
- **Détection « permission refusée » globale**, avant tout autre traitement, si :
  - le corps contient `<!--sslvpnerrmsgkey=sslvpn_login_permission_denied-->`, ou
  - les en-têtes contiennent `permission_denied denied` ou `Permission denied`.
  → erreur `ERR_HTTP_PERMISSION`.
- openfortivpn compare la ligne de statut à la chaîne exacte `HTTP/1.1 200 OK\r\n`.
  RECOMMANDÉ : tester le code numérique 200.

### 3.3 Encodage des formulaires (`url_encode`)
- Octets conservés : `A-Z a-z 0-9 - _ . ~` (et `isalnum` en locale C).
- Tout autre octet → `%XX` avec hexadécimal **majuscule** ; espace → `%20` (jamais `+`).
- UTF-8 encodé octet par octet (`é` → `%C3%A9`).
- Vecteur : `logincheck_request.http` (mot de passe `S3cr3t!&= é` →
  `S3cr3t%21%26%3D%20%C3%A9`).

---

## 4. Authentification (login / mot de passe)

### 4.1 Page de login (optionnelle)
openfortivpn n'envoie `GET /remote/login` que si ni utilisateur ni mot de passe ne sont
fournis. FortiClient et les navigateurs font `GET /remote/login?realm=<realm>` (ou
`GET /<realm>` qui redirige vers `/remote/login?realm=<realm>&lang=en`). FortiOS ≥ 7.4
peut répondre à `GET /` par une redirection JavaScript
`top.location="/remote/login"` (openconnect). RECOMMANDÉ : ne pas l'envoyer dans le MVP ;
l'ajouter seulement si une passerelle l'exige (cookies de pré-session) **[NV]**.
Vecteur : `login_request.http`.

### 4.2 `POST /remote/logincheck`
Corps (`application/x-www-form-urlencoded`, ordre d'openfortivpn) :

```
username=<enc(user)>&credential=<enc(password)>&realm=<enc(realm)>&ajax=1
```

- `realm=` est **toujours présent**, vide si aucun realm (`...&realm=&ajax=1`).
- openconnect envoie `username=..&credential=..&realm=..&ajax=1&just_logged_in=1` ;
  l'ordre et `just_logged_in` semblent indifférents.
- Variante sans mot de passe (openfortivpn, cas cert client/autre) :
  `username=..&realm=..&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1`. Hors MVP.
- Vecteur : `logincheck_request.http`.

### 4.3 Analyse de la réponse (ordre exact d'openfortivpn `auth_log_in`)
1. Chercher `ret=<n>` : la réponse **entière** (en-têtes + corps) est découpée sur les
   séparateurs `&`, `,`, `\r`, `\n` ; on prend le premier jeton commençant par `ret=`.
   - `ret=0` → **échec d'authentification** (identifiants refusés). Stop.
   - `ret=1` → succès (continuer).
   - `ret=6` → « challenge non supporté ». Stop.
   - autre valeur (ex. `2`, cas 2FA tokeninfo) → avertissement, continuer.
   - absent → continuer.
2. Statut `401 Authorization Required` → formulaire HTML d'OTP (hors MVP, §13).
3. Statut ≠ 200 → erreur, le code HTTP est remonté (ex. **405** = identifiants invalides
   selon openconnect ; voir `logincheck_failure_405.http`).
4. Extraire le cookie : **premier** en-tête `Set-Cookie:` ; y chercher `SVPNCOOKIE=` ; la
   valeur s'arrête au premier `;`, `\r` ou `\n`. Le cookie conservé est la chaîne
   complète `SVPNCOOKIE=<valeur>` (≤ 4096 octets). Valeur **vide** → pas de cookie.
   RECOMMANDÉ : parcourir **tous** les `Set-Cookie` (openfortivpn ne lit que le premier ;
   openconnect a eu un bug avec un SVPNCOOKIE répété).
5. Pas de cookie :
   - si la réponse contient une clé `tokeninfo=` → **2FA requis**. MVP : erreur explicite
     « authentification à deux facteurs requise (non supportée) ». Vecteur
     `logincheck_2fa_tokeninfo.http`. Champs de la réponse : `ret=2,reqid=..,polid=..,
     grp=..,portal=..,magic=..,tokeninfo=[|ftm_push],chal_msg=..`.
   - sinon → échec (`ERR_HTTP_NO_COOKIE`).
6. Host-check (rare) : si la réponse contient un jeton `action="<url>"`, openfortivpn
   POSTe `hostcheck=<..>&check_virtual_desktop=<..>` vers cette URL. Hors MVP **[NV]**.

Succès type (vecteur `logincheck_success.http`) :
```
HTTP/1.1 200 OK
Set-Cookie: SVPNCOOKIE=<base64-like>; path=/; secure; httponly
...
ret=1,redir=/remote/fortisslvpn_xml
```
Échec type (vecteur `logincheck_failure.http`) :
```
HTTP/1.1 200 OK
Set-Cookie: SVPNCOOKIE=; path=/; expires=Sun, 11 Mar 1984 12:00:00 GMT; secure; httponly
ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied&lang=en
```
La forme exacte des en-têtes et des `redir=` est reconstituée **[NV]** ; les critères de
décision (statut, `ret=`, `SVPNCOOKIE` non vide, `tokeninfo=`) sont, eux, ceux du code.

Table de décision RECOMMANDÉE (robuste aux deux variantes observées) :

| Condition (dans cet ordre) | Résultat |
|---|---|
| marqueur `permission_denied` (§3.2) | `AuthFailed` |
| `ret=0` | `AuthFailed` |
| `ret=6` | `UnsupportedChallenge` |
| statut 401 | `SecondFactorRequired(html)` |
| statut 405 | `AuthFailed` |
| statut ≠ 200 | `HttpStatus(code)` |
| `SVPNCOOKIE` non vide | `Ok(cookie)` |
| `tokeninfo=` présent | `SecondFactorRequired(tokeninfo)` |
| sinon | `NoCookie` |

Sécurité : ne jamais journaliser corps de requête, `Cookie`, `Set-Cookie` (openfortivpn
masque le mot de passe encodé dans les logs de debug, mais logue le cookie en debug :
à ne pas reproduire).

### 4.4 « Allocation » de VPN (openfortivpn `auth_request_vpn_allocation`)
Après succès : `GET /remote/index` puis `GET /remote/fortisslvpn`, réponses ignorées
(seul le succès HTTP/TLS compte). `/remote/fortisslvpn` est aussi l'ancienne
configuration HTML (FortiOS 4, non supportée) ; openconnect s'en sert seulement comme test
de validité du cookie. Rôle exact côté passerelle **[NV]**.

---

## 5. Configuration : `GET /remote/fortisslvpn_xml`

### 5.1 Requête
Gabarit §3.1, URI `/remote/fortisslvpn_xml`, avec cookie. openconnect ajoute
`?dual_stack=1` pour recevoir aussi `<ipv6>` (hors MVP). Vecteurs :
`fortisslvpn_xml_request.http`, `fortisslvpn_xml_response.http`.

Réponses d'erreur : redirection vers `/remote/login` (anciens FortiOS) ou 401/403 →
cookie invalide/expiré. openconnect note que **redemander la config peut invalider le
cookie** sur certaines passerelles : ne la demander qu'une fois par authentification.

### 5.2 Schéma (union d'openfortivpn et openconnect)
Racine `<sslvpn-tunnel ver="2" dtls="0|1" patch="1">`. Attributs avec guillemets simples
**ou** doubles. Éléments connus (enfants directs de la racine sauf mention) :

| Élément / attribut | Sens | Lu par |
|---|---|---|
| `dtls-config` `@heartbeat-interval` `@heartbeat-fail-count` `@heartbeat-idle-timeout` `@client-hello-timeout` | paramètres DTLS (s) | oc |
| `tunnel-method` `@value` = `ppp` \| `tun` | protocoles tunnel offerts (`tun` = « v2 », hors périmètre) | — |
| `fos` `@platform @major @minor @patch @build @branch [@mr_num]` | version FortiOS (info) | oc |
| `auth-ses` `@check-src-ip @tun-connect-without-reauth @tun-user-ses-timeout` | reconnexion sans ré-auth (§10.3) | oc |
| `client-config` `@save-password @keep-alive @auto-connect` | préférences FortiClient (info) | — |
| `ipv4/dns` `@ip` | serveur DNS (0..n, ordre = priorité) | ofv, oc |
| `ipv4/dns` `@domain` | suffixe de recherche DNS (peut être sur un `<dns>` portant aussi `@ip`) | ofv (1er seulement), oc (tous) |
| `ipv4/split-dns` `@domains` (liste `,`) `@dnsserver1..9` | split-DNS | oc (avertissement) |
| `ipv4/assigned-addr` `@ipv4` | adresse attribuée | ofv (comme « passerelle » de routes), oc |
| `ipv4/split-tunnel-info[@negate="1"?]/addr` `@ip @mask` | routes incluses (ou exclues si `negate="1"`) ; masque en notation pointée | ofv (inclusion, 1er bloc), oc |
| `ipv6/assigned-addr` `@ipv6 @prefix-len` | IPv6 attribuée | oc |
| `ipv6/dns` `@ipv6` `@domain` | DNS IPv6 | oc |
| `ipv6/split-tunnel-info[@negate]/addr` `@ipv6 @prefix-len` | routes IPv6 | oc |
| `idle-timeout` `@val` | inactivité max (s) avant coupure | oc |
| `auth-timeout` `@val` | durée de vie max de la session (s) | oc |

Vecteurs : `config_split.xml`, `config_full_tunnel.xml`, `config_dual_stack.xml`.

### 5.3 Règles d'interprétation RECOMMANDÉES
- Parser XML réel (quick-xml), tolérant : éléments/attributs inconnus ignorés, ne pas
  échouer sur `<ipv6>`. openfortivpn utilise un pseudo-parseur (`xml_find`/`xml_get`,
  valeurs ≤ 255 car.) : ne pas en reproduire les limites.
- **Split vs full tunnel** : au moins une `addr` dans un `split-tunnel-info` sans
  `negate="1"` → split-tunnel (routes = ces préfixes via le tunnel). Aucune → full-tunnel :
  route par défaut (ou 0.0.0.0/1 + 128.0.0.0/1) via le tunnel **et** route /32 vers l'IP
  publique de la passerelle via l'ancienne passerelle par défaut (sinon boucle).
  openfortivpn ignore aussi une route split égale à l'IP de la passerelle.
- `negate="1"` : préfixes à exclure (routes vers l'interface physique). openfortivpn ne lit
  que le **premier** `<split-tunnel-info>` sans regarder `negate` : bug à ne pas
  reproduire.
- Masques : accepter uniquement les masques contigus ; convertir en longueur de préfixe.
- DNS : openfortivpn prend les deux premiers `<dns ip>` du XML ; les DNS reçus par IPCP
  ne les remplacent que si `pppd_use_peerdns`. RECOMMANDÉ : XML prioritaire, IPCP en
  complément/secours ; journaliser une divergence.
- Adresse IP : **IPCP fait foi** (c'est elle que pppd configure) ; `assigned-addr` sert de
  contrôle de cohérence.
- Suffixes : agréger tous les `@domain` (dédupliqués, ordre d'apparition) ; FortiOS peut
  aussi envoyer plusieurs domaines séparés par `;` ou espace dans un seul attribut **[NV]**.

---

## 6. Ouverture du tunnel : `GET /remote/sslvpn-tunnel`

Octets exacts envoyés par openfortivpn (pas le gabarit §3.1) :

```
GET /remote/sslvpn-tunnel HTTP/1.1\r\n
Host: sslvpn\r\n
Cookie: SVPNCOOKIE=<valeur>\r\n
\r\n
```

- `Host: sslvpn` littéral, pas de User-Agent ni Content-Length. openconnect envoie le vrai
  `Host` + UA ; tous deux fonctionnent. RECOMMANDÉ : forme openfortivpn par défaut.
- Envoyée sur la connexion TLS qui vient de servir à `fortisslvpn_xml` (openfortivpn) ou une
  connexion neuve (openconnect).
- **Succès : aucune réponse HTTP.** La connexion devient immédiatement un flux de trames
  `0x5050` bidirectionnel ; le client peut (et openfortivpn le fait via pppd) émettre son
  LCP Configure-Request aussitôt, sans attendre de données de la passerelle.
- **Échec :** la passerelle renvoie une réponse HTTP (typiquement `HTTP/1.1 403 Forbidden`)
  à la place de la première trame. Détection : les 6 premiers octets reçus valent
  `HTTP/1` (`48 54 54 50 2f 31`). Message d'openfortivpn : mode tunnel non autorisé,
  mauvais realm, etc. Cause aussi probable : cookie expiré/consommé. Vecteurs :
  `sslvpn_tunnel_403.http`, `framing.hex:err_http_instead_of_ppp`.
  RECOMMANDÉ (openconnect) : si statut 4xx → erreur d'authentification (ré-auth complète).

---

## 7. Framing `0x5050`

### 7.1 Format exact (dans les deux sens)

```
 octet  0      1      2      3      4      5      6 ...
      +------+------+------+------+------+------+---------------------------+
      | total_len   | 0x50 | 0x50 |  ppp_len    | trame PPP (ppp_len octets) |
      +------+------+------+------+------+------+---------------------------+
```

| Champ | Taille | Valeur |
|---|---|---|
| `total_len` | u16 BE | `6 + ppp_len` |
| magic | 2 | `50 50` |
| `ppp_len` | u16 BE | longueur de la trame PPP qui suit |
| trame PPP | `ppp_len` | **protocole PPP sur 2 octets** (`c0 21`, `80 21`, `00 21`…) puis information |

- **Pas** d'adresse/contrôle `ff 03`, **pas** de FCS, **pas** de fanion `7e`, **pas**
  d'échappement : la trame PPP est « nue ». Preuve dans openfortivpn : en émission
  l'octet 6 est le premier octet issu de `hdlc_decode` qui retire `ff 03` et le FCS ; en
  réception `io.c` teste `pkt_data[0..1] == 80 21` directement (`packet_is_ip_plus_dns`).
- Protocole toujours sur 2 octets (PFC non négocié ; openconnect : la passerelle rejette
  PFC/ACFC).
- Une trame = exactement un paquet PPP. Plusieurs trames peuvent arriver dans un même
  enregistrement TLS et une trame peut être coupée entre deux lectures : bufferiser
  (vecteur `framing.hex:stream_three_frames`).

### 7.2 Validation en réception (openfortivpn `ssl_read`)
1. Lire exactement 6 octets.
2. Si `== "HTTP/1"` → erreur « réponse HTTP » (§6).
3. Erreur fatale (« bad header », arrêt du tunnel) si `magic != 0x5050` **ou**
   `total_len < 7` **ou** `total_len - 6 != ppp_len`.
4. Lire exactement `ppp_len` octets.

Vecteurs d'erreur : `framing.hex:err_bad_magic`, `err_inconsistent_lengths`,
`err_total_too_small`.

### 7.3 Tailles
- Maximum théorique : `total_len` = 65535 → `ppp_len` ≤ 65529.
- Pratique : `ppp_len` ≤ 2 + MRU (≈ 1356 pour MRU 1354). RECOMMANDÉ : accepter jusqu'à
  65529 en réception (ne pas couper la session pour un paquet plus grand que le MRU),
  émettre ≤ 2 + MRU du pair.
- Robustesse RECOMMANDÉE en réception (openconnect) : si la trame PPP commence par
  `ff 03`, l'ignorer ; si le premier octet de protocole est impair, protocole sur 1 octet.
  En émission : jamais de `ff 03`. (openconnect, lui, émet `ff 03` car ACFC n'est pas
  négocié ; la passerelle tolère donc les deux **[NV pour toutes versions]**.)

---

## 8. HDLC : openfortivpn/pppd vs PPP intégré

openfortivpn **ne parle pas PPP** : il délègue à `pppd` via un pseudo-terminal.
- G→C : trame 0x5050 → retrait de l'en-tête → `hdlc_encode` : ajoute `7e` initial (une
  seule fois), `ff 7d 23` (adresse + contrôle échappé), échappe tout octet `< 0x20`,
  `0x7d`, `0x7e` (et leurs versions avec bit 7) en `7d (x ^ 0x20)`, ajoute le FCS-16
  (RFC 1662, init `0xffff`, complémenté, octet de poids faible en premier, lui-même
  échappé) puis `7e` → écrit sur le pty.
- C→G : lit le pty, découpe sur `7e`, `hdlc_decode` : retire `ff 7d 23` si présent,
  dé-échappe, ignore les octets `< 0x20` non échappés, vérifie le FCS (résidu `0xf0b8`),
  retire les 2 octets de FCS → ajoute l'en-tête 0x5050.
- HDLC n'existe donc **que** sur le lien local openfortivpn↔pppd, jamais sur le fil.

Options pppd passées par openfortivpn (pertinentes pour reproduire le comportement) :
`230400 :169.254.2.1 noipdefault ipcp-accept-local noaccomp noauth default-asyncmap
nopcomp receive-all nodefaultroute nodetach lcp-max-configure 40 mru 1354`
[+ `ipcp-accept-remote`] [+ `usepeerdns`]. Conséquences :
- LCP : MRU 1354, Magic-Number ; **pas** d'ACCM (`default-asyncmap`), pas de PFC
  (`nopcomp`), pas d'ACFC (`noaccomp`), pas d'authentification PPP (`noauth`).
- IPCP : demande d'adresse 0.0.0.0 (`noipdefault`), accepte l'adresse fournie
  (`ipcp-accept-local`) ; adresse distante par défaut 169.254.2.1 si la passerelle n'en
  annonce pas ; `usepeerdns` ajoute DNS 129/131. pppd propose aussi VJ par défaut.
- Keepalive LCP : celui de `/etc/ppp/options` (souvent `lcp-echo-interval 30`,
  `lcp-echo-failure 4` sur Debian) — non fixé par openfortivpn.

**Ce que fait un client à PPP intégré (fortivpn-rs)** : aucun HDLC, aucun FCS, aucun
pty. Il produit/consomme directement « protocole (2 o) + paquet » dans l'enveloppe
0x5050, et implémente lui-même LCP + IPCP (§9). Les routines FCS/HDLC ne sont utiles que
pour des tests de compatibilité ; elles ne font pas partie du chemin de données.

---

## 9. PPP

### 9.1 Format des paquets de contrôle (LCP 0xc021, IPCP 0x8021, IPV6CP 0x8057)

```
 code(1) | identifier(1) | length(2, BE, inclut ces 4 octets) | données
 options : type(1) | length(1, inclut type+length) | valeur
```

| Code | Nom | Remarque |
|---|---|---|
| 1 | Configure-Request | |
| 2 | Configure-Ack | options recopiées octet pour octet, même id |
| 3 | Configure-Nak | options avec valeurs proposées |
| 4 | Configure-Reject | options refusées recopiées |
| 5 | Terminate-Request | |
| 6 | Terminate-Ack | |
| 7 | Code-Reject | (LCP seulement) |
| 8 | Protocol-Reject | (LCP seulement) données = protocole rejeté (2 o) + paquet |
| 9 | Echo-Request | (LCP) magic(4) + données |
| 10 | Echo-Reply | (LCP) magic local(4) + données recopiées |
| 11 | Discard-Request | (LCP) magic(4) + données ; ignorer |

Les données au-delà de `length` sont du bourrage à ignorer ; `length` > données reçues →
paquet invalide (à ignorer).

### 9.2 LCP

**Configure-Request émis par le client (RECOMMANDÉ = ce qu'émet pppd via openfortivpn)** :

| Option | Type | Long. | Valeur |
|---|---|---|---|
| Maximum-Receive-Unit | 1 | 4 | 1354 (`05 4a`) |
| Magic-Number | 5 | 6 | 32 bits aléatoires non nuls |

Octets : `lcp.hex:lcp_confreq_client`
```
00 16 50 50 00 10  c0 21  01 01 00 0e  01 04 05 4a  05 06 1a 2b 3c 4d
```
Ne pas proposer ACCM (2), PFC (7), ACFC (8) : rejetés par la passerelle (openconnect,
`ppp.c` : « Fortinet server rejects asyncmap and header compression »). Sur
Configure-Reject (`lcp.hex:lcp_confrej_gateway`) : retirer les options listées et renvoyer
un Configure-Request avec un **nouvel** identifiant. Sur Configure-Nak du MRU : adopter la
valeur proposée si ≥ 576 et ≤ 1500, sinon abandonner l'option.

**Configure-Request reçu de la passerelle** — options exactes **[NV]** (vecteur
`lcp_confreq_gateway` illustratif : MRU + Magic). Politique RECOMMANDÉE :

| Option reçue | Réponse |
|---|---|
| MRU (1) | Ack ; mémoriser comme taille max d'émission (MTU interface = min(MRU pair, notre MRU)) |
| ACCM (2) | Ack (sans effet : pas d'HDLC) |
| Magic-Number (5) | Ack si ≠ notre magic ; si égal (boucle) → Nak avec un autre magic aléatoire |
| PFC (7), ACFC (8) | Reject (on veut des en-têtes non compressés) |
| Authentication-Protocol (3) | Reject (pas d'auth PPP ; openfortivpn utilise `noauth` et n'a pas de secrets) **[NV : jamais observé]** |
| autre | Reject |

Règle RFC 1661 : si au moins une option doit être rejetée → Configure-Reject (seulement
les rejetées) ; sinon si au moins une doit être corrigée → Configure-Nak ; sinon
Configure-Ack (recopie exacte, même id). Vecteur `lcp_confack_client`.

LCP est **Opened** quand on a envoyé un Configure-Ack ET reçu un Configure-Ack pour
notre requête courante (id correspondant). On démarre alors IPCP.

### 9.3 Automate simplifié (client, connexion active)
Un automate RFC 1661 complet n'est pas nécessaire ; version minimale suffisante pour un
lien point à point fiable (TLS) :

```
États LCP : Starting -> ReqSent -> AckRcvd | AckSent -> Opened -> Closing -> Closed
  À l'ouverture du tunnel : envoyer ConfReq (id=n), état ReqSent, armer timer 3 s.
  Timeout (timer) : renvoyer ConfReq (même contenu, nouvel id), max 10 (pppd défaut ;
                    openfortivpn lcp-max-configure 40) -> échec « négociation PPP ».
  RCR+ (ConfReq acceptable)  : envoyer ConfAck ; ReqSent->AckSent, AckRcvd->Opened.
  RCR- (Nak/Rej nécessaire)  : envoyer ConfNak/ConfRej ; état inchangé (AckSent->ReqSent).
  RCA (ConfAck, id courant)  : ReqSent->AckRcvd, AckSent->Opened ; sinon ignorer.
  RCN (ConfNak/ConfRej)      : ajuster options, nouveau ConfReq (nouvel id).
  RTR (TermReq reçu)         : envoyer TermAck, -> Closed (fin de session).
  Opened + RCR               : (renégociation) PPP repart : IPCP down, renégocier
                               (RFC 1661) ; RECOMMANDÉ MVP : traiter comme
                               déconnexion et reconnecter proprement.
  Opened + Echo-Request      : Echo-Reply.
  Paquet LCP code inconnu    : Code-Reject.
  Protocole PPP inconnu (ex. 0x80fd CCP, 0x8057 si IPv6 non géré) : Protocol-Reject
                               (lcp.hex:lcp_protocol_reject_ipv6cp_client).
IPCP : même automate, démarré quand LCP est Opened.
```
Les paquets IPCP reçus avant LCP Opened : ignorer (ou mettre en file) ; les paquets IP
reçus avant IPCP Opened : ignorer.

### 9.4 IPCP
**Configure-Request initial du client** (`ipcp.hex:ipcp_confreq_client_1`) :

| Option | Type | Long. | Valeur |
|---|---|---|---|
| IP-Address | 3 | 6 | 0.0.0.0 |
| Primary-DNS-Address | 129 (`0x81`) | 6 | 0.0.0.0 |
| Secondary-DNS-Address | 131 (`0x83`) | 6 | 0.0.0.0 |

Ne pas proposer IP-Compression-Protocol (2, VJ) ni NBNS (130/132) : VJ est proposé par
pppd mais rejeté selon toute vraisemblance **[NV]** ; NBNS demandé par openconnect,
résultat inconnu **[NV]**. Si un Configure-Reject vise 129/131, les retirer et continuer
sans DNS IPCP (le XML en fournit).

**Échange attendu** :
1. G→C `Configure-Nak` (`ipcp_confnak_gateway`) : IP 10.10.0.2, DNS1, DNS2.
2. C→G nouveau `Configure-Request` (nouvel id) reprenant ces valeurs
   (`ipcp_confreq_client_2`).
3. G→C `Configure-Ack` (`ipcp_confack_gateway`). Forme exacte attendue par openfortivpn :
   `80 21 02 id 00 16 03 06 <IP> 81 06 <DNS1> 83 06 <DNS2>`.

**Configure-Request de la passerelle** : deux variantes connues (cf. `io.c`) :
- avec `03 06 <adresse PPP de la passerelle>` (`ipcp_confreq_gateway`) → Ack tel quel ;
- **vide** (longueur 4, `ipcp_confreq_gateway_empty`) → Ack vide.
Toute autre option → Reject. Ne jamais Nak l'adresse de la passerelle (l'adresse distante
n'a pas d'usage : l'interface est point à point, les routes pointent sur l'interface).

IPCP Opened (Ack envoyé + Ack reçu) ⇒ configurer l'interface : adresse = IP de l'Ack,
masque /32, MTU = §9.2 ; puis routes et DNS (§5.3). openfortivpn attend l'interface
jusqu'à 60 s après fin de négociation.

### 9.5 IPV6CP (hors MVP)
Protocole `0x8057`, option 1 Interface-Identifier (8 octets) (RFC 5072). La passerelle ne
le négocie que si IPv6 est activé (et vraisemblablement si `?dual_stack=1` a été demandé)
**[NV]**. MVP : si un paquet IPV6CP arrive, répondre LCP Protocol-Reject
(`lcp_protocol_reject_ipv6cp_client`). Paquets IPv6 = protocole `0x0057`.

### 9.6 Données
- IPv4 : protocole `0x0021` + paquet IP brut (`ip.hex:ipv4_icmp_echo_request`) :
  `00 44 50 50 00 3e 00 21 45 00 00 3c ...`.
- Interface TUN/Wintun ↔ tunnel : retirer/ajouter exactement 8 octets
  (`total_len`, `50 50`, `ppp_len`, `00 21`).
- MTU interface : 1354 par défaut (= MRU), ou MRU de la passerelle si plus petit.

### 9.7 Keepalive (LCP Echo)
- Réception d'Echo-Request : répondre **toujours** (dès LCP Opened) par Echo-Reply, même
  id, magic = **notre** magic, données recopiées (`lcp_echo_request_gateway` →
  `lcp_echo_reply_client`). Ignorer un Echo-Request dont le magic est égal au nôtre
  (boucle).
- Émission RECOMMANDÉE : Echo-Request toutes les 30 s d'inactivité en réception, échec
  après 4 sans réponse (≈ valeurs pppd Debian) → session morte, déclencher la
  reconnexion. openconnect utilise l'Echo-Request comme DPD et un Discard-Request
  (code 11) comme simple keepalive.
- Le trafic de contrôle LCP compte-t-il pour l'`idle-timeout` de la passerelle ? **[NV]**

### 9.8 Terminaison PPP
- Client : envoyer LCP Terminate-Request (`lcp_terminate_request_client`), attendre
  Terminate-Ack ≤ 1 s (openconnect : un seul envoi, attente 1 s), puis close_notify TLS.
  openfortivpn n'envoie **rien** : il ferme la connexion TLS (pppd est tué localement).
- Passerelle : Terminate-Request reçu → Terminate-Ack (`lcp_terminate_ack_client`),
  fermer TLS, état « déconnecté par la passerelle ».
- EOF TLS / erreur de lecture : fin de session.

---

## 10. Déconnexion et reconnexion

### 10.1 Logout
openfortivpn (`run_tunnel`, fin) : **nouvelle connexion TLS**, puis `GET /remote/logout`
(gabarit §3.1, avec cookie, `Content-Length: 0`), réponse ignorée, fermeture. Fait aussi
en cas d'échec après l'authentification. La réponse efface le cookie (Set-Cookie vide).
Vecteurs : `logout_request.http`, `logout_response.http`.
RECOMMANDÉ : Terminate LCP → fermeture du tunnel → logout sur nouvelle connexion
(timeout court, 5 s, erreurs ignorées).

### 10.2 Reconnexion — openfortivpn
`--persistent=<s>` : après coupure, attendre `<s>` secondes et refaire **toute** la
séquence (auth incluse).

### 10.3 Reconnexion sans ré-authentification
Si `<auth-ses tun-connect-without-reauth="1">` : la passerelle permet de rouvrir le tunnel
avec le même cookie pendant `tun-user-ses-timeout` secondes (FortiOS ≥ 6.2.1), depuis la
même IP source si `check-src-ip="1"`. D'après openconnect : rouvrir TLS + `GET
/remote/sslvpn-tunnel` + renégocier PPP, **sans** redemander la config XML (ce qui peut
invalider le cookie). Fiabilité réelle signalée comme médiocre **[NV]**. RECOMMANDÉ :
tenter une fois, puis ré-auth complète sur 403/HTTP au lieu de PPP.

---

## 11. Timeouts

| Étape | openfortivpn | RECOMMANDÉ |
|---|---|---|
| TCP connect | défaut OS | 15 s |
| Handshake TLS | aucun | 15 s |
| Réponse HTTP (auth, config) | aucun (bloquant) | 30 s |
| Première trame après `sslvpn-tunnel` | aucun (pppd) | 15 s |
| Retransmission ConfReq LCP/IPCP | pppd : 3 s | 3 s |
| Max ConfReq | `lcp-max-configure 40` (≈ 120 s) | 10 (≈ 30 s) |
| Interface UP après IPCP | 60 s (poll 200 ms) | n/a (configuration directe) |
| Echo LCP | config pppd système | 30 s, 4 échecs |
| Terminate-Ack | — | 1 s |
| Logout | aucun | 5 s |
| Session | — | respecter `auth-timeout` (ré-auth avant expiration ou à la coupure) |

---

## 12. Erreurs (table de correspondance)

| Situation | Détection | Erreur fortivpn-rs suggérée |
|---|---|---|
| Certificat refusé | §2.3 étape 3 | `TlsUntrusted { sha256_hex }` |
| Identifiants refusés | `ret=0`, 405, marqueurs `permission_denied`, cookie vide | `AuthFailed` |
| 2FA demandé | `tokeninfo=` sans cookie, ou 401 + formulaire | `SecondFactorRequired` (message explicite) |
| Challenge inconnu | `ret=6` | `UnsupportedChallenge` |
| Pas de cookie | 200 sans SVPNCOOKIE ni tokeninfo | `NoCookie` |
| Cookie expiré | redirection `/remote/login`, 401/403 sur config | `SessionExpired` |
| Mode tunnel refusé | `HTTP/1` au lieu de 0x5050 | `TunnelRefused { status }` |
| Framing invalide | §7.2 | `BadFrame` (fatal) |
| Négociation PPP | max ConfReq atteint | `PppNegotiationFailed` |
| Pair muet | 4 Echo sans réponse | `DeadPeer` (→ reconnexion) |
| Fin par la passerelle | Terminate-Request reçu, EOF TLS | `ClosedByPeer` |

---

## 13. Extensions hors MVP (points d'insertion)

- **OTP / FortiToken (story 1.2)** : §4.3 étape 5 — second `POST /remote/logincheck` avec
  `username=..&realm=..&reqid=..&polid=..&grp=..&portal=..&peer=..&code=<otp>&code2=&magic=..`
  (ou `..&ftmpush=1` sans `code`/`magic` pour FortiToken push). Variante HTML (401) : poster
  le formulaire `<FORM ACTION=...>` avec les `<INPUT type=hidden>` + champ password = OTP.
- **SAML (1.4)** : navigateur sur `https://<gw>:<port>/remote/saml/start?redirect=1[&realm=..]`,
  la passerelle redirige finalement le navigateur vers le listener local
  (`GET /?id=<id>`, openfortivpn `http_server.c`, port 8020 par défaut), puis
  `GET /remote/saml/auth_id?id=<id>` qui renvoie `SVPNCOOKIE` ; la suite est identique.
- **Certificat client (1.5)** : uniquement au niveau TLS (§2.2) ; `logincheck` alors sans
  `credential` (§4.2 variante).
- **Cookie externe** : openfortivpn `--cookie` saute §4 entièrement.
- **DTLS** : `dtls="1"` dans le XML ; même port en UDP, hello
  `be16(len) "GFtype\0clthello\0SVPNCOOKIE\0" <cookie> \0`, réponse `svrhello` + `ok`
  (openconnect). Hors périmètre.
- **Protocole tunnel « v2 »** (`<tunnel-method value="tun"/>`, FortiOS ≥ 5.6.6) : non PPP,
  non documenté ici.

---

## 14. Points non vérifiés

Aucune capture de passerelle réelle n'a été faite (interdit sans accord explicite). Points
déduits du code ou reconstitués, à confirmer par une capture anonymisée (TLS déchiffré,
par ex. via `SSLKEYLOGFILE` sur openfortivpn, sur demande de l'utilisateur) :

1. **Options LCP proposées par la passerelle** (MRU ? valeur ? ACCM ? PFC/ACFC ? auth ?).
   Le vecteur `lcp_confreq_gateway` est illustratif. Le client doit être tolérant (§9.2).
2. **Qui parle en premier** après `sslvpn-tunnel` et délai éventuel requis ; on suppose
   envoi immédiat possible (openfortivpn/pppd et openconnect le font).
3. **Tolérance à `ff 03`** en tête de trame C→G (openconnect l'émet, openfortivpn non) et
   absence de `ff 03` en G→C sur toutes versions FortiOS (déduite du fonctionnement de
   pppd via openfortivpn).
4. **Contenu exact de l'IPCP de la passerelle** (adresse annoncée : 169.254.x ? IP du
   FortiGate ? vide ?) et ordre Nak/Ack ; rejet de VJ ; réponse à NBNS 130/132.
5. **Forme exacte des réponses `logincheck`** (en-têtes, `redir=`, variante 200+`ret=0` vs
   405 selon versions, éventuels `Set-Cookie` multiples) — les vecteurs `.http` de réponse
   sont reconstitués.
6. **Nécessité de `/remote/index` + `/remote/fortisslvpn`** avant `fortisslvpn_xml`, et de
   la reconnexion TLS intermédiaire.
7. **`GET /remote/login?realm=`** préalable : requis par certaines passerelles ?
8. **Keepalive** : la passerelle émet-elle des Echo-Request, à quelle période ; les Echo
   comptent-ils pour `idle-timeout` ; tolérance aux Discard-Request.
9. **Comportement en fin de session** : la passerelle envoie-t-elle un LCP
   Terminate-Request à l'`idle-timeout`/`auth-timeout`, ou ferme-t-elle TLS directement ?
10. **Format multi-domaines** de `<dns domain>` (séparateurs) et sémantique précise de
    `<split-dns>` (à traduire en NRPT sous Windows).
11. **Filtrage User-Agent** côté passerelle (« Mozilla/5.0 SV1 » vs UA FortiClient).
12. **Suites TLS** acceptées par les FortiGate anciens avec rustls (pas de CBC/RSA-kx).
13. **Reconnexion sans ré-auth** (§10.3) : séquence exacte et fiabilité.
14. **Host-check** (`action=` dans la réponse de login) : fréquence et format réels.

---

## Annexe A — index des vecteurs

| Vecteur | Section |
|---|---|
| `logincheck_request.http`, `logincheck_success.http`, `logincheck_failure.http`, `logincheck_failure_405.http`, `logincheck_2fa_tokeninfo.http`, `login_request.http` | §3.3, §4 |
| `fortisslvpn_xml_request.http`, `fortisslvpn_xml_response.http`, `config_split.xml`, `config_full_tunnel.xml`, `config_dual_stack.xml` | §5 |
| `sslvpn_tunnel_request.http`, `sslvpn_tunnel_403.http` | §6 |
| `framing.hex` (flux concaténé, erreurs) | §7 |
| `lcp.hex` (ConfReq/Ack/Rej, Echo, Terminate, Protocol-Reject) | §9.2, §9.7, §9.8 |
| `ipcp.hex` (ConfReq/Nak/Ack, variantes passerelle, VJ) | §9.4 |
| `ip.hex` (ICMP echo IPv4) | §9.6 |
| `logout_request.http`, `logout_response.http` | §10.1 |
