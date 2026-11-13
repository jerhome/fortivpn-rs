# Vecteurs de test — protocole Fortinet SSL-VPN

Référencés par `docs/protocol.md`. Réutilisables par les tests unitaires de `crates/proto`
et par `tools/mock-gw`. **Toutes les données sont fictives** (hôte `vpn.example.com`,
adresses 10.x / 192.0.2.x / 198.51.100.x / 169.254.x, identifiants `jdoe` / `S3cr3t!&= é`,
cookie inventé).

## Format `.hex`

```
# commentaire (ignoré)
@frame <nom> dir=<c2g|g2c> len=<n>
00 16 50 50 00 10 c0 21 ...      <- octets hexadécimaux séparés par des espaces
05 06 1a 2b 3c 4d                <- la trame continue jusqu'au prochain @frame / EOF
```

- `c2g` : client -> passerelle ; `g2c` : passerelle -> client.
- Les octets sont ceux du flux TLS **déchiffré**, en-tête 0x5050 compris
  (sauf mention contraire dans le commentaire, ex. `*_raw_ip`).
- `len` = nombre total d'octets du vecteur (contrôle d'intégrité du parseur).
- Les vecteurs dont le nom commence par `err_` sont des entrées **invalides** que le
  décodeur doit rejeter.

| Fichier | Contenu |
|---|---|
| `lcp.hex` | LCP Configure-Request/Ack/Reject, Echo-Request/Reply, Terminate-Request/Ack, Protocol-Reject (IPV6CP) |
| `ipcp.hex` | IPCP Configure-Request (0.0.0.0), Nak (IP + DNS 129/131), Ack ; variantes passerelle avec/sans adresse ; contre-exemple VJ |
| `ip.hex` | ICMP Echo Request/Reply IPv4 encapsulés (checksums valides) + le paquet IP nu |
| `framing.hex` | 3 trames concaténées dans une lecture ; erreurs de framing ; réponse HTTP au lieu de PPP |

## Format `.http`

- Lignes de tête commençant par `#` : commentaires (à ignorer jusqu'à la première ligne
  ne commençant pas par `#`).
- Puis le message HTTP. Dans le fichier, les lignes de **ligne de départ et d'en-têtes**
  se terminent par LF ; **sur le fil, elles doivent être émises avec CRLF**
  (y compris la ligne vide de fin d'en-têtes).
- Le corps = octets exacts après la ligne vide, **moins le LF final unique** ajouté en fin
  de fichier. Les fins de ligne *à l'intérieur* du corps (XML) restent des LF ;
  `Content-Length` est calculé sur ce corps.

| Fichier | Contenu |
|---|---|
| `login_request.http` | `GET /remote/login?realm=...` (optionnel) |
| `logincheck_request.http` | `POST /remote/logincheck` au format exact d'openfortivpn |
| `logincheck_success.http` | 200 + `Set-Cookie: SVPNCOOKIE=...` + `ret=1` |
| `logincheck_failure.http` | 200 + `ret=0` + cookie vide |
| `logincheck_failure_405.http` | 405 Method Not Allowed (variante d'échec) |
| `logincheck_2fa_tokeninfo.http` | 2FA requis (`tokeninfo=`), pas de cookie |
| `fortisslvpn_xml_request.http` / `_response.http` | récupération de la configuration |
| `sslvpn_tunnel_request.http` | bascule en mode tunnel (aucune réponse HTTP si succès) |
| `sslvpn_tunnel_403.http` | refus du mode tunnel |
| `logout_request.http` / `logout_response.http` | déconnexion |

## XML

`config_split.xml` (split-tunnel + exclusions + split-DNS), `config_full_tunnel.xml`
(aucune route => tout dans le tunnel), `config_dual_stack.xml` (section `<ipv6>`, hors MVP).
Ils contiennent des commentaires XML explicatifs, absents des vraies réponses.

## Régénération

Les fichiers `.hex` et `.http` ont été produits par un script Python hors dépôt (S0.1) puis
vérifiés indépendamment (longueurs 0x5050, longueurs LCP/IPCP, checksums IP/ICMP).
Ce sont désormais des fichiers de référence : les modifier à la main en conservant
`len=` cohérent.
