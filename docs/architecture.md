# Architecture

## Vue d'ensemble

```
                 +----------------------------- crates/cli (binaire fortivpn) -----------------------------+
                 |  config TOML, mot de passe, codes de sortie, choix du backend à la compilation          |
                 +-------------------------------------------+--------------------------------------------+
                                                             |
                                                             v
                 +------------------- crates/core : Session, boucle tunnel tokio, reconnexion -----------+
                 |        trait Transport                                   trait NetBackend              |
                 +-----------+--------------------------+-------------------------+-----------------------+
                             |                          |                         |
                  SslVpnTransport                IpsecTransport             implémentations
                             |                     (crates/ipsec,        netlinux | netwin | netproxy
                             v                      IKE + ESP)
                      crates/proto (pur, sans I/O OS)
```

Flux d'une connexion SSL-VPN :

```
 mot de passe --> [1. Auth HTTPS]  POST /remote/logincheck --> cookie SVPNCOOKIE
                        |   (TLS : racines système + épinglage SHA-256 optionnel)
                        v
                  [2. Config XML]  GET /remote/fortisslvpn_xml --> IP, routes, DNS, domaines
                        |
                        v
                  [3. Tunnel]      GET /remote/sslvpn-tunnel, puis trames 0x5050 portant du PPP
                        |          (LCP : MRU, magic, echo-keepalive ; IPCP : IP, DNS)
                        v
                  [4. Backend réseau]  paquets IP <--> TUN + routes + DNS (Linux, Windows)
                                       ou pile smoltcp + SOCKS5 + redirections (mode proxy)
```

## Rôle des crates

| Crate | Rôle |
|---|---|
| `proto` | Protocole SSL-VPN : authentification HTTPS, XML de configuration, framing `0x5050`, machine à états PPP (LCP/IPCP). Pur, sans I/O système. |
| `core` | `Session`, boucle tunnel tokio, reconnexion ; traits `Transport` et `NetBackend`. |
| `ipsec` | Transport IPsec (IKE + ESP en espace utilisateur). En cours, secondaire. |
| `netlinux` | `NetBackend` Linux : TUN, adresses, routes ; sert aussi aux tests e2e (netns) dans WSL. |
| `netwin` | `NetBackend` Windows : Wintun, IP Helper (routes), DNS et NRPT, filtres WFP. Compilé sous `cfg(windows)`. |
| `netproxy` | `NetBackend` en espace utilisateur sans droits admin : pile `smoltcp`, proxy SOCKS5, redirections de ports. |
| `service` | Service Windows (SYSTEM) piloté par named pipe : protocole, machine d'états, serveur et client. |
| `cli` | Binaire `fortivpn` : commandes, configuration TOML, logs, codes de sortie. |
| `tools/mock-gw` | Fausse passerelle FortiGate (TLS, auth, XML, PPP) pour les tests. |

## Principes

- **Sans-I/O** : `proto` ne fait aucune entrée/sortie ; il transforme des octets en événements et inversement, ce qui le rend testable avec des vecteurs (`docs/vectors`) et fuzzable.
- **`Transport` / `NetBackend`** : `core` ne connaît que ces deux traits. Le transport (SSL-VPN ou IPsec) fournit une configuration réseau et un flux de paquets IP ; le backend applique cette configuration au système. Le backend est choisi à la compilation selon l'OS, ou à la configuration (`[proxy]`).
- **Nettoyage garanti** : routes, DNS et filtres sont retirés à l'arrêt (Drop, Ctrl+C) ; sous Windows, un journal d'état permet de défaire les changements d'un crash au démarrage suivant.
- **Sécurité** : mot de passe jamais stocké ni journalisé, ni dans la configuration, ni en variable d'environnement ; validation TLS avec épinglage optionnel ; blocage des fuites hors tunnel (IPv6, LLMNR/NBT-NS/mDNS) sous Windows ; `unsafe` confiné à `netwin` et `service` ; ne jamais écrire sous la clé de stratégies NRPT de l'entreprise. Les revues sont dans `docs/security/`.
- **Tests** : tout se développe et se teste sous Linux (WSL2) contre `mock-gw` ; le code Windows est seulement cross-compilé et analysé.
