# Sécurité — points à discuter pour des versions ultérieures

Points relevés en revue, **volontairement non traités** pour l'instant (décision de l'utilisateur, 2026-11-13).
À évoquer lors de la planification d'une version « durcie ».

## Mode proxy (netproxy) — revue docs/security/review-7.1-netproxy.md
- **M1 — SOCKS5 sans authentification** : tout processus local (autre utilisateur, session RDP, WSL en mode mirrored) peut utiliser le tunnel et résoudre des noms internes. Pistes : vérifier que le pair appartient à l'utilisateur courant (Windows : GetExtendedTcpTable → PID → SID) ; auth RFC 1929 optionnelle (non supportée par Firefox/Chrome).
- **M2 — Épuisement des 256 connexions** : clients muets ou qui ne lisent pas. Pistes : sémaphore par écouteur, timeout d'inactivité dans `bridge`, plafond des handshakes en cours.
- **F1** — `allow_non_loopback` sans avertissement au démarrage.
- **F2** — noms d'hôtes / IP cibles journalisés en debug.
- **F3** — `ProxyCleanup::stop` sans contrôle de génération (DoS possible lors d'une reconnexion).

## IPsec — revue docs/security/review-6.5-ipsec.md
- **M1** — un détenteur du PSK de groupe peut usurper la passerelle et obtenir la NT-Response MS-CHAPv2 (crackable hors ligne). Pistes : auth du répondeur par certificat épinglé, PSK par passerelle, `expected_idr` imposé, refus de PSK courte.
- F1–F8 : voir la story 6.S du backlog.

## Rappels d'autres revues
- WFP / kill-switch, NRPT GPO : choix produit documentés dans docs/BACKLOG.md (« Décisions produit ») et docs/security/review-5.3-*.md.

## Proxy — surveillance du port (proposition 7.S, non implémentée)
- Vérifier périodiquement (~30 s) qu'aucun autre processus n'écoute sur le même port : connexion loopback « sonde » qui doit arriver sur notre propre `accept` (jeton interne) ; sous Windows, `GetExtendedTcpTable` pour obtenir le PID d'un écouteur concurrent. En cas d'anomalie : avertissement, notification CLI/GUI, option de couper le proxy.
