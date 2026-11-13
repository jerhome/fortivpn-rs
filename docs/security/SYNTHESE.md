# Synthèse des revues de sécurité

Liste issue des revues de sécurité en lecture seule (passes 5.3-1 et 5.3-2, 6.5 IPsec, 7.1 netproxy) et de `docs/securite-versions-futures.md`. Aucune faille n'a été exploitée en pratique : ce sont des constats de revue. Les dépendances n'ont pas pu être vérifiées contre RustSec (`cargo audit`/`deny` absents) : à ajouter en CI.

Statuts : **corrigé** ; **corrigé, à valider sous Windows** (correctif écrit et compilé, jamais exécuté sous Windows) ; **reporté** (non traité, décision ou story ouverte) ; **accepté par conception**.

## Passe 5.3-1 ([rapport](docs/security/review-5.3-pass1.md))

| Réf. | Sévérité | Résumé | Statut |
|---|---|---|---|
| C1 | Critique | Journal d'état dans `%ProgramData%` : suppression/écrasement de fichier arbitraire par le processus admin (liens, variable d'environnement) | Corrigé, à valider sous Windows (journal dans HKLM) |
| E1 | Élevé | Journal non authentifié : suppression de routes/IP/DNS arbitraires au recover | Corrigé, à valider sous Windows |
| E2 | Élevé | Fuite IPv6 en full-tunnel (Windows et Linux) | Linux : corrigé ; Windows : corrigé (filtres WFP), à valider sous Windows |
| M1 | Moyen | Pas de verrou d'instance unique (une 2e instance démonte les routes de la 1re) | Corrigé, à valider sous Windows (voir 5.3-2 M4) |
| M2 | Moyen | DNS du tunnel non couvert par les routes (requêtes en clair) | Corrigé (Linux et Windows, route /32), à valider sous Windows |
| M3 | Moyen | NRPT locale ignorée si une NRPT GPO existe : fuite DNS | Corrigé par blocage DNS WFP en full-tunnel, à valider sous Windows (en split-tunnel : avertissement seulement, on n'écrit jamais sous la clé GPO) |
| M4 | Moyen | Intégrité de `wintun.dll` et du dossier d'installation non vérifiée | Corrigé, à valider sous Windows |
| F1 | Faible | Linux : `resolv.conf` suivi par lien / TOCTOU | Corrigé (fd, `O_NOFOLLOW`) |
| F2 | Faible | Données poussées par la passerelle peu bornées (domaines, routes, `local_ip`) | Partiellement corrigé (bornes XML via 5.3-2 M1) ; le reste (suffixes publics, validations d'adresses) non vérifié : reporté |
| F3 | Faible | LUID Wintun résolu par alias (mauvaise interface possible) | Corrigé, à valider sous Windows |
| F4 | Faible | LLMNR/NBT-NS/mDNS actifs hors tunnel en full-tunnel | Corrigé (filtres WFP), à valider sous Windows |
| F5 | Faible | Règles NRPT non volatiles | Reporté : à observer en recette 3.W |

## Passe 5.3-2 ([rapport](docs/security/review-5.3-pass2.md))

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

## Passe 6.5 — IPsec ([rapport](docs/security/review-6.5-ipsec.md)) : 0 critique, 0 élevé

Les correctifs relèvent de la story 6.S ; sauf mention contraire, ils restent **reportés**.

| Réf. | Sévérité | Résumé | Statut |
|---|---|---|---|
| M1 | Moyen | PSK de groupe : un détenteur du PSK peut usurper la passerelle et obtenir la NT-Response MS-CHAPv2 (crackable hors ligne) | Corrigé : authentification de la passerelle par certificat épinglé (`ResponderAuth::CertPinned`, méthodes AUTH 1 et 14 : RSA PKCS#1/PSS, ECDSA P-256 ; pin SHA-256 vérifié avant l'envoi de l'identité EAP). Limites : en mode `Psk` (défaut, compatibilité) ou `PskAndCertPinned` (« l'un ou l'autre ») la protection n'existe pas : recommander `CertPinned` ; épinglage seul, sans validation de chaîne ni de dates |
| F1 | Faible | Erreurs IKE_SA_INIT non authentifiées traitées comme fatales ; cookie non borné | Reporté |
| F2 | Faible | Rekey CHILD sans PFS accepté | Reporté |
| F3 | Faible | Secrets non effacés (exposant DH, plaintext SK, clés ESP reconstruites) | Reporté |
| F4 | Faible | `num-bigint` non constant-time pour MODP-2048 (risque pratique faible) | Reporté |
| F5 | Faible | Pas de test de sous-groupe pour MODP14 (sans conséquence sur la clé) | Reporté |
| F6 | Faible | Réponse en cache rejouable sans authentifier la requête (impact négligeable) | Reporté |
| F7 | Faible | Contenu CP/TS de la passerelle (IP, DNS, domaines) non validé | Reporté |
| F8 | Faible | Paquet IPv4 interne ESP non validé ; seuil de rekey à vérifier | Reporté |
| I1 | Info | Ordre de dérivation de la MSK confirmé seulement par le simulateur | Reporté : à valider contre un vrai FortiGate/strongSwan |

## Passe 7.1 — mode proxy ([rapport](docs/security/review-7.1-netproxy.md))

| Réf. | Sévérité | Résumé | Statut |
|---|---|---|---|
| E1 | Élevé | Port d'écoute sans `SO_EXCLUSIVEADDRUSE` : vol de port par un autre processus local (identifiants RDP/SSH) | Corrigé (bind exclusif + message) |
| M1 | Moyen | SOCKS5 sans authentification : tout processus local peut utiliser le tunnel | Corrigé (vérification du propriétaire de la connexion, option `owner_check`) |
| M2 | Moyen | Épuisement des 256 connexions (clients muets, pas de délai d'inactivité) | Corrigé (limites + délai d'inactivité) |
| F1 | Faible | `allow_non_loopback` sans avertissement | Reporté |
| F2 | Faible | Noms d'hôtes cibles journalisés en debug | Reporté |
| F3 | Faible | `ProxyCleanup::stop` sans contrôle de génération (déni de service à la reconnexion) | Reporté |

Les décisions de report sont détaillées dans [`docs/securite-versions-futures.md`](docs/securite-versions-futures.md).
