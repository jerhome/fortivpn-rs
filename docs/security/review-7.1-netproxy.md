# Revue sécurité 7.1 - crates/netproxy (lecture seule, sans compilation)

Fichiers : netproxy/src/{backend,config,socks,stack,lib}.rs ; cli/src/config.rs (`[proxy]`, validate_proxy l.457).

## Eleve
E1. backend.rs:91 - `std::net::TcpListener::bind` sans SO_EXCLUSIVEADDRUSE (Windows).
Scenario : un processus local (même session ou autre utilisateur / session RDP) lie 127.0.0.1:1080
(ou le port d'une redirection RDP/SSH) avec SO_REUSEADDR après nous : sous Windows il capte les nouvelles connexions
(vol de port). Un client RDP/SSH de l'utilisateur envoie alors ses identifiants (NLA, mot de passe SSH) à un faux serveur.
Correctif : créer la socket via socket2/windows-sys, setsockopt(SO_EXCLUSIVEADDRUSE) avant bind (cfg(windows)) ;
sous Linux ne pas poser SO_REUSEADDR. Ajouter un test de bind en double.

## Moyen
M1. socks.rs:3,68-86 / backend.rs:289 - SOCKS5 sans authentification, aucune vérification du pair (`peer`).
Scenario : tout processus local, tout autre utilisateur ou session RDP du même poste (loopback partagé), un malware
non privilégié, ou (WSL2 en mode mirrored, ou page web via DNS rebinding/requêtes HTTP vers localhost) accède
au réseau d'entreprise via le tunnel de l'utilisateur, scanne les IP internes et résout des noms internes via le DNS du tunnel.
Correctif : authentification RFC 1929 avec identifiant/secret aléatoire généré au démarrage (affiché/écrit dans un
fichier ACL utilisateur) ou, a minima, vérifier le SID/PID du pair (GetExtendedTcpTable) et refuser un autre utilisateur ;
documenter le risque pour les redirections (sans auth par nature). Rejeter une requête HTTP (octet 'G','P'... != 5) : déjà fait (Version).
M2. backend.rs:289-298, 302-330 ; config.rs:159 - épuisement des 256 slots (sémaphore partagé SOCKS+redirections).
Scenario : un client local ouvre 256 connexions et reste muet (10 s de handshake, répétable) ou se connecte à une cible
puis ne lit/n'écrit plus : aucun délai d'inactivité sur `bridge` (keep-alive smoltcp maintient la connexion), donc les slots
restent occupés indéfiniment et l'utilisateur légitime est refusé. Un slot reste de plus pris même par un hôte qui n'envoie rien.
Correctif : sémaphore par écouteur (ou par pair IP), timeout d'inactivité dans `bridge`, plafond de connexions en cours de
handshake plus bas.

## Faible
F1. config.rs:246 / cli config.rs:482 - `allow_non_loopback` accepte aussi les redirections ; aucun avertissement au démarrage.
Scenario : option activée "pour tester", SOCKS ouvert sans authentification sur le LAN/Wi-Fi => passerelle vers le réseau
d'entreprise. Correctif : tracing::warn! explicite, refuser SOCKS non loopback sans authentification (M1).
F2. backend.rs:344,354 ; stack.rs:379,390,418,432,477 - noms d'hôtes/IP cibles journalisés au niveau debug (`%target`, `%name`),
et `%peer` en warn (backend.rs:290, loopback seulement). Scenario : un journal de debug partagé pour support expose
les noms de serveurs internes (reconnaissance). Niveau info ne contient que socks/forwards (OK). Correctif : trace! ou masquage,
ne pas conserver en fichier par défaut.
F3. backend.rs:256-261 - `ProxyCleanup::stop` met `current = None` sans vérifier que la pile enregistrée est celle du guard.
Scenario : si un cleanup tardif de l'ancien guard survient après le `apply` de la nouvelle session, il neutralise la nouvelle
pile (déni de service, pas de fuite). Correctif : comparer l'identité (Arc/id de génération) avant d'effacer.

## Info / points vérifiés conformes
- Loopback imposé par défaut (config.rs:246 ; `::ffff:127.0.0.1` et 0.0.0.0 rejetés) ; défaut 127.0.0.1:1080 ; doublons refusés.
- DNS : uniquement les serveurs DNS du tunnel (stack.rs:292-302), aucun repli sur le DNS système ; sans DNS -> NoDns, pas de fuite.
  Noms bornés (253/63, jeu de caractères restreint), IPv6 refusé. Une requête DNS interne est tout de même possible pour
  tout nom (voir M1).
- SOCKS parsing : allocations <= 255 octets, lectures exactes, timeout 10 s sur l'ensemble de la négociation, pas de panic
  (read_exact/erreurs), BIND/UDP refusés. Pas de timeout sur l'écriture vers un client qui ne lit pas (voir M2).
- Pile smoltcp : files rx (RX_BATCH 64) et tx (256) bornées, tampons 64 Ko x 2 x 256 conn. (~32 Mo max) + 4x16 Ko par sens ;
  ports éphémères alloués avec recherche bornée ; résolutions bornées par max_connections ; délais calculés (pas d'attente active).
  Entrée provenant du seul tunnel (pair authentifié par TLS) : surface de DoS réseau faible.
- Reconnexion : à la coupure `current = None`, tâche pile abortée, connexions coupées (RST/EOF), nouvelles demandes refusées
  avec 0x03 ; écoutes conservées. Rien ne sort hors tunnel (pas de route/socket système vers la cible).
- Cibles de redirection : validées au chargement (IPv4/nom, port non nul) ; pas d'IP de loopback/lien-local filtrée côté
  tunnel (les paquets partent vers la passerelle, sans effet local) : pas de constat.
