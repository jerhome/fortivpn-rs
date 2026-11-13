# Revue sécurité 6.5 — crypto IPsec (crates/ipsec, hors transport.rs)

Périmètre : wire.rs, crypto.rs, sk.rs, mschapv2.rs, ike.rs, ike/established.rs, esp.rs. Lecture seule.
`cargo audit`/`cargo deny` non installés : aucune vérification RustSec effectuée (à faire en CI).

## Verdict
Aucun Critique/Élevé. Points conformes : prf+ (RFC 7296 §2.13, plafond 255 blocs), SKEYSEED initial
prf(Ni|Nr, g^ir) et rekey prf(SK_d, g^ir|Ni|Nr), KEYMAT (avec g^ir si PFS), AUTH (PSK/MSK, msg1/msg2 +
nonce du pair + prf(SK_p, IDx')), AUTH du répondeur vérifiée en temps constant AVANT l'envoi de
l'identité EAP (ike.rs:~960-985), S= MS-CHAPv2 vérifié avant d'acquitter (ike.rs:~1040), ICV IKE-CBC
vérifié (ct_eq) avant déchiffrement, GCM (tag avant sortie), ESP : ICV avant déchiffrement, fenêtre
anti-rejeu mise à jour seulement après ICV, padding vérifié après authentification (pas d'oracle),
IV GCM = séquence (jamais réutilisé, clés neuves à chaque rekey), compteur IV IKE-GCM global (non remis
à zéro au rekey IKE), aléa = ring SystemRandom (transport.rs:241/306), nonces 32 o, SPI non nuls,
DH ECP validé (point sur la courbe, scalaire non nul), MODP rejette 0/1/p-1/>=p/taille != 256.
Parsing : toutes les longueurs bornées (MAX_PAYLOADS 32, proposals 16, transforms 64, CP 256, TS 64,
nonce 16..256, message <= 65535), pas d'index non borné, pas de XML.

## Constats

### Moyen
M1. Authentification serveur par PSK de groupe + MS-CHAPv2 : détenteur du PSK = passerelle factice
 (ike.rs:~955-985 puis on_eap_challenge ~1000). Scénario : un utilisateur (ou ex-employé) connaissant le
 PSK de groupe, en position réseau (Wi-Fi hostile), répond à l'IKE_SA_INIT, passe l'AUTH PSK, reçoit
 l'identité EAP puis la NT-Response (MS-CHAPv2 ne permet pas de vérifier le serveur avant d'avoir
 répondu) : DES 3x56 bits => hash NT récupéré en quelques heures/minutes (crack.sh), équivalent d'un
 mot de passe (pass-the-hash MSCHAP). Correctif : documenter le risque ; proposer l'auth du répondeur par
 certificat (AUTH RSA/ECDSA + épinglage) ; en attendant, exiger `expected_idr` non vide et un PSK
 par passerelle (refuser PSK vide / court dans IkeConfig, ike.rs:~85 ; aucun contrôle aujourd'hui).

### Faible
F1. IKE_SA_INIT : réponses non authentifiées traitées comme fatales (ike.rs:~822-850, 880-895) :
 NO_PROPOSAL_CHOSEN / notify d'erreur / KE invalide / SA invalide => `fail()`. Scénario : attaquant
 sur le chemin (voyant SPIi) tue la connexion immédiatement au lieu d'attendre ; INVALID_KE_PAYLOAD/
 COOKIE forcent jusqu'à 4 relances (MAX_INIT_RESTARTS) ; cookie non borné (RFC : <= 64 o) => message
 > 65535 => échec d'encodage. Correctif : ignorer les erreurs non authentifiées jusqu'au timeout
 (RFC 7296 §2.21.1), borner cookie à 64 o. Pas de downgrade possible : AUTH couvre msg1/msg2.
F2. Rekey CHILD sans PFS accepté (established.rs: child_rekey_done ~l.585 `ch.dh` None ; select_esp/
 dh_ok ~l.915 côté requête du pair) alors que nous proposons toujours un groupe DH. Scénario :
 passerelle (authentifiée) ou bug serveur => KEYMAT sans g^ir ; perte de la propriété PFS demandée.
 Correctif : exiger ch.dh == Some(groupe offert) à la réponse ; refuser (NO_PROPOSAL_CHOSEN) les rekeys
 du pair sans KE.
F3. Secrets non effacés : exposant DH en BigUint (crypto.rs:~340 `x`, ~373 `x`, modpow) ; plaintext
 déchiffré `pt` des SK (sk.rs:~118, contient EAP/CP) ; start_key()/MSK temporaires [u8;16]
 (mschapv2.rs:~140) ; clé AES reconstruite à chaque paquet ESP (esp.rs gcm()/cbc(), aussi un coût CPU).
 Scénario : crash dump / swap de la machine. Correctif : Zeroizing sur ces tampons, objet chiffreur
 mis en cache dans Suite (feature `zeroize` de aes/aes-gcm).
F4. num-bigint non constant-time pour MODP-2048 (crypto.rs:~340-375). Risque réel côté client : faible.
 Exposants éphémères (neufs à chaque échange, 256 bits), y^x calculé une seule fois par clé ; attaque
 par canal auxiliaire demande plusieurs traces d'un même exposant ou un co-résident local (cache) ;
 un MITM distant ne voit que la latence réseau, bruitée. Non exploitable en pratique, mais défense en
 profondeur : préférer ECP-256 en premier (inverser dh_groups par défaut, ike.rs:~125 : MODP2048 est
 en tête) ou crypto-bigint/ring pour MODP. 
F5. Pas de test d'appartenance au sous-groupe d'ordre q pour MODP14 (crypto.rs:~364 : seulement
 2 <= y <= p-2). Un y non résidu quadratique (ordre 2q) révèle 1 bit (parité de x) : sans conséquence sur
 la clé de session ; correctif optionnel y^q mod p == 1 (coût d'une exponentiation).
F6. Retransmission de réponse en cache sans authentifier la requête (established.rs:~822-835) : un
 attaquant connaissant SPIs (en clair) et le dernier Message ID force le renvoi de la dernière réponse
 (destination fixe passerelle, pas de réflexion, facteur ~1-10). Impact négligeable.
F7. Contenu du CP/TS de la passerelle non validé (ike.rs on_final ~1180 ; established.rs:~970 TS du pair
 recopiés) : IP interne, DNS, sous-réseaux arbitraires (ex. 0.0.0.0/0 sous-réseau, DNS public) ;
 domaines DNS non filtrés dans wire.rs:205 (sans contrôle de taille/charset). Passerelle authentifiée
 donc en dehors du modèle de menace, et netlinux/dns.rs + netwin/plan.rs revalident les domaines
 (pas d'injection resolv.conf/netsh constatée). Correctif : valider aussi ici (IP unicast, masque
 cohérent, <= 8 domaines) pour limiter la portée d'une passerelle compromise.
F8. ESP : pas de validation du paquet IPv4 interne (version, longueur totale, source/dest vs IP
 attribuée/TSr) dans esp.rs open() ; à faire dans le transport avant écriture TUN (hors périmètre ici).
 Seuil de rekey sur next_seq() : s'assurer côté transport qu'il est bien < 2^32 (ESN non négocié : seule
 la transform ESN=0 est proposée, le code ESN/annexe A2 est donc inactif et a un cas th=0 saturant,
 sans effet tant que l'ICV est exigé).

### Info
I1. MSK EAP-MSCHAPv2 = Recv|Send|32x0 (mschapv2.rs:~150) : l'ordre (MAGIC2 puis MAGIC3) n'est confirmé
 que par le mock ; à valider contre un vecteur strongSwan/FortiGate (une inversion ferait échouer l'AUTH
 final, non exploitable, mais bloquant en interop).
I2. IDr non imposé par défaut (expected_idr None) : acceptable, l'AUTH lie l'IDr au PSK.
I3. Collisions de rekey : TEMPORARY_FAILURE pour IKE, plus petit nonce pour CHILD (RFC 7296 §2.8.1)
 correct ; une seule requête en vol, Message ID strict (pas de fenêtre) : pas de DoS mémoire. Les DH
 coûteux ne sont faits qu'après authentification SK (sauf la réponse INIT usurpée, cf. F1).
I4. Tests négatifs à ajouter : KE MODP y=p-1/0/1, nonce < 16 o, AUTH correct mais EAP avant AUTH, tag GCM
 altéré, ESP replay/hors fenêtre/ICV faux (déjà partiellement dans esp_tests.rs).
