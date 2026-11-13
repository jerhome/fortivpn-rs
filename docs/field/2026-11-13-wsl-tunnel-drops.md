# Test terrain WSL — 2026-11-13 ~20h45 (passerelle réelle, anonymisée)

- Connexion OK : 207–634 ms ; split-tunnel (2 routes, 0 exclusion, 2 DNS, 1 domaine de recherche).
- Session 1 : ~40 s après IPCP up → `Io(ConnectionReset)` (RST TCP de la passerelle) ; reconnexion : cookie refusé → ré-auth OK.
- Session 2 : ~150 s après → `DeadPeer` (nos LCP Echo-Request sans réponse) ; reconnexion : cookie refusé → ré-auth OK.
- WARN récurrent : `route déjà présente : laissée en place dest=<IP passerelle>/32` (EEXIST au démarrage, aussi lors du 1er test).
- DNS : stratégie Ignore côté CLI Linux → noms internes non résolus (attendu).
Hypothèse : réponses aux Echo-Request de la passerelle (ou nos Echo-Request) non conformes → la passerelle juge le pair mort (~10 s × 3-4 ≈ 40 s) et termine la session.
