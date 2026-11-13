# Publier une version

Tout se fait dans WSL2 (Linux) ; rien n'est exécuté sous Windows (le `.exe` est seulement cross-compilé).

```
scripts/package.sh <version>              # ex. 0.1.0 : construit les archives, sans publier
scripts/package.sh <version> --release    # + tag annoté v<version> et pré-release GitHub
```

Options : `--skip-check` (saute `scripts/check.sh`, déconseillé).

Étapes du script :

1. `scripts/check.sh` (fmt, clippy Linux, tests, clippy cross Windows).
2. `cargo build --release --locked` de `cli` et `gui` pour `x86_64-unknown-linux-gnu` et `x86_64-pc-windows-gnu`.
3. Production dans `dist/<version>/` (ignoré par git) :
   - `fortivpn-<v>-windows-x86_64.zip` : `fortivpn.exe`, `fortivpn-gui.exe`, `README.md`, `LICENSE`, `THIRD-PARTY-LICENSES.md`, `docs/guide-utilisateur.md`, `config.example.toml`, `LISEZMOI-wintun.txt` ;
   - `fortivpn-<v>-linux-x86_64.tar.gz` : idem avec `fortivpn` et `fortivpn-gui` (sans le LISEZMOI wintun) ;
   - `SHA256SUMS`.
4. Avec `--release` uniquement : refus si `gh` manque, si le tag existe ou si l'arbre git n'est pas propre ; puis `git tag -a v<version>`, `git push origin v<version>` et `gh release create --prerelease` avec les trois fichiers. Les notes viennent de `docs/release-notes/<version>.md` s'il existe (sinon une ligne par défaut), suivies des empreintes SHA-256.

Prérequis : cible `x86_64-pc-windows-gnu` (`rustup target add`), mingw-w64, `zip`, `gh` authentifié (pour `--release`).

Notes :

- `wintun.dll` n'est pas redistribuée : l'archive contient `LISEZMOI-wintun.txt` (téléchargement officiel de wintun 0.14.1, nécessaire au seul mode service).
- Les versions sont des pré-releases : le mode service Windows n'a pas encore été testé en réel.
- Vérification par l'utilisateur : `sha256sum -c SHA256SUMS`.
