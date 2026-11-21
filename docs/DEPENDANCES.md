# Dépendances et licences

Versions figées dans `go.mod` (Go 1.27.4). Le projet VicoVPN lui-même est publié sous **GPL-3.0-only** (voir `LICENSE` et `NOTICE`).

| Dépendance | Version | Licence | Usage |
|---|---|---|---|
| `github.com/quic-go/quic-go` | v0.65.0 | MIT | Transport QUIC/TLS 1.3 (client, relais, tests) |
| `golang.zx2c4.com/wintun` | pseudo-version 20230126 | MIT | Adaptateur TUN Windows |
| `golang.org/x/sys` | v0.47.0 | BSD-3-Clause | ioctl TUN Linux, primitives Windows |
| `golang.org/x/crypto`, `x/net` | indirects de quic-go | BSD-3-Clause | pile TLS interne de quic-go |
| `wintun.dll` (binaire précompilé) | wintun 0.14.1 | Licence propriétaire WireGuard LLC « Prebuilt Binaries » : usage libre, pas de modification, notices conservées | Pilote réseau signé installé à côté de `vicovpn-client.exe` |
| `github.com/jchv/go-webview2` | v0.0.0-20260205 | MIT (BSD-3-Clause) | Interface graphique Windows (`vicovpn-ui`, WebView2) |
| `github.com/jchv/go-winloader` | v0.0.0-20250406 | MIT | Chargement de WebView2Loader.dll |
| `github.com/akavel/rsrc` | v0.10.2 | MIT (outil de build, hors binaire) | Ressource manifeste embarquée dans `vicovpn-ui.exe` (DPI awareness) |

Runtime requis par `vicovpn-ui` : **WebView2 Runtime** (préinstallé sur
Windows 11). L'interface réutilise le visuel « masque et lumière verte »
de VicoMedia (wallpaper embarqué, palette sombre, glow vert).

## Remarques

- **wintun.dll** : téléchargé depuis `https://www.wintun.net/builds/wintun-0.14.1.zip`
  (site officiel référencé dans le cahier des charges). Le pilote est
  **signé** ; aucune signature propre n'est nécessaire.
- **Bindings wintun (MIT)** : compatibles avec la licence GPL-3.0 du projet.
  Le DLL précompilé garde sa propre licence (redistribution autorisée sans
  modification) ; il n'est pas versionné dans le dépôt, la CI le télécharge.
- **Aucun client/moteur VPN préexistant** n'est utilisé : le protocole
  applicatif, le tunnel IP, la politique et le routage sont écrits ici.
- quic-go est la bibliothèque de transport QUIC maintenue retenue par le
  cahier des charges (« bibliothèque maintenue »).
