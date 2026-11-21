# VicoVPN

VPN système Windows 11 x64 développé de zéro (client + service réseau +
protocole + relais), au sens du cahier des charges : un seul bouton protège
toutes les connexions Internet du PC, y compris les applications qui
ignorent le proxy Windows.

## Architecture

```
PC client ──QUIC/TLS1.3──> entrée (optionnel) ──> sortie ──> Internet
   TUN wintun        QUIC interne chiffrée de bout en bout
```

- `cmd/client` : moteur client (TUN wintun, coupe-circuit WFP via
  Windows Firewall, routes, DNS) + canal de commande `ctl` +
  **service Windows** (`-service install|uninstall|console|svc`).
- `cmd/ui` : interface graphique (`vicovpn-ui.exe`) fonctionnant sous
  compte standard via le canal ctl — Activer / Désactiver / Réessayer,
  sélection de sortie, états protégé/connexion/bloqué/désactivé.
- `cmd/relay` : logiciel relais (`exit` / `entry`), Linux et Windows ;
  `tun_ip6` active le transport IPv6 (NAT66 sur Linux).
- `cmd/ctl` : commandes `ACTIVER / DESACTIVER / REESSAYER / STATUS /
  RELAY / SELECT`.
- `cmd/recover` : récupération hors ligne (retire uniquement les objets
  `VicoVPN-*`).
- `internal/proto` : protocole applicatif v1 (voir docs/PROTOCOLE.md).
- `internal/engine` : sessions QUIC, pompes TUN↔réseau, politique de
  relais, limitation de débit.
- `internal/netcfg` : pare-feu Windows (règles WFP), routes, IP/DNS TUN ;
  NAT/forwarding relais Linux.
- `internal/tun` : wintun (Windows) / /dev/net/tun (Linux).
- **Mode Tor** : le client peut aussi sortir par Tor — pseudo-relais
  `tor-<pays>` (12 pays : nl, de, us, gb, fr, jp, ca, ch, se, br, au,
  es) sélectionnables dans l'UI comme n'importe quelle sortie. Tor +
  tun2socks capturent tout le trafic IP du PC ; le DNS est résolu à
  travers Tor (DNSPort). Voir `bin/tor/` (tor.exe + tun2socks.exe +
  wintun.dll + geoip). Limites : TCP seulement (pas d'UDP), lent.

## Démarrage rapide

```powershell
cd bin
# 1. Identité et configuration (relays.json, voir testdata\)
.\vicovpn-client.exe -gen-identity
# 2. Service Windows (compte SYSTEM, démarrage automatique)
.\vicovpn-client.exe -service install          # admin
# 3. Interface graphique (compte standard)
.\vicovpn-ui.exe
# Désinstallation : .\vicovpn-client.exe -service uninstall
```

Voir `scripts/README.md` (enrôlement, configuration, récupération) et
`docs/` (protocole, modèle de confiance, limites, recette).

## État de la recette

Voir `docs/RECETTE.md` : les tests unitaires et de session QUIC passent ;
les jalons exigeant une VM, des droits admin ou un relais étranger sont
marqués **non exécutés** avec la procédure pour les réaliser.

## Compiler

Prérequis : Windows 10/11 x64, Go (version de `go.mod`), Inno Setup 6
pour l'installateur. Les binaires tiers (`tor.exe`, `tun2socks.exe`,
`wintun.dll`, `geoip`) ne sont pas versionnés : place-les dans `bin\`
comme décrit dans `docs/DEPENDANCES.md`, puis :

```bat
Compiler VicoVPN.bat
```

La CI GitHub Actions (`.github/workflows/build.yml`) fait tout
automatiquement : tests, compilation, téléchargement des dépendances
(versions et empreintes vérifiées) et installateur, publié comme
artefact à chaque push et joint aux releases `v*`.

## Licence et droits

Copyright (C) 2026 **vico-hardware** (Vico Studio). L'auteur reste
titulaire de tous les droits d'auteur sur VicoVPN.

- **Code source** : licence **GNU GPL v3.0 uniquement** (voir [`LICENSE`](LICENSE)).
  Tu peux l'utiliser, l'étudier, le modifier et le redistribuer, à
  condition de conserver le copyright, de citer l'auteur et de publier
  tes modifications sous la même licence. Une redistribution fermée
  (propriétaire) est interdite sans accord écrit de l'auteur.
- **Marque et visuels** : les noms Vico / VicoVPN, le logo, l'icône, le
  fond d'écran, les visuels et les vidéos des encarts (`cmd/ui/assets/`)
  ne sont **pas** sous GPL et restent **tous droits réservés**. Un fork
  doit les remplacer et porter un autre nom.

Détails : [`NOTICE`](NOTICE) · Contributions : [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Politique de signature du code

Les versions publiées de l'installateur sont destinées à être signées
grâce à la signature de code gratuite fournie par
[SignPath.io](https://about.signpath.io), avec un certificat délivré par la
[SignPath Foundation](https://signpath.org).

- Auteurs et validateurs : [vico-hardware](https://github.com/vico-hardware)
  (seul mainteneur ; chaque release est approuvée manuellement).
- Seuls les binaires compilés par la CI de ce dépôt, à partir du code
  public, sont signés.

**Confidentialité** : VicoVPN ne transmet aucune information à des
systèmes tiers sans action de l'utilisateur. Le trafic passe par le
réseau Tor uniquement quand la protection est activée ; l'API de la
box (Freebox) n'est contactée que si l'utilisateur active la
« Protection maison ». Aucune télémétrie, aucune collecte de données.
