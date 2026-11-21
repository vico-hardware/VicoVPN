# Signature du code — SignPath Foundation (gratuit)

Objectif : que Windows SmartScreen et les antivirus ne bloquent plus
l'installateur (« Éditeur inconnu »). La SignPath Foundation signe
gratuitement les projets open source ; le certificat est au nom de
« SignPath Foundation », et la signature n'est faite que sur des binaires
compilés par la CI publique de ce dépôt.

## 1. Candidature (à faire une fois)

Formulaire : <https://signpath.org/apply>

Réponses prêtes à copier :

| Champ | Réponse |
|---|---|
| Project name | VicoVPN |
| Repository URL | https://github.com/vico-hardware/VicoVPN |
| Homepage | https://hardware24.fr/logiciels.html |
| License | GPL-3.0-only |
| Maintainer | vico-hardware |
| Build system | GitHub Actions (`.github/workflows/build.yml`) |
| Artifacts to sign | `VicoVPN-Setup-<version>.exe` (installateur Inno Setup) |

Description (anglais, à coller) :

> VicoVPN is a free and open-source Windows 10/11 privacy tool. One button
> routes all of the PC's traffic through the Tor network (tun2socks + wintun),
> with a firewall kill switch, Tor-resolved DNS, an optional ad-blocking DNS
> preset, and a "home protection" mode that lets other devices of the local
> network use the same protection. It ships no telemetry and contacts no
> server unless the user turns protection on. Releases are built
> reproducibly by GitHub Actions from the public source; the signed artifact
> is the Inno Setup installer.

## 2. Après acceptation

SignPath crée l'organisation et le projet. Dans le tableau de bord SignPath :

1. Projet **VicoVPN** (slug `VicoVPN`), connecteur **GitHub** relié à ce dépôt.
2. Configuration d'artefact, slug **`installer`** :
   ```xml
   <artifact-configuration xmlns="http://signpath.io/artifact-configuration/v1">
     <zip-file>
       <pe-file path="VicoVPN-Setup-*.exe">
         <authenticode-sign/>
       </pe-file>
     </zip-file>
   </artifact-configuration>
   ```
3. Politique de signature, slug **`release-signing`** (approbation manuelle).
4. Crée un jeton d'API (utilisateur CI).

Puis dans GitHub → *Settings → Secrets and variables → Actions* :

- variable `SIGNPATH_ORGANIZATION_ID` = l'ID d'organisation SignPath ;
- secret `SIGNPATH_API_TOKEN` = le jeton d'API.

## 3. Publier une version signée

```bat
git tag v1.1.5
git push origin v1.1.5
```

La CI compile, envoie l'installateur à SignPath, attend ton approbation
(clic dans SignPath), puis crée la release GitHub avec l'installateur
signé. Tant que les deux réglages ci-dessus ne sont pas faits, la release
est quand même créée, avec l'installateur non signé.
