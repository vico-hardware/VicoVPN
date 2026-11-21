# Modèle de confiance VicoVPN

## Acteurs

- **Client** : le PC protégé. Détient une identité (certificat auto-signé
  ECDSA P-256) et la liste des relais enrôlés avec leurs épingles.
- **Entrée** (optionnel) : relais qui transmet le canal interne chiffré.
  Voit l'IP publique du client et le volume/horaires du trafic.
- **Sortie** : relais qui termine la QUIC interne, applique la politique
  réseau et émet vers Internet. Voit l'IP de l'entrée (ou du client en mode
  direct laboratoire), jamais l'IP du domicile en mode deux relais.

## Ce qui est garanti par conception

- Le contenu applicatif est chiffré TLS 1.3 de bout en bout client↔sortie ;
  l'entrée ne voit que des paquets QUIC internes opaques.
- La destination et la sortie ne reçoivent pas l'IP publique du client en
  mode deux relais (sous réserve que la QUIC interne soit bien terminée
  chez la sortie — c'est le cas : le certificat de sortie est épinglé).
- Aucun certificat racine installé, aucune interception TLS.
- Le coupe-circuit est installé **avant** la première tentative de
  connexion ; toute connexion Internet non tunnel doit passer par le
  TUN ou être bloquée par les règles `VicoVPN-KS-*`.

## Ce qui n'est PAS garanti

- **Corrélation de trafic** : un observateur sur le trajet client↔entrée
  peut corréler volumes et horaires avec le trafic observé côté sortie si
  les deux points sont surveillés.
- **Collusion entrée+sortie** : ensemble, ils peuvent corréler.
- **Comptes personnels** : une connexion à un service authentifié révèle
  l'identité choisie par l'utilisateur.
- **DNS** : en V1, les requêtes DNS partent dans le tunnel vers des
  résolveurs publics configurés sur l'interface TUN. Leurs contenus sont
  chiffrés jusqu'à la sortie mais **visibles en clair par la sortie**
  (comme tout VPN sans DNS chiffré type DoH). Le blocage du DNS vers les
  serveurs LAN du réseau physique est assuré par le routage (tout passe
  par le TUN) — voir LIMITES.md.
- **Empreinte temporelle/passive** : les sessions QUIC ont des tailles et
  rythmes propres.

## Identités et enrôlement

- Chaque pair possède un certificat auto-signé ; l'authentification est
  **par épinglage d'empreinte SHA-256**, pas par chaîne de certificats.
- L'enrôlement consiste à copier le fichier `relays.json` (côté client) ou
  `clients.txt` (côté relais) par un **canal indépendant** (présentiel,
  SSH vérifié, etc.). Une compromission de ce canal compromet l'enrôlement.
- Révocation : retirer l'empreinte du fichier de l'autre côté + rotation
  de la paire de clés. Pas de CRL en V1.

## Secrets

- Clés privées stockées en clair dans `relays.json` / `relay.key` ; la
  protection repose sur les ACL NTFS (%ProgramData%\VicoVPN : SYSTEM +
  Administrateurs). **DPAPI est prévu en V2** (voir LIMITES.md).
- Journalisation : erreurs, versions, états uniquement — jamais de
  destinations, contenus ni historique de navigation.
