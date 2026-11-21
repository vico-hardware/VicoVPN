# Protection maison (onglet 2 · Maison)

Ce PC devient la passerelle des autres appareils de la maison (téléphone,
TV, console, objets connectés). Leur trafic passe par le tunnel Tor du PC,
dans le pays choisi, et leurs noms de domaine sont résolus à travers Tor.

## Fonctionnement

| Élément | Rôle |
|---|---|
| DNS maison | Le PC écoute le port 53 (UDP + TCP) sur son IP de la box et relaie vers le DNSPort de Tor (127.0.0.1:53). Seules les adresses privées sont servies (pas de résolveur ouvert). |
| Pare-feu | Règles entrantes `VicoVPN-GW-DNS-UDP/TCP` : port 53, sous-réseau local seulement, programme `vicovpn-client.exe` seulement. Retirées à la désactivation, au redémarrage du service et par `vicovpn-recover`. |
| Routage | Forwarding IPv4 activé sur la carte réseau ET sur `vicotor0`, en magasin **actif** (ne survit jamais à un redémarrage). |
| Coupe-circuit maison | Le forwarding n'est actif **que** si le tunnel est sain : état « protégé », `tor.exe` et `tun2socks.exe` vivants, adaptateur `vicotor0` présent, routes `0.0.0.0/1` + `128.0.0.0/1` vérifiées. Vérification toutes les 500 ms et réveil immédiat à la mort d'un processus. Toute commande qui relance le tunnel (Désactiver, Réessayer, changement de pays) coupe le forwarding **avant**. Pendant l'amorçage de Tor, les appareils n'ont pas Internet : rien ne sort en clair. |
| Changement d'IP du PC | Détecté toutes les 10 s : le DNS est ré-ouvert sur la nouvelle adresse, affichée dans l'onglet et le journal. |

## Appareils connectés

L'onglet liste chaque appareil (et « Ce PC ») avec son nom, son IP, son
adresse MAC, le volume reçu (↓) et envoyé (↑) depuis l'activation et le
nombre de connexions ouvertes.

- **Volume** : API statistiques locale de `tun2socks` (`--restapi` sur
  127.0.0.1, jeton aléatoire), relevée toutes les 2 s, plus le DNS relayé.
- **Nom**, dans l'ordre : nom donné avec « Renommer » (mémorisé par adresse
  MAC dans `appareils.json`), nom connu de la box (DNS inverse), nom
  NetBIOS (PC Windows, NAS), nom mDNS (iPhone, Mac, beaucoup d'Android).
  Sinon « Appareil inconnu » : il suffit de le renommer.
- Les téléphones récents utilisent une adresse MAC aléatoire par réseau
  Wi-Fi : le nom personnalisé reste valable tant que l'appareil garde la
  même adresse pour ce réseau.

Commandes ctl : `MAISON` (état), `MAISONON [tor-xx]`, `MAISONOFF`,
`MAISONINFO` (réglages prévus sans rien activer), `APPAREILS`,
`NOMMER <ip> [nom]`.

## Réglage d'un appareil

Sur l'appareil : paramètres Wi-Fi (ou Ethernet) → IP **manuelle /
statique** :

- **Adresse IP** : une adresse libre du réseau, différente pour chaque
  appareil (l'onglet propose `x.x.x.200` à `.250`, hors de la plage DHCP
  habituelle des box) ;
- **Masque** : celui affiché (souvent `255.255.255.0`, ou longueur de
  préfixe `24`) ;
- **Passerelle / routeur** : l'IP du PC affichée ;
- **DNS** : l'IP du PC affichée (DNS 1 et DNS 2 identiques).

Pour revenir à la normale : repasser l'appareil en IP automatique (DHCP).

## Limites

- **Sorties Tor uniquement** : un relais classique n'a qu'une IP tunnel par
  client et le PC ne fait pas de NAT ; `GWENABLE` refuse une sortie non Tor.
- **TCP seulement** : Tor ne transporte pas l'UDP (jeux en ligne, appels,
  QUIC). Le DNS est l'exception (relayé par le PC). Un appareil qui impose
  son propre DNS en UDP (ex. 8.8.8.8 codé en dur) n'aura pas de résolution :
  le DNS chiffré en TCP (DoT/DoH, « DNS privé » Android) fonctionne.
- **IPv6** : les appareils reçoivent l'IPv6 directement de la box et
  peuvent l'utiliser sans passer par le PC. **Désactiver l'IPv6 dans la box**
  (ou sur l'appareil) pour une protection complète.
- **Le PC doit rester allumé** ; un appareil réglé sur lui n'a plus
  Internet si le PC est éteint ou si la passerelle est désactivée. La
  passerelle ne redémarre pas seule après un redémarrage du PC.
- **IP du PC** : la fixer dans la box (réservation DHCP), sinon les
  appareils pointent vers une ancienne adresse après un changement de bail.
- **Fenêtre de coupure** : si `tun2socks` meurt brutalement, le forwarding
  est coupé en moins d'une seconde (réveil immédiat + netsh). Pendant ce
  bref instant, une connexion déjà ouverte d'un appareil pourrait repartir
  par la box. Supprimer cette fenêtre exige un filtre WFP sur la couche
  « forward » (V2).
- `ping` n'est pas un bon test (Tor ne transporte pas l'ICMP) : tester
  avec un navigateur.

## Mode Freebox (réglage automatique)

Avec une Freebox associée (onglet Maison → « Associer la Freebox », validation
sur l'écran de la box, puis droit « Modification des réglages de la Freebox »
coché dans Freebox OS → Paramètres → Gestion des accès → Applications) :

1. À l'activation : réglages de la box sauvegardés dans
   `freebox-sauvegarde.json` (IPv6, DHCP, baux), bail du PC renouvelé, puis
   **IPv6 et DHCP de la box coupés** via l'API Freebox OS.
2. Le **serveur DHCP de ce PC** (port 67) distribue à chaque appareil son
   adresse habituelle (baux de la box relus), avec ce PC comme passerelle et
   DNS, bail de 4 minutes. Un appareil bascule dès qu'il se reconnecte.
   Les appareils encore branchés directement sur la box sont listés « Pas
   encore protégés ».
3. À la désactivation : IPv6 et DHCP de la box remis comme avant ; pendant
   6 minutes, le DHCP du PC répond NAK aux renouvellements pour renvoyer les
   appareils vers la box (coupure ≤ 2 min par appareil).
4. Plantage / redémarrage : la sauvegarde est rejouée au démarrage du
   service ; `vicovpn-recover` la rejoue aussi ; bouton « Restaurer la box ».

Points à surveiller : appareils Free (Freebox Player) qui passent aussi par
ce PC pendant la protection ; PC en veille = plus de réseau pour les autres.

## Autres box (Livebox, Bbox, SFR / RED, autres) — mode guidé

Pas d'API officielle fiable pour piloter ces box : l'utilisateur coupe le
DHCP et l'IPv6 dans l'interface de sa box (guide intégré, marque détectée
automatiquement), puis clique « J'ai coupé le DHCP de ma box »
(`BOXGUIDE on`, mémorisé dans `box-guidee.json`).

- Pendant la protection : le DHCP de ce PC distribue PC = passerelle + DNS.
- Hors protection : le DHCP de ce PC continue en mode « normal » (box =
  passerelle + DNS), y compris après redémarrage du PC, pour que la maison
  garde le réseau.
- Si un appareil accepte une offre de la box (son DHCP répond de nouveau),
  le PC s'efface tout seul ; pendant la protection, un avertissement
  « le DHCP de la box répond encore » s'affiche.

Guide de premier démarrage : 7 étapes avec schémas animés, rouvrable avec
le bouton « ? » (préférence dans `%APPDATA%\VicoVPN\interface.json`).
