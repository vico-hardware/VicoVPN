# Recette VicoVPN — rapport d'essais

Légende : **OK** réussi · **KO** échoué · **NE** non exécuté
(dépend d'un relais étranger, d'une VM ou de droits non disponibles).

## Inventaire (Jalon 1)

| Élément | Résultat | Observation |
|---|---|---|
| Go 1.27.4 windows/amd64 | OK | installé via winget |
| Windows 11 Pro 10.0.26300 x64 | OK | PC de développement |
| Droits admin dans le shell agent | KO | `net session` → accès refusé : les essais TUN/pare-feu doivent être lancés dans un terminal élevé par l'utilisateur |
| VM locale | NE | aucune VM Hyper-V/VirtualBox détectée ; WSL = distro docker-desktop uniquement |
| wintun.dll 0.14.1 | OK | binaire officiel récupéré, placé dans `bin/` |
| Retour arrière sans Internet | OK (partiel) | `vicovpn-recover.exe` compile et cible uniquement les objets `VicoVPN-*` ; essai réel NE (nécessite admin) |

## Tests sur le PC de développement (2026-11-14, Windows 11, admin via sudo)

Laboratoire : relais `exit` (127.0.0.1:4443, TUN `vicovpn-exit` 10.99.0.1/24)
et `entry` (127.0.0.1:4444) sur le même hôte, client avec `-no-firewall`
(pas de coupe-circuit pendant les tests fonctionnels). wintun.dll 0.14.1.

| Essai | Attendu | Observation | Statut |
|---|---|---|---|
| Handshake client→entrée (QUIC externe) | session établie | `relay: session établie` côté entry, pays=DE | OK |
| QUIC interne client→sortie via entrée | session établie | exit voit la connexion depuis le port éphémère de l'entrée (aucun contact direct client↔sortie) | OK |
| État client | « protégé » stable | `STATUS` = protege, session stable >5 min, reconnect après coupure | OK |
| Ping ICMP 10.99.0.1 via route /32 forcée dans le TUN client | écho | 4/4 réponses | OK |
| TCP HTTP via tunnel (serveur bindé 10.99.0.1:8899) | page | HTTP 200 en ~37 ms | OK |
| UDP écho via tunnel (10.99.0.1:9999) | écho | datagramme reçu et réponse revenue | OK |
| IPv6 : négociation PolicyIPv6 |bit0 annoncé | `tun_ip6` sur la sortie → `ipv6` actif côté client | OK |
| IPv6 : ping ICMPv6 fd00:dead:beef::1 via TUN | écho | 3/4 (1ère perte = NDP en cours) ; NDP à travers le tunnel fonctionnel | OK |
| IPv6 : TCP HTTP [fd00:dead:beef::1]:8898 via TUN | page | HTTP 200, ~208 Ko reçus | OK |
| IPv6 : UDP écho [fd00:dead:beef::1]:9998 via TUN | écho | datagramme reçu et réponse revenue | OK |
| Révocation client | handshake refusé | `clients.txt` vidé + relais redémarré → `tls: bad certificate`, état `bloque` ; ré-enrôlement → `protege` | OK |
| Pare-feu relais Windows | trafic tunnel accepté | règles `VicoVPN-Relay-In-*` créées par RelayTunSetup (bug `-InterfaceIndex`/quoting corrigés) | OK |
| Service Windows | install/start/ctl | `vicovpn-client.exe -service install` → service SYSTEM auto-start, protection activée au démarrage, `STATUS` = protege via ctl | OK (en `-no-firewall` pour ne pas couper l'utilisateur) |
| Canal ctl standard-user | lecture jeton/addr | ACL `BUILTIN\Users:R` posée sur ctl.addr/ctl.token ; `RELAY`/`SELECT` répondent | OK |
| GUI vicovpn-ui (WebView2) | fenêtre + commandes | style VicoMedia (wallpaper embarqué) ; processus stable, pont `vicocmd` → ctl | OK partiel (rendu visuel non vérifié automatiquement) |
| Installateur | scripts | `install-client.ps1` / `uninstall-client.ps1` livrés, non exécutés sur machine propre | NE |
| Compteurs de paquets (VICOVPN_DEBUG) | flux bidirectionnel | SendPacket/ReceiveLoop actifs des deux côtés | OK |
| Auth négative (tests unitaires) | refus | mauvais épinglage et client non enrôlé refusés | OK |
| Syntaxe règles pare-feu | création | formats validés unitairement (tableau CIDR, plage IPv6) ; le blocage effectif a été observé lors d'un essai accidentel (coupure totale puis récupération propre) | OK partiel |
| Protect complet (routes+IP+DNS+pare-feu) | internet via tunnel | **non testé** : coupe-circuit = déconnexion de l'utilisateur ; et le relais Windows n'a pas de NAT (pas de sortie Internet réelle) | NE |
| Deux relais sur réseaux distincts / observation réelle | — | non testé : une seule machine, pas de VM | NE |
| Résilience (panne relais, changement interface, reboot) | blocage maintenu | partiellement observé : reconnexion auto après coupure de session | NE partiel |
| Sortie étrangère réelle | IP observée = relais | exige un volontaire | NE |

Note d'essai : sur un même hôte, la route connectée du sous-réseau TUN du
relais attire le trafic sans tunnel ; le test a donc forcé la destination
par une route /32 vers l'interface `VicoVPN`. Sur deux machines réelles ce
problème ne existe pas.

## Jalons non exécutés (matériel/droits manquants)

| Jalon | Statut | Pourquoi / comment le faire |
|---|---|---|
| 2. Premier tunnel (paquets IP, TCP/UDP, gros transferts) | NE | nécessite `vicovpn-client.exe` + `vicovpn-relay` en admin avec wintun.dll ; procédure en README §Labo |
| 3. Authentification (scénarios négatifs sur le fil) | OK partiel | couvert par `TestBadPin`/`TestUnknownClient` au niveau QUIC ; pas de test sur vrai TUN |
| 4. Protection du PC (navigateur, apps, services, IPv4/6, DNS) | NE | nécessite admin + relais local ; observation sur lien physique à faire |
| 5. Deux relais sur réseaux distincts | NE partiel | chemin payload vérifié en test unitaire ; VM/2 réseaux requis pour l'observation réelle de chaque relais |
| 6. Résilience (pannes, changement d'interface, reboot) | NE | idem |
| 7. Sortie étrangère réelle | NE | exige un volontaire acceptant d'installer le relais |
| 8. Distribution (installateur, MAJ, désinstall) | NE | pas d'installateur produit ; `vicovpn-recover` couvre la récupération |

## Validation locale / déploiement / revue

- **Validation locale** : tests Go ci-dessus (protocole, auth, politique,
  chemin deux relais au niveau paquets).
- **Déploiement réel** : rien n'a transité sur Internet ; aucun serveur
  loué, aucun infrastructure commandée.
- **Revue de sécurité** : non effectuée — signalé comme exigé par le
  cahier des charges.
