# Limites connues — V1

## Fonctionnel

- **GUI WebView2** : `vicovpn-ui.exe` affiche une page HTML locale
  (style VicoMedia : wallpaper « masque et lumière verte », palette
  sombre) et pilote le client via le canal ctl. Pas de systray, pas de
  persistance de la sélection de sortie (mémoire vive, `SELECT` +
  reconnexion). Dépend du WebView2 Runtime (préinstallé Windows 11).
- **Un seul client par relais de sortie** : tous les clients partagent la
  même IP tunnel `10.99.0.2` côté TUN du relais ; le isolation par
  connexion est logique (flux séparés) mais pas IP. Passer à une IP par
  client enrôlé en V2.
- **IPv6 optionnel, dépendant du relais** : le client demande IPv6
  (`-ipv6`, activé par défaut) mais n'active les routes `::/1` +
  `8000::/1` que si le relais annonce `PolicyIPv6`, ce qui exige
  `tun_ip6` dans sa configuration (ex. `fd00:dead:beef::1/64`). Le
  relais Linux configure alors le forwarding IPv6 + NAT66
  (ip6tables MASQUERADE) ; **un relais Windows n'a pas de NAT66
  automatique** — l'IPv6 tunnel-local fonctionne, pas la sortie
  Internet v6. Sans `tun_ip6`, l'IPv6 reste bloqué par le coupe-circuit.
  Le multicast link-local `ff02::/16` est autorisé par la politique du
  relais (requis pour le Neighbor Discovery dans le tunnel ; non
  routable sur Internet).
- **DNS** : les requêtes partent dans le tunnel vers `1.1.1.1`/`9.9.9.9`
  configurés sur l'interface TUN. Si l'OS préfère le DNS de l'interface
  physique (souvent un DNS de box/privé), ces requêtes entrent dans le
  tunnel et sont **abandonnées par la politique du relais** (destination
  privée) jusqu'à ce que Windows bascule sur le DNS du tunnel. Prévoir un
  proxy DNS local sur l'interface TUN en V2.
- **Relais Windows sans NAT automatique** : `netcfg.RelayTunSetup` active
  le routage IP mais pas le NAT. Utiliser un relais Linux (MASQUERADE
  géré) ou configurer ICS manuellement.
- **Mode deux relais = QUIC dans QUIC sur flux fiable** : le chemin
  externe est ordonné et fiable ; en cas de perte client↔entrée, toute la
  QUIC interne est retardée (head-of-line blocking). Une variante
  DATAGRAM existe dans le code (`PayloadPacketConn` pourrait l'utiliser)
  mais n'est pas activée : la taille utile se limiterait à ~1200 octets
  et les paquets internes risquent d'être trop gros. À évaluer en V2.
- **MTU non mesurée** : valeur fixe 1280 ; pas de path-MTU discovery
  applicative ni de tests de fragmentation en V1.
- **Reconnexion** : backoff 1 s→30 s ; pas de migration Wi-Fi/Ethernet
  explicite (le socket QUIC suit la route par défaut ; à tester).
- **Clés en clair** : `relays.json` et `relay.key` contiennent les clés
  privées ; protection = ACL NTFS uniquement. **DPAPI (CryptProtectData)
  prévu en V2.**
- **Canal ctl** : TCP loopback + jeton plutôt que named pipe à
  descripteur de sécurité (les named pipes Windows exigent des appels
  Win32 non exposés par x/sys/windows). À durcir en V2.
- **Journalisation minimale** : stdout seulement ; pas de fichier de log
  rotatif (volontaire : pas d'historique de navigation).

## Sécurité

- Pas de revue de sécurité externe effectuée.
- L'authentateur côté serveur fait confiance à l'empreinte épinglée ;
  pas de pinning de chaîne, pas de transparence de clé.
- `RequireAnyClientCert` + vérification manuelle de l'empreinte : un
  certificat client auto-signé arbitraire est refusé, mais la validation
  cryptographique complète du certificat (durée, extensions) n'est pas
  réimplémentée — l'empreinte suffit tant que la clé privée correspond.
- Le coupe-circuit Windows utilise des règles de pare-feu par plage
  d'adresses (complémentaire de l'ensemble autorisé). Elles sont créées
  **par interface physique** ; une interface ajoutée après
  `ACTIVER` ne sera pas couverte tant que la protection n'est pas
  réappliquée (RETRY/DISABLE+ENABLE).

## Exploitation

- `route delete 0.0.0.0 mask 128.0.0.0` dans `vicovpn-recover` supprime
  **toutes** les routes /1 correspondantes, y compris celles d'un autre
  VPN actif — documenté, à affiner avec l'état persisté (prioritaire).
- L'adaptateur wintun persiste si le processus meurt sans `Close` ;
  `vicovpn-recover` le désactive mais la suppression PnP complète peut
  nécessiter `pnputil` ou un redémarrage.

## Mode Tor (sorties `tor-<pays>`)

- **TCP uniquement** : Tor ne transporte pas l'UDP — pendant le mode Tor,
  UDP est coupé (jeux, appels, QUIC/HTTP3 direct). Le DNS passe par
  Tor (DNSPort 127.0.0.1:53) et tout le DNS des adaptateurs est forcé
  sur 127.0.0.1 tant que le mode est actif (restauré à la désactivation).
- **IPv6 coupé** : le pont TUN ne gère que IPv4 ; les routes IPv6 ne
  sont pas installées, le trafic v6 reste sur l'interface physique
  (Tor ne transporte pas v6 non plus — penser à bloquer v6 en mode Tor
  si un jour le coupe-circuit s'applique).
- **Pas de persistance** : la sélection `tor-*` est en mémoire vive
  comme `SELECT` (perdue au redémarrage du service).
- **Tun2socks ne pose pas les routes sous Windows** : le client ajoute
  `0.0.0.0/1` + `128.0.0.0/1` via `vicotor0` et les retire à l'arrêt.
- **Processus enfants** : si le client meurt brutalement (kill -9),
  tor.exe/tun2socks.exe peuvent rester orphelins et les routes/DNS
  modifiés — `vicovpn-recover` devra apprendre à les nettoyer (V2).
- **Anonymat** : Tor est le meilleur niveau gratuit, mais pas
  d'invisibilité absolue — comptes connectés, cookies et
  fingerprinting navigateur déanonymiment. Prévoir un profil/navigation
  dédié pour un usage réellement privé.

## Protection maison (onglet 2)

Voir `docs/PROTECTION_MAISON.md` : sorties Tor uniquement, TCP seulement,
IPv6 des appareils à couper dans la box, PC allumé en permanence, IP du PC
à réserver dans la box, fenêtre de coupure < 1 s si `tun2socks` meurt
brutalement (filtre WFP « forward » prévu en V2).
