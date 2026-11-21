# Protocole VicoVPN — version 1

Statut : **provisoire** (V1). Toute modification de format incrémente `Version`.

## 1. Transport

- QUIC (RFC 9000) sur UDP, TLS 1.3, implémenté par `quic-go`.
- Authentification mutuelle par certificats auto-signés ECDSA P-256.
  Chaque pair épingle l'empreinte SHA-256 (base64) du certificat de l'autre,
  obtenue par un canal indépendant lors de l'enrôlement.
  Côté relais : la liste des empreintes de certificats clients autorisés est
  configurée explicitement (`clients_file`).
- **0-RTT désactivé** : `quic.Dial` simple, aucun ticket de session réutilisé
  pour des données applicatives.
- DATAGRAM QUIC (RFC 9221) activé des deux côtés ; utilisé pour les paquets
  IP internes de protocole UDP quand le pair l'annonce (`PolicyDatagram`).

## 2. Négociation applicative

Après l'établissement QUIC :

1. Le client ouvre un **flux bidirectionnel de contrôle** et émet
   `ClientHello` ; le relais répond `ServerHello` sur le même flux.
2. Chaque pair ouvre **un flux unidirectionnel** vers l'autre pour les
   données. Une trame `TypeReady` est écrite immédiatement (QUIC
   n'annonce un flux sortant qu'à sa première donnée).

### Trames

Toutes les trames : `[u32 longueur_BIG_ENDIAN][u8 type][payload]`,
longueur = taille du type + payload. Limites : `MaxFrameSize = 1616`,
`MaxPacketSize = 1600`.

| Type | Sens | Payload |
|------|------|---------|
| 1 `ClientHello` | C→R | Voir §3 |
| 2 `ServerHello` | R→C | Voir §3 |
| 3 `Data` | les deux | paquet IP complet (IPv4/IPv6) |
| 4 `Close` | les deux | fermeture propre |
| 5 `Error` | les deux | code d'erreur texte (V1 : non utilisé) |
| 6 `Ready` | les deux | annonce de flux (payload vide) |

Les trames `TypeReady`, `TypeClose`, `TypeError` reçues sur le flux de
données sont ignorées par la boucle de réception.

### Routage des paquets IP

- Paquet IP **UDP non fragmenté** (IPv4 sans fragment, IPv6 avec
  `next header = 17` directement) + `PolicyDatagram` négocié →
  `DATAGRAM` QUIC (non fiable, sans ordre — sémantique UDP).
- Tout le reste (TCP, ICMP/ICMPv6, fragments, paquets avec en-têtes
  d'extension IPv6, UDP trop gros pour un datagramme) → trame `TypeData`
  sur le flux fiable ordonné.

## 3. Messages de contrôle

`ClientHello` (37 octets) :

```
u16 version | u16 mtu | u8 key_id[32] (réservé, zéro en V1) | u8 want_ipv6
```

`want_ipv6` : le client demande le transport IPv6. Le relais n'annonce
`PolicyIPv6` que si `tun_ip6` est configuré (double pile active) ; le
client n'installe alors les routes fourre-tout IPv6 (`::/1`, `8000::/1`)
qu'après réception du `ServerHello`. Sinon, l'IPv6 reste bloqué par le
coupe-circuit — jamais de trafic IPv6 en clair.

`ServerHello` :

```
u16 version | u16 mtu | u8 policy_flags | char country[]
```

`policy_flags` : bit0 = IPv6 accepté, bit1 = DATAGRAM accepté.
La MTU retenue = min(client, relais, `MaxPacketSize`).

## 4. Mode deux relais

1. Client ↔ entrée : session QUIC externe authentifiée (certificat de
   l'entrée épinglé).
2. Client ↔ sortie : **seconde session QUIC** dont les paquets UDP sont
   transportés comme charges utiles `TypeData` du flux fiable externe
   (`PayloadPacketConn`). La QUIC interne est authentifiée et chiffrée de
   bout en bout avec le certificat de la sortie épinglé.
3. L'entrée ne fait que recouvrir : charge utile externe ↔ datagramme UDP
   vers la sortie. Elle ne termine ni la QUIC interne ni le protocole
   applicatif interne. **Aucun contact direct client↔sortie** : ni pendant
   la découverte, ni la sélection, ni la reprise.

Conséquence : le chemin externe est un transport fiable ordonné ; la QUIC
interne subit du head-of-line blocking en cas de perte sur le trajet
client↔entrée. Coût : double encapsulation QUIC (voir docs/LIMITES.md).

## 5. Erreurs et reconnexion

- Échec de handshake (mauvais épinglage, client non enrôlé, version
  incompatible) → fermeture QUIC, aucune donnée applicative émise.
- Perte de session → le client repasse en état « bloqué » tant que le
  coupe-circuit est actif, puis retente avec backoff exponentiel
  (1 s → 30 s max). `RETRY` remet le backoff à zéro.
- `DISABLE` ou arrêt volontaire → retrait du coupe-circuit et des routes.
