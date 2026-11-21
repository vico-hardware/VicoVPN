# Enrôlement et configuration — VicoVPN

Toutes les commandes supposent `bin\` dans le PATH ou des chemins absolus.
Le client et les outils réseau exigent **un terminal administrateur**.

## 0. Provisionner un relais n'importe où (une commande)

Sur **n'importe quelle machine Linux** à l'étranger (VPS gratuit,
Raspberry Pi, vieux PC, VM cloud) :

```bash
# Copier scripts/provision-relay.sh + bin/vicovpn-relay-linux sur la machine,
# puis :
sudo bash provision-relay.sh exit :4443 FR 10.99.0.1/24 fd00:dead:beef::1/64
```

Le script installe le binaire, génère l'identité, écrit `relay.json`,
crée le service systemd et **affiche l'empreinte `cert_sha256`** à
coller dans `relays.json` côté client. Il ne reste qu'à ouvrir le port
UDP 4443 sur le pare-feu de la machine et à ajouter le bloc `relays`
côté client — la sortie est alors disponible dans la liste de l'UI.

## 1. Côté relais (sortie ou entrée)

```powershell
# Générer l'identité du relais (émet relay.crt / relay.key et affiche
# l'empreinte SHA-256 base64 à transmettre au client)
.\bin\vicovpn-relay.exe -keygen C:\vicovpn-relay

# Éditer relay.json (voir testdata\relay.example.json) : rôle, listen,
# pays déclaré, débit max, clients_file.

# Démarrer (Linux : vicovpn-relay-linux, root requis pour /dev/net/tun,
# iptables et sysctl)
.\bin\vicovpn-relay.exe -config relay.json
```

Le propriétaire du relais transmet au client, **par un canal indépendant** :
- l'adresse `hôte:port`,
- l'empreinte `cert_sha256` (affichée par `-keygen` ou
  `sha256` du `relay.crt`),
- le pays déclaré.

Pour enrôler un client : ajouter sa `key_id` (hex, depuis
`identity.key_id` de son `relays.json`) dans `clients.txt` et redémarrer.
Révocation : retirer la ligne + rotation de clé si compromission.

## 2. Côté client (Windows 11)

```powershell
# Terminal administrateur
.\bin\vicovpn-client.exe -gen-identity          # crée %ProgramData%\VicoVPN\relays.json (identité)
# Éditer %ProgramData%\VicoVPN\relays.json : coller les relais enrôlés
# (adresses + cert_sha256 reçus), garder identity intact.

# Service Windows (recommandé : protection au démarrage, compte SYSTEM)
.\bin\vicovpn-client.exe -service install       # admin
Start-Service VicoVPN

# Interface graphique (compte standard)
.\bin\vicovpn-ui.exe -config "$env:ProgramData\VicoVPN"

# Ou en console :
.\bin\vicovpn-client.exe

# Dans un autre terminal :
.\bin\vicovpn-ctl.exe STATUS     # etat courant (detaille : pays, mtu)
.\bin\vicovpn-ctl.exe ACTIVER    # si non lancé avec protection
.\bin\vicovpn-ctl.exe DESACTIVER # restaure la connexion normale
.\bin\vicovpn-ctl.exe REESSAYER  # retente immédiatement
.\bin\vicovpn-ctl.exe RELAY      # liste des sorties (nom|pays|choisie)
.\bin\vicovpn-ctl.exe SELECT <nom>  # change de sortie à chaud
```

## 3. Récupération hors ligne

Si le service/client est mort et que le réseau est bloqué :

```powershell
.\bin\vicovpn-recover.exe
```

Retire uniquement : routes `VicoVPN` enregistrées + routes /1 génériques,
règles pare-feu `VicoVPN-*`, DNS/métrique de l'interface `VicoVPN`.
Ne touche à rien d'autre. Redémarrer ensuite si besoin.

## 4. Laboratoire local (sans Internet sortant)

Le mode `-no-firewall` permet de tester le tunnel sans droits admin :

```powershell
# Terminal 1 : relais de sortie (sur une VM Linux de préférence, sinon
# Windows avec relais configuré — voir LIMITES.md pour le NAT)
.\bin\vicovpn-relay.exe -config relay.json

# Terminal 2 : client
.\bin\vicovpn-client.exe -no-firewall
.\bin\vicovpn-ctl.exe ACTIVER
# Puis tester : ping vers une IP via le tunnel, iperf, etc.
```

Pour un test complet Windows↔VM : installer `vicovpn-relay-linux` dans la
VM, créer `relays.json` avec `addr = <ip_vm>:4443`, lancer le client avec
le coupe-circuit (admin). Observer sur la VM : `tcpdump -i vicovpn-relay`.

## Icône de l'application

`python scripts/make-icon.py` régénère `cmd/ui/assets/icon.ico` +
`icon.png` (blason vert lumineux + V + point rouge, style VicoMedia).
Pour l'embarquer dans l'exe :

```powershell
cd cmd/ui
rsrc -manifest app.manifest -ico assets/icon.ico -o rsrc_windows_amd64.syso
cd ../..
go build -o bin/vicovpn-ui.exe ./cmd/ui
```
