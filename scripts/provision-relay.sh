#!/usr/bin/env bash
# provision-relay.sh — installe et enrôle un relais VicoVPN sur une machine
# Linux, n'importe où dans le monde. Une seule commande :
#
#   curl -fsSL <url>/provision-relay.sh | sudo bash -s -- exit
#
# (ou : copier le script + vicovpn-relay-linux sur la machine)
#
# Ce que fait le script :
#   1. Vérifie /dev/net/tun et installe iptables/ip6tables si besoin
#   2. Copie le binaire dans /usr/local/bin/vicovpn-relay
#   3. Génère l'identité du relais (clé + certificat)
#   4. Demande les paramètres (rôle, port d'écoute, pays, sortie éventuelle)
#   5. Affiche l'empreinte cert_sha256 à reporter dans relays.json du client
#   6. Crée un service systemd pour le démarrage automatique
#
# L'enrôlement des clients (clients.txt) se fait ensuite en ajoutant la
# key_id du client — voir docs/RECETTE.md section révocation.
set -euo pipefail

ROLE="${1:-exit}"
LISTEN="${2:-:4443}"
COUNTRY="${3:-ZZ}"
TUN_IP="${4:-10.99.0.1/24}"
TUN_IP6="${5:-}"
EXIT_ADDR="${6:-}"

if [ "$(id -u)" -ne 0 ]; then
  echo "À lancer en root : sudo bash provision-relay.sh" >&2
  exit 1
fi

DIR="/etc/vicovpn-relay"
BIN_SRC="$(cd "$(dirname "$0")" && pwd)/vicovpn-relay-linux"
[ -f "$BIN_SRC" ] || BIN_SRC="/usr/local/bin/vicovpn-relay"

echo "== Provisionnement relais VicoVPN ($ROLE) =="

# 1. Dépendances
if [ ! -c /dev/net/tun ]; then
  modprobe tun 2>/dev/null || true
fi
for t in ip iptables sysctl; do
  command -v "$t" >/dev/null || {
    echo "Outil manquant : $t — installez iproute2/iptables" >&2; exit 1; }
done
if [ -n "$TUN_IP6" ]; then
  command -v ip6tables >/dev/null || {
    echo "ip6tables requis pour tun_ip6" >&2; exit 1; }
fi

# 2. Binaire
if [ ! -x /usr/local/bin/vicovpn-relay ]; then
  if [ -f "$BIN_SRC" ]; then
    install -m 755 "$BIN_SRC" /usr/local/bin/vicovpn-relay
  else
    echo "Binaire introuvable : placer vicovpn-relay-linux à côté du script" >&2
    exit 1
  fi
fi

# 3. Identité
mkdir -p "$DIR" && chmod 700 "$DIR"
if [ ! -f "$DIR/relay.crt" ]; then
  /usr/local/bin/vicovpn-relay -keygen "$DIR"
fi

# Empreinte à reporter côté client (flag -fingerprint : ne régénère rien)
FP=$(/usr/local/bin/vicovpn-relay -fingerprint "$DIR/relay.crt")
echo ""
echo ">>> EMPREINTE À NOTER (cert_sha256) : $FP"

# 4. clients.txt (à remplir avec les key_id clients)
touch "$DIR/clients.txt"

# 5. relay.json
cat > "$DIR/relay.json" <<EOF
{
  "role": "$ROLE",
  "listen": "$LISTEN",
  "cert_file": "$DIR/relay.crt",
  "key_file": "$DIR/relay.key",
  "country": "$COUNTRY",
  "mtu": 0,
  "rate_kbps": 0,
  "tun_name": "vicovpn-relay",
  "tun_ip": "$TUN_IP",
  "tun_ip6": "$TUN_IP6",
  "exit_addr": "$EXIT_ADDR",
  "clients_file": "$DIR/clients.txt"
}
EOF
chmod 600 "$DIR/relay.json" "$DIR/relay.key"

# 6. Service systemd
cat > /etc/systemd/system/vicovpn-relay.service <<EOF
[Unit]
Description=VicoVPN relay ($ROLE)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/vicovpn-relay -config $DIR/relay.json
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=$DIR

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now vicovpn-relay

echo ""
echo "== Terminé =="
echo "Relais $ROLE actif sur $LISTEN (pays déclaré : $COUNTRY)"
echo ""
echo "Côté client, ajouter dans relays.json :"
cat <<JSON
  {
    "name": "mon-relai-$COUNTRY",
    "role": "exit",
    "addr": "<IP_PUBLIQUE_DE_CETTE_MACHINE>:$([ "$LISTEN" = ":4443" ] && echo 4443 || echo ${LISTEN##*:})",
    "cert_sha256": "$FP",
    "country": "$COUNTRY"
  }
JSON
echo ""
echo "N'oubliez pas d'ouvrir le port UDP correspondant sur le pare-feu"
echo "de cette machine (ufw/iptables/cloud security group)."
