#!/usr/bin/env bash
# Mise en place d'un relais VicoVPN sur Linux (sortie ou entrée).
# Usage : sudo bash setup-relay-linux.sh <role:exit|entry> [listen] [tun_ip] [tun_ip6]
set -euo pipefail

ROLE="${1:-exit}"
LISTEN="${2:-:4443}"
TUN_IP="${3:-10.99.0.1/24}"
TUN_IP6="${4:-}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "À lancer en root (sudo)." >&2
  exit 1
fi

# 1. Vérifier /dev/net/tun et les outils réseau.
for t in ip iptables sysctl; do
  command -v "$t" >/dev/null || { echo "outil manquant : $t" >&2; exit 1; }
done
if [ -n "$TUN_IP6" ]; then
  command -v ip6tables >/dev/null || { echo "ip6tables requis pour tun_ip6" >&2; exit 1; }
fi
[ -c /dev/net/tun ] || { echo "/dev/net/tun absent — charger le module tun" >&2; exit 1; }
modprobe tun 2>/dev/null || true

# 2. Compiler le relais si nécessaire.
BIN="$DIR/bin/vicovpn-relay-linux"
if [ ! -x "$BIN" ]; then
  command -v go >/dev/null || { echo "Go requis pour compiler" >&2; exit 1; }
  (cd "$DIR" && GOOS=linux GOARCH=amd64 go build -o "$BIN" ./cmd/relay)
fi

# 3. Identité du relais.
mkdir -p "$DIR/relay-$ROLE"
if [ ! -f "$DIR/relay-$ROLE/relay.crt" ]; then
  "$BIN" -keygen "$DIR/relay-$ROLE"
  echo ">>> Notez l'empreinte cert_sha256 affichée ci-dessus : à transmettre"
  echo ">>> au client par un canal indépendant."
fi

# 4. clients.txt : à remplir avec les key_id des clients enrôlés.
touch "$DIR/relay-$ROLE/clients.txt"

# 5. relay.json
cat > "$DIR/relay-$ROLE/relay.json" <<EOF
{
  "role": "$ROLE",
  "listen": "$LISTEN",
  "cert_file": "$DIR/relay-$ROLE/relay.crt",
  "key_file": "$DIR/relay-$ROLE/relay.key",
  "country": "ZZ",
  "mtu": 0,
  "rate_kbps": 0,
  "tun_name": "vicovpn-relay",
  "tun_ip": "$TUN_IP",
  "tun_ip6": "$TUN_IP6",
  "clients_file": "$DIR/relay-$ROLE/clients.txt"
}
EOF
if [ "$ROLE" = "entry" ]; then
  echo "N'oubliez pas de renseigner exit_addr dans relay.json (adresse UDP de la sortie)."
fi

echo "Démarrage du relais $ROLE sur $LISTEN ..."
exec "$BIN" -config "$DIR/relay-$ROLE/relay.json"
