// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

// Package netcfg applique la configuration réseau du produit sous Windows :
// coupe-circuit (règles Windows Firewall / WFP), routes, adresse et DNS de
// l'interface TUN. Toutes les règles créées portent le préfixe "VicoVPN-"
// pour permettre une suppression ciblée (outil de récupération).
package netcfg

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RulePrefix préfixe tous les objets créés par le produit.
const RulePrefix = "VicoVPN-"

// TunInterface est le nom de l'adaptateur wintun.
const TunInterface = "VicoVPN"

// ClientIP / ClientCIDR : adresse tunnel côté client.
const (
	ClientIP   = "10.99.0.2"
	ClientCIDR = "10.99.0.0/24"
	RelayIP    = "10.99.0.1"
	// Tunnel IPv6 : ULA fd00:dead:beef::/64 (jamais routable sur Internet).
	ClientIP6   = "fd00:dead:beef::2"
	ClientCIDR6 = "fd00:dead:beef::/64"
	RelayIP6    = "fd00:dead:beef::1"
)

// windowsNetOps implémente engine.ClientNetOps.
type windowsNetOps struct {
	mu        sync.Mutex
	protected bool
	routes    []string // routes ajoutées (pour suppression)
	stateDir  string   // dossier de configuration client (état persisté)
}

// NewClientNetOps retourne l'implémentation Windows. stateDir reçoit le
// fichier d'état pour l'outil de récupération.
func NewClientNetOps(stateDir string) *windowsNetOps {
	return &windowsNetOps{stateDir: stateDir}
}

var _ interface {
	Protect(context.Context, string, int, []string, bool) error
	EnableIPv6(context.Context, string) error
	Unprotect() error
	IsProtected() bool
} = (*windowsNetOps)(nil)

func (w *windowsNetOps) IsProtected() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.protected
}

// Protect installe le coupe-circuit complet. Ordre obligatoire :
// 1) règles pare-feu (filtres avant connexion), 2) route hôte du relais via
// la passerelle physique, 3) routes /1 via le TUN, 4) IP + MTU + DNS.
func (w *windowsNetOps) Protect(ctx context.Context, tunName string, mtu int, allowedUDPDests []string, wantIPv6 bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.protected {
		return nil
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	entryIPs, entryPorts := splitDestinations(allowedUDPDests)

	// --- 1. Pare-feu ---
	ifaces, err := physicalIfaces()
	if err != nil {
		return fmt.Errorf("netcfg: interfaces physiques: %w", err)
	}
	blockV4, err := v4BlockList(entryIPs)
	if err != nil {
		return err
	}
	// Tableau PowerShell 'a','b' : la forme CSV simple est rejetée par
	// New-NetFirewallRule.
	blockV4Arr := "'" + strings.Join(blockV4, "','") + "'"
	for _, in := range ifaces {
		// Blocage de tout le trafic sortant hors ensemble autorisé.
		if err := addFirewallRule(ctx, in, "Block-V4", "Any", blockV4Arr, "", ""); err != nil {
			return err
		}
		// ::/0 n'est pas accepté : plage IPv6 complète equivalente.
		if err := addFirewallRule(ctx, in, "Block-V6", "Any", "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "", ""); err != nil {
			return err
		}
		// Autorisation explicite du transport QUIC vers l'entrée/sortie.
		for i, ip := range entryIPs {
			port := ""
			if i < len(entryPorts) {
				port = entryPorts[i]
			}
			plen := "/32"
			if net.ParseIP(ip) != nil && net.ParseIP(ip).To4() == nil {
				plen = "/128"
			}
			if err := addFirewallRule(ctx, in, "Allow-Entry", "UDP", ip+plen, port, "Allow"); err != nil {
				return err
			}
		}
	}

	// --- 2. Route hôte du relais via la passerelle physique ---
	// Nécessaire pour que le trafic QUIC ne soit pas aspiré par le TUN.
	for _, ip := range entryIPs {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.IsLoopback() {
			continue // loopback : pas de route hôte nécessaire
		}
		if parsed.To4() == nil {
			if wantIPv6 {
				if err := w.addHostRouteV6(ctx, ip); err != nil {
					return fmt.Errorf("netcfg: route hôte IPv6 %s: %w", ip, err)
				}
				w.routes = append(w.routes, "HOST6/"+ip)
			}
			continue
		}
		if err := w.addHostRoute(ctx, ip); err != nil {
			return fmt.Errorf("netcfg: route hôte %s: %w", ip, err)
		}
		w.routes = append(w.routes, "HOST/"+ip)
	}

	// --- 3. Routes tunnel /1 (capturent tout IPv4 sans effacer la défaut) ---
	ifIdx, err := interfaceIndex(tunName)
	if err != nil {
		return fmt.Errorf("netcfg: index de %s: %w", tunName, err)
	}
	for _, r := range []struct{ dst, mask string }{
		{"0.0.0.0", "128.0.0.0"},
		{"128.0.0.0", "128.0.0.0"},
	} {
		if err := run(ctx, "route", "add", r.dst, "mask", r.mask, "0.0.0.0", "IF", strconv.Itoa(ifIdx), "metric", "1"); err != nil {
			return fmt.Errorf("netcfg: route %s/%s: %w", r.dst, r.mask, err)
		}
		w.routes = append(w.routes, r.dst+"/"+r.mask)
	}

	// --- 4. IP, MTU, métrique et DNS de l'interface tunnel ---
	if err := configureTunInterface(ctx, tunName, mtu, wantIPv6); err != nil {
		return err
	}

	// Persister les routes pour l'outil de récupération hors ligne.
	if w.stateDir != "" {
		_ = os.MkdirAll(w.stateDir, 0o700)
		b, _ := json.Marshal(struct {
			Routes    []string `json:"routes"`
			Protected bool     `json:"protected"`
		}{Routes: append([]string{}, w.routes...), Protected: true})
		_ = os.WriteFile(filepath.Join(w.stateDir, "netcfg-state.json"), b, 0o600)
	}

	w.protected = true
	return nil
}

// TorProtect installe le coupe-circuit pour le mode Tor : tout le trafic
// sortant des interfaces physiques est bloqué sauf vers les IPs des
// gardes Tor (Tor n'a besoin que d'elles pour sortir) et les plages
// locales indispensables (RFC1918, loopback, link-local, DHCP).
// Le blocage est par adresse distante : les gardes sont exclues de la
// liste bloquée, donc tor.exe passe sans règle Allow dédiée.
func TorProtect(ctx context.Context, guardIPs []string) error {
	ifaces, err := physicalIfaces()
	if err != nil {
		return fmt.Errorf("netcfg: interfaces physiques: %w", err)
	}
	allowed := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"255.255.255.255/32",
	}
	for _, ip := range guardIPs {
		if p := net.ParseIP(ip); p != nil && p.To4() != nil {
			allowed = append(allowed, p.String()+"/32")
		}
	}
	blockV4, err := v4Complement(allowed)
	if err != nil {
		return err
	}
	blockV4Arr := "'" + strings.Join(blockV4, "','") + "'"
	for _, in := range ifaces {
		if err := addFirewallRule(ctx, in, "TorBlock-V4", "Any", blockV4Arr, "", ""); err != nil {
			return err
		}
		// ::/0 n'est pas accepté : plage IPv6 complète equivalente.
		if err := addFirewallRule(ctx, in, "TorBlock-V6", "Any", "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "", ""); err != nil {
			return err
		}
	}
	return nil
}

// TorUnprotect retire les règles du coupe-circuit Tor (et toute règle
// VicoVPN-*, le mode étant exclusif).
func TorUnprotect(ctx context.Context) error {
	return removeFirewallRules(ctx)
}

// Unprotect retire tout ce que Protect a installé. Idempotent.
func (w *windowsNetOps) Unprotect() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var firstErr error
	ctx := context.Background()

	// Routes tunnel et routes hôte.
	for _, r := range w.routes {
		if strings.HasPrefix(r, "HOST6/") {
			w.removeHostRouteV6(ctx, strings.TrimPrefix(r, "HOST6/"))
			continue
		}
		if strings.HasPrefix(r, "HOST/") {
			_ = run(ctx, "route", "delete", strings.TrimPrefix(r, "HOST/"))
			continue
		}
		if strings.HasPrefix(r, "V6/") {
			w.removeIPv6Route(ctx, strings.TrimPrefix(r, "V6/"))
			continue
		}
		_ = run(ctx, "route", "delete", r, "mask", "128.0.0.0")
	}
	w.routes = nil

	// Règles pare-feu.
	if err := removeFirewallRules(ctx); err != nil && firstErr == nil {
		firstErr = err
	}

	// IP/Métrique/DNS : on laisse l'interface telle quelle ; elle est
	// détruite avec l'adaptateur wintun à la fermeture du service.
	w.protected = false
	// Effacer l'état persisté.
	if w.stateDir != "" {
		_ = os.Remove(filepath.Join(w.stateDir, "netcfg-state.json"))
	}
	return firstErr
}

// EnableIPv6 ajoute les routes fourre-tout IPv6 via le TUN. Appelé
// uniquement après négociation de PolicyIPv6 avec le relais.
func (w *windowsNetOps) EnableIPv6(ctx context.Context, tunName string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.protected {
		return fmt.Errorf("netcfg: EnableIPv6 sans protection active")
	}
	idx, err := interfaceIndex(tunName)
	if err != nil {
		return fmt.Errorf("netcfg: index de %s: %w", tunName, err)
	}
	for _, prefix := range []string{"::/1", "8000::/1"} {
		if err := runPS(ctx, fmt.Sprintf(`New-NetRoute -InterfaceIndex %d -DestinationPrefix '%s' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null`, idx, prefix)); err != nil {
			return fmt.Errorf("netcfg: route IPv6 %s: %w", prefix, err)
		}
		w.routes = append(w.routes, "V6/"+prefix)
	}
	return nil
}

// removeIPv6Route supprime une route IPv6 du TUN.
func (w *windowsNetOps) removeIPv6Route(ctx context.Context, prefix string) {
	idx, err := interfaceIndex(TunInterface)
	if err != nil {
		return
	}
	_ = runPS(ctx, fmt.Sprintf(`Remove-NetRoute -InterfaceIndex %d -DestinationPrefix '%s' -Confirm:$false -ErrorAction SilentlyContinue`, idx, prefix))
}

// addHostRouteV6 ajoute une route hôte /128 vers un relais IPv6 via la
// passerelle physique courante.
func (w *windowsNetOps) addHostRouteV6(ctx context.Context, ip string) error {
	out, err := psJSONCtx(ctx, fmt.Sprintf(`(Find-NetRoute -RemoteIPAddress %s | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 | ConvertTo-Json -Compress)`, ip))
	if err != nil {
		return err
	}
	var r struct {
		NextHop        string `json:"NextHop"`
		InterfaceIndex int    `json:"InterfaceIndex"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return fmt.Errorf("route introuvable pour %s", ip)
	}
	if r.InterfaceIndex == 0 {
		return fmt.Errorf("interface introuvable pour %s", ip)
	}
	prefix := ip + "/128"
	// NextHop link-local : suffixer la zone d'interface exigée par IPv6.
	if strings.HasPrefix(r.NextHop, "fe80:") {
		r.NextHop = fmt.Sprintf("%s%%%d", r.NextHop, r.InterfaceIndex)
	}
	if r.NextHop == "" || r.NextHop == "::" {
		// Destinataire sur lien : route on-link.
		return runPS(ctx, fmt.Sprintf(`New-NetRoute -InterfaceIndex %d -DestinationPrefix '%s' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null`, r.InterfaceIndex, prefix))
	}
	return runPS(ctx, fmt.Sprintf(`New-NetRoute -InterfaceIndex %d -DestinationPrefix '%s' -NextHop '%s' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null`, r.InterfaceIndex, prefix, r.NextHop))
}

// removeHostRouteV6 supprime la route hôte IPv6 du relais.
func (w *windowsNetOps) removeHostRouteV6(ctx context.Context, ip string) {
	out, err := psJSONCtx(ctx, fmt.Sprintf(`(Get-NetRoute -DestinationPrefix '%s' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty InterfaceIndex | ConvertTo-Json -Compress)`, ip+"/128"))
	if err == nil && out != "" && out != "null" {
		var idx int
		if json.Unmarshal([]byte(out), &idx) == nil && idx > 0 {
			_ = runPS(ctx, fmt.Sprintf(`Remove-NetRoute -InterfaceIndex %d -DestinationPrefix '%s' -Confirm:$false -ErrorAction SilentlyContinue`, idx, ip+"/128"))
		}
	}
}

// addHostRoute ajoute une route /32 vers le relais via la passerelle
// physique courante, sans passer par le TUN.
func (w *windowsNetOps) addHostRoute(ctx context.Context, ip string) error {
	// Trouver la route actuellement utilisée pour cette IP.
	out, err := psJSONCtx(ctx, fmt.Sprintf(`(Find-NetRoute -RemoteIPAddress %s | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 | ConvertTo-Json -Compress)`, ip))
	if err != nil {
		return err
	}
	var r struct {
		NextHop        string `json:"NextHop"`
		InterfaceIndex int    `json:"InterfaceIndex"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return fmt.Errorf("route introuvable pour %s", ip)
	}
	gw := r.NextHop
	if gw == "" || gw == "0.0.0.0" {
		// Destinataire sur lien : route on-link via l'interface.
		if err := run(ctx, "route", "add", ip, "mask", "255.255.255.255", "0.0.0.0", "IF", strconv.Itoa(r.InterfaceIndex), "metric", "1"); err != nil {
			return err
		}
	} else {
		if err := run(ctx, "route", "add", ip, "mask", "255.255.255.255", gw, "metric", "1"); err != nil {
			return err
		}
	}
	return nil
}

// configureTunInterface attribue IP, MTU, métrique et DNS à l'interface TUN.
func configureTunInterface(ctx context.Context, name string, mtu int, wantIPv6 bool) error {
	idx, err := interfaceIndex(name)
	if err != nil {
		return fmt.Errorf("netcfg: index de %s: %w", name, err)
	}
	// Adresse /32 : le tunnel est le seul chemin, pas de passerelle.
	// Silencieusement ignorée si déjà présente (reconnexion).
	_ = runPS(ctx, fmt.Sprintf(`New-NetIPAddress -InterfaceIndex %d -IPAddress '%s' -PrefixLength 32 -ErrorAction SilentlyContinue | Out-Null`, idx, ClientIP))
	if err := runPS(ctx, fmt.Sprintf(`Set-NetIPInterface -InterfaceIndex %d -InterfaceMetric 1 -ErrorAction SilentlyContinue | Out-Null`, idx)); err != nil {
		return err
	}
	if mtu > 0 {
		if err := runPS(ctx, fmt.Sprintf(`Set-NetIPInterface -InterfaceIndex %d -NlMtuBytes %d -ErrorAction SilentlyContinue | Out-Null`, idx, mtu)); err != nil {
			return err
		}
	}
	// DNS via le tunnel : seuls des résolveurs publics, le trafic part
	// dans le tunnel de toute façon. Windows répartit les adresses par
	// famille (IPv4/IPv6) dans une même liste.
	dns := "('1.1.1.1','9.9.9.9')"
	if wantIPv6 {
		// Adresse IPv6 ULA du tunnel (/128 : pas de préfixe annoncé).
		_ = runPS(ctx, fmt.Sprintf(`New-NetIPAddress -InterfaceIndex %d -IPAddress '%s' -PrefixLength 128 -AddressFamily IPv6 -ErrorAction SilentlyContinue | Out-Null`, idx, ClientIP6))
		dns = "('1.1.1.1','9.9.9.9','2606:4700:4700::1111','2620:fe::fe')"
	}
	if err := runPS(ctx, fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses %s -ErrorAction SilentlyContinue | Out-Null`, idx, dns)); err != nil {
		return err
	}
	return nil
}

// physicalIfaces liste les interfaces physiques actives (hors tunnel).
func physicalIfaces() ([]string, error) {
	out, err := psJSON(`Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress`)
	if err != nil {
		return nil, err
	}
	var names []string
	if strings.TrimSpace(out) == "" || out == "null" {
		return nil, fmt.Errorf("aucune interface physique active")
	}
	if err := json.Unmarshal([]byte(out), &names); err != nil {
		// JSON simple : une seule chaîne.
		var s string
		if err2 := json.Unmarshal([]byte(out), &s); err2 == nil {
			names = []string{s}
		} else {
			return nil, err
		}
	}
	return names, nil
}

// interfaceIndex retourne l'index de la pile IPv4 de l'interface.
func interfaceIndex(name string) (int, error) {
	out, err := psJSON(fmt.Sprintf(`(Get-NetAdapter -Name '%s' -ErrorAction Stop | Select-Object -ExpandProperty ifIndex | ConvertTo-Json -Compress)`, name))
	if err != nil {
		return 0, err
	}
	var idx int
	if err := json.Unmarshal([]byte(out), &idx); err != nil {
		return 0, err
	}
	return idx, nil
}

// splitDestinations extrait IP et port de destinations "hôte:port".
// Les noms d'hôte sont résolus en IPv4.
func splitDestinations(dests []string) (ips, ports []string) {
	for _, d := range dests {
		host, port, err := net.SplitHostPort(d)
		if err != nil {
			ips = append(ips, d)
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			if ua, err := net.ResolveUDPAddr("udp", d); err == nil && ua.IP != nil {
				ip = ua.IP
			}
		}
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ips = append(ips, v4.String())
		} else {
			ips = append(ips, ip.String())
		}
		ports = append(ports, port)
	}
	return ips, ports
}

// v4BlockList calcule les CIDR IPv4 à bloquer = tout sauf les IP des
// relais et les plages locales indispensables (RFC1918, loopback,
// link-local, CGNAT, broadcast DHCP).
func v4BlockList(entryIPs []string) ([]string, error) {
	allowed := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"255.255.255.255/32",
	}
	for _, ip := range entryIPs {
		if v4 := net.ParseIP(ip).To4(); v4 != nil {
			allowed = append(allowed, v4.String()+"/32")
		}
	}
	return v4Complement(allowed)
}

// v4Complement retourne la liste minimale de CIDR couvrant 0.0.0.0/0
// moins les CIDR autorisés.
func v4Complement(allowedCIDRs []string) ([]string, error) {
	type r struct{ lo, hi uint32 }
	var ranges []r
	for _, c := range allowedCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		ip := n.IP.To4()
		if ip == nil {
			continue
		}
		ones, _ := n.Mask.Size()
		base := binaryToUint32(net.IP(ip).To4())
		size := uint64(1) << uint(32-ones)
		ranges = append(ranges, r{base, base + uint32(size-1)})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })
	// Fusionner les chevauchements.
	merged := ranges[:0]
	for _, x := range ranges {
		if len(merged) == 0 || x.lo > merged[len(merged)-1].hi+1 {
			merged = append(merged, x)
		} else if x.hi > merged[len(merged)-1].hi {
			merged[len(merged)-1].hi = x.hi
		}
	}
	var out []string
	var prev uint64
	covered := false
	for _, m := range merged {
		if uint64(m.lo) > prev {
			out = appendCIDRs(out, uint32(prev), m.lo-1)
		}
		if m.hi == ^uint32(0) {
			covered = true
			break
		}
		prev = uint64(m.hi) + 1
	}
	if !covered {
		out = appendCIDRs(out, uint32(prev), ^uint32(0))
	}
	return out, nil
}

// appendCIDRs décompose [lo,hi] en CIDR minimaux.
func appendCIDRs(out []string, lo, hi uint32) []string {
	l, h := uint64(lo), uint64(hi)
	for l <= h {
		remaining := h - l + 1
		// Plus grand bloc aligné possible.
		maxSize := uint64(1)
		for maxSize*2 <= remaining && l&(maxSize*2-1) == 0 && maxSize < 0x80000000 {
			maxSize *= 2
		}
		bits := 32 - bitsLen(uint32(maxSize-1))
		out = append(out, fmt.Sprintf("%s/%d", uint32ToIP(uint32(l)), bits))
		l += maxSize
	}
	return out
}

func bitsLen(v uint32) int {
	n := 0
	for v != 0 {
		v >>= 1
		n++
	}
	return n
}

func binaryToUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", v>>24, (v>>16)&0xff, (v>>8)&0xff, v&0xff)
}

// addFirewallRule crée une règle Windows Firewall nommée VicoVPN-<tag>-<iface>.
func addFirewallRule(ctx context.Context, iface, tag, proto, remoteAddr, remotePort, action string) error {
	if action == "" {
		action = "Block"
	}
	name := RulePrefix + "KS-" + tag + "-" + iface
	// Supprimer une éventuelle règle existante du même nom.
	_ = runPS(ctx, fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, name))
	args := []string{
		"-DisplayName", name,
		"-Direction", "Outbound",
		"-Action", action,
		"-InterfaceAlias", iface,
		"-RemoteAddress", remoteAddr,
	}
	if proto != "Any" && proto != "" {
		args = append(args, "-Protocol", proto)
	}
	if remotePort != "" {
		args = append(args, "-RemotePort", remotePort)
	}
	return runPSArgs(ctx, args)
}

// removeFirewallRules supprime les règles du produit, sauf celles de la
// passerelle maison (VicoVPN-GW-*), gérées par la passerelle elle-même :
// un redémarrage du tunnel (changement de pays, nouvelle tentative) ne
// doit pas fermer le DNS des appareils. vicovpn-recover retire tout.
func removeFirewallRules(ctx context.Context) error {
	return runPS(ctx, fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%s*' -ErrorAction SilentlyContinue | `+
		`Where-Object { $_.DisplayName -notlike '%sGW-*' } | Remove-NetFirewallRule`, RulePrefix, RulePrefix))
}

// requireAdmin vérifie que le processus est élevé.
func requireAdmin() error {
	out, err := HiddenCmd(context.Background(), "net", "session").Output()
	if err != nil {
		return fmt.Errorf("netcfg: droits administrateur requis (net session: %v)", err)
	}
	_ = out
	return nil
}

// psJSON exécute PowerShell et retourne la sortie JSON brute.
func psJSON(script string) (string, error) {
	ctx := context.Background()
	return psJSONCtx(ctx, script)
}

// HiddenCmd retourne une commande externe qui ne crée JAMAIS de fenêtre
// console : le client est une application GUI et chaque enfant console
// (powershell, netsh, tor, tun2socks…) ouvrirait sinon une fenêtre noire.
func HiddenCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	return cmd
}

func psJSONCtx(ctx context.Context, script string) (string, error) {
	cmd := HiddenCmd(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("powershell: %s: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// runPS exécute un script PowerShell sans sortie attendue.
func runPS(ctx context.Context, script string) error {
	cmd := HiddenCmd(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runPSArgs exécute New-NetFirewallRule avec arguments (chaque argument
// est quoté pour éviter les problèmes de parsing PowerShell, ex. "::/0").
func runPSArgs(ctx context.Context, args []string) error {
	quoted := make([]string, len(args))
	for i, a := range args {
		// Les noms de paramètres (-Foo) et les arguments déjà quotés
		// (tableaux 'a','b') sont laissés tels quels.
		if strings.HasPrefix(a, "-") || (len(a) >= 2 && a[0] == '\'' && a[len(a)-1] == '\'') {
			quoted[i] = a
			continue
		}
		quoted[i] = "'" + strings.ReplaceAll(a, "'", "''") + "'"
	}
	script := "New-NetFirewallRule " + strings.Join(quoted, " ")
	return runPS(ctx, script)
}

// RelayTunSetup configure un relais sous Windows : adresse IP sur l'interface
// TUN et activation du routage IP (IPEnableRouter). Le NAT n'est PAS géré
// automatiquement — pour un relais Windows, utiliser le partage de connexion
// (ICS) ou un hôte Linux. Voir docs/LIMITES.md.
func RelayTunSetup(tunName, tunAddr, tunAddr6 string, mtu int) error {
	ctx := context.Background()
	ip, prefix, err := parseTunAddr(tunAddr)
	if err != nil {
		return err
	}
	// Activer le routage IP.
	if err := runPS(ctx, `Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -Value 1`); err != nil {
		return fmt.Errorf("netcfg: IPEnableRouter: %w", err)
	}
	// Attendre que l'adaptateur soit visible et récupérer son index.
	var idx int
	for i := 0; i < 20; i++ {
		out, err := psJSONCtx(ctx, fmt.Sprintf(`(Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty ifIndex | ConvertTo-Json -Compress)`, tunName))
		if err == nil && out != "" && out != "null" {
			if jerr := json.Unmarshal([]byte(out), &idx); jerr == nil && idx > 0 {
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if idx == 0 {
		return fmt.Errorf("netcfg: adaptateur %s introuvable", tunName)
	}
	// Adresse sur l'interface TUN.
	addrScript := fmt.Sprintf(`New-NetIPAddress -InterfaceIndex %d -IPAddress '%s' -PrefixLength %d -ErrorAction Stop | Out-Null`, idx, ip, prefix)
	if err := runPS(ctx, addrScript); err != nil {
		return fmt.Errorf("netcfg: adresse TUN: %w", err)
	}
	// Adresse IPv6 ULA si configurée. Pas de NAT66 automatique sous
	// Windows : voir docs/LIMITES.md (recommandé : relais Linux).
	if tunAddr6 != "" {
		ip6, prefix6, err := parseTunAddr(tunAddr6)
		if err != nil {
			return err
		}
		_ = runPS(ctx, fmt.Sprintf(`New-NetIPAddress -InterfaceIndex %d -IPAddress '%s' -PrefixLength %d -AddressFamily IPv6 -ErrorAction Stop | Out-Null`, idx, ip6, prefix6))
	}
	if mtu > 0 {
		_ = runPS(ctx, fmt.Sprintf(`Set-NetIPInterface -InterfaceIndex %d -NlMtuBytes %d -ErrorAction SilentlyContinue | Out-Null`, idx, mtu))
	}
	// Autoriser le trafic entrant depuis les sous-réseaux du tunnel sur
	// cette interface uniquement (équivalent des règles FORWARD/INPUT
	// iptables côté Linux). Sans cela, le pare-feu Windows de l'hôte
	// bloque les paquets des clients.
	if err := allowTunnelInbound(ctx, tunName, tunAddr, tunAddr6); err != nil {
		return fmt.Errorf("netcfg: règles pare-feu relais: %w", err)
	}
	return nil
}

// allowTunnelInbound crée une règle d'autorisation entrante limitée aux
// sous-réseaux tunnel sur l'interface TUN du relais.
func allowTunnelInbound(ctx context.Context, tunName, tunAddr, tunAddr6 string) error {
	var nets []string
	for _, a := range []string{tunAddr, tunAddr6} {
		if a == "" {
			continue
		}
		if !strings.Contains(a, "/") {
			a += "/24"
		}
		if _, n, err := net.ParseCIDR(a); err == nil {
			nets = append(nets, n.String())
		}
	}
	if len(nets) == 0 {
		return nil
	}
	remote := "'" + strings.Join(nets, "','") + "'"
	name := RulePrefix + "Relay-In-" + tunName
	_ = runPS(ctx, fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, name))
	return runPSArgs(ctx, []string{
		"-DisplayName", name,
		"-Direction", "Inbound",
		"-Action", "Allow",
		"-InterfaceAlias", tunName,
		"-RemoteAddress", remote,
		"-Protocol", "Any",
	})
}

// RelayTunTeardown retire la configuration du relais Windows.
func RelayTunTeardown(tunName, tunAddr, tunAddr6 string) error {
	ctx := context.Background()
	// Règles pare-feu du relais (nommées VicoVPN-Relay-In-*).
	_ = runPS(ctx, fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%sRelay-In-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, RulePrefix))
	ip, prefix, err := parseTunAddr(tunAddr)
	if err == nil {
		_ = runPS(ctx, fmt.Sprintf(`$a = Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($a) { Remove-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress '%s' -PrefixLength %d -Confirm:$false -ErrorAction SilentlyContinue }`, tunName, ip, prefix))
	}
	if tunAddr6 != "" {
		if ip6, prefix6, err := parseTunAddr(tunAddr6); err == nil {
			_ = runPS(ctx, fmt.Sprintf(`$a = Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($a) { Remove-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress '%s' -PrefixLength %d -AddressFamily IPv6 -Confirm:$false -ErrorAction SilentlyContinue }`, tunName, ip6, prefix6))
		}
	}
	return nil
}

func parseTunAddr(addr string) (string, int, error) {
	ip, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		// Accepter aussi "ip" sans masque => /24.
		if ip := net.ParseIP(addr); ip != nil {
			return ip.String(), 24, nil
		}
		return "", 0, fmt.Errorf("netcfg: adresse TUN invalide %q", addr)
	}
	ones, _ := ipnet.Mask.Size()
	return ip.String(), ones, nil
}

// run exécute une commande externe.
func run(ctx context.Context, name string, args ...string) error {
	cmd := HiddenCmd(ctx, name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
