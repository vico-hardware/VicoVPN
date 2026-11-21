// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package main

// gateway : mode « Protection Maison ». Ce PC devient la passerelle des
// appareils de la maison (téléphone, TV, console…) :
//
//   - forwarder DNS UDP/TCP :53 sur les IP LAN du PC -> DNSPort Tor
//     (127.0.0.1:53) : les appareils résolvent leurs noms à travers Tor ;
//   - routage IPv4 (forwarding) sur la carte physique ET sur l'adaptateur
//     du tunnel (vicotor0) : le trafic des appareils suit la même table
//     de routage que le PC et entre dans le tunnel Tor.
//
// Règle de sûreté (coupe-circuit maison) : le forwarding n'est JAMAIS
// actif tant que le tunnel n'est pas sain. Windows Firewall ne filtre pas
// le trafic routé : si le tunnel tombe alors que le forwarding est actif,
// les paquets des appareils repartiraient directement vers la box (fuite
// de la vraie IP). Un chien de garde (500 ms + réveil immédiat à la mort
// de tor/tun2socks) coupe donc le forwarding dès que le tunnel n'est plus
// sain, et le rétablit quand il l'est de nouveau. Les transitions pilotées
// (désactivation, changement de pays, nouvelle tentative) coupent le
// forwarding AVANT de toucher au tunnel (Hold/Release).
//
// Le forwarding est posé en « store=active » : il ne survit jamais à un
// redémarrage (et le service le coupe de toute façon à son démarrage).

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vicovpn/vicovpn/internal/freebox"
	"github.com/vicovpn/vicovpn/internal/netcfg"
)

// gwTunAlias est l'adaptateur du tunnel Tor (créé par tun2socks).
const gwTunAlias = "vicotor0"

// gwRulePrefix : règles pare-feu entrantes de la passerelle. Elles ne sont
// PAS retirées par les coupe-circuits (voir netcfg.removeFirewallRules).
const gwRulePrefix = netcfg.RulePrefix + "GW-"

// dnsUpstream est le DNSPort de Tor (voir torstack_windows.go).
const dnsUpstream = "127.0.0.1:53"

// lanAddr décrit une adresse IPv4 LAN du PC.
type lanAddr struct {
	Alias  string // nom de la carte (« Ethernet », « Wi-Fi »…)
	IP     string
	Prefix int
	Box    string // passerelle par défaut de la carte (la box)
}

// Mask retourne le masque en notation pointée (255.255.255.0).
func (a lanAddr) Mask() string {
	m := net.CIDRMask(a.Prefix, 32)
	if m == nil {
		return ""
	}
	return net.IP(m).String()
}

// gateway porte l'état du mode passerelle.
type gateway struct {
	mu      sync.Mutex
	dir     string
	tor     *torStack
	on      bool      // passerelle demandée
	fwdOn   bool      // forwarding actuellement actif
	holds   int       // transitions en cours (forwarding interdit)
	lan     []lanAddr // adresses sur lesquelles le DNS écoute
	pcs     []net.PacketConn
	ls      []net.Listener
	fwdIdx  []int // index des interfaces où le forwarding a été activé
	stop    chan struct{}
	kick    chan struct{}
	lastErr string

	// Appareils (voir devices_windows.go).
	devs     map[string]*device  // par IP
	names    map[string]string   // noms donnés par l'utilisateur
	connPrev map[string][2]int64 // compteurs tun2socks par connexion
	pcUp     int64               // trafic du PC lui-même
	pcDown   int64
	pcConns  int

	// Mode Freebox (voir boxmode_windows.go).
	fbx      *freebox.Client
	boxMode  bool   // IPv6 + DHCP de la box coupés, ce PC distribue
	boxErr   string // pourquoi le mode Freebox n'a pas pu s'activer
	ipv6Kept bool   // la box a refusé de couper son IPv6
	// Profil Freebox qui bloque l'accès direct des appareils basculés.
	blockProfile int
	blocked      []string
	blockErr     string
	dhcp         *dhcpServer // serveur DHCP actif
	dhcpOld      *dhcpServer // serveur en phase de retour (NAK)
	waiting      []waitingHost

	statsState string // dernier état des statistiques tun2socks journalisé

	// Mode guidé (box sans pilotage : voir guided_windows.go).
	guidedMode bool        // protection active avec le DHCP de ce PC
	dhcpNormal *dhcpServer // DHCP « normal » (box en passerelle) hors protection
	boxDHCPAt  time.Time   // dernière fois que le DHCP de la box a répondu
}

func newGateway(dir string, tor *torStack) *gateway {
	return &gateway{dir: dir, tor: tor, kick: make(chan struct{}, 1)}
}

// Kick réveille le chien de garde (non bloquant). Appelé par la pile Tor
// quand un de ses processus meurt.
func (g *gateway) Kick() {
	select {
	case g.kick <- struct{}{}:
	default:
	}
}

// detectLAN retourne les adresses IPv4 privées des cartes physiques
// actives, avec leur préfixe et la passerelle (box) de la carte.
func detectLAN() ([]lanAddr, error) {
	ps := `Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object { ` +
		`$a = $_.Name; ` +
		`$gw = (Get-NetRoute -InterfaceAlias $a -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop; ` +
		`Get-NetIPAddress -InterfaceAlias $a -AddressFamily IPv4 -ErrorAction SilentlyContinue | ` +
		`ForEach-Object { "$a|$($_.IPAddress)|$($_.PrefixLength)|$gw" } }`
	outb, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(string(outb)))
	}
	var res []lanAddr
	for _, l := range strings.Split(string(outb), "\n") {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) < 3 {
			continue
		}
		p := net.ParseIP(strings.TrimSpace(f[1])).To4()
		if p == nil || !isLANv4(p) {
			continue
		}
		pl, err := strconv.Atoi(strings.TrimSpace(f[2]))
		if err != nil || pl < 8 || pl > 30 {
			continue
		}
		a := lanAddr{Alias: strings.TrimSpace(f[0]), IP: p.String(), Prefix: pl}
		if len(f) > 3 {
			if b := net.ParseIP(strings.TrimSpace(f[3])).To4(); b != nil && !b.Equal(net.IPv4zero) {
				a.Box = b.String()
			}
		}
		res = append(res, a)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("aucune adresse IPv4 privée sur une carte réseau active (le PC est-il branché à la box ?)")
	}
	return res, nil
}

// isLANv4 : plages privées utilisables par des appareils de la maison.
func isLANv4(p net.IP) bool {
	return p[0] == 10 || (p[0] == 172 && p[1] >= 16 && p[1] <= 31) ||
		(p[0] == 192 && p[1] == 168) || (p[0] == 100 && p[1] >= 64 && p[1] <= 127)
}

// setForwarding active/désactive le routage IPv4 sur TOUTES les cartes
// physiques (hygiène au démarrage, arrêt de la passerelle).
func setForwarding(enable bool) error {
	verb := "Disabled"
	if enable {
		verb = "Enabled"
	}
	ps := fmt.Sprintf(`Get-NetAdapter -Physical | ForEach-Object { `+
		`Set-NetIPInterface -InterfaceAlias $_.Name -AddressFamily IPv4 -Forwarding %s -ErrorAction SilentlyContinue }`, verb)
	return netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
}

// setIfForwarding change le forwarding IPv4 d'une interface par index,
// dans le magasin actif uniquement (jamais persistant). netsh est
// nettement plus rapide que PowerShell — important pour le coupe-circuit.
func setIfForwarding(idx int, enable bool) error {
	v := "disabled"
	if enable {
		v = "enabled"
	}
	out, err := netcfg.HiddenCmd(context.Background(), "netsh", "interface", "ipv4", "set", "interface",
		strconv.Itoa(idx), "forwarding="+v, "store=active").CombinedOutput()
	if err == nil {
		return nil
	}
	// Repli PowerShell (netsh localisé / paramètre refusé).
	verb := "Disabled"
	if enable {
		verb = "Enabled"
	}
	ps := fmt.Sprintf(`Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -Forwarding %s -PolicyStore ActiveStore -ErrorAction Stop`, idx, verb)
	if out2, err2 := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput(); err2 != nil {
		return fmt.Errorf("routage de l'interface %d impossible (netsh : %s / PowerShell : %s)",
			idx, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
	}
	return nil
}

// tunnelHealthy indique si le tunnel Tor est réellement utilisable :
// état « protégé », processus vivants ET adaptateur présent.
func (g *gateway) tunnelHealthy() (bool, int) {
	if g.tor == nil || !g.tor.Healthy() {
		return false, 0
	}
	ifc, err := net.InterfaceByName(gwTunAlias)
	if err != nil || ifc.Flags&net.FlagUp == 0 {
		return false, 0
	}
	return true, ifc.Index
}

// Start active la passerelle : règles pare-feu entrantes DNS, écouteurs
// DNS sur les IP LAN, chien de garde. Le forwarding n'est PAS activé ici :
// le chien de garde l'active seulement quand le tunnel est sain.
func (g *gateway) Start() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.on {
		return nil
	}
	lan, err := detectLAN()
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := allowGatewayDNS(); err != nil {
		return fmt.Errorf("pare-feu : %w", err)
	}
	if err := g.listenLocked(lan); err != nil {
		g.closeListenersLocked()
		removeGatewayRules()
		return err
	}
	g.lan = lan
	g.on = true
	g.lastErr = ""
	g.devs = map[string]*device{}
	g.connPrev = map[string][2]int64{}
	g.pcUp, g.pcDown, g.pcConns = 0, 0, 0
	g.loadNames()
	g.waiting = nil
	// Freebox associée : la box est sauvegardée, son IPv6 et son DHCP
	// coupés, et ce PC distribue les réglages. Sinon : réglage manuel.
	if freebox.LoadSaved(g.dir) != nil {
		_ = freebox.Restore(g.dir) // reste d'un plantage : état d'origine d'abord
	}
	g.takeoverLocked()
	if !g.boxMode {
		g.guidedTakeoverLocked()
	}
	g.stop = make(chan struct{})
	go g.watchdog(g.stop)
	go g.statsLoop(g.stop)
	logEvent(g.dir, "protection maison : en attente du tunnel ("+g.ipsLocked()+")")
	return nil
}

// Stop désactive la passerelle : forwarding coupé en premier, puis DNS et
// règles pare-feu.
func (g *gateway) Stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.on {
		return
	}
	g.on = false
	if g.stop != nil {
		close(g.stop)
		g.stop = nil
	}
	g.forwardOffLocked()
	_ = setForwarding(false) // balayage complet (cartes apparues entre-temps)
	g.closeListenersLocked()
	g.releaseGuidedLocked()
	g.releaseBoxLocked()
	if g.dhcpOld != nil || g.dhcpNormal != nil {
		removeGatewayDNSRules() // le DHCP répond encore (NAK) pendant le retour
	} else {
		removeGatewayRules()
	}
	g.lan = nil
	g.devs, g.connPrev = nil, nil
	logEvent(g.dir, "protection maison désactivée")
}

// On : la protection maison est-elle demandée ?
func (g *gateway) On() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.on
}

// Hold coupe immédiatement le forwarding et l'interdit jusqu'au Release
// correspondant. À appeler AVANT toute opération qui arrête/relance le
// tunnel, pour qu'aucun paquet d'appareil ne sorte en clair.
func (g *gateway) Hold() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.holds++
	g.forwardOffLocked()
}

// Release lève un Hold ; le chien de garde réévalue aussitôt.
func (g *gateway) Release() {
	g.mu.Lock()
	if g.holds > 0 {
		g.holds--
	}
	g.mu.Unlock()
	g.Kick()
}

// forwardOffLocked coupe le forwarding sur les interfaces où il a été
// activé (rapide, netsh par index).
func (g *gateway) forwardOffLocked() {
	if !g.fwdOn && len(g.fwdIdx) == 0 {
		return
	}
	for _, idx := range g.fwdIdx {
		_ = setIfForwarding(idx, false)
	}
	g.fwdIdx = nil
	if g.fwdOn {
		g.fwdOn = false
		logEvent(g.dir, "protection maison : routage coupé (tunnel indisponible)")
	}
}

// forwardOnLocked active le forwarding sur les cartes LAN et le tunnel.
func (g *gateway) forwardOnLocked(tunIdx int) error {
	idxs := []int{tunIdx}
	seen := map[string]bool{}
	for _, a := range g.lan {
		if seen[a.Alias] {
			continue
		}
		seen[a.Alias] = true
		ifc, err := net.InterfaceByName(a.Alias)
		if err != nil {
			return fmt.Errorf("carte %q introuvable : %w", a.Alias, err)
		}
		idxs = append(idxs, ifc.Index)
	}
	for _, idx := range idxs {
		if err := setIfForwarding(idx, true); err != nil {
			// Échec partiel : tout remettre à l'arrêt.
			_ = setIfForwarding(idx, false)
			for _, done := range g.fwdIdx {
				_ = setIfForwarding(done, false)
			}
			g.fwdIdx = nil
			return err
		}
		g.fwdIdx = append(g.fwdIdx, idx)
	}
	g.fwdOn = true
	logEvent(g.dir, "protection maison : protégée — appareils routés dans le tunnel ("+g.ipsLocked()+")")
	return nil
}

// watchdog applique la règle « forwarding seulement si tunnel sain ».
func (g *gateway) watchdog(stop chan struct{}) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	lastLANCheck := time.Now()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		case <-g.kick:
		}
		healthy, tunIdx := g.tunnelHealthy()

		g.mu.Lock()
		if !g.on {
			g.mu.Unlock()
			return
		}
		switch {
		case (!healthy || g.holds > 0) && g.fwdOn:
			g.forwardOffLocked()
		case healthy && g.holds == 0 && !g.fwdOn:
			if err := g.forwardOnLocked(tunIdx); err != nil {
				if g.lastErr != err.Error() {
					logEvent(g.dir, "protection maison : "+err.Error())
				}
				g.lastErr = err.Error()
			} else {
				g.lastErr = ""
			}
		}
		needLAN := time.Since(lastLANCheck) > 10*time.Second
		g.mu.Unlock()

		if needLAN {
			lastLANCheck = time.Now()
			g.checkLAN()
		}
	}
}

// checkLAN vérifie que les IP LAN écoutées existent toujours (bail DHCP
// changé, câble/Wi-Fi changé) et ré-ouvre les écouteurs sinon.
func (g *gateway) checkLAN() {
	present := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				present[n.IP.String()] = true
			}
		}
	}
	g.mu.Lock()
	missing := false
	for _, a := range g.lan {
		if !present[a.IP] {
			missing = true
		}
	}
	g.mu.Unlock()
	if !missing {
		return
	}
	lan, err := detectLAN()
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.on {
		return
	}
	// Adresses changées : le forwarding est recalculé sur les nouvelles
	// cartes au prochain tour du chien de garde.
	g.forwardOffLocked()
	g.closeListenersLocked()
	if err != nil {
		g.lan = nil
		g.lastErr = err.Error()
		logEvent(g.dir, "protection maison : réseau perdu ("+err.Error()+")")
		return
	}
	if err := g.listenLocked(lan); err != nil {
		g.closeListenersLocked()
		g.lan = nil
		g.lastErr = err.Error()
		logEvent(g.dir, "protection maison : "+err.Error())
		return
	}
	g.lan = lan
	g.lastErr = ""
	logEvent(g.dir, "protection maison : nouvelle adresse du PC ("+g.ipsLocked()+") — à reporter sur les appareils")
}

// Status retourne l'état de la passerelle au format ctl :
//
//	OK inactif
//	OK <protege|connexion|bloque> ip=.. masque=.. box=.. appareils=N fwd=0|1 info=<texte libre>
func (g *gateway) Status() string {
	healthy, _ := g.tunnelHealthy()
	torSt, torInfo := "desactive", ""
	if g.tor != nil {
		torSt, torInfo = g.tor.Status()
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.on {
		return "OK inactif"
	}
	st, info := "connexion", "en attente du tunnel Tor"
	switch {
	case g.fwdOn && (g.boxMode || g.guidedMode):
		st, info = "protege", "appareils routés dans le tunnel — réglages distribués automatiquement"
	case g.fwdOn:
		st, info = "protege", "appareils routés dans le tunnel"
	case g.lastErr != "":
		st, info = "bloque", g.lastErr
	case torSt == "bloque":
		st, info = "bloque", "tunnel bloqué : "+torInfo+" — appareils coupés d'Internet"
	case torSt == "desactive":
		st, info = "bloque", "aucun tunnel Tor actif — choisis une sortie Tor"
	case torSt == "connexion":
		st, info = "connexion", torInfo+" — appareils en attente, rien ne sort en clair"
	case healthy:
		st, info = "connexion", "activation du routage…"
	}
	var b strings.Builder
	b.WriteString("OK " + st)
	if len(g.lan) > 0 {
		a := g.lan[0]
		fmt.Fprintf(&b, " ip=%s masque=%s box=%s", a.IP, a.Mask(), dashIfEmpty(a.Box))
	}
	if g.guidedMode && !g.boxDHCPAt.IsZero() && time.Since(g.boxDHCPAt) < 10*time.Minute {
		info += " — attention : le DHCP de la box répond encore, coupe-le"
	}
	fmt.Fprintf(&b, " appareils=%d attente=%d auto=%d guide=%d fwd=%d info=%s", g.activeDevicesLocked(), len(g.waiting), b2i(g.boxMode), b2i(g.guidedMode), b2i(g.fwdOn), info)
	return b.String()
}

// Info retourne les réglages prévus pour les appareils sans activer la
// passerelle (affichage de l'onglet avant activation).
func gatewayInfo() string {
	lan, err := detectLAN()
	if err != nil {
		return "ERR " + err.Error()
	}
	a := lan[0]
	return fmt.Sprintf("OK ip=%s masque=%s box=%s carte=%s", a.IP, a.Mask(), dashIfEmpty(a.Box), strings.ReplaceAll(a.Alias, " ", "_"))
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (g *gateway) ipsLocked() string {
	ips := make([]string, 0, len(g.lan))
	for _, a := range g.lan {
		ips = append(ips, a.IP)
	}
	return strings.Join(ips, ", ")
}

// activeDevicesLocked compte les appareils actifs (vus depuis 10 min).
func (g *gateway) activeDevicesLocked() int {
	n := 0
	for _, d := range g.devs {
		if time.Since(d.Last) < 10*time.Minute {
			n++
		}
	}
	return n
}

// listenLocked ouvre les écouteurs DNS sur chaque IP LAN.
func (g *gateway) listenLocked(lan []lanAddr) error {
	for _, a := range lan {
		addr := net.JoinHostPort(a.IP, "53")
		pc, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return fmt.Errorf("DNS UDP %s indisponible (port 53 déjà pris ? ex. Partage de connexion Internet) : %w", addr, err)
		}
		g.pcs = append(g.pcs, pc)
		go g.serveUDP(pc)

		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			return fmt.Errorf("DNS TCP %s indisponible : %w", addr, err)
		}
		g.ls = append(g.ls, ln)
		go g.serveTCP(ln)
	}
	return nil
}

func (g *gateway) closeListenersLocked() {
	for _, pc := range g.pcs {
		_ = pc.Close()
	}
	for _, l := range g.ls {
		_ = l.Close()
	}
	g.pcs, g.ls = nil, nil
}

// fromLAN refuse les requêtes qui ne viennent pas d'une adresse privée
// (le PC ne doit pas devenir un résolveur ouvert).
func fromLAN(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	p := net.ParseIP(host).To4()
	return p != nil && isLANv4(p)
}

// serveUDP relaie les requêtes DNS UDP vers le DNSPort Tor.
func (g *gateway) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if !fromLAN(src) || n < 12 {
			continue
		}
		g.countDNS(src, n, 0)
		pkt := append([]byte(nil), buf[:n]...)
		go func() {
			up, err := net.DialTimeout("udp", dnsUpstream, 3*time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			_ = up.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := up.Write(pkt); err != nil {
				return
			}
			resp := make([]byte, 4096)
			m, err := up.Read(resp)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(resp[:m], src)
			g.countDNS(src, 0, m)
		}()
	}
}

// serveTCP relaie les requêtes DNS TCP (troncature ou gros messages).
func (g *gateway) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if !fromLAN(c.RemoteAddr()) {
			_ = c.Close()
			continue
		}
		g.countDNS(c.RemoteAddr(), 0, 0)
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			up, err := net.DialTimeout("tcp", dnsUpstream, 3*time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			_ = up.SetDeadline(time.Now().Add(30 * time.Second))
			go func() {
				n, _ := io.Copy(up, c)
				g.countDNS(c.RemoteAddr(), int(n), 0)
				_ = up.Close()
			}()
			n, _ := io.Copy(c, up)
			g.countDNS(c.RemoteAddr(), 0, int(n))
		}(c)
	}
}

// allowGatewayDNS ouvre le port 53 (UDP+TCP) en entrée, uniquement depuis
// le sous-réseau local et uniquement pour ce programme.
func allowGatewayDNS() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	removeGatewayRules()
	// DHCP (mode Freebox) : les demandes arrivent de 0.0.0.0, donc pas de
	// restriction « sous-réseau local » possible ; port 67 de ce programme.
	ps := fmt.Sprintf(`New-NetFirewallRule -DisplayName '%sDHCP' -Direction Inbound -Action Allow `+
		`-Protocol UDP -LocalPort 67 -RemotePort 68 -Profile Any -Program '%s' -ErrorAction Stop | Out-Null`,
		gwRulePrefix, strings.ReplaceAll(exe, "'", "''"))
	if out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	for _, proto := range []string{"UDP", "TCP"} {
		ps := fmt.Sprintf(`New-NetFirewallRule -DisplayName '%sDNS-%s' -Direction Inbound -Action Allow `+
			`-Protocol %s -LocalPort 53 -RemoteAddress LocalSubnet -Profile Any -Program '%s' -ErrorAction Stop | Out-Null`,
			gwRulePrefix, proto, proto, strings.ReplaceAll(exe, "'", "''"))
		if out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// removeGatewayDNSRules retire les règles DNS et garde celle du DHCP.
func removeGatewayDNSRules() {
	_ = netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%sDNS-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, gwRulePrefix)).Run()
}

func removeGatewayRules() {
	_ = netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%s*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, gwRulePrefix)).Run()
}
