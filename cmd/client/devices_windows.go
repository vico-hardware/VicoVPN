// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package main

// devices : liste des appareils de la protection maison — nom, adresses,
// volume de données échangé.
//
//   - Volume : statistiques de tun2socks (API REST locale, une entrée par
//     connexion avec IP source et octets montants/descendants) + octets
//     DNS relayés par le PC. Compté depuis l'activation de la passerelle.
//   - Adresse MAC : table de voisinage IPv4 de Windows (Get-NetNeighbor).
//   - Nom : nom donné dans l'interface (prioritaire, mémorisé dans
//     appareils.json), sinon nom connu de la box (DNS inverse), sinon
//     NetBIOS (PC Windows, NAS…), sinon mDNS (iPhone, Mac, Android…).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vicovpn/vicovpn/internal/netcfg"
)

// device décrit un appareil vu par la passerelle.
type device struct {
	IP      string
	MAC     string
	Name    string
	NameSrc string // perso | box | netbios | mdns
	Up      int64  // octets envoyés par l'appareil vers Internet
	Down    int64  // octets reçus d'Internet
	Conns   int    // connexions actives
	Last    time.Time
	tried   time.Time // dernière recherche de nom
	viaDHCP bool      // adresse distribuée par ce PC
}

// namesFile mémorise les noms donnés aux appareils (clé mac:… ou ip:…).
const namesFile = "appareils.json"

func (g *gateway) loadNames() {
	g.names = map[string]string{}
	b, err := os.ReadFile(filepath.Join(g.dir, namesFile))
	if err == nil {
		_ = json.Unmarshal(b, &g.names)
	}
}

func (g *gateway) saveNamesLocked() {
	b, err := json.MarshalIndent(g.names, "", "  ")
	if err == nil {
		_ = os.WriteFile(filepath.Join(g.dir, namesFile), b, 0o600)
	}
}

// customNameLocked retourne le nom donné par l'utilisateur, s'il existe.
func (g *gateway) customNameLocked(d *device) string {
	if d.MAC != "" {
		if n := g.names["mac:"+d.MAC]; n != "" {
			return n
		}
	}
	return g.names["ip:"+d.IP]
}

// SetName nomme un appareil (nom vide = retour au nom automatique).
func (g *gateway) SetName(ip, name string) error {
	name = cleanName(name)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.names == nil {
		g.loadNames()
	}
	key := "ip:" + ip
	d := g.devs[ip]
	if d != nil && d.MAC != "" {
		key = "mac:" + d.MAC
	}
	delete(g.names, "ip:"+ip)
	if name == "" {
		delete(g.names, key)
		if d != nil {
			d.Name, d.NameSrc, d.tried = "", "", time.Time{}
		}
	} else {
		g.names[key] = name
		if d != nil {
			d.Name, d.NameSrc = name, "perso"
		}
	}
	g.saveNamesLocked()
	return nil
}

// cleanName : une ligne, sans séparateur du protocole, 40 caractères max.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '|' || r < 32 {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	for utf8.RuneCountInString(s) > 40 {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// devLocked retourne (et crée au besoin) l'appareil d'adresse ip.
func (g *gateway) devLocked(ip string) *device {
	d := g.devs[ip]
	if d == nil {
		d = &device{IP: ip}
		if n := g.customNameLocked(d); n != "" {
			d.Name, d.NameSrc = n, "perso"
		}
		g.devs[ip] = d
	}
	return d
}

// isDeviceLocked : l'adresse appartient au réseau de la box et n'est pas
// celle du PC (le trafic du PC lui-même sort du tunnel avec une autre IP
// source).
func (g *gateway) isDeviceLocked(ip string) bool {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return false
	}
	for _, a := range g.lan {
		if a.IP == ip {
			return false
		}
		_, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", a.IP, a.Prefix))
		if err == nil && n.Contains(p) {
			return true
		}
	}
	return false
}

// countDNS ajoute le trafic DNS relayé à l'appareil.
func (g *gateway) countDNS(addr net.Addr, up, down int) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.devs == nil {
		return
	}
	d := g.devLocked(host)
	d.Up += int64(up)
	d.Down += int64(down)
	d.Last = time.Now()
}

// ---------------------------------------------------------------------
// Statistiques tun2socks
// ---------------------------------------------------------------------

type t2sSnapshot struct {
	Connections []struct {
		ID       string `json:"id"`
		Metadata struct {
			SourceIP string `json:"sourceIP"`
		} `json:"metadata"`
		Upload   int64 `json:"upload"`
		Download int64 `json:"download"`
	} `json:"connections"`
}

// statsLoop relève les compteurs toutes les 2 s et cherche les noms et
// adresses MAC des appareils toutes les 20 s.
func (g *gateway) statsLoop(stop chan struct{}) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	httpc := &http.Client{Timeout: 1500 * time.Millisecond}
	n := 0
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		g.pollConnections(httpc)
		g.syncBlocked()
		if n%10 == 0 {
			g.resolveDevices()
			g.boxHosts()
		}
		if n%150 == 75 {
			go g.pcLeaseCheck()
		}
		n++
	}
}

func (g *gateway) pollConnections(httpc *http.Client) {
	if g.tor == nil {
		return
	}
	addr, token := g.tor.API()
	if addr == "" {
		return
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/connections", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpc.Do(req)
	if err != nil {
		g.statsDiag("indisponibles (" + err.Error() + ")")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		g.statsDiag(fmt.Sprintf("refusées (HTTP %d)", resp.StatusCode))
		return
	}
	g.statsDiag("actives")
	var snap t2sSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.devs == nil {
		return
	}
	now := time.Now()
	next := make(map[string][2]int64, len(snap.Connections))
	conns := map[string]int{}
	for _, c := range snap.Connections {
		prev := g.connPrev[c.ID]
		du, dd := c.Upload-prev[0], c.Download-prev[1]
		if du < 0 {
			du = 0
		}
		if dd < 0 {
			dd = 0
		}
		next[c.ID] = [2]int64{c.Upload, c.Download}
		src := c.Metadata.SourceIP
		if g.isDeviceLocked(src) {
			d := g.devLocked(src)
			d.Up += du
			d.Down += dd
			d.Last = now
			conns[src]++
		} else {
			g.pcUp += du
			g.pcDown += dd
			conns[""]++
		}
	}
	g.connPrev = next
	for ip, d := range g.devs {
		d.Conns = conns[ip]
	}
	g.pcConns = conns[""]
}

// statsDiag note une seule fois au journal l'état des statistiques.
func (g *gateway) statsDiag(st string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.statsState == st || (g.statsState != "" && strings.HasPrefix(g.statsState, "indisponibles") && strings.HasPrefix(st, "indisponibles")) {
		return
	}
	g.statsState = st
	logEvent(g.dir, "protection maison : statistiques de trafic "+st)
}

// ---------------------------------------------------------------------
// Noms et adresses MAC
// ---------------------------------------------------------------------

// resolveDevices complète MAC et noms (hors verrou pendant le réseau).
func (g *gateway) resolveDevices() {
	g.mu.Lock()
	if g.devs == nil {
		g.mu.Unlock()
		return
	}
	var todo []string
	needMAC := false
	box := ""
	if len(g.lan) > 0 {
		box = g.lan[0].Box
	}
	for ip, d := range g.devs {
		if d.MAC == "" {
			needMAC = true
		}
		if d.NameSrc == "" && time.Since(d.tried) > 2*time.Minute {
			d.tried = time.Now()
			todo = append(todo, ip)
		}
	}
	g.mu.Unlock()

	if needMAC {
		macs := neighborMACs()
		g.mu.Lock()
		for ip, d := range g.devs {
			if m := macs[ip]; m != "" && d.MAC != m {
				d.MAC = m
				if n := g.customNameLocked(d); n != "" {
					d.Name, d.NameSrc = n, "perso"
				}
			}
		}
		g.mu.Unlock()
	}

	for _, ip := range todo {
		go func(ip string) {
			name, src := lookupName(ip, box)
			if name == "" {
				return
			}
			g.mu.Lock()
			defer g.mu.Unlock()
			if d := g.devs[ip]; d != nil && d.NameSrc == "" {
				d.Name, d.NameSrc = name, src
			}
		}(ip)
	}
}

// neighborMACs lit la table de voisinage IPv4 (ip -> MAC).
func neighborMACs() map[string]string {
	out := map[string]string{}
	b, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.State -in @('Reachable','Stale','Delay','Probe','Permanent') -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' } | `+
			`ForEach-Object { "$($_.IPAddress)|$($_.LinkLayerAddress)" }`).Output()
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) == 2 && f[1] != "" {
			out[f[0]] = strings.ToUpper(strings.ReplaceAll(f[1], "-", ":"))
		}
	}
	return out
}

// lookupName essaie la box, NetBIOS puis mDNS.
func lookupName(ip, box string) (string, string) {
	if box != "" {
		if n := boxPTR(ip, box); n != "" {
			return n, "box"
		}
	}
	if n := netbiosName(ip); n != "" {
		return n, "netbios"
	}
	if n := mdnsName(ip); n != "" {
		return n, "mdns"
	}
	return "", ""
}

// shortHost garde la première étiquette d'un nom DNS et écarte les noms
// génériques fabriqués à partir de l'adresse.
func shortHost(name, ip string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	if name == "" || strings.Contains(name, strings.ReplaceAll(ip, ".", "-")) ||
		strings.Contains(name, ip) || net.ParseIP(name) != nil {
		return ""
	}
	return cleanName(name)
}

// boxPTR interroge le DNS de la box (DNS inverse des baux DHCP).
func boxPTR(ip, box string) string {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", net.JoinHostPort(box, "53"))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	names, err := r.LookupAddr(ctx, ip)
	if err != nil {
		return ""
	}
	for _, n := range names {
		if s := shortHost(n, ip); s != "" {
			return s
		}
	}
	return ""
}

// netbiosName : requête « node status » (UDP 137).
func netbiosName(ip string) string {
	c, err := net.DialTimeout("udp4", net.JoinHostPort(ip, "137"), time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	q := make([]byte, 0, 50)
	id := make([]byte, 2)
	_, _ = rand.Read(id)
	q = append(q, id...)
	q = append(q, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	// Nom « * » encodé (first-level encoding NetBIOS, 32 octets).
	q = append(q, 0x20)
	raw := make([]byte, 16)
	raw[0] = '*'
	for _, b := range raw {
		q = append(q, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	q = append(q, 0, 0x00, 0x21, 0x00, 0x01) // NBSTAT, IN
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(q); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	b := buf[:n]
	off := skipDNSName(b, 12)
	if off < 0 || off+10 > len(b) {
		return ""
	}
	off += 10 // type, classe, TTL, longueur
	if off >= len(b) {
		return ""
	}
	count := int(b[off])
	off++
	for i := 0; i < count && off+18 <= len(b); i++ {
		name := strings.TrimSpace(string(b[off : off+15]))
		suffix := b[off+15]
		flags := binary.BigEndian.Uint16(b[off+16 : off+18])
		off += 18
		if suffix == 0x00 && flags&0x8000 == 0 && name != "" {
			return cleanName(name)
		}
	}
	return ""
}

// mdnsName : requête mDNS unicast PTR sur l'appareil (UDP 5353).
func mdnsName(ip string) string {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return ""
	}
	c, err := net.DialTimeout("udp4", net.JoinHostPort(ip, "5353"), time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	q := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, lbl := range []string{
		fmt.Sprint(p[3]), fmt.Sprint(p[2]), fmt.Sprint(p[1]), fmt.Sprint(p[0]), "in-addr", "arpa",
	} {
		q = append(q, byte(len(lbl)))
		q = append(q, lbl...)
	}
	q = append(q, 0, 0x00, 0x0c, 0x80, 0x01) // PTR, IN + réponse unicast
	_ = c.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	if _, err := c.Write(q); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	b := buf[:n]
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		if off = skipDNSName(b, off); off < 0 || off+4 > len(b) {
			return ""
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if off = skipDNSName(b, off); off < 0 || off+10 > len(b) {
			return ""
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10
		if off+rdlen > len(b) {
			return ""
		}
		if typ == 12 {
			if name, ok := readDNSName(b, off); ok {
				return shortHost(name, ip)
			}
		}
		off += rdlen
	}
	return ""
}

// skipDNSName retourne la position après un nom DNS (étiquettes ou
// pointeur de compression), -1 si le message est mal formé.
func skipDNSName(b []byte, off int) int {
	for off < len(b) {
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1
		case l&0xC0 == 0xC0:
			if off+2 > len(b) {
				return -1
			}
			return off + 2
		default:
			off += 1 + l
		}
	}
	return -1
}

// readDNSName décode un nom DNS avec pointeurs de compression.
func readDNSName(b []byte, off int) (string, bool) {
	var labels []string
	for jumps := 0; jumps < 20 && off < len(b); {
		l := int(b[off])
		switch {
		case l == 0:
			return strings.Join(labels, "."), true
		case l&0xC0 == 0xC0:
			if off+2 > len(b) {
				return "", false
			}
			off = int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3FFF)
			jumps++
		default:
			if off+1+l > len(b) {
				return "", false
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", false
}

// ---------------------------------------------------------------------
// Réponse ctl
// ---------------------------------------------------------------------

// Devices retourne la liste pour l'interface :
//
//	OK
//	pc|-|-|Ce PC|-|<down>|<up>|<conns>|0
//	dev|<ip>|<mac>|<nom>|<source du nom>|<down>|<up>|<conns>|<vu il y a (s)>
func (g *gateway) Devices() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.on || g.devs == nil {
		return "OK"
	}
	var b strings.Builder
	b.WriteString("OK\n")
	fmt.Fprintf(&b, "pc|-|-|Ce PC|-|%d|%d|%d|0\n", g.pcDown, g.pcUp, g.pcConns)
	list := make([]*device, 0, len(g.devs))
	for ip, d := range g.devs {
		if time.Since(d.Last) > 30*time.Minute {
			delete(g.devs, ip)
			continue
		}
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool {
		ti, tj := list[i].Up+list[i].Down, list[j].Up+list[j].Down
		if ti != tj {
			return ti > tj
		}
		return list[i].IP < list[j].IP
	})
	for _, d := range list {
		fmt.Fprintf(&b, "dev|%s|%s|%s|%s|%d|%d|%d|%d\n",
			d.IP, dashIfEmpty(d.MAC), dashIfEmpty(d.Name), dashIfEmpty(d.NameSrc),
			d.Down, d.Up, d.Conns, int(time.Since(d.Last).Seconds()))
	}
	// Appareils encore branchés directement sur la box (pas encore basculés).
	for _, w := range g.waiting {
		fmt.Fprintf(&b, "wait|%s|%s|%s|freebox|0|0|0|0\n", w.IP, dashIfEmpty(w.MAC), dashIfEmpty(cleanName(w.Name)))
	}
	return strings.TrimRight(b.String(), "\n")
}

// randomToken : jeton de l'API REST locale de tun2socks.
func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// freeLocalPort réserve brièvement un port TCP libre sur 127.0.0.1.
func freeLocalPort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr, nil
}
