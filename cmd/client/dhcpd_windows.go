// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package main

// dhcpd : serveur DHCP de la protection maison (mode Freebox). Le DHCP de
// la box est coupé pendant la protection ; ce PC distribue à chaque
// appareil une adresse, avec lui-même comme passerelle et comme DNS.
//
//   - Même adresse que celle donnée par la box (baux relus avant coupure),
//     baux statiques de la box respectés.
//   - Bail court (4 min) : à la désactivation, les appareils reviennent
//     vite à la box. Pendant 6 min après l'arrêt, le serveur répond NAK à
//     tout renouvellement, ce qui renvoie l'appareil vers le DHCP de la box.
//   - Ce PC lui-même (s'il redemande son adresse) reçoit la box comme
//     passerelle.
//   - Les appareils qui se reconnectent (INIT-REBOOT) avec leur ancienne
//     adresse reçoivent un ACK immédiat avec ce PC comme passerelle.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	dhcpLeaseTime = 4 * time.Minute
	dhcpRetour    = 6 * time.Minute
	dhcpLeaseFile = "dhcp-baux.json"
)

type dhcpLease struct {
	MAC    string    `json:"mac"`
	IP     string    `json:"ip"`
	Host   string    `json:"host"`
	Expiry time.Time `json:"expiry"`
}

type dhcpServer struct {
	mu       sync.Mutex
	dir      string
	conn     net.PacketConn
	self     net.IP // IP LAN du PC (passerelle + DNS des appareils)
	mask     net.IPMask
	box      net.IP
	start    uint32 // plage d'adresses distribuées
	end      uint32
	leases   map[string]*dhcpLease // par MAC
	prefer   map[string]string     // MAC -> IP donnée par la box
	reserved map[string]string     // IP -> MAC (baux statiques de la box)
	selfMACs map[string]bool
	arp      map[string]string // IP -> MAC (table de voisinage)
	retour   bool
	closed   bool
	onLease  func(mac, ip, host string)
	// normal : protection arrêtée en mode guidé (DHCP de la box coupé à la
	// main) — le PC distribue la box comme passerelle et DNS, pour que la
	// maison garde le réseau tant que le DHCP de la box n'est pas rétabli.
	normal bool
	// onBoxDHCP : un appareil a accepté une offre de la box (son DHCP
	// répond donc encore).
	onBoxDHCP func()
}

// SetNormal bascule entre « protection » (passerelle = PC) et « normal »
// (passerelle = box).
func (s *dhcpServer) SetNormal(on bool) {
	s.mu.Lock()
	s.normal = on
	s.mu.Unlock()
}

func ip2u(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }
func u2ip(v uint32) net.IP {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// newDHCPServer prépare le serveur pour le réseau de lan, avec la plage
// [start, end] (vide = calculée sur le sous-réseau).
func newDHCPServer(dir string, lan lanAddr, start, end string, prefer map[string]string, reserved map[string]string) (*dhcpServer, error) {
	self := net.ParseIP(lan.IP).To4()
	box := net.ParseIP(lan.Box).To4()
	if self == nil || box == nil {
		return nil, fmt.Errorf("DHCP : adresse du PC ou de la box inconnue")
	}
	mask := net.CIDRMask(lan.Prefix, 32)
	netw := self.Mask(mask)
	bcast := ip2u(netw) | ^binary.BigEndian.Uint32(mask)
	s := &dhcpServer{
		dir: dir, self: self, mask: mask, box: box,
		leases: map[string]*dhcpLease{}, prefer: prefer, reserved: reserved,
		selfMACs: map[string]bool{}, arp: map[string]string{},
	}
	if a, b := net.ParseIP(start).To4(), net.ParseIP(end).To4(); a != nil && b != nil &&
		a.Mask(mask).Equal(netw) && b.Mask(mask).Equal(netw) && ip2u(a) <= ip2u(b) {
		s.start, s.end = ip2u(a), ip2u(b)
	} else {
		s.start, s.end = ip2u(netw)+10, bcast-5
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			if len(i.HardwareAddr) == 6 {
				s.selfMACs[strings.ToUpper(i.HardwareAddr.String())] = true
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, dhcpLeaseFile)); err == nil {
		var list []*dhcpLease
		if json.Unmarshal(b, &list) == nil {
			for _, l := range list {
				if l.MAC != "" && l.IP != "" {
					s.leases[l.MAC] = l
				}
			}
		}
	}
	return s, nil
}

// Start ouvre le port 67 sur l'IP LAN du PC (Windows y délivre aussi les
// diffusions reçues par cette carte).
func (s *dhcpServer) Start() error {
	pc, err := net.ListenPacket("udp4", net.JoinHostPort(s.self.String(), "67"))
	if err != nil {
		return fmt.Errorf("DHCP : port 67 indisponible (autre serveur DHCP ou Partage de connexion Internet ?) : %w", err)
	}
	s.conn = pc
	go s.serve()
	go s.arpLoop()
	return nil
}

// Retour : la protection est arrêtée. Le serveur répond NAK aux
// renouvellements pendant dhcpRetour, puis se ferme.
func (s *dhcpServer) Retour() {
	s.mu.Lock()
	s.retour = true
	s.mu.Unlock()
	time.AfterFunc(dhcpRetour, s.Close)
}

func (s *dhcpServer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// Leases retourne une copie des baux actifs.
func (s *dhcpServer) Leases() []dhcpLease {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []dhcpLease
	for _, l := range s.leases {
		if time.Now().Before(l.Expiry) {
			out = append(out, *l)
		}
	}
	return out
}

func (s *dhcpServer) arpLoop() {
	for {
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return
		}
		m := neighborMACs()
		s.mu.Lock()
		s.arp = m
		s.mu.Unlock()
		time.Sleep(60 * time.Second)
	}
}

func (s *dhcpServer) saveLocked() {
	list := make([]*dhcpLease, 0, len(s.leases))
	for _, l := range s.leases {
		list = append(list, l)
	}
	if b, err := json.MarshalIndent(list, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(s.dir, dhcpLeaseFile), b, 0o600)
	}
}

// inSubnet : adresse du réseau local, ni réseau ni diffusion, ni PC ni box.
func (s *dhcpServer) inSubnet(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil || !ip.Mask(s.mask).Equal(s.self.Mask(s.mask)) {
		return false
	}
	host := ip2u(ip) &^ binary.BigEndian.Uint32(s.mask)
	return host != 0 && host != ^binary.BigEndian.Uint32(s.mask)
}

// usableLocked : l'adresse peut-elle être donnée à mac ?
func (s *dhcpServer) usableLocked(ip net.IP, mac string) bool {
	if ip.Equal(s.self) {
		return s.selfMACs[mac] // le PC garde son adresse
	}
	if !s.inSubnet(ip) || ip.Equal(s.box) {
		return false
	}
	str := ip.String()
	if owner, ok := s.reserved[str]; ok && owner != mac {
		return false
	}
	for m, l := range s.leases {
		if m != mac && l.IP == str && time.Now().Before(l.Expiry) {
			return false
		}
	}
	if owner, ok := s.arp[str]; ok && owner != mac {
		return false
	}
	return true
}

// pickLocked choisit l'adresse à proposer.
func (s *dhcpServer) pickLocked(mac string, requested net.IP) net.IP {
	if s.selfMACs[mac] {
		return s.self
	}
	for _, cand := range []string{s.reservedFor(mac), s.leaseIP(mac), s.prefer[mac]} {
		if ip := net.ParseIP(cand).To4(); ip != nil && s.usableLocked(ip, mac) {
			return ip
		}
	}
	if requested != nil && s.usableLocked(requested, mac) {
		return requested
	}
	for v := s.start; v <= s.end; v++ {
		ip := u2ip(v)
		if _, pref := s.preferredByOther(ip.String(), mac); pref {
			continue
		}
		if s.usableLocked(ip, mac) {
			return ip
		}
	}
	return nil
}

func (s *dhcpServer) reservedFor(mac string) string {
	for ip, m := range s.reserved {
		if m == mac {
			return ip
		}
	}
	return ""
}

func (s *dhcpServer) leaseIP(mac string) string {
	if l := s.leases[mac]; l != nil {
		return l.IP
	}
	return ""
}

// preferredByOther : adresse déjà attribuée par la box à un autre appareil.
func (s *dhcpServer) preferredByOther(ip, mac string) (string, bool) {
	for m, p := range s.prefer {
		if p == ip && m != mac {
			return m, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------
// Protocole
// ---------------------------------------------------------------------

const (
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpDecline  = 4
	dhcpAck      = 5
	dhcpNak      = 6
	dhcpRelease  = 7
	dhcpInform   = 8
)

type dhcpMsg struct {
	raw     []byte
	xid     []byte
	flags   uint16
	ciaddr  net.IP
	giaddr  net.IP
	chaddr  []byte
	mac     string
	typ     byte
	reqIP   net.IP
	server  net.IP
	host    string
	hasOpts bool
}

func parseDHCP(b []byte) (*dhcpMsg, bool) {
	if len(b) < 240 || b[0] != 1 || b[1] != 1 || b[2] != 6 {
		return nil, false
	}
	if binary.BigEndian.Uint32(b[236:240]) != 0x63825363 {
		return nil, false
	}
	m := &dhcpMsg{
		raw: b, xid: b[4:8], flags: binary.BigEndian.Uint16(b[10:12]),
		ciaddr: net.IP(b[12:16]).To4(), giaddr: net.IP(b[24:28]).To4(), chaddr: b[28:44],
	}
	m.mac = strings.ToUpper(net.HardwareAddr(b[28:34]).String())
	for i := 240; i < len(b); {
		code := b[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		l := int(b[i+1])
		if i+2+l > len(b) {
			break
		}
		v := b[i+2 : i+2+l]
		switch code {
		case 53:
			if l == 1 {
				m.typ = v[0]
			}
		case 50:
			if l == 4 {
				m.reqIP = net.IP(append([]byte(nil), v...))
			}
		case 54:
			if l == 4 {
				m.server = net.IP(append([]byte(nil), v...))
			}
		case 12:
			m.host = cleanName(string(v))
		}
		i += 2 + l
	}
	return m, m.typ != 0
}

func (s *dhcpServer) serve() {
	buf := make([]byte, 1500)
	for {
		n, _, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		m, ok := parseDHCP(append([]byte(nil), buf[:n]...))
		if !ok || !m.giaddr.Equal(net.IPv4zero) {
			continue // pas de relais DHCP sur un réseau domestique
		}
		s.handle(m)
	}
}

func (s *dhcpServer) handle(m *dhcpMsg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	now := time.Now()
	switch m.typ {
	case dhcpDiscover:
		if s.retour {
			return // la box répond de nouveau
		}
		ip := s.pickLocked(m.mac, m.reqIP)
		if ip == nil {
			logEvent(s.dir, "DHCP : plus d'adresse libre pour "+m.mac)
			return
		}
		s.reply(m, dhcpOffer, ip)

	case dhcpRequest:
		if m.server != nil && !m.server.Equal(s.self) {
			// L'appareil a choisi un autre serveur : si c'est la box, son
			// DHCP fonctionne encore.
			if m.server.Equal(s.box) && s.onBoxDHCP != nil {
				go s.onBoxDHCP()
			}
			return
		}
		if s.retour && !s.selfMACs[m.mac] {
			s.reply(m, dhcpNak, nil)
			return
		}
		want := m.reqIP
		if want == nil {
			want = m.ciaddr
		}
		if want == nil || want.Equal(net.IPv4zero) {
			return
		}
		if !s.usableLocked(want, m.mac) {
			s.reply(m, dhcpNak, nil)
			return
		}
		l := s.leases[m.mac]
		if l == nil {
			l = &dhcpLease{MAC: m.mac}
			s.leases[m.mac] = l
		}
		fresh := l.IP != want.String() || now.After(l.Expiry)
		l.IP, l.Expiry = want.String(), now.Add(dhcpLeaseTime)
		if m.host != "" {
			l.Host = m.host
		}
		s.reply(m, dhcpAck, want)
		if fresh {
			s.saveLocked()
			who := l.Host
			if who == "" {
				who = m.mac
			}
			logEvent(s.dir, "DHCP : "+l.IP+" attribuée à "+who)
		}
		if s.onLease != nil && !s.selfMACs[m.mac] {
			go s.onLease(m.mac, l.IP, l.Host)
		}

	case dhcpRelease:
		if l := s.leases[m.mac]; l != nil && l.IP == m.ciaddr.String() {
			l.Expiry = now
			s.saveLocked()
		}

	case dhcpDecline:
		if m.reqIP != nil {
			// Adresse déjà utilisée par un appareil en IP fixe.
			s.arp[m.reqIP.String()] = "conflit"
			if l := s.leases[m.mac]; l != nil && l.IP == m.reqIP.String() {
				delete(s.leases, m.mac)
			}
		}

	case dhcpInform:
		if !s.retour && m.ciaddr != nil && s.inSubnet(m.ciaddr) {
			s.reply(m, dhcpAck, nil)
		}
	}
}

// reply construit et envoie OFFER/ACK/NAK.
func (s *dhcpServer) reply(m *dhcpMsg, typ byte, yiaddr net.IP) {
	p := make([]byte, 240, 400)
	p[0], p[1], p[2] = 2, 1, 6
	copy(p[4:8], m.xid)
	binary.BigEndian.PutUint16(p[10:12], m.flags)
	if typ == dhcpAck && m.typ == dhcpInform {
		copy(p[12:16], m.ciaddr)
	} else if typ != dhcpNak && m.ciaddr != nil {
		copy(p[12:16], m.ciaddr)
	}
	if yiaddr != nil {
		copy(p[16:20], yiaddr.To4())
	}
	copy(p[28:44], m.chaddr)
	binary.BigEndian.PutUint32(p[236:240], 0x63825363)

	opt := func(code byte, v []byte) { p = append(p, code, byte(len(v))); p = append(p, v...) }
	u32 := func(d time.Duration) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(d/time.Second))
		return b
	}
	opt(53, []byte{typ})
	opt(54, s.self.To4())
	if typ != dhcpNak {
		router, dns := s.self, s.self
		if s.selfMACs[m.mac] || s.normal {
			router, dns = s.box, s.box // le PC lui-même sort par la box
		}
		if m.typ != dhcpInform {
			opt(51, u32(dhcpLeaseTime))
			opt(58, u32(dhcpLeaseTime/2))
			opt(59, u32(dhcpLeaseTime*7/8))
		}
		opt(1, []byte(s.mask))
		opt(3, router.To4())
		opt(6, dns.To4())
		bc := ip2u(s.self) | ^binary.BigEndian.Uint32(s.mask)
		opt(28, u2ip(bc))
	} else {
		opt(56, []byte("adresse refusee"))
	}
	p = append(p, 255)
	for len(p) < 300 {
		p = append(p, 0)
	}

	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	if typ != dhcpNak && m.ciaddr != nil && !m.ciaddr.Equal(net.IPv4zero) {
		dst.IP = m.ciaddr
	}
	_, _ = s.conn.WriteTo(p, dst)
}
