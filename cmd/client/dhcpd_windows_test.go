// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fakeConn capture les réponses du serveur DHCP.
type fakeConn struct {
	net.PacketConn
	out [][]byte
	dst []net.Addr
}

func (f *fakeConn) WriteTo(b []byte, a net.Addr) (int, error) {
	f.out = append(f.out, append([]byte(nil), b...))
	f.dst = append(f.dst, a)
	return len(b), nil
}
func (f *fakeConn) Close() error { return nil }

func dhcpPacket(typ byte, mac net.HardwareAddr, ciaddr, req, server net.IP, host string) []byte {
	p := make([]byte, 240)
	p[0], p[1], p[2] = 1, 1, 6
	copy(p[4:8], []byte{1, 2, 3, 4})
	if ciaddr != nil {
		copy(p[12:16], ciaddr.To4())
	}
	copy(p[28:34], mac)
	binary.BigEndian.PutUint32(p[236:240], 0x63825363)
	p = append(p, 53, 1, typ)
	if req != nil {
		p = append(p, 50, 4)
		p = append(p, req.To4()...)
	}
	if server != nil {
		p = append(p, 54, 4)
		p = append(p, server.To4()...)
	}
	if host != "" {
		p = append(p, 12, byte(len(host)))
		p = append(p, host...)
	}
	return append(p, 255)
}

// replyInfo extrait type, yiaddr et routeur d'une réponse.
func replyInfo(t *testing.T, b []byte) (byte, net.IP, net.IP) {
	t.Helper()
	if b[0] != 2 {
		t.Fatalf("op=%d", b[0])
	}
	var typ byte
	var router net.IP
	for i := 240; i < len(b) && b[i] != 255; {
		if b[i] == 0 {
			i++
			continue
		}
		l := int(b[i+1])
		switch b[i] {
		case 53:
			typ = b[i+2]
		case 3:
			router = net.IP(b[i+2 : i+6])
		}
		i += 2 + l
	}
	return typ, net.IP(b[16:20]), router
}

func TestDHCPServer(t *testing.T) {
	lan := lanAddr{Alias: "Ethernet", IP: "192.168.1.87", Prefix: 24, Box: "192.168.1.254"}
	prefer := map[string]string{"AA:BB:CC:DD:EE:01": "192.168.1.20"}
	s, err := newDHCPServer(t.TempDir(), lan, "192.168.1.1", "192.168.1.50", prefer, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeConn{}
	s.conn = fc
	srvIP := net.ParseIP("192.168.1.87")
	phone, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	tv, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	h := func(b []byte) {
		m, ok := parseDHCP(b)
		if !ok {
			t.Fatal("paquet illisible")
		}
		s.handle(m)
	}

	// 1. DISCOVER du téléphone -> OFFER de l'adresse qu'il avait (box).
	h(dhcpPacket(dhcpDiscover, phone, nil, nil, nil, "iPhone-de-Vico"))
	typ, yi, rt := replyInfo(t, fc.out[0])
	if typ != dhcpOffer || yi.String() != "192.168.1.20" || rt.String() != "192.168.1.87" {
		t.Fatalf("OFFER: type=%d ip=%s routeur=%s", typ, yi, rt)
	}
	// 2. REQUEST -> ACK, bail enregistré avec le nom.
	h(dhcpPacket(dhcpRequest, phone, nil, yi, srvIP, "iPhone-de-Vico"))
	typ, yi, rt = replyInfo(t, fc.out[1])
	if typ != dhcpAck || yi.String() != "192.168.1.20" || rt.String() != "192.168.1.87" {
		t.Fatalf("ACK: type=%d ip=%s routeur=%s", typ, yi, rt)
	}
	if l := s.leases["AA:BB:CC:DD:EE:01"]; l == nil || l.Host != "iPhone-de-Vico" || time.Until(l.Expiry) < 3*time.Minute {
		t.Fatalf("bail: %+v", l)
	}
	// 3. Autre appareil qui redemande l'adresse du téléphone -> NAK.
	h(dhcpPacket(dhcpRequest, tv, nil, net.ParseIP("192.168.1.20"), nil, ""))
	if typ, _, _ := replyInfo(t, fc.out[2]); typ != dhcpNak {
		t.Fatalf("conflit: type=%d", typ)
	}
	// 4. INIT-REBOOT de la TV avec son ancienne adresse libre -> ACK direct.
	h(dhcpPacket(dhcpRequest, tv, nil, net.ParseIP("192.168.1.33"), nil, "TV"))
	typ, yi, _ = replyInfo(t, fc.out[3])
	if typ != dhcpAck || yi.String() != "192.168.1.33" {
		t.Fatalf("init-reboot: type=%d ip=%s", typ, yi)
	}
	// 5. Adresse hors réseau -> NAK.
	h(dhcpPacket(dhcpRequest, tv, nil, net.ParseIP("10.0.0.5"), nil, ""))
	if typ, _, _ := replyInfo(t, fc.out[4]); typ != dhcpNak {
		t.Fatalf("hors réseau: type=%d", typ)
	}
	// 6. Le PC lui-même : garde son IP, avec la box comme passerelle.
	var selfMAC string
	for m := range s.selfMACs {
		selfMAC = m
		break
	}
	if selfMAC != "" {
		pm, _ := net.ParseMAC(selfMAC)
		h(dhcpPacket(dhcpRequest, pm, nil, srvIP, nil, ""))
		typ, yi, rt = replyInfo(t, fc.out[len(fc.out)-1])
		if typ != dhcpAck || !yi.Equal(srvIP) || rt.String() != "192.168.1.254" {
			t.Fatalf("PC: type=%d ip=%s routeur=%s", typ, yi, rt)
		}
	}
	// 7. Renouvellement unicast (ciaddr) -> ACK envoyé à l'appareil.
	n := len(fc.out)
	h(dhcpPacket(dhcpRequest, phone, net.ParseIP("192.168.1.20"), nil, nil, ""))
	if typ, _, _ := replyInfo(t, fc.out[n]); typ != dhcpAck || fc.dst[n].(*net.UDPAddr).IP.String() != "192.168.1.20" {
		t.Fatalf("renouvellement: type=%d dst=%v", typ, fc.dst[n])
	}
	// 8. Retour à la box : renouvellement -> NAK, DISCOVER ignoré.
	s.retour = true
	n = len(fc.out)
	h(dhcpPacket(dhcpRequest, phone, net.ParseIP("192.168.1.20"), nil, nil, ""))
	if typ, _, _ := replyInfo(t, fc.out[n]); typ != dhcpNak {
		t.Fatalf("retour: type=%d", typ)
	}
	h(dhcpPacket(dhcpDiscover, phone, nil, nil, nil, ""))
	if len(fc.out) != n+1 {
		t.Fatal("DISCOVER servi pendant le retour")
	}
}
